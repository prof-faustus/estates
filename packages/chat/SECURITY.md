# @estates/chat — security boundary

Reference cryptographic infrastructure. This document is written so an auditor or
attacker can find a flaw fast. If anything here is wrong, it is a vulnerability.

## What this package is

Multiparty membership + **end-to-end-encrypted** chat over an **untrusted relay**.
Peers announce a Bitmessage-style address (`ripemd160(sha256(pub))`) + public key;
chat bodies are multi-recipient ECIES (`encryptBroadcast`) so the relay and
non-members see only ciphertext. Isomorphic (`@noble`, `fetch`/SSE).

## Threat model

- The **relay is hostile**: it may reorder, drop, replay, inject, or fabricate any
  frame, and may send arbitrarily malformed bytes.
- **Peers are hostile**: a peer may send any bytes claiming any `kind`, spoof an
  address, forge an envelope, or try to DoS a client.
- Assume a funded adversary actively trying to crash a client, poison membership,
  read others' messages, or forge a message.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `ChatRoom.ingest` (every inbound frame) | **Fully untrusted** | Total: never throws, never mutates state on malformed input. All bytes pass `decodeNetMsg` first. |
| `decodeNetMsg(bytes)` | **Fully untrusted** | Validates `kind` + every field (type, hex, exact length, bounded name, ≤1 MiB frame) before returning; `null` on anything unexpected. Never throws. |
| `isEnvelope` / `isHex` | **Fully untrusted** | Structural type-guards; bound sizes (≤1 MiB ct, ≤4096 recipients) so no hostile input forces a large allocation. |
| `decryptBroadcast(env, me)` | **Fully untrusted** `env` | Total: validates the envelope, then AEAD-decrypts; returns `null` on malformed / not-addressed / tampered. Never throws, never returns forged plaintext. |
| `encryptBroadcast`, `post`, `join` | **Trusted** (our own outbound) | Construct well-formed frames. |

## Invariants (each is a test — see INVARIANTS.md)

- **Identity binding:** a `join` is accepted only if `address == ripemd160(sha256(pub))`.
  A peer cannot register an address it does not hold the key for.
- **Confidentiality:** the relay only ever sees ciphertext; a non-recipient (or a
  revoked member) gets `null`. Forward access control: a late joiner cannot read
  pre-join history.
- **Integrity / unforgeability:** a tampered ciphertext fails the AES-256-GCM tag
  and yields `null` — never forged plaintext.
- **Totality (DoS / crash resistance):** no byte string — malformed JSON, wrong
  types, missing fields, malformed envelope, oversized frame, 50k fuzzed inputs —
  can make the receive path throw, hang, or mutate the member set.

## What must never be assumed

- That a frame's `kind` or fields exist or have the right type/length — all checked.
- That an `Envelope`'s `recipients` is an array or its hex fields are well-formed.
- That the relay delivers our frames unaltered (we authenticate by address-binding
  + AEAD, not by trusting the transport).

## Known non-goals

- Metadata privacy at the relay (who talks to whom / when) — out of scope; the relay
  sees addresses and timing, never plaintext.
- Replay suppression at the chat layer (a relayed duplicate decrypts to the same
  text; the game/transcript layer handles ordering/replay).
