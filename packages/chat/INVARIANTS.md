# @estates/chat — invariants (every claim is an executable test)

Tests live in `packages/chat/test/chat.test.ts` (+ `live.test.ts` for the HTTP
relay). Read a claim, find the test, try to break it.

## Confidentiality & access control

| # | Claim | Test |
|---|---|---|
| C1 | Every intended recipient decrypts; a non-member cannot | "broadcast encryption: every recipient decrypts; a non-member cannot" |
| C2 | Revoking a recipient makes the next envelope unreadable to them | "revocation: dropping a recipient makes the next envelope unreadable" + "revoked member stops receiving …" |
| C3 | The relay only ever sees ciphertext | "the relay only sees ciphertext (never plaintext)" |
| C4 | A late joiner cannot read pre-join history | "forward access control: a late joiner cannot read messages sent before it joined" |
| C5 | 2-party (`postTo`) is readable only by the chosen member + sender | "2-party ECDH (postTo): only the chosen member (+ sender) can read" |

## Integrity & identity

| # | Claim | Test |
|---|---|---|
| I1 | A tampered ciphertext fails AEAD and yields null (no forged plaintext) | "tampered ciphertext fails to decrypt (AES-GCM auth)" |
| I2 | A `join` is accepted only if `address == ripemd160(sha256(pub))` (no identity spoof) | "ingest is FAIL-CLOSED …" (spoofed address rejected; correct join accepted) |
| I3 | Address binds the pubkey deterministically | "Bitmessage-style address is deterministic and binds the pubkey" |

## Totality / DoS resistance (untrusted bytes)

| # | Claim | Test |
|---|---|---|
| V1 | `isHex` rejects non-string / odd-length / wrong-length / over-ceiling | "isHex validates type, even-length, exact-length, and bounds" |
| V2 | `isEnvelope` rejects every malformed shape (no unchecked deref) | "isEnvelope rejects every malformed shape" |
| V3 | `decryptBroadcast` never throws on any malformed envelope | "decryptBroadcast is TOTAL: never throws on any malformed/hostile envelope" |
| V4 | `ingest` never throws and never mutates the member set on hostile frames | "ingest is FAIL-CLOSED: hostile frames never throw, never mutate the member set" |
| V5 | The decoder survives 50k random byte/JSON frames with no throw/hang | "decoder is FUZZ-PROOF: 50k random byte/JSON frames never throw or hang" |

## How to attack this package (auditor guide)

1. Publish raw bytes to the relay that a `ChatRoom` is subscribed to:
   - non-JSON, `null`, `42`, `"str"`, `[]` → must be ignored, no throw (V4).
   - `{kind:'chat', from:'aa…', env:{}}` (the historical crash) → ignored (V3/V4).
   - `{kind:'join', address:<X>, pub:<key>}` where `ripemd160(sha256(pub)) != X`
     → must NOT become a member (I2). If it does, identity is forgeable — a finding.
2. Send an `Envelope` with `recipients` = a 1e9-length array or a 1 GiB `ct` → must
   be rejected by `isEnvelope` (bounded; no allocation) — else a DoS finding.
3. Flip any byte of a real `ct` → `decryptBroadcast` must return null (I1).
4. Fuzz `ingest` with arbitrary bytes (V5). Any throw / hang / forged member is a
   finding.
