# @estates/channel — security boundary

Reference cryptographic infrastructure: the **mutually-authenticated, forward-secret
session handshake** (BRC-103 style) that two peers run over a raw socket before any
game traffic. Written so an auditor can attack it. Anything here that is wrong is a
vulnerability.

## What this package is

A pure, isomorphic (@noble) handshake + authenticated framing:

```
initiate() ── Hello{idPub, ephPub, nonce, signPub, sig} ─▶ respond()
complete() ◀─ Ack{idPub, ephPub, nonce, signPub, sig} ──── (responder)
session.key = HKDF-SHA256( ECDH(myEph, theirEph).x , "estates-channel-v1" )
```

The identity signature (secp256k1 ECDSA over `SHA256("hello"‖ephPub‖nonce‖signPub)`)
binds each party's long-term identity key to its **ephemeral** ECDH key (no MITM) and
vouches for the party's Ed25519 **signing** key. The Ack additionally binds to the
initiator's ephemeral key (no cross-session replay). Frames are AES-256-GCM.

## Threat model

The peer is **fully hostile** and supplies the entire Hello/Ack as untrusted bytes:

- arbitrary / missing / wrong-typed fields, non-hex, odd-length hex, over/under-length keys;
- a JSON scalar/`null` where an object is expected;
- a **validly-signed** Hello whose `ephPub` is an *off-curve* point (the signature
  covers a hash, so a peer can sign over arbitrary ephPub bytes with their own honest
  identity key) — the ECDH must not crash on it;
- substituting a different ephemeral key under someone else's identity (MITM);
- replaying an Ack into a different session;
- opening a frame with the wrong key.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `respond(id, hello)` | **Fully untrusted** | **Total.** Validates the Hello, runs ECDH, and returns `{ack, session}` or `null`. NEVER throws — not on a non-object, bad hex, wrong key length, a forged signature, **or an off-curve ephemeral key**. |
| `complete(pending, ack)` | **Fully untrusted** | Same, for the Ack; additionally rejects an Ack not bound to our ephemeral key (anti-replay). NEVER throws. |
| `openFrame(session, frame)` | **Fully untrusted** | Returns the plaintext or `null`; never throws on a malformed/forged frame (GCM auth-tag failure → null). |
| `initiate`, `seal`, `signData` | **Trusted** (our own keys) | Construct outbound messages/frames with our keys. |

## The off-curve trap (why ECDH sits inside the guard)

A valid identity signature proves the *signer*, NOT that `ephPub` is a curve point —
`verify()` checks the ECDSA over a hash that merely *contains* the ephPub bytes. The
ephemeral key only becomes a curve point at `sessionKey()` (`secp.getSharedSecret`),
where @noble throws on a bad point. So **every crypto operation after field decode runs
inside a `try/catch` returning `null`**, not just `hexToBytes`. Otherwise a single
unauthenticated handshake message crashes the listening node (remote DoS).

## Invariants (each is a test — see INVARIANTS.md)

- **Mutual auth:** both peers derive the identical session key and learn each other's
  verified identity; a forged/tampered/odd-hex/wrong-identity Hello is rejected.
- **No MITM:** substituting the ephemeral key breaks the identity→ephemeral binding.
- **No replay:** an Ack is bound to the initiator's ephemeral key; a replayed Ack into a
  second session is rejected.
- **Confidentiality/integrity:** frames round-trip both ways; the wire is ciphertext; a
  frame cannot be opened with the wrong key.
- **Totality / DoS:** `respond`/`complete` never throw — not on a `null`/scalar/garbage
  handshake, not on a validly-signed off-curve ephemeral key, not on 50k fuzzed Hellos.

## What must never be assumed

- That a signed Hello has a well-formed or on-curve ephemeral key.
- That `idPub`/`ephPub`/`signPub`/`sig` are valid hex of the right length — all re-checked.
- That `verify` passing means the ECDH inputs are safe — it does not; the ECDH is guarded.

## Known non-goals

- Hiding the fact that a handshake occurred / identity pubkeys (visible on the wire).
- Post-quantum security (secp256k1 ECDH + ECDSA, Ed25519).
- Anti-DoS at the connection-rate level (handled by the transport / OS, not here).
