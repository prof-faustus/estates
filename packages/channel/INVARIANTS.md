# @estates/channel — invariants (every claim is an executable test)

Tests live in `packages/channel/test/channel.test.ts`. Read a claim, find the test, try
to break it.

## Mutual authentication & key agreement

| # | Claim | Test |
|---|---|---|
| A1 | Both peers derive the SAME session key and learn each other's verified identity | "handshake: both peers derive the SAME session key and learn each other's identity" |
| A2 | A forged/tampered/odd-hex/wrong-identity Hello is rejected (identity not proven) | "a forged/tampered hello is rejected (identity not proven)" |
| A3 | Substituting the ephemeral key breaks the identity→ephemeral binding (no MITM) | "MITM cannot derive the session: substituting the ephemeral key breaks the identity binding" |
| A4 | An Ack is bound to the initiator's ephemeral key (no cross-session replay) | "an Ack is bound to the initiator's ephemeral key (no cross-session replay)" |

## Confidentiality & integrity of frames

| # | Claim | Test |
|---|---|---|
| C1 | Frames round-trip both directions; the wire carries only ciphertext | "authenticated frames round-trip both directions; the relay sees only ciphertext" |
| C2 | A frame cannot be opened with the wrong session key | "a frame cannot be opened with the wrong session key" |

## Totality / DoS resistance

| # | Claim | Test |
|---|---|---|
| V1 | A validly-SIGNED Hello carrying an OFF-CURVE ephemeral key returns null, never throws | "a VALIDLY-SIGNED hello carrying an OFF-CURVE ephemeral key returns null, never throws (remote-DoS #1)" |
| V2 | null/array/scalar/garbage handshakes never throw | "respond/complete are TOTAL: null/array/scalar/garbage handshakes never throw" |
| V3 | 50k random Hellos never throw or hang | "respond/complete are FUZZ-PROOF: 50k random hellos never throw" |

## How to attack this package (auditor guide)

1. Sign a Hello honestly with your own identity key, but set `ephPub` to 33 bytes of an
   off-curve point. `respond` must return `null` — if it throws (ECDH "point not on
   curve"), that is an unauthenticated remote-crash finding (V1).
2. Send `null`, `42`, `[]`, `{}`, or fields of the wrong type/length → `null`, no throw (V2).
3. Take a real Hello, swap in a different ephemeral key → rejected: the identity sig no
   longer matches (A3). Try to keep the sig and change `idPub` → rejected (A2).
4. Capture an Ack and replay it into a second `initiate()` session → rejected (A4).
5. Re-seal a frame under a different key, or flip a ciphertext byte → `openFrame` returns
   `null` (GCM tag fails), never throws (C2).
6. Fuzz `respond`/`complete` with random hex blobs (V3). Any throw/hang is a finding.
