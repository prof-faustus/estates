# @estates/sidecar — security boundary

Reference cryptographic infrastructure: the **peer-to-peer game transport** that runs
a full ESTATES game over a single direct socket between two players, with no relay and
no server. Written so an auditor can attack it. Anything here that is wrong is a
vulnerability.

## What this package is

`GamePeer` drives one seat of a two-party game over a `@estates/link` `PeerLink` (an
authenticated, framed TCP channel). Each peer:

- signs every move it makes with its own Ed25519 player key,
- runs a dealerless commit→reveal **beacon** for dice (neither peer can choose the
  roll),
- binds each move to the on-chain output-key manifest (`pkhs`) it will spend to,
- replays the identical ordered move stream through the pure `@estates/engine`, so both
  peers stay byte-for-byte in lockstep.

The wire carries four frame types only: `bc` (beacon commit), `br` (beacon reveal),
`move` (a signed action, optionally with its beacon transcript + pkhs manifest), and
`chat` (an end-to-end encrypted `@estates/chat` envelope).

## Threat model

The peer on the other end of the socket is **fully hostile**. It may:

- send arbitrary bytes, non-JSON, truncated/oversized frames;
- send a validly-shaped frame whose contents are semantically hostile — an unknown
  action `type`, out-of-range `dice`, a 1e12 turn counter, a beacon with non-hex
  fields, a `pkhs` manifest with thousands of entries or non-hex values;
- send a correctly-**signed** move whose dice were *chosen* rather than derived from
  the revealed beacon secrets;
- send a correctly-signed move whose on-wire `pkhs` differ from the manifest the
  signature actually committed to (output-key swap);
- spam any frame type to try to crash, hang (DoS), or corrupt the peer's state.

**A valid signature proves authorship, never well-formedness.** `decodeFrame` proves
well-formedness, and it runs *before* the signature is checked and *before* any value
reaches the engine.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `GamePeer.recv` (every inbound frame) | **Fully untrusted bytes** | Total: never throws, never advances/mutates state on a malformed or hostile frame, never allocates unbounded. Each frame passes `decodeFrame` (shape) → signature check (authorship) → beacon/pkhs binding (authority) → `apply` (in `try/catch`) before any state change. |
| `decodeFrame(bytes)` | **Fully untrusted** | Parses JSON in a guard, validates `t` and EVERY field of the matched frame type (int ranges 0..MAX, exact hex byte-lengths, bounded `beacon`, bounded `pkhs` map). Returns `null` on anything unexpected. **Never throws.** Sub-objects are validated *in place* so the exact bytes the signature covered are preserved. |
| `isAction(x)` | **Fully untrusted** | Exact per-type validation; `ROLL.dice` each 1..6, `propertyId`/`amount`/`seat` bounded; rejects unknown/`__proto__`/non-object shapes. |
| `isBeaconTranscript(x)` | **Fully untrusted** | `cm/cp/sm/sp` each exactly 32-byte hex; `seatM`/`seatP` bounded seat indices. |
| `isPkhs(x)` | **Fully untrusted** | A map of at most `SC_MAX_PKHS` (64) entries, each value exactly 20-byte hex. |
| `verifyRollBeacon` | **Trusted check** | A `ROLL` is applied only if the transcript's revealed secrets hash to its commitments AND the engine's beacon of those secrets equals the move's dice. A chosen-dice `ROLL` is rejected. |
| `send`, `takeTurn`, `chat` | **Trusted** (our own outbound) | Sign with our key; construct canonical frames. |

## Bounds (no attacker-controlled allocation)

| Constant | Value | Guards against |
|---|---|---|
| `SC_MAX_SEATS` | 8 | seat-index overrun |
| `SC_PROP_MAX` | 39 | property-id overrun |
| `SC_MAX_ROLL` | 1_000_000 | unbounded beacon round counter |
| `SC_MAX_PKHS` | 64 | oversized output-key manifest |
| `SC_ED_SIG` | 64 B | signature-length confusion |
| `SC_SHA256` | 32 B | commitment/secret-length confusion |

`@estates/link` enforces the frame-size cap (`1<<20`) before bytes reach `recv`.

## Invariants (each is a test — see INVARIANTS.md)

- **Authorship:** a forged / wrong-key / tampered move is dropped.
- **Validity ≠ signature:** a validly-signed but malformed frame (unknown action,
  out-of-range dice, malformed beacon, oversized/non-hex pkhs) is rejected by
  `decodeFrame` before the signature is checked and before any value reaches the engine.
- **Beacon dice:** a `ROLL` is applied only from a verified commit→reveal transcript;
  chosen dice (`dice ≠ beacon(secrets)`) are rejected.
- **Manifest binding:** the signed payload commits to the `pkhs` manifest; an on-wire
  manifest that differs from the signed one is rejected (output-key swap defeated).
- **Totality / DoS:** no frame — malformed, oversized, 1e12 counters, 100k fuzzed — makes
  `recv`/`decodeFrame` throw, hang, or advance state.

## What must never be assumed

- That a frame is well-formed because it is signed.
- That `action`, `beacon`, or `pkhs` are the shapes TypeScript claims — all re-validated
  at runtime.
- That `dice`, `turn`, `seatM/seatP`, or the `pkhs` size are sane — all bounded.
- That a signed `ROLL`'s dice are honest — they must equal the beacon of the revealed
  secrets.

## Known non-goals

- Socket-level metadata privacy (addresses + timing are visible; game secrets are not —
  dice are beacon-committed, chat is encrypted in `@estates/chat`).
- Liveness against a peer that connects then refuses to reveal/move (surfaced to the
  human as a stalled turn; no state is forged in the meantime).
