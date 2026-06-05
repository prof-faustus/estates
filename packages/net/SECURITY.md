# @estates/net — security boundary

Reference cryptographic infrastructure: the **untrusted-relay transport** (C7). A relay
orders and fans out opaque byte payloads; canonical game state is derived purely by
replaying the ordered transcript through the engine. Written so an auditor can attack it.

## What this package is

- `Relay` — an opaque contract: `publish(payload)` assigns a sequence and fans out;
  `subscribe(onMessage, fromSeq)` replays history then streams live; it never interprets
  payloads. `InMemoryRelay` is the reference/test double for the production HTTP+SSE relay.
- `PeerSession` — a peer's deterministic view. It `ingest`s payloads, applying one iff it
  decodes AND is the next ordered entry. A roll's dice are re-derived from its reveals via
  the SAME `verifyRollEntry` the auditor uses, so a malicious relay can at worst
  censor/reorder — it cannot forge state.

Wire payloads are JSON `Envelope { seq, entry }`, where `entry` is a `roll` (commitments,
reveals, dice) or an `action`.

## Threat model

The relay AND every publishing peer are **fully hostile**. A payload may be:

- non-JSON, or valid JSON that is `null`/a scalar/an array;
- a validly-shaped envelope with a hostile `seq` (negative, `1e12`) or a hostile entry:
  unknown `kind`, an unknown/`__proto__`/out-of-range `action`, non-array `commits`,
  **non-hex `c`/`secret` that would throw inside `fromHex`**, or an oversized
  commit/reveal list (memory exhaustion);
- delivered out of order / replayed.

A subscriber callback may itself throw; that must not break fan-out to honest peers.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `decodeEnvelope(payload)` | **Fully untrusted** | **Total.** Caps size (≤1 MiB), parses JSON in a guard, requires an object, validates `seq` (int 0..1e9) and the full `entry` (kind, bounded `action`, bounded seat-keyed hex lists of length ≤ 8, 32-byte hex, in-range dice). Returns `null` on anything unexpected. NEVER throws. |
| `PeerSession.ingest` | **Fully untrusted** | Routes through `decodeEnvelope`; applies only the next in-order entry; `applyEntry` runs in `try/catch` (defence in depth around `fromHex`/engine). Never throws; never advances state on a bad payload. |
| `PeerSession.applyEntry` | **Validated input** | A roll is applied only via `verifyRollEntry` (commitments + participant set + openings + canonical dice) — identical to `@estates/audit`; the live path is no laxer. |
| `InMemoryRelay.publish`/`subscribe` | **Untrusted handlers** | Each subscriber dispatch is isolated in `try/catch`, so one throwing subscriber cannot break fan-out or the publisher. `fromSeq` is bounded to a non-negative integer. |
| `broadcast` | **Trusted** (our own outbound) | Encodes our envelope. |

## Invariants (each is a test — see INVARIANTS.md)

- **Decode is total:** `decodeEnvelope` accepts valid envelopes and rejects every hostile
  payload (non-JSON, scalar, bad seq, unknown kind, non-array/non-hex/oversized roll,
  bad action) — without throwing.
- **No forged state:** `ingest` never advances state on a hostile/out-of-order payload;
  rolls are applied only from a verified commit→reveal transcript.
- **Fan-out isolation:** a throwing subscriber, or a hostile payload, never breaks
  delivery to honest peers.
- **DoS resistance:** 100k random payloads never make `decodeEnvelope` throw or hang.

## What must never be assumed

- That a payload is JSON, an object, or has a sane `seq`.
- That `commits`/`reveals` are arrays of valid-hex entries — `fromHex` would throw on bad
  hex, so the hex is validated at decode, before `fromHex` ever runs.
- That a subscriber callback is well-behaved.

## Known non-goals

- Relay-level metadata privacy (ordering/timing is visible; dice are beacon-committed and
  chat is encrypted elsewhere).
- Liveness against a censoring relay (a peer can reconnect/replay history elsewhere; the
  relay cannot forge state, only withhold it).
