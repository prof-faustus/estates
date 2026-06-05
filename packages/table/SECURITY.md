# @estates/table — security boundary

Reference cryptographic infrastructure: the live multiplayer protocol. Written so an
auditor can attack it. Anything here that is wrong is a vulnerability.

## What this package is

The table controller. Peers exchange **signed** messages over an **untrusted relay**;
every peer replays the relay's global message order through the pure engine, so all
clients stay byte-for-byte in lockstep. Dice come from a dealerless commit→reveal
beacon. The human host alone starts a game.

## Threat model

- The **relay is hostile**: arbitrary reorder / drop / replay / inject / fabricate of
  any frame, and arbitrarily malformed bytes.
- **Peers are hostile**: a peer may send any bytes, claim any `kind`/seat, sign a
  well-formed-but-semantically-hostile message (e.g. a `start` with a 1e9 seatCount),
  spoof another's seat, or try to forge a move / DoS a client.
- **Relay ordering is NOT authentication.** Authorship is proven only by an Ed25519
  signature over the canonical message.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `NetTable.rebuild` (the ordered log) | **Fully untrusted bytes** | Total: never throws, never mutates state on a malformed frame, never allocates unbounded. Each frame passes `decodeSigned` (shape) → signature check (authorship) → invariant checks (authority) before touching state. |
| `decodeSigned(bytes)` | **Fully untrusted** | Validates `kind` + EVERY field (type, int range 0..MAX, exact hex length, bounded `config`/`seatMap`/`name`) and returns null on anything unexpected. Never throws. **A valid signature does NOT bypass this** — it runs first. |
| `decodeAnnounce(bytes)` | **Fully untrusted** | Same, for lobby announcements. |
| `isAction`, `isEngineConfig` | **Fully untrusted** | Exact per-type validation; `seatCount`/`bankReserve`/`propertyId`/`seat`/`dice` bounded. |
| `send`, `createTable`, `join`, `start` | **Trusted** (our own outbound) | Sign with our key; construct canonical frames. |

## Protocol messages (each is a formal, signed object)

All carry `{ id, signPub (Ed25519 pub, 32B hex), sig (64B hex) }`. The signature
covers `signedBytes(msg, signPub) = JSON({ ...msg, signPub })`.

| kind | fields (validated bounds) | who signs | accepted only when |
|---|---|---|---|
| `table` | maxSeats (2..8), network, host | the host | first `table` wins; sets host = signer |
| `seat` | seat (0..7), who, name (≤256), bot | the seat's own key | not started, seat free, `who == signer`, signer holds no other seat |
| `start` | by, config (validated EngineConfig), seatMap[] | the host (signer == table host) | not started AND the bound seatMap == the claimed seats |
| `commit` | roll (0..1e6), seat (0..7), c (32B hex) | the seat's key | one commit per seat per roll |
| `reveal` | roll, seat, s (32B hex) | the seat's key | one reveal per seat per roll; opens its commitment |
| `action` | action (validated Action) | the ACTIVE seat (or the leaving seat for `LEAVE`) | game started; the engine accepts it |

## Invariants (each is a test — see INVARIANTS.md)

- **Authorship:** an unsigned / wrong-key / tampered message is dropped (relay order
  is not authentication).
- **Validity ≠ signature:** a validly-signed but malformed message (hostile config,
  unknown action, out-of-range seat, bad hex) is rejected by `decodeSigned` BEFORE
  the signature is checked and BEFORE any value reaches the engine.
- **No identity spoof:** a `seat` is accepted only if `who == signer`; one key holds
  one seat. `start` only from the table host, binding the exact seat map.
- **Beacon dice:** a `ROLL` is applied only from a verified commit→reveal set
  (`verifyRollEntry`); raw `submit(ROLL)` is a no-op.
- **Totality / DoS:** no frame — malformed, oversized, 1e9 counts, 100k fuzzed —
  makes `rebuild`/`decodeSigned` throw, hang, or forge state.

## What must never be assumed

- That a frame is well-formed because it is signed.
- That `config.seatCount`, `seat`, or `roll` are sane integers — all bounded.
- That `action`/`config`/`seatMap` are the shapes TypeScript claims — all re-validated
  at runtime.

## Known non-goals

- Relay-level metadata privacy (addresses + timing are visible; never plaintext game
  secrets — dice are beacon-committed, chat is encrypted in `@estates/chat`).
- Liveness against a peer that refuses to reveal (handled by the sidecar's stall path;
  the legacy relay table surfaces it to the human).
