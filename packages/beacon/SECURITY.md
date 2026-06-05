# @estates/beacon — security boundary

Reference cryptographic infrastructure: **provably-fair dice** for live multiplayer,
with no dealer and no trusted RNG. Written so an auditor can attack it.

## What this package is

A two-phase commit→reveal dice beacon. Each roll:

1. **Commit:** every active seat publishes `c_i = SHA-256(secret_i)`.
2. **Reveal:** every seat reveals `secret_i`; a reveal that does not open its prior
   commitment (`verifyReveal`) is rejected.
3. **Derive:** the dice are a **debiased** map (rejection sampling over an
   HMAC-SHA256 counter PRF — modulo bias removed) of
   `H(reveal_1 ‖ … ‖ reveal_n ‖ turn_index ‖ prev_beacon)` into two integers in
   `[1..6]`. The output `beacon` becomes `prev_beacon` for the next roll, chaining
   all rolls into one verifiable transcript.

Reveals are folded in **canonical seat order**, so the result is independent of
network arrival order.

## The property this exists to guarantee

> No single seat (or coalition short of everyone) can steer the dice, and the whole
> dice history is independently verifiable by anyone.

- **Unbiasable** iff ≥1 honest seat commits before any reveal: because each seat is
  bound by its commitment before any secret is revealed, no seat can choose its
  secret as a function of the others — changing any single reveal changes the seed
  unpredictably (hash pre-image resistance). A coalition that controls all but one
  seat still cannot predict or steer the honest seat's contribution.
- **No modulo bias:** rejection sampling makes each face in `[1..6]` equiprobable —
  a plain `H mod 6` would skew toward low faces.
- **Replay-bound:** `turn_index` and `prev_beacon` are folded in, so the same
  reveals cannot be replayed at a different turn or on a different chain to force a
  known roll.
- **Liveness vs. grief:** a seat that commits but withholds its reveal is dropped on
  timeout; the roll still stands as long as ≥1 honest reveal remains, so a single
  non-revealer cannot stall the game — yet cannot bias it either (it was committed).

## Threat model

- A seat tries to pick its secret after seeing others' reveals → impossible; it is
  bound by its earlier commitment (`verifyReveal` rejects a non-opening reveal).
- A seat forges a reveal that does not match its commitment → rejected.
- A coalition tries to make a single seat's contribution decide the dice → changing
  any one reveal changes the seed (no seat can steer).
- Replay of a prior roll's reveals at another turn / chain to force a known result →
  differs (turn_index + prev_beacon binding).
- A committed non-revealer griefs the roll → dropped on timeout; roll stands.

## What this package does NOT do

- It does not transport the commits/reveals — that is the table/relay layer
  (`@estates/table`), which binds each commit/reveal to its seat's one-game key.
- It does not decide *when* the reveal window closes (timeout policy) — the caller
  supplies the live seat set; the beacon only refuses to use a non-opening reveal.
