# @estates/beacon — invariants (every claim is an executable test)

Tests live in `packages/beacon/test/beacon.test.ts`. Read a claim, find the test,
try to break it.

## Commitment binding

| # | Claim | Test |
|---|---|---|
| B1 | `commit`/`verifyReveal` round-trip; a forged reveal (wrong secret) is rejected | "commit / verifyReveal round-trip; forged reveal rejected" |

## Well-formed output

| # | Claim | Test |
|---|---|---|
| O1 | Dice are always in `[1..6]` and the total in `[2..12]` | "dice are always in [1..6] and total in [2..12]" |
| O2 | Rough uniformity: each face appears across many rolls (no degenerate output) | "rough uniformity: each face appears across many rolls (no degenerate output)" |

## Determinism & order-independence

| # | Claim | Test |
|---|---|---|
| D1 | Same reveals + turn + prev_beacon yield the same roll | "determinism: same reveals + turn + prev_beacon yield the same roll" |
| D2 | Reveal order does not matter (canonical by seat) | "reveal order does not matter (canonical by seat)" |

## Unbiasable & replay-bound

| # | Claim | Test |
|---|---|---|
| U1 | Changing any single reveal changes the seed — no seat can steer the dice | "unbiasable: changing any single reveal changes the seed (no seat can steer)" |
| U2 | prev_beacon chaining: the same reveals at the same turn differ across chains | "prev_beacon chaining: same reveals at the same turn differ across chains" |
| U3 | turn_index binds the roll: replay across turns differs | "turn_index binds the roll (replay across turns differs)" |

## Liveness vs. griefing

| # | Claim | Test |
|---|---|---|
| L1 | A committed non-revealer is dropped on timeout; the roll stands on the honest reveal | "timeout default: a committed non-revealer is dropped; roll stands on the honest reveal" |
