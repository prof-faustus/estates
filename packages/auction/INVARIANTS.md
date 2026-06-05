# @estates/auction — invariants (every claim is an executable test)

Tests live in `packages/auction/test/auction.test.ts`. Read a claim, find the test,
try to break it.

## Sealed-bid concealment & binding

| # | Claim | Test |
|---|---|---|
| C1 | commit/reveal round-trip; a forged reveal (wrong bid) is invalid | "commit/reveal round-trip; forged reveal (wrong bid) is invalid" |
| C2 | The commitment hides the bid (different bids → different commitments) | "sealed: the commitment hides the bid (different bids -> different commits)" |
| C3 | A reveal not matching its commitment cannot steal the win | "a reveal not matching its commitment cannot steal the win" |

## Deterministic resolution

| # | Claim | Test |
|---|---|---|
| R1 | The highest valid bid wins; losers reported | "highest valid bid wins; losers reported" |
| R2 | Ties break to the lowest seat | "ties break to the lowest seat" |
| R3 | A committed non-revealer is dropped; a revealed lower bid then wins | "committed non-revealer is dropped; a revealed lower bid then wins" |
| R4 | No valid bids → unsold (returns to bank) | "no valid bids -> unsold (returns to bank)" |

## Input validation

| # | Claim | Test |
|---|---|---|
| V1 | Bids must be non-negative integers; nonce must be ≥16 bytes | "bids must be non-negative integers; nonce must be ≥16 bytes" |
