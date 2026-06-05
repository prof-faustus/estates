# @estates/auction — security boundary

Reference cryptographic infrastructure: a **sealed-bid auction** (commit→reveal),
mirroring the dice beacon. Written so an auditor can attack it.

## What this package is

Two phases per auction:
1. **Commit:** each seat publishes `c = SHA-256(bid ‖ nonce ‖ seat)` — the bid is
   concealed (sealed-bid) and bound to the seat.
2. **Reveal:** each seat reveals `(bid, nonce)`; a reveal that does not open its
   commitment is dropped.

The **highest valid revealed bid wins**; ties break to the lowest seat. A commitment
with no valid reveal is dropped (timeout default). If there are no valid bids, the
property is unsold and returns to the bank. The winner pays its bid to the bank
reserve and receives the 1-sat title NFT (atomic settle — `@estates/trade` tx shape).

## The properties this exists to guarantee

> 1. Bids are concealed until reveal (no one bids against a known bid).
> 2. The bid is bound to its bidder and amount — it cannot be changed after commit.
> 3. The highest valid bid wins deterministically; griefing cannot steal it.

- **Sealed:** the commitment hides the bid (different bids → different commitments,
  pre-image resistance), so no seat can react to another's amount.
- **Binding:** a reveal that does not match its commitment is invalid and cannot
  steal the win; the seat is folded into the hash, so a bid cannot be re-attributed.
- **Deterministic resolution:** highest valid bid wins; ties → lowest seat; a
  committed non-revealer is dropped and a revealed lower bid then wins.
- **Input validation:** bids must be non-negative integers and the nonce must be
  ≥16 bytes (a weak/short nonce would weaken concealment).

## Threat model

- A seat waits to see others' bids before choosing its own → impossible; bids are
  committed before any reveal.
- A seat reveals a different bid than it committed to (to win or to grief) → the
  non-opening reveal is invalid and ignored.
- A seat commits then withholds its reveal to stall → dropped on timeout; the
  auction resolves on the remaining valid bids.
- A degenerate input (negative/non-integer bid, short nonce) → rejected.

## What this package does NOT do

- It does not move money or the NFT — settlement is the atomic trade
  (`@estates/trade`) paying the bid to the reserve (`@estates/bank`) and delivering
  the title NFT. It decides the winner and price only.
