# @estates/engine — invariants (every claim is an executable test)

Tests live in `packages/engine/test/engine.test.ts`. Read a claim, find the test,
try to break it.

## Determinism & construction

| # | Claim | Test |
|---|---|---|
| D1 | Initial state: seats funded, all titles with the bank, AWAIT_ROLL | "initial state: seats funded, all titles with the bank, AWAIT_ROLL" |
| D2 | Identical action sequences yield identical states | "determinism: identical action sequences yield identical states" |

## Fairness gate (live games)

| # | Claim | Test |
|---|---|---|
| F1 | `requireFairDecks` rejects missing/biased deckOrder, accepts a real permutation | "live-fairness gate: requireFairDecks rejects missing/biased deckOrder, accepts a real permutation" |

## Core money flows

| # | Claim | Test |
|---|---|---|
| B1 | Buy flow: roll to a property, BUY transfers deed + sats | "buy flow: roll to a property, BUY transfers deed + sats" |
| B2 | Decline returns the title to the bank (Phase-1 default) | "decline returns the title to the bank (Phase-1 default)" |
| B3 | Rent: landing on another seat's property pays derived rent | "rent: landing on another seat’s property pays derived rent" |
| B4 | Doubles grant another roll; three doubles send the seat to the Holding Yard | "doubles grant another roll; three doubles send the seat to the Holding Yard" |
| B5 | Salary: a card that advances past The Gate collects salary | "salary: a card that advances past The Gate collects salary" |
| B6 | Income levy: flat vs percent choice | "income levy: flat vs percent choice" |

## Building rules

| # | Claim | Test |
|---|---|---|
| H1 | Even-build is enforced and consumes house supply | "even-build is enforced and consumes house supply" |
| H2 | Cannot build without the full group | "cannot build without the full group" |
| H3 | Mortgage pays out, blocks build, and unmortgage costs the premium | "mortgage pays out, blocks build, and unmortgage costs the premium" |

## Conservation, liquidation, leaving

| # | Claim | Test |
|---|---|---|
| L1 | Raise-funds: a charge beyond cash auto-mortgages rather than bankrupting | "raise-funds: a charge beyond cash auto-mortgages rather than bankrupting" |
| L2 | Bankruptcy: insufficient even after liquidation removes the seat and ends the game | "bankruptcy: insufficient even after liquidation removes the seat and ends the game" |
| L3 | A player who leaves gives their money + titles to the leading player (who then wins) | "a player who leaves gives their money + titles to the leading player (who then wins)" |
| L4 | Leave in a 3-player game routes assets to the highest-worth remaining player; game continues | "leave in a 3-player game routes assets to the highest-worth remaining player; game continues" |

## Rejections

| # | Claim | Test |
|---|---|---|
| R1 | Wrong-phase actions are rejected, not applied | "wrong-phase actions are rejected, not applied" |
