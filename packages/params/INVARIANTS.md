# @estates/params — invariants (every claim is an executable test)

Tests live in `packages/params/test/params.test.ts`. Read a claim, find the test,
try to break it.

## Banned-construct gate (it must actually fail)

| # | Claim | Test |
|---|---|---|
| L1 | lint-bans passes on the clean tree (the gate is green) | "lint-bans passes on the clean tree (the gate is green)" |
| L2 | lint-bans FAILS on an OP_RETURN violation | "lint-bans FAILS on an OP_RETURN violation" |
| L3 | lint-bans FAILS on a branded string in content | "lint-bans FAILS on a branded string in content" |

## Source-of-truth + units

| # | Claim | Test |
|---|---|---|
| P1 | params version + unit | "params version + unit" |
| P2 | Starting balance, salary, seat bounds | "starting balance, salary, seat bounds" |

## Board & deck structure

| # | Claim | Test |
|---|---|---|
| B1 | Board has 40 spaces with sequential ids 0..39 | "board has 40 spaces with sequential ids 0..39" |
| B2 | Exactly 28 title-NFT spaces (22 properties + 4 stations + 2 utilities) | "exactly 28 title-NFT spaces (22 properties + 4 stations + 2 utilities)" |
| B3 | Group membership references real titled spaces of that group | "group membership references real titled spaces of that group" |
| B4 | Both card decks have 12 cards and exactly one Reprieve grant each | "both card decks have 12 cards and exactly one Reprieve grant each" |

## Derived economy (nothing stored twice)

| # | Claim | Test |
|---|---|---|
| E1 | Rent derivation — Tanyard Lane (base 60) | "rent derivation — Tanyard Lane (base 60)" |
| E2 | Station rent ladder 25/50/100/200 | "station rent ladder 25/50/100/200" |
| E3 | Utility rent = dice × {4 | 10} | "utility rent = dice × {4 | 10}" |
| E4 | Mortgage + unmortgage | "mortgage + unmortgage" |
| E5 | Build cost is per-group and matches the SoT | "build cost is per-group and matches the SoT" |
