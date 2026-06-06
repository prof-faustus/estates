# @estates/cardchain — invariants (every claim is an executable test)

Tests live in `packages/cardchain/test/cardchain.test.ts` (plus the genesis-mint test in
`packages/bank/test/bank.test.ts`). Read a claim, find the test, try to break it.

## Cards are full 1-sat NFT UTXOs

| # | Claim | Test |
|---|---|---|
| F1 | A deck is minted as real 1-sat card NFTs (bank-held): unique UTXOs + one-use keys; table-bound | "a deck is minted as REAL 1-sat card NFTs (bank-held): unique UTXOs + one-use keys" |
| F2 | Genesis can mint the Fate/Treasury decks as 12+12 concealed 1-sat card NFTs (bank-held) | "genesis can ALSO mint the Fate/Treasury decks as concealed 1-sat card NFTs (bank-held)" |

## A draw/pass SPENDS the outpoint + re-seals (the previous holder loses access)

| # | Claim | Test |
|---|---|---|
| D1 | A draw spends the bank card outpoint and re-seals to the player; the BANK loses access, the player gains it | "a DRAW spends the bank outpoint + re-seals to the player; the BANK loses access, the player gains it" |
| D2 | Alice→Bob spends Alice's outpoint, re-seals to Bob; Alice LOSES access, Bob gains it; the custody chain verifies | "Alice → Bob: spends Alice’s outpoint, re-seals to Bob; Alice LOSES access; the custody chain verifies" |

## No copy / double-spend / resurrection

| # | Claim | Test |
|---|---|---|
| R1 | A re-spend of an already-spent card (resurrection) is rejected by the custody chain | "a re-spend of an already-spent card (resurrection) is REJECTED by the custody chain" |

## Notes

- "Loses access" is proven by `openHeld(...)` returning `null` for the previous holder
  (and `non-null` = the exact face for the current holder) **after** the card is re-sealed
  to someone else — the spent outpoint plus the ECIES re-seal together mean the prior
  holder cannot read or re-use the card. The underlying NFT spend semantics (Alice's
  outpoint consumed → Bob's successor, copy/resurrection rejected) are additionally tested
  in `packages/cardnft/test/cardnft.test.ts`.
