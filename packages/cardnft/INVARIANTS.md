# @estates/cardnft — invariants (every claim is an executable test)

Tests live in `packages/cardnft/test/cardnft.test.ts`. Read a claim, find the test,
try to break it.

## NFT identity

| # | Claim | Test |
|---|---|---|
| N1 | A card NFT is a real 1-sat UTXO: an outpoint + a 1-sat output whose script commits to (tableId, commitment, cardPub) and is locked to the owner | "a card NFT is a real 1-sat UTXO with an outpoint + identity-committing script" |

## True move (Alice → Bob)

| # | Claim | Test |
|---|---|---|
| M1 | A transfer SPENDS Alice's outpoint and creates Bob's successor 1-sat NFT (fresh key, same concealed identity) | "transfer SPENDS Alice's outpoint and creates Bob's successor 1-sat NFT (UTXO continuity)" |
| M2 | After transfer Alice's card is DEAD (`isLiveCard` false); Bob's is LIVE | "Alice's old card is DEAD after transfer; Bob's is LIVE" |

## Rejections (a copy is not a move)

| # | Claim | Test |
|---|---|---|
| R1 | A "transfer" that does NOT spend Alice's outpoint is rejected as a copy | "a \"transfer\" that does NOT spend Alice's outpoint is REJECTED as a copy" |
| R2 | A successor that reuses Alice's retired key, pays the wrong owner, or changes identity is rejected | "a successor that reuses Alice's retired key, wrong owner, or changed identity is REJECTED" |
| R3 | A spent card cannot be resurrected (spent outpoint stays dead) | "a SPENT card cannot be resurrected: a transcript with the retired key/outpoint is rejected" |

## Custody chain (whole-game transcript)

| # | Claim | Test |
|---|---|---|
| C1 | A whole chain (mint→Alice→Bob→Carol) is a sequence of true moves; the final live card is the last successor | "a whole custody chain (mint→Alice→Bob→Carol) is a sequence of true moves; final live card is Carol's" |
| C2 | The chain rejects re-spending an already-spent outpoint (resurrection/double-spend) | "the custody chain REJECTS a re-spend of an already-spent outpoint (resurrection)" |
| C3 | The chain rejects a transfer that does not spend the current live card | "the custody chain REJECTS a transfer that does not spend the current live card" |

## TEE (assumed OK per requirements)

| # | Claim | Test |
|---|---|---|
| T1 | A TEE deletion quote binds the retired key + the spent outpoint; a mis-bound/absent quote is rejected | "TEE deletion quote (assumed OK) binds the retired key + spent outpoint" |

## How to attack this package (auditor guide)

1. After a transfer, keep Alice's old `CardNft`, key, and blind and try to "use" it —
   confirm `isLiveCard(old, spentSet)` is false (M2/R3). If a retained copy is ever
   live, that is a finding.
2. Build a tx that mints Bob's output but spends some OTHER outpoint (not Alice's) →
   `verifyCardTransfer` must reject it (R1).
3. Make the successor reuse Alice's retired `cardPub`, or lock to a different pkh than
   the output pays, or change the commitment → rejected (R2).
4. Re-present a spent outpoint as if fresh → it stays in the spent set (R3).
5. Submit a TEE quote that does not bind this retired key / spent outpoint → rejected
   (T1). Remember the live-ownership guarantee is the UTXO spend, not the TEE.
6. Fuzz `verifyCardTransfer` with a malformed tx → it must return `{ok:false}`, never
   throw.
