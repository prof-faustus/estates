# @estates/chainmap — invariants (every claim is an executable test)

Tests live in `packages/chainmap/test/chainmap.test.ts`. Read a claim, find the
test, try to break it.

## Faithful engine ↔ NFT mapping

| # | Claim | Test |
|---|---|---|
| M1 | An unowned title maps to a 1-sat NFT held by the bank | "an unowned title maps to a 1-sat NFT held by the bank" |
| M2 | Engine title state round-trips through the NFT blob (build + mortgage reflected) | "engine title state round-trips through the NFT blob (build + mortgage reflected)" |
| M3 | `validateTitleSemantics`: every genesis title is semantically valid; mismatches rejected | "validateTitleSemantics: every genesis title is semantically valid; mismatches rejected" |

## Value-bearing legs

| # | Claim | Test |
|---|---|---|
| L1 | A buy emits NFT(bank→buyer) + price(→reserve) | "a buy emits NFT(bank→buyer) + price(→reserve)" |
| L2 | A build re-mints the NFT at the new level + pays the build cost | "a build re-mints the NFT at the new level + pays the build cost" |
| L3 | A mortgage re-mints with the flag set + pays the mortgage value to the owner | "a mortgage re-mints with the flag set + pays the mortgage value to the owner" |

## Custody (no reused static address)

| # | Claim | Test |
|---|---|---|
| K1 | The bank reserve leg is COVENANT-locked by default (no reused bankPkh) | "bank reserve leg is COVENANT-locked by default (no reused bankPkh)" |
| K2 | Quorum is opt-in: bankMode "quorum" pays the banker pkh (M-of-N) | "quorum is opt-in: bankMode \"quorum\" pays the banker pkh (M-of-N)" |
| K3 | Owned-title NFT custody uses the FRESH provider key, never the static seat pkh | "owned-title NFT custody uses the FRESH provider key, never the static seat pkh" |
| K4 | A bank-held (unowned) title NFT is covenant-locked, not bankPkh | "a bank-held (unowned) title NFT is covenant-locked, not bankPkh" |
