# @estates/ledger — invariants (every claim is an executable test)

Tests live in `packages/ledger/test/ledger.test.ts` and
`packages/ledger/test/true-move.test.ts`. Read a claim, find the test, try to break
it.

## Move chain (the transcript is the txid sequence)

| # | Claim | Test |
|---|---|---|
| C1 | Genesis is a real tx with a real txid; output 0 is the move-chain cursor | "genesis is a real tx with a real txid; output 0 is the move-chain cursor" |
| C2 | Every move is a real tx that LINKS to the previous (chain of txids) | "every move is a real tx that LINKS to the previous (chain of txids)" |

## Genesis manifest integrity

| # | Claim | Test |
|---|---|---|
| G1 | `verifyGenesisManifest` accepts a fully-derived + certified genesis and rejects raw / reused / forged outputs | "verifyGenesisManifest: accepts a fully-derived+certified genesis, rejects raw/reused/forged" |

## True move (a transfer is a spend, not a copy)

| # | Claim | Test |
|---|---|---|
| M1 | A re-mint SPENDS the prior NFT outpoint as an input (Alice's output is consumed) | "a re-mint SPENDS the prior NFT outpoint as an input (Alice’s output is consumed)" |
| M2 | `verifyTrueMove` REJECTS a re-mint that fails to burn the prior output (a copy) | "verifyTrueMove REJECTS a re-mint that fails to burn the prior output (a copy)" |
| M3 | `MoveChain` tracks custody: each transfer burns the current output and the next burns the one after | "MoveChain tracks custody: each transfer burns the CURRENT output and the next burns the one after" |
| M4 | The FIRST mint of a title (no prior outpoint) is allowed without a burn | "the FIRST mint of a title (no prior outpoint) is allowed without a burn" |
