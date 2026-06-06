# @estates/trade — invariants (every claim is an executable test)

Tests live in `packages/trade/test/trade.test.ts`. Read a claim, find the test, try
to break it.

## Atomic execution

| # | Claim | Test |
|---|---|---|
| A1 | A fully co-signed trade is valid: the NFT is reassigned and sats paid | "fully co-signed trade is valid; NFT reassigned and sats paid" |
| A2 | Partial signing (counterparty declines) is invalid — nothing moves | "partial signing (counterparty declines) is invalid — nothing moves" |
| A3 | A two-NFT swap moves both deeds atomically (both or neither) | "two-NFT swap: both deeds change hands atomically" |

## Tamper resistance (anti-front-running)

| # | Claim | Test |
|---|---|---|
| T1 | Tampering with an output after signing invalidates the trade | "tampering with an output after signing invalidates the trade (anti-front-running)" |
| T2 | A wrong-key signature does not satisfy an input it does not own | "a wrong-key signature does not satisfy an input it does not own" |

## One-game binding (a trade moves only this game's NFTs)

| # | Claim | Test |
|---|---|---|
| G1 | `verifyTradeForGame` accepts a co-signed trade whose NFTs all belong to the game | "verifyTradeForGame accepts a co-signed trade whose NFTs all belong to the game" |
| G2 | `verifyTradeForGame` REJECTS a cross-game trade (a foreign-game NFT) | "verifyTradeForGame REJECTS a cross-game trade (a foreign-game NFT)" |
| G3 | A no-NFT (sats-only) trade and a bad gameId are rejected (fail closed) | "verifyTradeForGame rejects a no-NFT (sats-only) trade and a bad gameId" |

## Value conservation

| # | Claim | Test |
|---|---|---|
| V1 | `verifyTradeValue` checks conservation against REAL prev UTXO values + fee | "verifyTradeValue checks conservation against REAL prev UTXO values + fee" |
