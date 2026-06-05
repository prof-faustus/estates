# @estates/wallet — invariants (every claim is an executable test)

Tests live in `packages/wallet/test/wallet.test.ts`. Read a claim, find the test,
try to break it.

## Key material

| # | Claim | Test |
|---|---|---|
| K1 | Real addresses carry the right network version bytes (mainnet vs testnet) | "real addresses: mainnet vs testnet version bytes" |
| K2 | `fromWif` round-trips to the same address + private key | "fromWif round-trips to the same address + private key" |

## Signing (self-verified)

| # | Claim | Test |
|---|---|---|
| S1 | Build + sign a real BIP-143 P2PKH tx — and the wallet SELF-VERIFIES it (script-valid) | "build + sign a real BIP-143 P2PKH tx — and the wallet SELF-VERIFIES it (script-valid)" |

## No stranded value

| # | Claim | Test |
|---|---|---|
| V1 | `drainTo` refunds the FULL balance (minus fee) to one address — nothing stranded | "drainTo refunds the FULL balance (minus fee) to one address — nothing stranded" |

## Money guards

| # | Claim | Test |
|---|---|---|
| G1 | Mainnet is refused without confirmation; regtest needs an rpc url | "money guards: mainnet refused without confirm; regtest needs an rpc url" |
