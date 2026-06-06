# @estates/lobby — invariants (every claim is an executable test)

Tests live in `packages/lobby/test/lobby.test.ts`. Read a claim, find the test, try
to break it.

## Seating

| # | Claim | Test |
|---|---|---|
| S1 | Join assigns the lowest free seat; double-join rejected; full lobby rejected | "join assigns the lowest free seat; double-join rejected; full lobby rejected" |
| S2 | Only the authority may fill a bot, and the policy must be valid | "only the authority may fill a bot, and the policy must be valid" |

## Start gate (authority + quorum + human)

| # | Claim | Test |
|---|---|---|
| G1 | START requires authority, ≥2 seats, ≥1 human, and (non-override) all ready | "START requires authority, ≥2 seats, ≥1 human, and (non-override) all ready" |
| G2 | All-bots is rejected (need a human); non-authority START rejected | "all-bots is rejected (need a human); non-authority START rejected" |
| G3 | START emits an EngineConfig seeded by the banker buy-in (same model on regtest) | "START emits an EngineConfig seeded by the banker buy-in — SAME model on regtest" |
| G4 | The funding model is IDENTICAL on regtest, testnet, and mainnet (no free grant anywhere) | "the funding model is IDENTICAL on regtest, testnet, and mainnet (no auto-fund anywhere)" |

## Immutability

| # | Claim | Test |
|---|---|---|
| I1 | The chosen network is carried unchanged into the genesis EngineConfig (per network) | "the funding model is IDENTICAL on regtest, testnet, and mainnet (no auto-fund anywhere)" |
| I2 | Actions after START are rejected | "actions after START are rejected" |
