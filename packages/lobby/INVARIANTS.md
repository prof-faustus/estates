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
| G3 | Regtest START auto-funds and emits an EngineConfig that seeds the core | "regtest START auto-funds and emits an EngineConfig that seeds the core" |

## Immutability

| # | Claim | Test |
|---|---|---|
| I1 | Network mode is fixed at genesis (testnet does not auto-fund seat balances) | "network mode is fixed at genesis (testnet does not auto-fund seat balances)" |
| I2 | Actions after START are rejected | "actions after START are rejected" |
