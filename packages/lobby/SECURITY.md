# @estates/lobby — security boundary

Reference infrastructure: the **waiting room** — a pure state machine that seats
players and emits the `EngineConfig` that seeds a game. Written so an auditor can
attack it.

## What this package is

Pure join / leave / ready / fill-bot / start. The **network mode is fixed at lobby
genesis and immutable**. The start-authority (host) may START once there are ≥2
occupied seats including ≥1 human, optionally overriding the all-ready gate. On
regtest, START auto-funds seat balances and the bank reserve (explicit + logged) and
emits the `EngineConfig` for `@estates/engine`.

## The properties this exists to guarantee

> 1. Only the authority can start, and only a legal table can start.
> 2. A game always has at least one human (no all-bot game).
> 3. The network mode cannot change after genesis; real-value funding is explicit.

- **Authority + quorum gate:** START requires the authority, ≥2 seats, ≥1 human, and
  (without override) all-ready; a non-authority START is rejected.
- **Human-control:** an all-bots lobby cannot start — every game has a human, who
  controls every real decision (the project's human-control invariant).
- **Immutable network:** the network mode is fixed at genesis; testnet/mainnet do not
  silently auto-fund (only regtest does, explicitly and logged).
- **No post-start mutation:** actions after START are rejected.

## Threat model

- A non-authority tries to start, or to start a table with no human / too few seats →
  rejected.
- Someone tries to switch the network (e.g. regtest→mainnet) mid-lobby → impossible;
  mode is fixed at genesis.
- A double-join, a join into a full lobby, or an invalid bot policy → rejected.
- Actions after START leak into the lobby state → rejected.

## What this package does NOT do

- It does not run the game (that is `@estates/engine` via the config it emits) and
  does not move real money beyond the explicit, logged regtest auto-fund.
