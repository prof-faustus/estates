# @estates/cli — security boundary

Reference infrastructure: the **launcher** that builds a REAL on-chain table on a
network the user chooses. Written so an auditor can attack it.

## What this package is

`estates table` builds one real BSV genesis transaction that funds each seat's
starting balance (native sats) and a **bank covenant reserve** output (trustless —
spendable only by a rules-legal payout, no trusted banker). `estates keygen` mints a
fresh key/address. The network is the user's explicit choice: a regtest node
(JSON-RPC), testnet, or mainnet.

## The properties this exists to guarantee

> 1. The reserve is the trustless, game-bound covenant — not a reused banker pkh.
> 2. Real value is never spent without explicit confirmation.
> 3. The table/game id is explicit and one-game-bound.

- **Game-bound reserve:** the reserve output uses `rulesHash(gameId)` — pass
  `--game-id <64hex>` (shared via the lobby) or omit it to mint a fresh random id;
  the chosen `gameId` is echoed in the output so peers match it. A reserve is
  worthless outside its game (see `@estates/bank`).
- **Money guard:** mainnet (real value) is refused without `--confirm-real-value`
  (enforced in `@estates/wallet`); regtest auto-funds only against the user's own
  node.
- **Real, self-verified tx:** the genesis is a real BIP-143-signed tx; the wallet
  self-verifies its inputs before broadcast.

## Threat model

- A non-32-byte or malformed `--game-id` → rejected (must be 64 hex).
- An accidental mainnet broadcast → refused without the explicit money-guard flag.
- A reserve locked to a reusable banker key an attacker could grind → no: default is
  the trustless, game-bound covenant.

## What this package does NOT do

- It does not custody keys beyond the funder wallet it is given, and makes no
  gameplay decisions. It assembles + broadcasts the genesis tx; rules/enforcement
  live in `@estates/engine` / `@estates/bank`.
