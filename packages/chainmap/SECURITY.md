# @estates/chainmap — security boundary

Reference infrastructure: the bridge from the **pure engine's title state** to
**on-chain 1-sat NFTs + transaction legs**. Pure — it returns outputs and signs
nothing. Written so an auditor can attack it.

## What this package is

The engine tracks a title as `{ owner, buildLevel, mortgaged }`; on-chain that is a
1-sat NFT whose live-script state blob carries the same fields. This package maps one
to the other and emits the transaction **legs** for value-bearing actions:

- **Buy:** NFT moves bank→buyer, price→reserve.
- **Build / mortgage / unmortgage:** RE-MINT the NFT (spend the old 1-sat output,
  create a new 1-sat output with the updated state) plus the native-sat leg.

Custody choices are security-relevant:
- **Owned-title NFT custody** uses a **FRESH provider-derived one-use key** (BRC-42),
  never a reused static seat pkh.
- **Bank-held (unowned) NFTs and the reserve** are **covenant-locked by default**
  (trustless, game-bound `rulesHash(ctx.gameId)`), not a reused bank pkh. Quorum mode
  (P2PKH to the banker) is opt-in.

## The properties this exists to guarantee

> 1. The on-chain NFT blob always faithfully reflects the engine title state.
> 2. Custody never reuses a static address: owned → fresh provider key; bank-held →
>    game-bound covenant.
> 3. Re-mints and purchases conserve value across the emitted legs.

- **Faithful mapping:** engine state round-trips through the NFT blob (build +
  mortgage reflected); `validateTitleSemantics` rejects any title whose on-chain
  semantics do not match a legal genesis title.
- **No reused custody:** owned-title custody calls the provider for a fresh pkh per
  (seat, purpose); bank-held NFTs and the reserve sit under the game-bound covenant,
  not a static bank pkh.
- **Game binding:** the covenant rules hash defaults to `rulesHash(ctx.gameId)`, so
  the reserve/bank-held NFTs belong to exactly one game (see `@estates/bank`).

## Threat model

- An attacker hopes a build/mortgage silently changes ownership or value → re-mints
  carry the same identity and emit the matching native-sat leg; mapping is faithful.
- A bank-held NFT or reserve is locked to a reused/static pkh an attacker could grind
  → no: default custody is the game-bound covenant.
- A title whose on-chain semantics differ from any legal genesis title →
  `validateTitleSemantics` rejects it.

## What this package does NOT do

- It signs nothing and broadcasts nothing — it returns outputs/legs for the wallet /
  sidecar to fund + sign. Script validity is `@estates/scriptvm`; the covenant
  enforcement is `@estates/bank`; the rules are `@estates/engine`.
