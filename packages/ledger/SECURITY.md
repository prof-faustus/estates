# @estates/ledger — security boundary

Reference cryptographic infrastructure: the **on-chain move chain** — the sequence
of txids is itself the authoritative, SPV-provable transcript of the game. Written
so an auditor can attack it.

## What this package is

- **Genesis:** one transaction sets up the table. Output 0 is the **move-chain
  cursor** (a 1-sat commitment output); other outputs fund seats and mint the deck
  NFTs / reserve. `verifyGenesisManifest` proves every genesis output is a
  certified, freshly-derived one-use key or the game-bound covenant — no raw,
  reused, or forged scripts.
- **Moves:** thereafter **every move is its own real transaction** that SPENDS the
  previous move's cursor output and re-creates a new one, and SPENDS the prior NFT
  output of every title it re-mints. The chain of txids is the transcript.
- **True move:** `verifyTrueMove` enforces that a re-mint **consumes** (burns) the
  prior NFT outpoint — a transfer is a spend, not a copy.

## The properties this exists to guarantee

> 1. The game transcript is a single, unforgeable chain of on-chain transactions.
> 2. A title transfer destroys the predecessor (no duplicated NFTs).
> 3. Genesis outputs are all accounted for and use fresh, certified custody.

- **Linkage:** each move tx spends the prior cursor, so the txid sequence cannot be
  reordered or branched without breaking the chain — anyone can SPV-verify it.
- **True move (no copies):** a re-mint that fails to burn the prior NFT output is
  rejected as a copy; `MoveChain` tracks custody so each transfer burns the current
  output and the next burns the one after. The **first** mint of a title (no prior
  outpoint) is allowed without a burn.
- **Genesis integrity:** `verifyGenesisManifest` rejects a raw output with no entry,
  a reused one-use key, a key that reuses the identity key as a spend key, a forged
  certification signature, and (for covenant outputs) a script that is not the
  game-bound reserve covenant — fail-closed.

## Threat model

- An attacker re-mints a title without spending its prior outpoint (a duplicate
  NFT) → rejected by `verifyTrueMove`.
- A move tx that does not link to the prior cursor → not part of the chain.
- A genesis with a raw/forged/reused output key, or a covenant output not bound to
  this game → `verifyGenesisManifest` rejects it.
- A malformed/hostile tx or manifest → checks are total (no throw / no silent pass).

## What this package does NOT do

- Funding inputs and signatures are attached by the wallet / native sidecar at
  broadcast time; this module builds the canonical linkable structure and the chain
  linkage. Script/signature validity is `@estates/scriptvm`; the action commitment
  encoding is `@estates/txmap`.
