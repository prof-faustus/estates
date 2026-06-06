# @estates/trade — security boundary

Reference cryptographic infrastructure: **atomic player↔player trade** — one
transaction, both legs move or neither. Written so an auditor can attack it.

## What this package is

A trade is a single transaction whose inputs are the things each party gives (NFT
outpoints + one funding UTXO) and whose outputs are the things each party receives
(reassigned NFTs + sats/change). Each party signs **only their own inputs** with
**SIGHASH_ALL** (`0x41`, BSV's FORKID), so every signature commits to the **entire
output set**. Real secp256k1 ECDSA via `node:crypto` models the co-signing.

`verifyTradeValue` checks value conservation against the **real** previous-UTXO
values plus the fee.

## The properties this exists to guarantee

> 1. Atomicity: both legs move, or nothing does.
> 2. No party can alter the division after signing (anti-front-running).
> 3. A party only ever risks what it explicitly signs.
> 4. One-game binding: a trade moves only THIS game's NFTs (no cross-game asset).

- **One-game binding:** every ESTATES NFT carries the 32-byte domain-separated
  `gameTag` of its game. `verifyTradeForGame(st, gameId)` decodes every NFT output
  from the tx itself (`nftStateFromScript`) and rejects the trade unless **every**
  NFT belongs to `gameId` (and at least one NFT moves). So a deed from game A can
  never be moved inside a game-B trade, and two games' assets cannot be mixed — the
  same one-game binding the seat keys (manifest) and the reserve (`rulesHash(gameId)`)
  carry.

- **Atomicity:** the trade is one tx. If either party declines (never signs its
  inputs), the tx is incomplete → invalid → nothing moves.
- **Output integrity:** because each signature is SIGHASH_ALL over all outputs,
  changing any output after a party signs invalidates that signature — a
  counterparty cannot re-point an output to themselves after seeing the signature.
- **Own-input only:** a signature is bound to the input's owning pkh; a wrong-key
  signature does not satisfy an input it does not own.
- **Conservation:** outputs + fee equal the sum of real prevout values; value cannot
  be conjured or silently siphoned.

## Threat model

- Counterparty signs, then edits an output to pay themselves → the existing
  signature no longer verifies (anti-front-running).
- A party tries to spend an input it does not own (wrong key) → the input is not
  satisfied.
- One party declines / withholds its signature → tx invalid, nothing moves (no
  partial execution).
- A trade that does not conserve value (inflated/missing sats) → rejected by
  `verifyTradeValue` against real prevout values + fee.

## What this package does NOT do

- No data-output opcode; no CLTV/CSV (any maturity is tx-level nLockTime/nSequence).
- It does not choose *what* a fair trade is — humans propose the legs; this enforces
  that the agreed legs execute atomically and cannot be tampered with.
- The production sighash/script verification reference is `@estates/scriptvm`
  (BIP-143); this package models the co-signing and value conservation.
