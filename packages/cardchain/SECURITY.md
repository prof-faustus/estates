# @estates/cardchain — security boundary

Reference cryptographic infrastructure: the **live card-NFT lifecycle** — concealed
Fate/Treasury cards as full 1-sat BSV NFT UTXOs, drawn and passed by real outpoint-
spending transfers. Written so an auditor can attack it.

## What this package is

The pure `@estates/engine` draws cards deterministically by deck cursor. This package
maps that lifecycle onto on-chain card NFTs (`@estates/cardnft`):

- **Genesis mint** (`cardDeckOutputs` / `bindCardNfts`, wired by `@estates/bank`): the
  Fate/Treasury decks are minted as concealed 1-sat card NFTs held by the bank, in the
  jointly-generated dealerless draw order. Each card is a real UTXO `<tableId‖commitment‖
  cardPub> OP_DROP P2PKH(owner)`.
- **Draw / pass** (`passCard`): a REAL transaction that **spends** the current holder's
  card outpoint and creates the new holder's successor 1-sat NFT, **re-sealed** to the new
  holder via single-use ECIES.
- **Open** (`openHeld`): a holder opens the encrypted face with their own key.

## The properties this exists to guarantee

> 1. A concealed card is a FULL 1-sat NFT UTXO (not a re-sealed copy).
> 2. A draw/pass SPENDS the prior outpoint — the old card is on-chain DEAD.
> 3. The card is ENCRYPTED to the current holder: when it is sent to a new holder it is
>    re-sealed, and the previous holder LOSES all access to the face.

- **Full NFT:** `mintCardDeck` / genesis produces real 1-sat UTXOs (`verifyDeckNfts`:
  table-bound, 1-sat, unique outpoints + one-use keys).
- **True move:** `passCard` (via `cardnft.transferCardNft`) spends the holder's outpoint
  and creates the successor; a "transfer" that does not spend it is a copy and is rejected
  (`verifyCardTransfer`). The whole chain is checked by `verifyCardCustodyChain` (no copy,
  double-spend, or resurrection). `isLiveCard` is false for any spent outpoint.
- **Encryption / access loss:** the face is sealed (ECIES → AES-256-GCM, AAD-bound to the
  table + card key) to the *current* holder's key. On transfer it is re-sealed to the new
  holder with a fresh one-use key (old key retired). The previous holder — **even if they
  keep the blind** — cannot decrypt the new seal (`openHeld` returns null for them), so
  they have genuinely lost access. The bank that dealt a card to a player likewise loses
  access once it is re-sealed to that player.

## Threat model

- A player keeps their old card object/key after passing it and tries to use it → the
  outpoint is spent (dead) and the face is sealed to the new holder (can't decrypt).
- A "pass" that mints the new holder's card WITHOUT spending the old outpoint (a copy) →
  rejected by `verifyCardTransfer` / `verifyCardCustodyChain`.
- Re-spending an already-spent card (resurrection / double-spend) → rejected by the
  custody chain.
- A previous holder (or any non-holder) tries to read the face after transfer → cannot
  open the re-sealed envelope.
- A card from another game/table is presented → rejected (table-bound `tableId`).

## What this package does NOT do

- It does not make the engine impure — the engine draws by cursor; this maps draws to
  NFT transfers. It does not broadcast; it builds the transfer txs (the wallet/sidecar
  broadcasts). The concealment crypto is `@estates/deck`; the UTXO machinery is
  `@estates/cardnft`; the genesis tx is `@estates/bank`.
