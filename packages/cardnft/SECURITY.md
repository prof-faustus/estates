# @estates/cardnft — security boundary

Reference cryptographic infrastructure: a concealed card as a **full 1-sat BSV NFT
(UTXO)**, so passing a card from Alice to Bob **spends Alice's output** — her card
becomes on-chain dead, not a retained copy. Written so an auditor can attack it.

## What this package is

A card's concealment lives in `@estates/deck` (sealed face, commitment, one-use key).
This package adds the **on-chain NFT**: a 1-sat output whose locking script is
`<tableId‖commitment‖cardPub> OP_DROP P2PKH(owner)`. A `CardNft` is that output's
outpoint + the concealed fields + the owner pkh. A transfer is a real transaction:
spend Alice's card outpoint → create Bob's successor 1-sat NFT.

## The property this exists to guarantee

> When a card passes Alice → Bob, Alice must no longer have it.

Two layers:
- **On-chain (authoritative, no trust):** the transfer SPENDS Alice's 1-sat card
  outpoint. Once spent it leaves the UTXO set; the chain rejects any later spend of
  it. Alice's retained `CardNft` object references a dead outpoint — worthless.
- **Cryptographic (custody):** Bob's successor uses a FRESH one-use key and the face
  is re-sealed to Bob (`@estates/deck.transferCard`); Alice cannot decrypt Bob's
  custody. The old card key is retired and must never reappear.
- **TEE (optional, assumed OK per requirements):** a `teeDeletionQuote` can attest the
  TEE deleted the plaintext face/key/blind Alice already saw. This covers only
  *plaintext she has already legitimately seen*; the **live-ownership** deletion is the
  on-chain spend and needs NO TEE.

## Threat model

- Alice keeps her old `CardNft`, its key, its blind, and tries to use/re-present it
  after transferring → must be detectable as dead (spent outpoint).
- A "transfer" that mints Bob's card WITHOUT spending Alice's outpoint (a copy) → must
  be rejected.
- A successor that reuses Alice's retired key, pays the wrong owner, or changes the
  concealed identity → must be rejected.
- A spent card key/outpoint reappearing later (resurrection) → must be rejected.
- Hostile/malformed tx or quote → never throws.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `mintCardNft` | trusted (our mint) | pairs a deck card with its 1-sat UTXO; validates table id. |
| `transferCardNft` | trusted (our outbound) | builds the spend tx (input = Alice's outpoint, output = Bob's 1-sat NFT), re-seals + retires the old key. Funding/fee inputs + Alice's unlocking signature are attached by the wallet at broadcast. |
| `verifyCardTransfer(tx, alice, bobPkh, newCard)` | **untrusted tx** | Total: rejects unless the tx spends Alice's exact outpoint AND a 1-sat output equals `cardNftOutput(sameIdentity, bobPkh)` AND the successor key is fresh AND the identity is unchanged. Never throws. |
| `isLiveCard(card, spentSet)` | **untrusted** | false once the card's outpoint is spent — Alice's retained copy is dead. |
| `verifyTeeDeletionQuote(q, retired, spent)` | **untrusted** | binds the quote to the retired key + spent outpoint; a real deployment also checks the platform attestation signature (documented boundary). |

## Invariants (each is a test — see INVARIANTS.md)

- A card is a real 1-sat UTXO with an identity-committing script.
- A transfer spends Alice's outpoint and creates Bob's successor 1-sat NFT.
- After transfer Alice's card is dead (`isLiveCard` false), Bob's is live.
- A copy (no spend of Alice's outpoint), a retired-key reuse, a wrong-owner lock, or a
  changed identity is rejected.
- A spent outpoint never becomes live again (no resurrection).
- A TEE deletion quote binds the retired key + spent outpoint.

## What must never be assumed

- That re-sealing to Bob alone removes Alice's access — only the UTXO spend does.
- That a `CardNft` object held by a party is live — check it against the spent set.
- That a TEE is present for the live-ownership guarantee — it is the chain spend.

## Known non-goals

- Broadcasting / fee selection / Alice's unlocking signature (wallet, at broadcast).
- Hiding that a card exists on-chain (the 1-sat output is visible; its identity is the
  concealed commitment, not the plaintext face).
- Platform-specific TEE attestation verification (the signature-check boundary is left
  to the deployment; `verifyTeeDeletionQuote` checks binding/shape).
