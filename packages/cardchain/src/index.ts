/**
 * @estates/cardchain — the LIVE card-NFT lifecycle.
 *
 * The Fate/Treasury decks are minted as CONCEALED 1-sat BSV NFTs (held by the bank)
 * at table genesis, and every draw / pass is a REAL transaction that SPENDS the current
 * holder's card UTXO and creates the new holder's successor NFT — RE-SEALED to the new
 * holder, so the PREVIOUS holder LOSES all access to the card's encrypted face, and the
 * spent outpoint is on-chain dead. No copy, no double-spend, no resurrection (verifiable
 * via @estates/cardnft.verifyCardCustodyChain).
 *
 * The @estates/engine stays PURE (it draws cards deterministically by deck cursor); this
 * module maps that card lifecycle onto @estates/cardnft NFT transfers. It bridges
 * @estates/params (deck contents) + @estates/deck (concealment) + @estates/cardnft (UTXO).
 *
 * WHY (the audit's requirement, met here): "concealed cards are full BSV NFT UTXOs" and
 * "Alice → Bob spends Alice's old outpoint, and the NFT is encrypted so Alice loses
 * access when sent to Bob". The first is the 1-sat card NFT; the second is the UTXO spend
 * PLUS the ECIES re-seal to the new holder (the old holder can no longer decrypt).
 */
import { loadParams } from '@estates/params';
import { mintCard, openCard, genCardKey, type ConcealedCard, type CardFace, type CardSecret, type CardKey } from '@estates/deck';
import { type TxOutput } from '@estates/onchain';
import {
  cardNftOutput, mintCardNft, transferCardNft, deckToNfts, verifyDeckNfts, isLiveCard,
  type CardNft, type Outpoint, type CardTransfer, type DeckCheck,
} from '@estates/cardnft';
import { ripemd160, sha256 } from '@estates/keys';

const P = loadParams();

/** The hash160 (P2PKH) of a compressed pubkey — the on-chain owner of a card NFT. */
export function holderPkh(pub: Uint8Array): Uint8Array {
  return ripemd160(sha256(pub));
}

// only the concealed-card decks (Fate/Treasury) are card NFTs; titles/Reprieve are
// minted as their own NFTs by @estates/bank genesis.
const DECK_KIND: Readonly<Record<string, 'FATE' | 'TREASURY'>> = { Fate: 'FATE', Treasury: 'TREASURY' };

/** The CardFaces for a deck in PARAMS order (face id = index into params P.decks[name]). */
export function deckFaces(deckName: string): CardFace[] {
  const cards = P.decks[deckName];
  if (!cards) throw new Error(`cardchain: unknown deck ${deckName}`);
  const kind = DECK_KIND[deckName];
  if (!kind) throw new Error(`cardchain: deck ${deckName} is not an NFT card deck`);
  return cards.map((_c, id) => ({ kind, id }));
}

export interface MintedCardDeck { readonly nfts: CardNft[]; readonly secrets: CardSecret[] }

/**
 * Mint a deck as concealed 1-sat card NFTs in the given draw `order` (the jointly-
 * generated dealerless order), each sealed to the bank and paired with its genesis
 * outpoint. `order[pos]` is the params face index minted at deck position `pos`. The
 * `secrets[pos]` are the bank's view (face + blind + key) — the bank knows every card it
 * holds; concealment is from the OTHER seats (who see only the commitment).
 */
export function mintCardDeck(
  gameId: string, deckName: string, order: readonly number[],
  bankPub: Uint8Array, bankPkh: Uint8Array, outpoints: readonly Outpoint[],
): MintedCardDeck {
  const faces = deckFaces(deckName);
  if (order.length !== faces.length) throw new Error('cardchain: order length must equal the deck size');
  if (outpoints.length !== faces.length) throw new Error('cardchain: one genesis outpoint per card required');
  const nfts: CardNft[] = [];
  const secrets: CardSecret[] = [];
  order.forEach((faceIdx, pos) => {
    const face = faces[faceIdx];
    if (!face) throw new Error(`cardchain: order references a non-existent face ${faceIdx}`);
    const { card, secret } = mintCard(gameId, face, bankPub);   // concealed, sealed to the bank
    nfts.push(mintCardNft(card, bankPkh, outpoints[pos]!));
    secrets.push(secret);
  });
  return { nfts, secrets };
}

export interface CardDeckGenesis {
  readonly outputs: readonly TxOutput[];        // 1-sat card NFT outputs to add to the genesis tx
  readonly concealed: readonly ConcealedCard[]; // the concealment per deck position (no outpoint yet)
  readonly secrets: readonly CardSecret[];       // the BANK's view (face + blind + key) per position
}

/**
 * Build the 1-sat card NFT OUTPUTS for a deck to mint at genesis (sealed to the bank, in
 * the jointly-generated draw `order`). The outputs are appended to the genesis tx; once
 * the genesis txid is known, `bindCardNfts(concealed, bankPkh, outpoints)` produces the
 * live CardNft records. Returned `secrets` are the bank's (it holds every card initially).
 */
export function cardDeckOutputs(
  gameId: string, deckName: string, order: readonly number[], bankPub: Uint8Array, bankPkh: Uint8Array,
): CardDeckGenesis {
  const faces = deckFaces(deckName);
  if (order.length !== faces.length) throw new Error('cardchain: order length must equal the deck size');
  const outputs: TxOutput[] = [];
  const concealed: ConcealedCard[] = [];
  const secrets: CardSecret[] = [];
  order.forEach((faceIdx) => {
    const face = faces[faceIdx];
    if (!face) throw new Error(`cardchain: order references a non-existent face ${faceIdx}`);
    const { card, secret } = mintCard(gameId, face, bankPub);
    outputs.push(cardNftOutput(card.tableId, card.commitment, card.cardPub, bankPkh));
    concealed.push(card);
    secrets.push(secret);
  });
  return { outputs, concealed, secrets };
}

/** Bind genesis-minted concealed cards to their on-chain outpoints (after the genesis
 *  txid is known) → the live bank-held card NFTs. */
export function bindCardNfts(concealed: readonly ConcealedCard[], bankPkh: Uint8Array, outpoints: readonly Outpoint[]): CardNft[] {
  return deckToNfts(concealed, bankPkh, outpoints);
}

/** The ConcealedCard view of a card NFT (its concealment fields). */
export function concealedOf(nft: CardNft): ConcealedCard {
  return { tableId: nft.tableId, cardPub: nft.cardPub, commitment: nft.commitment, sealed: nft.sealed };
}

/**
 * Pass a card to a new holder: a REAL tx that SPENDS the current outpoint and creates
 * the new holder's successor 1-sat NFT, RE-SEALED to the new holder. The previous holder
 * LOSES access — the face is sealed to the new holder's key and the old card key is
 * retired; the spent outpoint is on-chain dead. (Used for a draw bank→player and any
 * player→player pass of a held card.)
 */
export function passCard(
  nft: CardNft, secret: CardSecret, toPub: Uint8Array, toPkh: Uint8Array, teeDeletionQuote?: string,
): CardTransfer {
  return transferCardNft(nft, concealedOf(nft), secret.face, toPub, toPkh, teeDeletionQuote);
}

/**
 * Open a card the caller holds: the face iff the ECIES seal opens for `holderPriv` AND it
 * matches the commitment AND is bound to this game. null otherwise — in particular a
 * PREVIOUS holder, even if they kept the blind, gets null after the card was re-sealed to
 * someone else (they have lost access).
 */
export function openHeld(nft: CardNft, holderPriv: Uint8Array, blind: Uint8Array): CardFace | null {
  return openCard(concealedOf(nft), holderPriv, blind, nft.tableId);
}

export { verifyDeckNfts, isLiveCard, genCardKey };
export type { CardNft, CardTransfer, DeckCheck, CardSecret, CardKey, Outpoint };
