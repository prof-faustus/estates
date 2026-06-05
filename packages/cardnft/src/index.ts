/**
 * @estates/cardnft — a concealed card as a FULL 1-sat BSV NFT (UTXO).
 *
 * @estates/deck conceals a card's identity (sealed face + commitment + one-use
 * key). This package makes that card a REAL on-chain NFT: a 1-sat output whose
 * locking script carries the card's on-chain state `<tableId‖commitment‖cardPub>
 * OP_DROP P2PKH(owner)`. A transfer is then a real transaction that SPENDS Alice's
 * card UTXO and CREATES Bob's successor 1-sat NFT — so Alice's card is on-chain
 * DEAD (spent, no longer live), not merely re-sealed. The chain enforces it; no
 * trust, no copy. (A TEE may additionally attest deletion of the plaintext face
 * Alice already saw — assumed OK per requirements — but the LIVE-ownership
 * deletion is the UTXO spend, verified here without any TEE.)
 *
 * WHAT/HOW/WHY:
 *  - WHAT: CardNft = the deck ConcealedCard + its UTXO (outpoint, 1 sat, owner).
 *  - HOW: mint creates the 1-sat output; transfer builds a tx spending the old
 *    outpoint and creating the new one; verifyCardTransfer checks the old UTXO is
 *    spent and the new is a 1-sat NFT committing to the same identity, locked to Bob.
 *  - WHY: "Alice no longer has it" is only real if her UTXO is consumed. A re-seal
 *    alone leaves Alice able to open her retained copy — the audit's exact finding.
 */
import {
  type ConcealedCard, transferCard, type CardFace, isTableIdHex,
} from '@estates/deck';
import { OP, op, push, p2pkh, serializeScript, NFT_SATS, type TxOutput } from '@estates/onchain';
import { txid, type Tx } from '@estates/tx';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

export interface Outpoint { readonly txid: string; readonly vout: number }

/** A card's full NFT record: its concealment + its on-chain UTXO identity. */
export interface CardNft {
  readonly outpoint: Outpoint;     // the live 1-sat UTXO (txid:vout)
  readonly satoshis: number;       // 1
  readonly tableId: string;        // 32-byte hex (game/table binding)
  readonly commitment: string;     // 32-byte hex (concealed face binding; stable across transfer)
  readonly cardPub: string;        // 33-byte hex (current one-use custody key)
  readonly ownerPkh: string;       // 20-byte hex (P2PKH owner = current holder)
  readonly sealed: ConcealedCard['sealed']; // face sealed to the current holder
}

const isHexLen = (x: unknown, n: number): x is string => typeof x === 'string' && x.length === n && /^[0-9a-fA-F]+$/.test(x);

// On-chain card state blob: tableId(32) ‖ commitment(32) ‖ cardPub(33) = 97 bytes.
const CARD_TAG = new TextEncoder().encode('ESTATES_CARD_NFT_V1');
export function encodeCardState(tableId: string, commitment: string, cardPub: string): Uint8Array {
  if (!isTableIdHex(tableId) || !isHexLen(commitment, 64) || !isHexLen(cardPub, 66)) throw new Error('encodeCardState: bad field');
  return concatBytes(CARD_TAG, hexToBytes(tableId), hexToBytes(commitment), hexToBytes(cardPub));
}

/** The 1-sat NFT output for a card: `<state> OP_DROP P2PKH(owner)`. */
export function cardNftOutput(tableId: string, commitment: string, cardPub: string, ownerPkh: Uint8Array): TxOutput {
  if (ownerPkh.length !== 20) throw new Error('ownerPkh must be 20 bytes');
  return { satoshis: NFT_SATS, script: serializeScript([push(encodeCardState(tableId, commitment, cardPub)), op(OP.OP_DROP), ...p2pkh(ownerPkh)]) };
}

/** Mint a card NFT: pair a deck ConcealedCard with its on-chain 1-sat UTXO. */
export function mintCardNft(card: ConcealedCard, ownerPkh: Uint8Array, outpoint: Outpoint): CardNft {
  if (!isTableIdHex(card.tableId)) throw new Error('mintCardNft: bad tableId');
  return {
    outpoint, satoshis: NFT_SATS, tableId: card.tableId, commitment: card.commitment,
    cardPub: card.cardPub, ownerPkh: bytesToHex(ownerPkh), sealed: card.sealed,
  };
}

export interface CardTransfer {
  readonly tx: Tx;                 // spends Alice's card UTXO, creates Bob's
  readonly newCard: CardNft;       // Bob's successor NFT (live)
  readonly spent: Outpoint;        // Alice's now-dead outpoint
  readonly retiredCardPub: string; // Alice's old one-use key (retired, never reused)
  readonly teeDeletionQuote?: string; // optional TEE attestation of plaintext deletion
}

/**
 * TRANSFER Alice's card NFT to Bob: build the tx that SPENDS Alice's outpoint and
 * CREATES Bob's successor 1-sat NFT (same commitment/identity, fresh card key,
 * sealed to Bob, locked to Bob's pkh). After this, Alice's outpoint is spent —
 * her card is dead. (Funding/fee inputs + Alice's unlocking signature are attached
 * by the wallet at broadcast, like every ESTATES move.)
 */
export function transferCardNft(
  alice: CardNft, concealed: ConcealedCard, face: CardFace, newHolderPub: Uint8Array, newOwnerPkh: Uint8Array,
  teeDeletionQuote?: string,
): CardTransfer {
  if (alice.cardPub !== concealed.cardPub || alice.tableId !== concealed.tableId) throw new Error('transferCardNft: CardNft/ConcealedCard mismatch');
  if (newOwnerPkh.length !== 20) throw new Error('newOwnerPkh must be 20 bytes');
  const { card: bobConcealed, event } = transferCard(concealed, face, newHolderPub); // re-seal + retire old key
  const out = cardNftOutput(bobConcealed.tableId, bobConcealed.commitment, bobConcealed.cardPub, newOwnerPkh);
  const tx: Tx = {
    version: 1,
    inputs: [{ prevTxid: alice.outpoint.txid, prevVout: alice.outpoint.vout, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [{ value: out.satoshis, script: out.script }],
    lockTime: 0,
  };
  const newOutpoint: Outpoint = { txid: txid(tx), vout: 0 };
  const newCard: CardNft = {
    outpoint: newOutpoint, satoshis: NFT_SATS, tableId: bobConcealed.tableId, commitment: bobConcealed.commitment,
    cardPub: bobConcealed.cardPub, ownerPkh: bytesToHex(newOwnerPkh), sealed: bobConcealed.sealed,
  };
  return { tx, newCard, spent: alice.outpoint, retiredCardPub: event.retired, ...(teeDeletionQuote !== undefined ? { teeDeletionQuote } : {}) };
}

export interface TransferCheck { readonly ok: boolean; readonly reason: string }

/**
 * VERIFY a card transfer is a real move (the audit's missing piece): the tx SPENDS
 * Alice's exact outpoint, and CREATES a 1-sat output that (a) commits to the SAME
 * tableId+commitment identity, (b) is locked to Bob's pkh, (c) carries a FRESH
 * card key (≠ Alice's). A transfer that fails any of these is a forbidden copy.
 * Total: never throws.
 */
export function verifyCardTransfer(tx: Tx, alice: CardNft, bobOwnerPkh: Uint8Array, newCard: CardNft): TransferCheck {
  try {
    if (!tx || !Array.isArray(tx.inputs) || !Array.isArray(tx.outputs)) return fail('malformed tx');
    if (!tx.inputs.some((i) => i.prevTxid === alice.outpoint.txid && i.prevVout === alice.outpoint.vout)) return fail("Alice's card outpoint is NOT spent (copy, not a move)");
    if (newCard.cardPub === alice.cardPub) return fail('successor reuses the retired card key');
    const o = tx.outputs[newCard.outpoint.vout];
    if (!o || o.value !== NFT_SATS) return fail('successor is not a 1-sat output');
    const want = cardNftOutput(newCard.tableId, newCard.commitment, newCard.cardPub, bobOwnerPkh).script;
    if (bytesToHex(o.script) !== bytesToHex(want)) return fail('successor output does not commit to the same identity locked to Bob');
    if (newCard.commitment !== alice.commitment || newCard.tableId !== alice.tableId) return fail('identity changed across transfer');
    return { ok: true, reason: "true move: Alice's 1-sat card UTXO spent; Bob's successor 1-sat NFT created with same identity" };
  } catch (e) { return fail(`verify threw: ${(e as Error).message}`); }
}

/** A card is LIVE iff its outpoint has not been spent. After a transfer, Alice's
 *  old outpoint is in the spent set → her retained copy is DEAD. */
export function isLiveCard(card: CardNft, spentOutpoints: ReadonlySet<string>): boolean {
  return !spentOutpoints.has(`${card.outpoint.txid}:${card.outpoint.vout}`);
}
export const opKey = (o: Outpoint): string => `${o.txid}:${o.vout}`;

/**
 * TEE deletion quote (assumed OK per min requirements): attests the TEE deleted
 * Alice's plaintext face/key/blind on transfer. The chain spend already kills her
 * LIVE ownership; this only covers plaintext she already saw. Here we validate the
 * quote is well-formed + binds the retired key + outpoint (a real TEE attestation
 * verifier would check the platform signature; that boundary is documented).
 */
export interface TeeDeletionQuote { readonly retiredCardPub: string; readonly spent: Outpoint; readonly attestation: string }
export function verifyTeeDeletionQuote(q: unknown, retiredCardPub: string, spent: Outpoint): TransferCheck {
  if (!q || typeof q !== 'object') return fail('no TEE deletion quote');
  const o = q as Record<string, unknown>;
  if (o.retiredCardPub !== retiredCardPub) return fail('quote does not retire this card key');
  const sp = o.spent as Outpoint | undefined;
  if (!sp || sp.txid !== spent.txid || sp.vout !== spent.vout) return fail('quote does not bind the spent outpoint');
  if (typeof o.attestation !== 'string' || o.attestation.length < 16) return fail('quote attestation missing/short');
  return { ok: true, reason: 'TEE deletion quote binds the retired key + spent outpoint' };
}

function fail(reason: string): TransferCheck { return { ok: false, reason }; }
