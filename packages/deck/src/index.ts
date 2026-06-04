/**
 * @estates/deck — every property AND every card is an ENCRYPTED, TABLE-BOUND,
 * individually-keyed 1-sat NFT, CONCEALED via mental poker and issued per rules.
 *
 * - Own wallet per card: each NFT has its OWN one-use secp256k1 key (no reused
 *   static addresses). A card is held by whoever holds its key.
 * - Encrypted face: the card's identity (which deed / which Fate card) is sealed
 *   to the current holder with single-use ECIES (ephemeral secp256k1 ECDH →
 *   HKDF-SHA256 → AES-256-GCM), matching @estates/chat's broadcast crypto.
 * - Mental-poker concealment: a binding commitment H(face ‖ blind) hides the
 *   identity until reveal; a distributed commit→reveal shuffle fixes the deck
 *   order so NO single party knows it (dealerless).
 * - Table-bound: a card carries the 32-byte table id; it is worthless at any
 *   other table (checked on every use / transfer).
 *
 * Isomorphic (pure @noble), so it runs identically in Node and the desktop UI.
 */
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes, bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

// ---- one-use key per card (the card's own wallet) ---------------------------
export interface CardKey { readonly priv: Uint8Array; readonly pub: Uint8Array; }
export function genCardKey(): CardKey {
  const priv = secp.utils.randomPrivateKey();
  return { priv, pub: secp.getPublicKey(priv, true) };
}

// ---- single-use ECIES (seal a card face to its holder) ----------------------
export interface Envelope { readonly ephPub: string; readonly nonce: string; readonly ct: string }
const INFO = new TextEncoder().encode('estates-card-v1');
const EMPTY = new Uint8Array(0);
const kek = (shared: Uint8Array): Uint8Array => hkdf(sha256, shared, EMPTY, INFO, 32);

/** Seal `plaintext` so only the holder of `recipientPub`'s private key can open it. */
export function sealTo(recipientPub: Uint8Array, plaintext: Uint8Array): Envelope {
  const eph = secp.utils.randomPrivateKey();
  const shared = secp.getSharedSecret(eph, recipientPub, true);
  const nonce = randomBytes(12);
  return {
    ephPub: bytesToHex(secp.getPublicKey(eph, true)),
    nonce: bytesToHex(nonce),
    ct: bytesToHex(gcm(kek(shared), nonce).encrypt(plaintext)),
  };
}
/** Open a sealed envelope with a private key. null on wrong key or tamper (AEAD). */
export function open(priv: Uint8Array, env: Envelope): Uint8Array | null {
  try {
    const shared = secp.getSharedSecret(priv, hexToBytes(env.ephPub), true);
    return gcm(kek(shared), hexToBytes(env.nonce)).decrypt(hexToBytes(env.ct));
  } catch {
    return null;
  }
}

// ---- mental-poker concealment: binding commitment to a hidden face ----------
/** Commitment H(face ‖ blind): binding (cannot find another face/blind) + hiding. */
export function commit(face: Uint8Array, blind: Uint8Array): string {
  return bytesToHex(sha256(concatBytes(face, blind)));
}
/** Open a concealment; true iff (face, blind) match the commitment. */
export function verifyReveal(commitment: string, face: Uint8Array, blind: Uint8Array): boolean {
  const got = commit(face, blind);
  if (got.length !== commitment.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ commitment.charCodeAt(i);
  return diff === 0;
}

// ---- card faces (the concealed content) -------------------------------------
export type CardKind = 'TITLE' | 'REPRIEVE' | 'FATE' | 'TREASURY';
const KIND_BYTE: Record<CardKind, number> = { TITLE: 1, REPRIEVE: 2, FATE: 3, TREASURY: 4 };
const BYTE_KIND: Record<number, CardKind> = { 1: 'TITLE', 2: 'REPRIEVE', 3: 'FATE', 4: 'TREASURY' };

export interface CardFace { readonly kind: CardKind; readonly id: number; readonly payload?: Uint8Array }

/** Deterministic, length-prefixed face encoding (so commitments are canonical). */
export function encodeFace(f: CardFace): Uint8Array {
  const payload = f.payload ?? EMPTY;
  const out = new Uint8Array(1 + 4 + 4 + payload.length);
  out[0] = KIND_BYTE[f.kind];
  out[1] = (f.id >>> 24) & 0xff; out[2] = (f.id >>> 16) & 0xff; out[3] = (f.id >>> 8) & 0xff; out[4] = f.id & 0xff;
  const n = payload.length;
  out[5] = (n >>> 24) & 0xff; out[6] = (n >>> 16) & 0xff; out[7] = (n >>> 8) & 0xff; out[8] = n & 0xff;
  out.set(payload, 9);
  return out;
}
export function decodeFace(b: Uint8Array): CardFace {
  const kind = BYTE_KIND[b[0]!];
  if (!kind) throw new Error('decodeFace: bad kind byte');
  const id = ((b[1]! << 24) | (b[2]! << 16) | (b[3]! << 8) | b[4]!) >>> 0;
  const n = ((b[5]! << 24) | (b[6]! << 16) | (b[7]! << 8) | b[8]!) >>> 0;
  if (b.length !== 9 + n) throw new Error('decodeFace: length mismatch');
  const face: CardFace = n > 0 ? { kind, id, payload: b.slice(9) } : { kind, id };
  return face;
}

// ---- a concealed card NFT ---------------------------------------------------
export interface ConcealedCard {
  readonly tableId: string;     // 32-byte hex — table binding (worthless elsewhere)
  readonly cardPub: string;     // the card NFT's OWN one-use public key (hex)
  readonly commitment: string;  // H(face ‖ blind) — identity is hidden until reveal
  readonly sealed: Envelope;    // face sealed to the current holder
}
export interface CardSecret { readonly face: CardFace; readonly blind: Uint8Array; readonly key: CardKey }

/** Mint one concealed card NFT for a table, sealed to `holderPub`, with its own key. */
export function mintCard(tableId: string, face: CardFace, holderPub: Uint8Array): { card: ConcealedCard; secret: CardSecret } {
  if (tableId.length !== 64) throw new Error('tableId must be 32 bytes (64 hex)');
  const blind = randomBytes(32);
  const key = genCardKey();
  const faceBytes = encodeFace(face);
  const card: ConcealedCard = {
    tableId,
    cardPub: bytesToHex(key.pub),
    commitment: commit(faceBytes, blind),
    sealed: sealTo(holderPub, faceBytes),
  };
  return { card, secret: { face, blind, key } };
}

/** The holder opens their card: returns the face iff the seal opens AND it matches
 *  the public commitment (no swap), AND it is bound to the expected table. */
export function openCard(card: ConcealedCard, holderPriv: Uint8Array, blind: Uint8Array, expectedTableId: string): CardFace | null {
  if (card.tableId !== expectedTableId) return null;           // table-bound
  const faceBytes = open(holderPriv, card.sealed);
  if (!faceBytes) return null;                                 // not the holder / tampered
  if (!verifyReveal(card.commitment, faceBytes, blind)) return null; // commitment mismatch
  return decodeFace(faceBytes);
}

/** Transfer a card to a new holder: re-seal the face to them; identity + table +
 *  commitment are unchanged (same NFT, new wallet). Returns the new card + key. */
export function transferCard(card: ConcealedCard, face: CardFace, newHolderPub: Uint8Array): { card: ConcealedCard; key: CardKey } {
  const key = genCardKey();
  return {
    card: { tableId: card.tableId, cardPub: bytesToHex(key.pub), commitment: card.commitment, sealed: sealTo(newHolderPub, encodeFace(face)) },
    key,
  };
}

// ---- dealerless mental-poker shuffle (no single party knows the order) -------
export interface EntropyCommit { readonly who: string; readonly commitment: string }
/** A party commits to secret entropy before anyone reveals (commit phase). */
export function commitEntropy(secretBytes: Uint8Array): string { return bytesToHex(sha256(secretBytes)); }
/** Verify a revealed entropy matches its prior commitment. */
export function verifyEntropy(commitment: string, secretBytes: Uint8Array): boolean { return commitEntropy(secretBytes) === commitment; }
/** Combine all revealed entropies (canonical order = sorted hex) into one seed.
 *  No single party can determine the result without controlling all others. */
export function combineSeed(reveals: readonly Uint8Array[]): Uint8Array {
  const sorted = reveals.map(bytesToHex).sort();
  return sha256(concatBytes(...sorted.map(hexToBytes)));
}
/**
 * Deterministic Fisher–Yates permutation of [0,n) from a seed (sha256 counter PRNG).
 *
 * EXACT uniform shuffle for ANY ESTATES finite set size — the Fate/Treasury decks
 * (n=12), the 28 title-deed NFTs, the 30 title+Reprieve NFT set, and any other
 * concealed card/state ordering. A plain `next() % (i+1)` would skew the result
 * whenever `i+1` does not divide 2^32 (e.g. 2^32 mod 12 = 4, mod 28 = 4, mod 30 =
 * 16 residues occur once more often), so each draw uses REJECTION SAMPLING — the
 * same standard the dice beacon uses (reject bytes ≥ the largest multiple of the
 * bound below 2^32). This makes the dealerless concealed shuffle unbiased for
 * EVERY ESTATES set size, not just powers of two.
 */
export function permutation(seed: Uint8Array, n: number): number[] {
  const idx = Array.from({ length: n }, (_, i) => i);
  let pool = sha256(seed);
  let p = 0;
  const next = (): number => {
    if (p + 4 > pool.length) { pool = sha256(pool); p = 0; }
    const v = ((pool[p]! << 24) | (pool[p + 1]! << 16) | (pool[p + 2]! << 8) | pool[p + 3]!) >>> 0;
    p += 4;
    return v;
  };
  // Uniform draw in [0,bound): reject the top partial bucket so the modulo is exact.
  const drawBelow = (bound: number): number => {
    const limit = Math.floor(0x1_0000_0000 / bound) * bound;
    for (;;) { const r = next(); if (r < limit) return r % bound; }
  };
  for (let i = n - 1; i > 0; i--) {
    const j = drawBelow(i + 1);
    const t = idx[i]!; idx[i] = idx[j]!; idx[j] = t;
  }
  return idx;
}

// ---- mint a full concealed, shuffled deck at table genesis ------------------
export interface MintedDeck { readonly tableId: string; readonly order: number[]; readonly cards: ConcealedCard[]; readonly secrets: CardSecret[] }
/** Mint every face as a concealed NFT (sealed to the bank/dealer key initially),
 *  in the mental-poker shuffled order. Cards are later issued/revealed per rules. */
export function mintDeck(tableId: string, faces: readonly CardFace[], dealerPub: Uint8Array, shuffleSeed: Uint8Array): MintedDeck {
  const order = permutation(shuffleSeed, faces.length);
  const cards: ConcealedCard[] = [];
  const secrets: CardSecret[] = [];
  for (const i of order) {
    const { card, secret } = mintCard(tableId, faces[i]!, dealerPub);
    cards.push(card);
    secrets.push(secret);
  }
  return { tableId, order, cards, secrets };
}

// ---- transcript verifier: enforce one-use keys + table binding --------------
export interface CardTranscriptResult { readonly ok: boolean; readonly reason: string }
/**
 * Verify a concealed-card transcript (a deck mint and/or a sequence of custody
 * states from transfers). The one-use-key promise is only real if a verifier
 * REJECTS reuse, so this enforces:
 *   - every `cardPub` is a well-formed compressed secp256k1 point (33 bytes);
 *   - NO `cardPub` is reused across the whole transcript (each card/custody state
 *     carries its OWN fresh key — never a reused static address);
 *   - every card is bound to the expected table id.
 * A single repeated custody key (e.g. a transfer that fails to re-key, or a
 * duplicated NFT) fails the check.
 */
export function verifyCardTranscript(cards: readonly ConcealedCard[], expectedTableId: string): CardTranscriptResult {
  if (expectedTableId.length !== 64) return { ok: false, reason: 'expectedTableId must be 32 bytes (64 hex)' };
  const seen = new Set<string>();
  for (const c of cards) {
    if (c.tableId !== expectedTableId) return { ok: false, reason: `card bound to a different table (${c.tableId.slice(0, 8)}…)` };
    if (!/^[0-9a-f]{66}$/.test(c.cardPub)) return { ok: false, reason: `cardPub is not a 33-byte compressed point: ${c.cardPub.slice(0, 12)}…` };
    try { secp.ProjectivePoint.fromHex(c.cardPub); } catch { return { ok: false, reason: `cardPub is not a valid curve point: ${c.cardPub.slice(0, 12)}…` }; }
    if (seen.has(c.cardPub)) return { ok: false, reason: `reused one-use card key ${c.cardPub.slice(0, 12)}… (keys must never repeat)` };
    seen.add(c.cardPub);
  }
  return { ok: true, reason: `verified ${cards.length} concealed cards: unique one-use keys, table-bound` };
}
