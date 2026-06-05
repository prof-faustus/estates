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

/** True iff `pub` is a valid compressed secp256k1 point (33 bytes, on curve). */
export function isValidPub(pub: Uint8Array): boolean {
  try { secp.ProjectivePoint.fromHex(bytesToHex(pub)); return pub.length === 33; } catch { return false; }
}

/**
 * Seal `plaintext` to the holder of `recipientPub`. Optional `aad` is bound by
 * AES-GCM as ADDITIONAL AUTHENTICATED DATA — the open side must present the SAME
 * aad or decryption fails, so the ciphertext is cryptographically tied to (e.g.)
 * the table id + the card's public key, not merely accompanied by them.
 * Validates the recipient key first (never feeds an off-curve point to ECDH).
 */
export function sealTo(recipientPub: Uint8Array, plaintext: Uint8Array, aad: Uint8Array = EMPTY): Envelope {
  if (!isValidPub(recipientPub)) throw new Error('sealTo: recipient public key is not a valid compressed point');
  const eph = secp.utils.randomPrivateKey();
  const shared = secp.getSharedSecret(eph, recipientPub, true);
  const nonce = randomBytes(12);
  return {
    ephPub: bytesToHex(secp.getPublicKey(eph, true)),
    nonce: bytesToHex(nonce),
    ct: bytesToHex(gcm(kek(shared), nonce, aad).encrypt(plaintext)),
  };
}
/** Open a sealed envelope with a private key. null on wrong key, wrong aad, or
 *  tamper (AEAD). The `aad` MUST match the one used to seal. */
export function open(priv: Uint8Array, env: Envelope, aad: Uint8Array = EMPTY): Uint8Array | null {
  try {
    if (!env || typeof env !== 'object') return null;
    const shared = secp.getSharedSecret(priv, hexToBytes(env.ephPub), true);
    return gcm(kek(shared), hexToBytes(env.nonce), aad).decrypt(hexToBytes(env.ct));
  } catch {
    return null;
  }
}

// ---- mental-poker concealment: binding commitment to a hidden face ----------
/** Commitment H(face ‖ blind): binding (cannot find another face/blind) + hiding.
 *  Generic primitive (entropy etc.). Card commitments use the DOMAIN-SEPARATED
 *  `cardCommit` below, which also binds the protocol tag + table/game id. */
export function commit(face: Uint8Array, blind: Uint8Array): string {
  return bytesToHex(sha256(concatBytes(face, blind)));
}

// Domain-separated card-face commitment (audit: a commitment must be bound to the
// protocol + game/table, never a bare H(face‖blind)). Bound to the STABLE tableId
// (= gameId) and a version tag. cardPub is NOT in the commitment because a card's
// key ROTATES on every transfer while its identity/commitment is preserved; the
// rotating cardPub is bound instead in the per-custody AEAD aad (see cardAad).
const CARD_COMMIT_TAG = new TextEncoder().encode('ESTATES_CARD_COMMIT_V1');
function cardCommit(tableId: string, faceBytes: Uint8Array, blind: Uint8Array): string {
  return bytesToHex(sha256(concatBytes(CARD_COMMIT_TAG, hexToBytes(tableId), faceBytes, blind)));
}
/** The AEAD aad binding a sealed face to its table + the holding card's key. */
function cardAad(tableId: string, cardPub: string): Uint8Array {
  return concatBytes(new TextEncoder().encode('ESTATES_CARD_AAD_V1|'), hexToBytes(tableId), hexToBytes(cardPub));
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

const MAX_FACE_PAYLOAD = 1 << 16; // 64 KiB — far above any real card payload
/**
 * Reject an invalid face BEFORE encoding (audit: TypeScript types do not validate
 * runtime values — a hostile `kind`/`id`/`payload` would otherwise encode as
 * malformed bytes). Throws on anything that is not a well-formed face.
 */
export function validateFace(f: unknown): asserts f is CardFace {
  if (!f || typeof f !== 'object') throw new Error('validateFace: not an object');
  const o = f as Record<string, unknown>;
  if (typeof o.kind !== 'string' || !(o.kind in KIND_BYTE)) throw new Error('validateFace: bad kind');
  if (typeof o.id !== 'number' || !Number.isInteger(o.id) || o.id < 0 || o.id > 0xffffffff) throw new Error('validateFace: id must be a uint32');
  if (o.payload !== undefined && (!(o.payload instanceof Uint8Array) || o.payload.length > MAX_FACE_PAYLOAD)) throw new Error('validateFace: bad payload');
}

/** Deterministic, length-prefixed face encoding (so commitments are canonical). */
export function encodeFace(f: CardFace): Uint8Array {
  validateFace(f);
  const payload = f.payload ?? EMPTY;
  const out = new Uint8Array(1 + 4 + 4 + payload.length);
  out[0] = KIND_BYTE[f.kind];
  out[1] = (f.id >>> 24) & 0xff; out[2] = (f.id >>> 16) & 0xff; out[3] = (f.id >>> 8) & 0xff; out[4] = f.id & 0xff;
  const n = payload.length;
  out[5] = (n >>> 24) & 0xff; out[6] = (n >>> 16) & 0xff; out[7] = (n >>> 8) & 0xff; out[8] = n & 0xff;
  out.set(payload, 9);
  return out;
}
// Throws by contract on a malformed face (so commitments stay canonical). Callers
// that handle untrusted faces (openCard, fed bytes a possibly-MALICIOUS minter
// committed to) MUST catch — see openCard. The explicit length guard means the
// header is never read past the buffer (no `undefined`-coercion arithmetic).
export function decodeFace(b: Uint8Array): CardFace {
  if (!(b instanceof Uint8Array) || b.length < 9) throw new Error('decodeFace: too short');
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
  if (!isTableIdHex(tableId)) throw new Error('tableId must be 32 bytes (64 hex)');
  if (!isValidPub(holderPub)) throw new Error('mintCard: holder public key is not a valid compressed point');
  const blind = randomBytes(32);
  const key = genCardKey();
  const faceBytes = encodeFace(face);
  const cardPub = bytesToHex(key.pub);
  const card: ConcealedCard = {
    tableId,
    cardPub,
    commitment: cardCommit(tableId, faceBytes, blind),          // domain-separated (tag + tableId)
    sealed: sealTo(holderPub, faceBytes, cardAad(tableId, cardPub)), // AEAD bound to table + card key
  };
  return { card, secret: { face, blind, key } };
}

/** The holder opens their card: returns the face iff the seal opens AND it matches
 *  the public commitment (no swap), AND it is bound to the expected table. */
export function openCard(card: ConcealedCard, holderPriv: Uint8Array, blind: Uint8Array, expectedTableId: string): CardFace | null {
  if (!card || typeof card !== 'object') return null;
  if (!isTableIdHex(expectedTableId) || card.tableId !== expectedTableId) return null;  // table-bound
  if (typeof card.cardPub !== 'string') return null;
  // AEAD aad must match the table + card key it was sealed under (open is total).
  const faceBytes = open(holderPriv, card.sealed, cardAad(card.tableId, card.cardPub));
  if (!faceBytes) return null;                                 // not the holder / wrong aad / tampered
  if (card.commitment !== cardCommit(card.tableId, faceBytes, blind)) return null; // domain-separated commitment mismatch
  // A MALICIOUS minter may have committed+sealed a malformed face: the commitment
  // check passes (it matches the garbage), but decodeFace would throw. Stay total —
  // a card whose face does not decode is simply "not a valid card" → null.
  try { return decodeFace(faceBytes); } catch { return null; }
}

/** A transcript event proving a card key was RETIRED on transfer (audit: a
 *  transfer must emit a retirement event for the old key, so a verifier can prove
 *  the old key is one-use and never reused). */
export interface TransferEvent {
  readonly tableId: string;
  readonly retired: string;   // the old cardPub (now retired, must never reappear)
  readonly newCardPub: string;
}

/** Transfer a card to a new holder: re-seal the face to them with a FRESH one-use
 *  key (the old key is retired). The identity + table + commitment are preserved
 *  (the commitment is bound to the stable tableId, not the rotating key); the new
 *  seal's AEAD aad binds the NEW card key. Returns the new card, its key, and a
 *  retirement event for the old key. */
export function transferCard(card: ConcealedCard, face: CardFace, newHolderPub: Uint8Array): { card: ConcealedCard; key: CardKey; event: TransferEvent } {
  if (!isTableIdHex(card.tableId)) throw new Error('transferCard: card.tableId must be 32-byte hex');
  if (!isValidPub(newHolderPub)) throw new Error('transferCard: new holder public key is not a valid compressed point');
  const key = genCardKey();
  const newCardPub = bytesToHex(key.pub);
  const newCard: ConcealedCard = {
    tableId: card.tableId,
    cardPub: newCardPub,
    commitment: card.commitment,
    sealed: sealTo(newHolderPub, encodeFace(face), cardAad(card.tableId, newCardPub)),
  };
  return { card: newCard, key, event: { tableId: card.tableId, retired: card.cardPub, newCardPub } };
}

// ---- dealerless mental-poker shuffle (no single party knows the order) -------
export interface EntropyCommit { readonly who: string; readonly commitment: string }
/** A party commits to secret entropy before anyone reveals (commit phase). */
export function commitEntropy(secretBytes: Uint8Array): string { return bytesToHex(sha256(secretBytes)); }
/** Verify a revealed entropy matches its prior commitment. */
export function verifyEntropy(commitment: string, secretBytes: Uint8Array): boolean { return commitEntropy(secretBytes) === commitment; }
/** Combine all revealed entropies (canonical order = sorted hex) into one seed.
 *  No single party can determine the result without controlling all others.
 *  Legacy/low-level: prefer `combineSeedBound` for live shuffles (it binds the
 *  participant identities + game id + commitments so a missing/substituted party
 *  is detected). */
export function combineSeed(reveals: readonly Uint8Array[]): Uint8Array {
  const sorted = reveals.map(bytesToHex).sort();
  return sha256(concatBytes(...sorted.map(hexToBytes)));
}

/** A signed-shuffle participant: a seat, its key, its prior entropy commitment,
 *  and the revealed secret that must open that commitment. */
export interface SeedParty {
  readonly seat: number;
  readonly pub: string;          // hex
  readonly commitment: string;   // hex = commitEntropy(reveal)
  readonly reveal: Uint8Array;
}
/**
 * BOUND seed combination (audit: combineSeed must bind the PARTICIPANT SET, not
 * just sort reveal bytes — otherwise a missing/duplicate/substituted party is
 * undetectable). Verifies every reveal opens its commitment, rejects duplicate
 * seats/keys, and folds (gameId ‖ for each party in seat order: seat‖pub‖
 * commitment‖reveal) into the seed. Returns null on any inconsistency (total).
 */
export function combineSeedBound(parties: readonly SeedParty[], gameId: string): Uint8Array | null {
  if (!isTableIdHex(gameId) || !Array.isArray(parties) || parties.length === 0 || parties.length > 64) return null;
  const seats = new Set<number>(); const pubs = new Set<string>();
  const sorted = [...parties].sort((a, b) => a.seat - b.seat);
  const parts: Uint8Array[] = [new TextEncoder().encode('ESTATES_SHUFFLE_SEED_V1|'), hexToBytes(gameId)];
  for (const p of sorted) {
    if (!Number.isInteger(p.seat) || p.seat < 0 || p.seat > 63) return null;
    if (typeof p.pub !== 'string' || !/^[0-9a-f]+$/.test(p.pub) || p.pub.length % 2 !== 0) return null;
    if (!(p.reveal instanceof Uint8Array)) return null;
    if (typeof p.commitment !== 'string' || commitEntropy(p.reveal) !== p.commitment) return null; // reveal must open its commitment
    if (seats.has(p.seat) || pubs.has(p.pub)) return null;                                          // no duplicate party
    seats.add(p.seat); pubs.add(p.pub);
    parts.push(u32be(p.seat), hexToBytes(p.pub), hexToBytes(p.commitment), p.reveal);
  }
  return sha256(concatBytes(...parts));
}
const u32be = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);

/**
 * DEALERLESS DECK ORDER — the jointly-generated shuffle for a live game (audit:
 * every random event, incl. the deck order, must be generated by ALL parties so no
 * single machine/holder determines it). From every seat's committed→revealed
 * entropy it derives ONE participant-bound seed (combineSeedBound), then an EXACT,
 * unbiased permutation for each named deck (domain-separated per deck so the decks
 * are independent). The result is deterministic + verifiable: any party can
 * recompute it from the public commitments + reveals, and changing/missing any
 * party changes it — so it is jointly generated, not dealer-chosen. Returns null on
 * any inconsistent party set (bad opening, duplicate, etc.).
 *
 * `deckSizes` maps each deck name to its size (e.g. { Fate: 12, Treasury: 12 }).
 */
export function dealerlessDeckOrder(parties: readonly SeedParty[], gameId: string, deckSizes: Readonly<Record<string, number>>): Record<string, number[]> | null {
  const base = combineSeedBound(parties, gameId);
  if (!base) return null;
  const order: Record<string, number[]> = {};
  for (const name of Object.keys(deckSizes).sort()) {
    const n = deckSizes[name]!;
    if (!Number.isSafeInteger(n) || n < 0 || n > MAX_DECK_SIZE) return null;
    const seed = sha256(concatBytes(base, new TextEncoder().encode('ESTATES_DECK_ORDER_V1|deck:' + name)));
    order[name] = permutation(seed, n);
  }
  return order;
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
export const MAX_DECK_SIZE = 1 << 16; // 65536 — far above any real ESTATES set
export function permutation(seed: Uint8Array, n: number): number[] {
  // Guard the size (audit): a non-integer / negative / huge n would otherwise
  // allocate unboundedly or loop forever. ESTATES sets are ≤ a few dozen.
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_DECK_SIZE) throw new Error(`permutation: n out of range (0..${MAX_DECK_SIZE})`);
  if (!(seed instanceof Uint8Array)) throw new Error('permutation: seed must be Uint8Array');
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
// A 32-byte table id must be valid lowercase hex, not merely 64 chars long
// (length-only checks let "zz…" through — audit finding).
export function isTableIdHex(x: unknown): x is string {
  return typeof x === 'string' && x.length === 64 && /^[0-9a-f]{64}$/.test(x);
}

/**
 * @param priorUsedKeys card keys already used by PREVIOUS games (or earlier in a
 *   global history). A one-use card key must never appear here — that is the
 *   CROSS-GAME reuse rejection (audit finding). Omit it to check only within-game
 *   uniqueness.
 */
export function verifyCardTranscript(
  cards: readonly ConcealedCard[],
  expectedTableId: string,
  priorUsedKeys?: Iterable<string>,
): CardTranscriptResult {
  if (!isTableIdHex(expectedTableId)) return { ok: false, reason: 'expectedTableId must be 32 bytes (64 hex)' };
  const prior = priorUsedKeys ? new Set(priorUsedKeys) : null;
  const seen = new Set<string>();
  for (const c of cards) {
    if (!isTableIdHex(c.tableId)) return { ok: false, reason: `card tableId is not 32-byte hex (${String(c.tableId).slice(0, 8)}…)` };
    if (c.tableId !== expectedTableId) return { ok: false, reason: `card bound to a different table (${c.tableId.slice(0, 8)}…)` };
    if (!/^[0-9a-f]{66}$/.test(c.cardPub)) return { ok: false, reason: `cardPub is not a 33-byte compressed point: ${c.cardPub.slice(0, 12)}…` };
    try { secp.ProjectivePoint.fromHex(c.cardPub); } catch { return { ok: false, reason: `cardPub is not a valid curve point: ${c.cardPub.slice(0, 12)}…` }; }
    if (prior?.has(c.cardPub)) return { ok: false, reason: `card key ${c.cardPub.slice(0, 12)}… was used in a prior game (keys serve at most ONE game)` };
    if (seen.has(c.cardPub)) return { ok: false, reason: `reused one-use card key ${c.cardPub.slice(0, 12)}… (keys must never repeat)` };
    seen.add(c.cardPub);
  }
  return { ok: true, reason: `verified ${cards.length} concealed cards: unique one-use keys, table-bound${prior ? ', no cross-game reuse' : ''}` };
}
