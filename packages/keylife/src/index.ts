/**
 * @estates/keylife — the ONE-GAME KEY LIFECYCLE.
 *
 * GOVERNING RULE (mandatory): every cryptographic key the game uses is valid for
 * AT MOST ONE GAME. A key may last a whole game, but it must be retired before a
 * new game starts; reusing any key across games is REJECTED.
 *
 * This is enforced by a signed GENESIS KEY MANIFEST that binds every key — seat,
 * card, holder, chat, bank, settlement, trade — to a single `gameId`, plus a
 * verifier that rejects:
 *   - a manifest whose authority signature does not cover its contents,
 *   - a key reused for two purposes / two seats inside one game,
 *   - the SAME key appearing under two different `gameId`s (cross-game reuse),
 *   - a key used in a transcript that is not bound by that game's manifest.
 *
 * WHAT / HOW / WHY:
 *  - WHAT: a self-describing, authority-signed list of (purpose, pubkey) bound to
 *    one gameId + protocolVersion + paramsHash.
 *  - HOW: the genesis authority (an Ed25519 key, itself entry purpose 'genesis')
 *    signs the canonical manifest bytes; verifiers re-validate every field and the
 *    signature, then cross-check pubkeys across manifests for reuse.
 *  - WHY: without a manifest, "one-use keys" is only a convention; a verifier that
 *    REJECTS reuse is what makes it real (audit finding #1/#2). Binding to gameId +
 *    paramsHash also prevents replaying a key set into a different game/ruleset.
 *
 * Boundary: every input here is UNTRUSTED bytes/objects. No function throws on a
 * hostile input — each returns a typed {ok,reason} result (fail-closed).
 */
import { signData, verifyData } from '@estates/channel';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export type KeyPurpose =
  | 'genesis'     // the manifest authority (Ed25519)
  | 'seat'        // a player's per-game seat signing key (Ed25519)
  | 'card'        // a concealed card's one-use custody key (secp256k1)
  | 'holder'      // a card holder's key (secp256k1)
  | 'chat'        // a chat/session epoch key (secp256k1)
  | 'bank'        // a bank-policy key (secp256k1/Ed25519)
  | 'settlement'  // a settlement key (secp256k1)
  | 'trade';      // a trade input key (secp256k1)

export type KeyType = 'ed25519' | 'secp256k1';
const PURPOSES = new Set<string>(['genesis', 'seat', 'card', 'holder', 'chat', 'bank', 'settlement', 'trade']);
const KEYTYPES = new Set<string>(['ed25519', 'secp256k1']);

export interface KeyEntry {
  readonly purpose: KeyPurpose;
  readonly pub: string;        // hex (33-byte compressed secp256k1, or 32-byte Ed25519)
  readonly keyType: KeyType;
  readonly seat?: number;      // for purpose 'seat'
}

export interface GameKeyManifest {
  readonly gameId: string;          // 32-byte hex — the single game these keys serve
  readonly protocolVersion: string;
  readonly paramsHash: string;      // 32-byte hex — the ruleset these keys are bound to
  readonly entries: readonly KeyEntry[];
  readonly authorityPub: string;    // 32-byte hex Ed25519 (the 'genesis' entry's pub)
  readonly sig: string;             // 128-hex Ed25519 over the canonical manifest bytes
}

export interface ManifestCheck { readonly ok: boolean; readonly reason: string }

// ---- bounds (no attacker-controlled allocation) ----------------------------
const MAX_ENTRIES = 4096;           // generous: seats + a full concealed deck + epochs
const HEX32 = 64;                   // 32-byte hex
const ED_PUB = 64;                  // Ed25519 pub = 32 bytes
const ED_SIG = 128;                 // Ed25519 sig = 64 bytes
const SECP_PUB = 66;                // compressed secp256k1 pub = 33 bytes
const MAX_SEAT = 7;

const isHexLen = (x: unknown, n: number): x is string =>
  typeof x === 'string' && x.length === n && /^[0-9a-fA-F]+$/.test(x);
const isHexBytes = (x: unknown): x is string =>
  typeof x === 'string' && x.length > 0 && x.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(x);
const isInt = (x: unknown, lo: number, hi: number): x is number =>
  typeof x === 'number' && Number.isInteger(x) && x >= lo && x <= hi;

function fromHex(h: string): Uint8Array {
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}

/** sha256 hex of arbitrary bytes — used to bind a ruleset (paramsHash). */
export function hashHex(bytes: Uint8Array): string { return bytesToHex(sha256(bytes)); }

/** The canonical bytes the authority signs (and a verifier re-derives). The sig
 *  and authorityPub are NOT inside the signed body (the signature wraps them). */
function manifestBody(m: Pick<GameKeyManifest, 'gameId' | 'protocolVersion' | 'paramsHash' | 'entries'>): Uint8Array {
  // entries are serialised in a fixed field order so the signature is exact and
  // independent of object key order.
  const entries = m.entries.map((e) => ({ purpose: e.purpose, pub: e.pub, keyType: e.keyType, seat: e.seat ?? null }));
  return new TextEncoder().encode(JSON.stringify({
    k: 'estates-keymanifest-v1', gameId: m.gameId, protocolVersion: m.protocolVersion, paramsHash: m.paramsHash, entries,
  }));
}

/** Build + sign a manifest. `authorityPriv/Pub` is an Ed25519 keypair, and MUST
 *  also appear in `entries` as the single purpose:'genesis' entry. */
export function buildManifest(
  gameId: string, protocolVersion: string, paramsHash: string,
  entries: readonly KeyEntry[], authorityPriv: Uint8Array, authorityPub: string,
): GameKeyManifest {
  const body = manifestBody({ gameId, protocolVersion, paramsHash, entries });
  return { gameId, protocolVersion, paramsHash, entries, authorityPub, sig: bytesToHex(signData(body, authorityPriv)) };
}

/**
 * Verify ONE manifest in isolation: structure + bounds + no in-game reuse +
 * authority signature. Total: returns {ok:false,reason} on any hostile input,
 * never throws.
 */
export function verifyManifest(m: unknown): ManifestCheck {
  if (!m || typeof m !== 'object') return fail('manifest is not an object');
  const o = m as Record<string, unknown>;
  if (!isHexLen(o.gameId, HEX32)) return fail('gameId must be 32-byte hex');
  if (typeof o.protocolVersion !== 'string' || o.protocolVersion.length === 0 || o.protocolVersion.length > 64) return fail('bad protocolVersion');
  if (!isHexLen(o.paramsHash, HEX32)) return fail('paramsHash must be 32-byte hex');
  if (!isHexLen(o.authorityPub, ED_PUB)) return fail('authorityPub must be 32-byte hex');
  if (!isHexLen(o.sig, ED_SIG)) return fail('sig must be 64-byte hex');
  if (!Array.isArray(o.entries) || o.entries.length === 0 || o.entries.length > MAX_ENTRIES) return fail('entries out of range');

  const seenPub = new Set<string>();
  const seenSeat = new Set<number>();
  let genesisCount = 0;
  const cleanEntries: KeyEntry[] = [];
  for (let i = 0; i < o.entries.length; i++) {
    const e = o.entries[i] as Record<string, unknown>;
    if (!e || typeof e !== 'object') return fail(`entry ${i} is not an object`);
    if (typeof e.purpose !== 'string' || !PURPOSES.has(e.purpose)) return fail(`entry ${i} bad purpose`);
    if (typeof e.keyType !== 'string' || !KEYTYPES.has(e.keyType)) return fail(`entry ${i} bad keyType`);
    const expectLen = e.keyType === 'ed25519' ? ED_PUB : SECP_PUB;
    if (!isHexLen(e.pub, expectLen)) return fail(`entry ${i} pub wrong length for ${e.keyType}`);
    if (seenPub.has(e.pub as string)) return fail(`entry ${i} reuses key ${(e.pub as string).slice(0, 12)}… inside one game`);
    seenPub.add(e.pub as string);
    let seat: number | undefined;
    if (e.purpose === 'seat') {
      if (!isInt(e.seat, 0, MAX_SEAT)) return fail(`entry ${i} seat out of range`);
      if (seenSeat.has(e.seat)) return fail(`entry ${i} duplicate seat ${e.seat}`);
      seenSeat.add(e.seat); seat = e.seat;
    } else if (e.seat !== undefined && e.seat !== null) {
      if (!isInt(e.seat, 0, MAX_SEAT)) return fail(`entry ${i} seat out of range`);
      seat = e.seat;
    }
    if (e.purpose === 'genesis') {
      genesisCount++;
      if (e.keyType !== 'ed25519') return fail('genesis key must be ed25519');
      if (e.pub !== o.authorityPub) return fail('genesis entry pub must equal authorityPub');
    }
    cleanEntries.push(seat === undefined ? { purpose: e.purpose as KeyPurpose, pub: e.pub as string, keyType: e.keyType as KeyType } : { purpose: e.purpose as KeyPurpose, pub: e.pub as string, keyType: e.keyType as KeyType, seat });
  }
  if (genesisCount !== 1) return fail('manifest must have exactly one genesis entry (the authority)');

  // authority signature over the canonical body
  let body: Uint8Array, sig: Uint8Array, apub: Uint8Array;
  try {
    body = manifestBody({ gameId: o.gameId as string, protocolVersion: o.protocolVersion, paramsHash: o.paramsHash as string, entries: cleanEntries });
    sig = fromHex(o.sig as string); apub = fromHex(o.authorityPub as string);
  } catch { return fail('hex decode failed'); }
  if (!verifyData(body, sig, apub)) return fail('authority signature invalid (manifest tampered or wrong key)');

  return { ok: true, reason: `manifest verified: ${cleanEntries.length} keys bound to game ${(o.gameId as string).slice(0, 12)}…` };
}

/** All pubkeys a (verified) manifest binds. */
export function manifestKeys(m: GameKeyManifest): string[] {
  return m.entries.map((e) => e.pub);
}

/**
 * CROSS-GAME REUSE: given several manifests (each already verified), reject if
 * the SAME pubkey appears under two DIFFERENT gameIds — i.e. a key outliving its
 * one game. Re-listing the same key inside the same gameId is fine (idempotent).
 */
export function verifyNoCrossGameReuse(manifests: readonly GameKeyManifest[]): ManifestCheck {
  const owner = new Map<string, string>(); // pub -> gameId
  for (const m of manifests) {
    for (const e of m.entries) {
      const prev = owner.get(e.pub);
      if (prev !== undefined && prev !== m.gameId)
        return fail(`key ${e.pub.slice(0, 12)}… reused across games ${prev.slice(0, 8)}… and ${m.gameId.slice(0, 8)}… (a key serves at most ONE game)`);
      owner.set(e.pub, m.gameId);
    }
  }
  return { ok: true, reason: `no cross-game key reuse across ${manifests.length} game(s)` };
}

/**
 * A key is FRESH for `gameId` iff it is bound by that game's manifest and does
 * not appear in any PRIOR game's manifest (so a key from game N is rejected in
 * game N+1 — one-game expiry). `priorManifests` are the manifests of earlier,
 * already-finalised games.
 */
export function assertFreshForGame(pub: string, gameId: string, manifestForGame: GameKeyManifest, priorManifests: readonly GameKeyManifest[]): ManifestCheck {
  if (!isHexBytes(pub)) return fail('pub is not hex');
  if (manifestForGame.gameId !== gameId) return fail('manifestForGame is not this game');
  if (!manifestForGame.entries.some((e) => e.pub === pub)) return fail(`key ${pub.slice(0, 12)}… is not bound by game ${gameId.slice(0, 8)}…`);
  for (const pm of priorManifests) {
    if (pm.gameId === gameId) continue;
    if (pm.entries.some((e) => e.pub === pub))
      return fail(`key ${pub.slice(0, 12)}… was already used in game ${pm.gameId.slice(0, 8)}… (expired; one key per game)`);
  }
  return { ok: true, reason: `key fresh for game ${gameId.slice(0, 8)}…` };
}

function fail(reason: string): ManifestCheck { return { ok: false, reason }; }
