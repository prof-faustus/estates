/**
 * @estates/onchain — 1-sat NFTs + native-sat payments (tx-nft doc §3, §4).
 *
 * A title deed (and a Reprieve card) is a 1-satoshi UTXO whose live script
 * carries the object's state as pushdata (consumed by OP_DROP/OP_2DROP),
 * followed by a P2PKH ownership predicate. Ownership transfers by spending the
 * 1-sat output into a new 1-sat output with the new owner. Money is native
 * satoshis (ordinary P2PKH outputs) — never a token. No data-output opcode, no
 * locktime-verify opcodes; state is pushdata in live script, timing is tx-level.
 */
import { createHash } from 'node:crypto';
import { OP, op, push, p2pkh, serializeScript, scriptHex, containsOpReturn, type ScriptItem } from './script.ts';

export * from './script.ts';

export const NFT_SATS = 1; // every ESTATES NFT is a 1-sat NFT (R10)

export type NftKind = 'TITLE' | 'REPRIEVE';

/** Outpoint of the genesis output this object descends from (provenance root). */
export interface Outpoint { readonly txid: string; readonly vout: number; } // txid = 64-hex

export interface TitleState {
  readonly kind: NftKind;
  readonly gameTag: Uint8Array;   // 32-byte domain-separated game id
  readonly propertyId: number;    // 0–39 (TITLE); 0 for REPRIEVE
  readonly groupId: number;       // group ordinal; 0 for REPRIEVE
  readonly buildLevel: number;    // 0–5 (TITLE); 0 for REPRIEVE
  readonly mortgaged: boolean;
  readonly genesis: Outpoint;
}

const KIND_BYTE: Record<NftKind, number> = { TITLE: 0x01, REPRIEVE: 0x02 };
const STATE_LEN = 1 + 32 + 1 + 1 + 1 + 1 + 32 + 4; // = 73 bytes, fixed layout

function fromHex(h: string): Uint8Array {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}

export const BOARD_SIZE = 40; // board spaces 0..39
/** Reject impossible NFT state (audit #6): out-of-range ids/levels, non-canonical
 *  REPRIEVE, bad vout — so a malformed/adversarial title can never encode. */
export function validateTitleState(s: TitleState): void {
  if (s.kind !== 'TITLE' && s.kind !== 'REPRIEVE') throw new Error('bad kind');
  if (s.gameTag.length !== 32) throw new Error('gameTag must be 32 bytes');
  if (!Number.isInteger(s.propertyId) || s.propertyId < 0 || s.propertyId >= BOARD_SIZE) throw new Error('propertyId out of range 0..39');
  if (!Number.isInteger(s.groupId) || s.groupId < 0 || s.groupId > 255) throw new Error('groupId out of range 0..255');
  if (!Number.isInteger(s.buildLevel) || s.buildLevel < 0 || s.buildLevel > 5) throw new Error('buildLevel out of range 0..5');
  if (typeof s.mortgaged !== 'boolean') throw new Error('mortgaged must be boolean');
  if (s.kind === 'REPRIEVE' && (s.propertyId !== 0 || s.groupId !== 0 || s.buildLevel !== 0)) throw new Error('REPRIEVE must have propertyId=groupId=buildLevel=0');
  if (!Number.isInteger(s.genesis.vout) || s.genesis.vout < 0 || s.genesis.vout > 0xffffffff) throw new Error('genesis.vout must be a uint32');
}
const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/** Canonical fixed-layout encoding of an NFT's state blob. */
export function encodeTitleState(s: TitleState): Uint8Array {
  validateTitleState(s); // reject impossible state rather than masking it (audit #6)
  const txid = fromHex(s.genesis.txid);
  if (txid.length !== 32) throw new Error('genesis.txid must be 32 bytes (64 hex)');
  const out = new Uint8Array(STATE_LEN);
  let o = 0;
  out[o++] = KIND_BYTE[s.kind];
  out.set(s.gameTag, o); o += 32;
  out[o++] = s.propertyId;
  out[o++] = s.groupId;
  out[o++] = s.buildLevel;
  out[o++] = s.mortgaged ? 1 : 0;
  out.set(txid, o); o += 32;
  out[o++] = (s.genesis.vout >>> 24) & 0xff;
  out[o++] = (s.genesis.vout >>> 16) & 0xff;
  out[o++] = (s.genesis.vout >>> 8) & 0xff;
  out[o++] = s.genesis.vout & 0xff;
  return out;
}

export function decodeTitleState(blob: Uint8Array): TitleState {
  if (blob.length !== STATE_LEN) throw new Error(`state blob must be ${STATE_LEN} bytes`);
  let o = 0;
  const kindByte = blob[o++];
  const kind: NftKind = kindByte === KIND_BYTE.REPRIEVE ? 'REPRIEVE' : 'TITLE';
  if (kindByte !== KIND_BYTE.TITLE && kindByte !== KIND_BYTE.REPRIEVE) throw new Error('bad kind byte');
  const gameTag = blob.slice(o, o + 32); o += 32;
  const propertyId = blob[o++]!;
  const groupId = blob[o++]!;
  const buildLevel = blob[o++]!;
  const mortByte = blob[o++]!;
  if (mortByte !== 0 && mortByte !== 1) throw new Error('non-canonical mortgaged byte');
  const mortgaged = mortByte === 1;
  const txid = toHex(blob.slice(o, o + 32)); o += 32;
  const vout = ((blob[o]! << 24) | (blob[o + 1]! << 16) | (blob[o + 2]! << 8) | blob[o + 3]!) >>> 0;
  const state: TitleState = { kind, gameTag, propertyId, groupId, buildLevel, mortgaged, genesis: { txid, vout } };
  validateTitleState(state); // reject impossible decoded state (audit #6)
  return state;
}

/** Locking script for a 1-sat NFT: `<state> OP_DROP <P2PKH(owner)>`. */
export function nftLockingScript(state: TitleState, ownerPkh: Uint8Array): ScriptItem[] {
  return [push(encodeTitleState(state)), op(OP.OP_DROP), ...p2pkh(ownerPkh)];
}

export interface TxOutput { readonly satoshis: number; readonly script: Uint8Array; }

/** A 1-sat NFT output bound to an owner. */
export function nftOutput(state: TitleState, ownerPkh: Uint8Array): TxOutput {
  return { satoshis: NFT_SATS, script: serializeScript(nftLockingScript(state, ownerPkh)) };
}

/** A 1-sat NFT output under an ARBITRARY custody script: `<state> OP_DROP <custody>`.
 *  Used to lock a bank-held NFT under the bank covenant instead of a reused pkh. */
export function nftOutputWith(state: TitleState, custody: ScriptItem[]): TxOutput {
  return { satoshis: NFT_SATS, script: serializeScript([push(encodeTitleState(state)), op(OP.OP_DROP), ...custody]) };
}

/** An ordinary native-sat payment output (money is sats, never a token). */
export function paymentOutput(satoshis: number, ownerPkh: Uint8Array): TxOutput {
  if (!Number.isInteger(satoshis) || satoshis < 0) throw new Error('satoshis must be a non-negative integer');
  return { satoshis, script: serializeScript(p2pkh(ownerPkh)) };
}

/** Compute the game tag = SHA-256(gameId ‖ "ESTATES" ‖ kind). Domain-separated. */
export function gameTag(gameId: Uint8Array, kind: NftKind): Uint8Array {
  return new Uint8Array(createHash('sha256').update(gameId).update('ESTATES').update(kind).digest());
}

/**
 * Provenance check: an NFT is valid only if its state names the genesis outpoint
 * it descends from (tx-nft §3 forgery resistance — full chain-walk is the
 * indexer's job; this asserts the claimed root matches the expected one).
 */
export function hasGenesis(state: TitleState, expected: Outpoint): boolean {
  return state.genesis.txid === expected.txid && state.genesis.vout === expected.vout;
}

export { scriptHex, containsOpReturn };
