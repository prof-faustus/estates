/**
 * @estates/tx — canonical BSV transaction serialization + txid.
 *
 * Every move on chain is a real Bitcoin transaction; this is the wire format that
 * gives each one a real txid (the id an SPV Merkle proof, @estates/spv, references,
 * and the outpoint the next move spends). Pure, deterministic, isomorphic
 * (@noble) — no SDK, no node. Values are whole satoshis (bigint-safe 8-byte LE).
 */
import { sha256 } from '@noble/hashes/sha256';

export interface TxInput {
  readonly prevTxid: string;     // 64-hex, DISPLAY byte order (as users see it)
  readonly prevVout: number;
  readonly scriptSig: Uint8Array; // unlocking script (empty for an unsigned tx)
  readonly sequence: number;
}
export interface TxOutput {
  readonly value: number | bigint; // satoshis
  readonly script: Uint8Array;     // locking script
}
export interface Tx {
  readonly version: number;
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
  readonly lockTime: number;
}

export function hash256(b: Uint8Array): Uint8Array { return sha256(sha256(b)); }

const fromHex = (h: string): Uint8Array => {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
};
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const reversed = (b: Uint8Array): Uint8Array => b.slice().reverse();

// ---- LE integer + varint writers -------------------------------------------
function u32le(n: number): Uint8Array { return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]); }
function u64le(v: number | bigint): Uint8Array {
  let n = BigInt(v);
  if (n < 0n) throw new Error('value must be non-negative');
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
/** Bitcoin CompactSize / varint. */
export function varint(n: number): Uint8Array {
  if (n < 0) throw new Error('varint must be non-negative');
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >>> 8) & 0xff]);
  if (n <= 0xffffffff) return new Uint8Array([0xfe, ...u32le(n)]);
  return new Uint8Array([0xff, ...u64le(n)]);
}

function concat(parts: Uint8Array[]): Uint8Array {
  let len = 0; for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Canonical serialization of a transaction (the bytes that are hashed for txid). */
export function serializeTx(tx: Tx): Uint8Array {
  const parts: Uint8Array[] = [u32le(tx.version), varint(tx.inputs.length)];
  for (const i of tx.inputs) {
    const prev = fromHex(i.prevTxid);
    if (prev.length !== 32) throw new Error('prevTxid must be 32 bytes (64 hex)');
    parts.push(reversed(prev), u32le(i.prevVout), varint(i.scriptSig.length), i.scriptSig, u32le(i.sequence));
  }
  parts.push(varint(tx.outputs.length));
  for (const o of tx.outputs) parts.push(u64le(o.value), varint(o.script.length), o.script);
  parts.push(u32le(tx.lockTime));
  return concat(parts);
}

// ---- LE integer + varint readers -------------------------------------------
function rdU32(b: Uint8Array, o: number): number { return (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0; }
function rdVarint(b: Uint8Array, o: number): [number, number] {
  const f = b[o]!;
  if (f < 0xfd) return [f, o + 1];
  if (f === 0xfd) return [b[o + 1]! | (b[o + 2]! << 8), o + 3];
  if (f === 0xfe) return [rdU32(b, o + 1), o + 5];
  let v = 0n; for (let k = 0; k < 8; k++) v |= BigInt(b[o + 1 + k]!) << BigInt(8 * k); return [Number(v), o + 9];
}

/** Parse canonical tx bytes back into a Tx (inverse of serializeTx). Strict: throws
 *  on truncation. Used to re-verify a signed tx (e.g. against @estates/scriptvm). */
export function deserializeTx(bytes: Uint8Array): Tx {
  let o = 0;
  const version = rdU32(bytes, o); o += 4;
  let nIn: number; [nIn, o] = rdVarint(bytes, o);
  const inputs = [];
  for (let i = 0; i < nIn; i++) {
    if (o + 36 > bytes.length) throw new Error('truncated input');
    const prevTxid = toHex(reversed(bytes.slice(o, o + 32))); o += 32;
    const prevVout = rdU32(bytes, o); o += 4;
    let sl: number; [sl, o] = rdVarint(bytes, o);
    const scriptSig = bytes.slice(o, o + sl); o += sl;
    const sequence = rdU32(bytes, o); o += 4;
    inputs.push({ prevTxid, prevVout, scriptSig, sequence });
  }
  let nOut: number; [nOut, o] = rdVarint(bytes, o);
  const outputs = [];
  for (let i = 0; i < nOut; i++) {
    let val = 0n; for (let k = 0; k < 8; k++) val |= BigInt(bytes[o + k]!) << BigInt(8 * k); o += 8;
    let sl: number; [sl, o] = rdVarint(bytes, o);
    const script = bytes.slice(o, o + sl); o += sl;
    outputs.push({ value: Number(val), script });
  }
  const lockTime = rdU32(bytes, o);
  return { version, inputs, outputs, lockTime };
}

/** txid in DISPLAY byte order (reverse of hash256(serialized)). */
export function txid(tx: Tx): string { return toHex(reversed(hash256(serializeTx(tx)))); }
/** Raw serialized tx as hex. */
export function txHex(tx: Tx): string { return toHex(serializeTx(tx)); }
