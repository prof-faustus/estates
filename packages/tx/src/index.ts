/**
 * @estates/tx — canonical BSV transaction serialization, txid, and a FAIL-CLOSED
 * deserializer. Reference cryptographic infrastructure: this comment, and the
 * per-function notes below, are written so an AUDITOR can attack this code easily.
 *
 * WHAT
 *   Encodes a `Tx` to canonical Bitcoin wire bytes (`serializeTx`), derives its
 *   real txid (`txid`), and parses untrusted wire bytes back to a `Tx`
 *   (`deserializeTx`). Every on-chain move is a real Bitcoin transaction; these
 *   bytes are exactly what is hashed for the txid an SPV Merkle proof references
 *   and the outpoint the next move spends.
 *
 * HOW
 *   Bitcoin's canonical layout: version(4 LE) ‖ varint(nIn) ‖ inputs ‖ varint(nOut)
 *   ‖ outputs ‖ lockTime(4 LE). Each input = reverse(prevTxid)(32) ‖ vout(4 LE) ‖
 *   varint(scriptLen) ‖ script ‖ sequence(4 LE). Each output = value(8 LE) ‖
 *   varint(scriptLen) ‖ script. txid = reverse(sha256(sha256(serialized))). Pure,
 *   deterministic, isomorphic (@noble only — no SDK, no node:crypto).
 *
 * WHY
 *   The txid is consensus-critical and must be byte-exact (one wrong byte = a
 *   different tx = a broken SPV proof / unspendable cursor). Whole-satoshi values
 *   use bigint for the 8-byte field so no value is silently truncated by JS f64.
 *
 * WHY THIS DESIGN (and alternatives rejected)
 *   We do NOT use @bsv/sdk or any external library: it shipped circular ESM that
 *   broke the production bundle (a temporal-dead-zone crash) AND an external
 *   dependency is unauditable here / violates the standalone rule. A from-scratch,
 *   @noble-only codec is small enough to read in full and audit line-by-line.
 *
 * SECURITY BOUNDARY
 *   serializeTx/txid: inputs are TRUSTED (constructed by our own code); they throw
 *   on programmer error (e.g. a non-32-byte prevTxid) — that is a build-time bug,
 *   not attacker input. deserializeTx: input is FULLY UNTRUSTED (hostile peer/disk
 *   bytes); it must NEVER throw, hang, read out of bounds, or over-allocate — it
 *   returns `Tx | null` and rejects anything non-canonical. See deserializeTx.
 *   MUST NEVER ASSUME: that serialized input came from us, that counts/lengths fit
 *   memory, or that the buffer is long enough — all are checked.
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

/**
 * Bounded, fail-closed byte reader. EVERY read is bounds-checked against the
 * buffer; on any out-of-bounds it sets `failed` and yields a zero value (it never
 * reads past the end, never throws, never allocates beyond the buffer). The caller
 * checks `failed` and returns null. (SANS/CWE: untrusted input; NASA: bounded.)
 */
class Reader {
  private readonly b: Uint8Array;   // explicit field (strip-only mode forbids TS parameter properties)
  private o = 0;
  failed = false;
  constructor(b: Uint8Array) { this.b = b; }
  get rem(): number { return this.b.length - this.o; }
  private need(n: number): boolean {
    if (this.failed || !Number.isInteger(n) || n < 0 || n > this.rem) { this.failed = true; return false; }
    return true;
  }
  u32(): number { if (!this.need(4)) return 0; const v = (this.b[this.o]! | (this.b[this.o + 1]! << 8) | (this.b[this.o + 2]! << 16) | (this.b[this.o + 3]! << 24)) >>> 0; this.o += 4; return v; }
  u64(): number {
    if (!this.need(8)) return 0;
    let v = 0n; for (let k = 0; k < 8; k++) v |= BigInt(this.b[this.o + k]!) << BigInt(8 * k); this.o += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) { this.failed = true; return 0; }   // no silent precision loss
    return Number(v);
  }
  /** CompactSize. Rejects non-canonical encodings and values past MAX_SAFE_INTEGER. */
  varint(): number {
    if (!this.need(1)) return 0;
    const f = this.b[this.o++]!;
    if (f < 0xfd) return f;
    if (f === 0xfd) { if (!this.need(2)) return 0; const v = this.b[this.o]! | (this.b[this.o + 1]! << 8); this.o += 2; if (v < 0xfd) { this.failed = true; return 0; } return v; }
    if (f === 0xfe) { const v = this.u32(); if (!this.failed && v <= 0xffff) { this.failed = true; } return v; }
    const v = this.u64(); if (!this.failed && v <= 0xffffffff) { this.failed = true; } return v;
  }
  take(n: number): Uint8Array { if (!this.need(n)) return EMPTY; const s = this.b.slice(this.o, this.o + n); this.o += n; return s; }
}
const EMPTY = new Uint8Array(0);
const MIN_INPUT_BYTES = 41;   // 32 prevTxid + 4 vout + 1 (empty scriptSig varint) + 4 sequence
const MIN_OUTPUT_BYTES = 9;   // 8 value + 1 (empty script varint)
const MAX_TX_BYTES = 0x10000000; // 256 MiB hard cap on a single tx

/**
 * Parse canonical tx bytes back into a Tx (inverse of serializeTx). FAIL-CLOSED:
 * returns `null` on ANY malformed/hostile input — never throws, never reads out of
 * bounds, never runs an attacker-sized loop or allocation, and rejects trailing
 * bytes. Counts are bounded by the minimum bytes each element needs, so a giant
 * varint count cannot drive a long loop or a huge allocation.
 */
export function deserializeTx(bytes: Uint8Array): Tx | null {
  if (!(bytes instanceof Uint8Array) || bytes.length < 10 || bytes.length > MAX_TX_BYTES) return null;
  const r = new Reader(bytes);
  const version = r.u32();

  const nIn = r.varint();
  if (r.failed || nIn > Math.floor(r.rem / MIN_INPUT_BYTES)) return null;   // can't fit that many inputs
  const inputs: TxInput[] = [];
  for (let i = 0; i < nIn; i++) {
    const prev = r.take(32);
    const prevVout = r.u32();
    const sl = r.varint();
    if (r.failed || sl > r.rem) return null;
    const scriptSig = r.take(sl);
    const sequence = r.u32();
    if (r.failed) return null;
    inputs.push({ prevTxid: toHex(reversed(prev)), prevVout, scriptSig, sequence });
  }

  const nOut = r.varint();
  if (r.failed || nOut > Math.floor(r.rem / MIN_OUTPUT_BYTES)) return null;
  const outputs: TxOutput[] = [];
  for (let i = 0; i < nOut; i++) {
    const value = r.u64();
    const sl = r.varint();
    if (r.failed || sl > r.rem) return null;
    const script = r.take(sl);
    if (r.failed) return null;
    outputs.push({ value, script });
  }

  const lockTime = r.u32();
  if (r.failed || r.rem !== 0) return null;   // reject trailing garbage — exactly one canonical parse
  return { version, inputs, outputs, lockTime };
}

/** txid in DISPLAY byte order (reverse of hash256(serialized)). */
export function txid(tx: Tx): string { return toHex(reversed(hash256(serializeTx(tx)))); }
/** Raw serialized tx as hex. */
export function txHex(tx: Tx): string { return toHex(serializeTx(tx)); }
