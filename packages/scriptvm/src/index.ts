/**
 * @estates/scriptvm — a BSV Script interpreter that proves an input SATISFIES its
 * prevout (red-team #4). Serialization is not validation: this executes the
 * unlocking + locking scripts on a stack machine with REAL BIP-143 sighash +
 * ECDSA OP_CHECKSIG, enforces the banned opcodes, and checks fee/value
 * conservation. It covers exactly the ESTATES script forms — P2PKH, the
 * `<state> OP_DROP <P2PKH>` NFT/commit output, and the `<rh> <tag> OP_2DROP
 * OP_TRUE` bank covenant — so a produced move/genesis tx can be proven spend-valid.
 */
import { verifyHash, sha256, ripemd160 } from '@estates/keys';
import { hash256, varint, type Tx } from '@estates/tx';
import { OP, BANNED_OPCODES, type ScriptItem } from '@estates/onchain';

export interface Prevout { readonly value: number; readonly script: Uint8Array }
export interface ScriptCheck { readonly ok: boolean; readonly reason: string }
export interface TxCheck extends ScriptCheck { readonly fee: number }

const u32le = (n: number): Uint8Array => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
function u64le(v: number): Uint8Array {
  const out = new Uint8Array(8); let x = BigInt(v);
  for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
// STRICT hex parser (audit 4.5): even length + hex-only, else throw. A malformed txid/script
// hex must never silently become a zero/NaN byte array in a sighash-critical path.
function fromHex(h: string): Uint8Array {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('scriptvm: invalid hex');
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}
const reversed = (b: Uint8Array): Uint8Array => b.slice().reverse();
function concat(...parts: Uint8Array[]): Uint8Array { let n = 0; for (const p of parts) n += p.length; const o = new Uint8Array(n); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; }
const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
const hash160 = (b: Uint8Array): Uint8Array => ripemd160(sha256(b));

// The in-tree verifyHash takes a compact (r‖s) signature; Bitcoin scriptSigs carry DER. Convert.
function derToCompact(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new Error('bad DER');
  let o = 2;
  if (der[o++] !== 0x02) throw new Error('bad DER (r)');
  const rlen = der[o++]!; const r = der.slice(o, o + rlen); o += rlen;
  if (der[o++] !== 0x02) throw new Error('bad DER (s)');
  const slen = der[o++]!; const s = der.slice(o, o + slen);
  const norm = (x: Uint8Array): Uint8Array => {
    let i = 0; while (i < x.length - 1 && x[i] === 0) i++;
    const t = x.slice(i); if (t.length > 32) throw new Error('int too long');
    const out = new Uint8Array(32); out.set(t, 32 - t.length); return out;
  };
  return concat(norm(r), norm(s));
}
/** Encode a compact (r‖s) signature as DER — for producing standard scriptSigs. */
export function compactToDer(compact: Uint8Array): Uint8Array {
  const enc = (x0: Uint8Array): Uint8Array => {
    let i = 0; while (i < x0.length - 1 && x0[i] === 0) i++;
    let x: Uint8Array = x0.slice(i);
    if ((x[0]! & 0x80) !== 0) x = concat(new Uint8Array([0]), x);
    return x;
  };
  const r = enc(compact.slice(0, 32)); const s = enc(compact.slice(32, 64));
  const body = concat(new Uint8Array([0x02, r.length]), r, new Uint8Array([0x02, s.length]), s);
  return concat(new Uint8Array([0x30, body.length]), body);
}

/** Parse a serialized script into items (pushes + opcodes). Rejects truncated pushes. */
export function parseScript(script: Uint8Array): ScriptItem[] {
  const items: ScriptItem[] = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++]!;
    if (op > 0 && op < OP.OP_PUSHDATA1) {
      if (i + op > script.length) throw new Error('truncated push');
      items.push({ push: script.slice(i, i + op) }); i += op;
    } else if (op === OP.OP_PUSHDATA1) {
      const n = script[i++]!; if (i + n > script.length) throw new Error('truncated pushdata1'); items.push({ push: script.slice(i, i + n) }); i += n;
    } else if (op === OP.OP_PUSHDATA2) {
      const n = script[i]! | (script[i + 1]! << 8); i += 2; if (i + n > script.length) throw new Error('truncated pushdata2'); items.push({ push: script.slice(i, i + n) }); i += n;
    } else {
      items.push({ op });
    }
  }
  return items;
}

/** BIP-143 sighash for input `i` spending `prevout` under `hashType` (SIGHASH_ALL|FORKID=0x41). */
export function sighash(tx: Tx, i: number, prevout: Prevout, hashType: number): Uint8Array {
  const hashPrevouts = hash256(concat(...tx.inputs.map((inp) => concat(reversed(fromHex(inp.prevTxid)), u32le(inp.prevVout)))));
  const hashSequence = hash256(concat(...tx.inputs.map((inp) => u32le(inp.sequence))));
  const hashOutputs = hash256(concat(...tx.outputs.map((o) => concat(u64le(Number(o.value)), varint(o.script.length), o.script))));
  const inp = tx.inputs[i]!;
  const preimage = concat(
    u32le(tx.version),
    hashPrevouts, hashSequence,
    reversed(fromHex(inp.prevTxid)), u32le(inp.prevVout),       // outpoint
    varint(prevout.script.length), prevout.script,              // scriptCode
    u64le(prevout.value), u32le(inp.sequence),
    hashOutputs, u32le(tx.lockTime), u32le(hashType),
  );
  return hash256(preimage);
}

const truthy = (b: Uint8Array | undefined): boolean => !!b && b.some((x) => x !== 0);

interface EvalCtx { tx: Tx; i: number; prevout: Prevout }

/** Execute `items` against `stack`, throwing on any failure (banned op, bad verify, underflow). */
function run(items: ScriptItem[], stack: Uint8Array[], ctx: EvalCtx | null): void {
  for (const it of items) {
    if ('push' in it) { stack.push(it.push); continue; }
    const op = it.op;
    if (BANNED_OPCODES.includes(op)) throw new Error(`banned opcode 0x${op.toString(16)}`);
    switch (op) {
      case OP.OP_0: stack.push(new Uint8Array(0)); break;
      case 0x51: stack.push(new Uint8Array([1])); break;                       // OP_TRUE / OP_1
      case OP.OP_DUP: { const a = stack[stack.length - 1]; if (!a) throw new Error('DUP underflow'); stack.push(a.slice()); break; }
      case OP.OP_DROP: if (stack.pop() === undefined) throw new Error('DROP underflow'); break;
      case OP.OP_2DROP: if (stack.pop() === undefined || stack.pop() === undefined) throw new Error('2DROP underflow'); break;
      case OP.OP_SHA256: { const a = stack.pop(); if (!a) throw new Error('SHA256 underflow'); stack.push(sha256(a)); break; }
      case OP.OP_HASH160: { const a = stack.pop(); if (!a) throw new Error('HASH160 underflow'); stack.push(hash160(a)); break; }
      case OP.OP_EQUALVERIFY: { const a = stack.pop(); const b = stack.pop(); if (!a || !b) throw new Error('EQUALVERIFY underflow'); if (!eq(a, b)) throw new Error('EQUALVERIFY failed'); break; }
      case OP.OP_CHECKSIG: {
        const pub = stack.pop(); const sig = stack.pop();
        if (!pub || !sig) throw new Error('CHECKSIG underflow');
        if (!ctx) throw new Error('CHECKSIG without tx context');
        if (sig.length < 9) { stack.push(new Uint8Array(0)); break; }
        const hashType = sig[sig.length - 1]!;
        const der = sig.slice(0, -1);
        let ok = false;
        try { ok = verifyHash(pub, sighash(ctx.tx, ctx.i, ctx.prevout, hashType), derToCompact(der)); } catch { ok = false; }
        stack.push(ok ? new Uint8Array([1]) : new Uint8Array(0));
        break;
      }
      default: throw new Error(`unsupported opcode 0x${op.toString(16)}`);
    }
  }
}

/** Verify that input `i` of `tx` satisfies `prevout`'s locking script. */
export function verifyInput(tx: Tx, i: number, prevout: Prevout): ScriptCheck {
  const inp = tx.inputs[i];
  if (!inp) return { ok: false, reason: `no input ${i}` };
  let unlock: ScriptItem[], lock: ScriptItem[];
  try { unlock = parseScript(inp.scriptSig); lock = parseScript(prevout.script); } catch (e) { return { ok: false, reason: `parse: ${(e as Error).message}` }; }
  if (unlock.some((it) => 'op' in it)) return { ok: false, reason: 'scriptSig must be push-only' };
  const stack: Uint8Array[] = [];
  try {
    run(unlock, stack, null);
    run(lock, stack, { tx, i, prevout });
  } catch (e) { return { ok: false, reason: `script failed: ${(e as Error).message}` }; }
  if (!truthy(stack[stack.length - 1])) return { ok: false, reason: 'script left a false / empty top of stack' };
  return { ok: true, reason: 'input satisfies its prevout' };
}

/**
 * Validate a whole tx against its resolved prevouts: every input must satisfy its
 * locking script, NO output may carry a banned opcode, and the fee (Σ prevout −
 * Σ output) must be non-negative. This is the spend-validity the replay needs.
 */
export function verifyTx(tx: Tx, prevouts: readonly Prevout[]): TxCheck {
  if (prevouts.length !== tx.inputs.length) return { ok: false, reason: `have ${prevouts.length} prevouts for ${tx.inputs.length} inputs`, fee: 0 };
  for (const o of tx.outputs) {
    let items: ScriptItem[]; try { items = parseScript(o.script); } catch (e) { return { ok: false, reason: `output parse: ${(e as Error).message}`, fee: 0 }; }
    if (items.some((it) => 'op' in it && BANNED_OPCODES.includes(it.op))) return { ok: false, reason: 'output carries a banned opcode', fee: 0 };
  }
  const inSats = prevouts.reduce((n, p) => n + p.value, 0);
  const outSats = tx.outputs.reduce((n, o) => n + Number(o.value), 0);
  const fee = inSats - outSats;
  if (fee < 0) return { ok: false, reason: `negative fee (${fee}): outputs exceed inputs`, fee };
  for (let i = 0; i < tx.inputs.length; i++) {
    const r = verifyInput(tx, i, prevouts[i]!);
    if (!r.ok) return { ok: false, reason: `input ${i}: ${r.reason}`, fee };
  }
  return { ok: true, reason: `all ${tx.inputs.length} inputs satisfied; fee ${fee}`, fee };
}
