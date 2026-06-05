// Emit BSV transaction txid VECTORS from the audited @estates/tx reference, so the
// native C# Tx port can be cross-validated: same tx bytes -> same txid.
import { writeFileSync } from 'node:fs';
import { txid, serializeTx, type Tx } from '../packages/tx/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const script = (...bytes: number[]) => new Uint8Array(bytes);
const bigScript = (n: number) => new Uint8Array(Array.from({ length: n }, (_, i) => i & 0xff)); // exercises varint 0xfd

const txs: Tx[] = [
  // simple 1-in 1-out
  { version: 1, inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [{ value: 1500, script: script(0x76, 0xa9, 0x14, 0x11) }], lockTime: 0 },
  // multi in/out, non-zero vout/sequence/locktime, 1-sat NFT-ish output
  { version: 2, inputs: [
      { prevTxid: 'cd'.repeat(32), prevVout: 3, scriptSig: script(0x47, 1, 2, 3), sequence: 0xfffffffe },
      { prevTxid: 'ef'.repeat(32), prevVout: 1, scriptSig: new Uint8Array(0), sequence: 0 },
    ], outputs: [
      { value: 1, script: script(0x6a, 0x01, 0x01) },
      { value: 999_999, script: bigScript(260) }, // > 0xff bytes => varint 0xfd path
    ], lockTime: 500000 },
  // large value (8-byte LE) output
  { version: 1, inputs: [{ prevTxid: '12'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [{ value: 2_100_000_000_000, script: script(0x51) }], lockTime: 0 },
];

const vectors = txs.map((t, i) => ({
  name: `tx-${i}`,
  tx: {
    version: t.version,
    inputs: t.inputs.map((x) => ({ prevTxid: x.prevTxid, prevVout: x.prevVout, scriptSig: hx(x.scriptSig), sequence: x.sequence })),
    outputs: t.outputs.map((o) => ({ value: o.value, script: hx(o.script) })),
    lockTime: t.lockTime,
  },
  serialized: hx(serializeTx(t)),
  txid: txid(t),
}));

const out = 'apps/native/Estates.Conformance/tx-vectors.json';
writeFileSync(out, JSON.stringify(vectors, null, 2));
console.log(`wrote ${out}: ${vectors.length} tx vectors`);
for (const v of vectors) console.log(`  ${v.name} txid=${v.txid}`);
