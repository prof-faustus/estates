// Emit ECDSA/BIP-143 sighash VECTORS from @estates/scriptvm + @estates/tx so the
// native C# Scriptvm port can be cross-validated: same BIP-143 sighash, and a
// TS-signed P2PKH input verifies (and a tampered sig fails) in C#.
import { writeFileSync } from 'node:fs';
import * as secp from '../packages/scriptvm/node_modules/@noble/secp256k1/index.js';
import { sha256 } from '../packages/scriptvm/node_modules/@noble/hashes/sha256.js';
import { ripemd160 } from '../packages/scriptvm/node_modules/@noble/hashes/ripemd160.js';
import { hmac } from '../packages/scriptvm/node_modules/@noble/hashes/hmac.js';
import { sighash, compactToDer } from '../packages/scriptvm/src/index.ts';
import { paymentOutput } from '../packages/onchain/src/index.ts';
import { type Tx } from '../packages/tx/src/index.ts';

(secp as { etc: { hmacSha256Sync: (k: Uint8Array, ...m: Uint8Array[]) => Uint8Array } }).etc.hmacSha256Sync =
  (k: Uint8Array, ...m: Uint8Array[]) => hmac(sha256, k, (secp as { etc: { concatBytes: (...a: Uint8Array[]) => Uint8Array } }).etc.concatBytes(...m));

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const hash160 = (b: Uint8Array) => ripemd160(sha256(b));
const HASHTYPE = 0x41; // SIGHASH_ALL | FORKID

const priv = sha256(new TextEncoder().encode('estates-scriptvm-vector-key')); // deterministic 32-byte key
const pub = secp.getPublicKey(priv, true);
const prevout = { value: 2500, script: paymentOutput(2500, hash160(pub)).script };
const tx: Tx = {
  version: 1,
  inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
  outputs: [{ value: 2000, script: paymentOutput(2000, hash160(secp.getPublicKey(sha256(new TextEncoder().encode('payee')), true))).script }],
  lockTime: 0,
};
const h = sighash(tx, 0, prevout, HASHTYPE);
const der = compactToDer((secp.sign(h, priv) as { toCompactRawBytes(): Uint8Array }).toCompactRawBytes());
const sigFull = new Uint8Array([...der, HASHTYPE]);
const tampered = new Uint8Array(sigFull); tampered[10] ^= 0xff; // corrupt the DER body

const vector = {
  tx: {
    version: tx.version,
    inputs: tx.inputs.map((x) => ({ prevTxid: x.prevTxid, prevVout: x.prevVout, scriptSig: hx(x.scriptSig), sequence: x.sequence })),
    outputs: tx.outputs.map((o) => ({ value: o.value, script: hx(o.script) })),
    lockTime: tx.lockTime,
  },
  inputIndex: 0,
  hashType: HASHTYPE,
  prevoutScript: hx(prevout.script),
  prevoutValue: prevout.value,
  pub: hx(pub),
  expectedSighash: hx(h),
  validSig: hx(sigFull),
  tamperedSig: hx(tampered),
};

const path = 'apps/native/Estates.Conformance/scriptvm-vectors.json';
writeFileSync(path, JSON.stringify(vector, null, 2));
console.log(`wrote ${path}`);
console.log('  sighash:', vector.expectedSighash);
