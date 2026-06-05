import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';
import { paymentOutput, push, OP, serializeScript } from '@estates/onchain';
import { covenantOutput, rulesHash } from '@estates/bank';
import type { Tx } from '@estates/tx';
import { verifyInput, verifyTx, sighash, compactToDer, parseScript } from '../src/index.ts';

// enable sync ECDSA signing in @noble
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
const hash160 = (b: Uint8Array) => ripemd160(sha256(b));
const HASHTYPE = 0x41; // SIGHASH_ALL | FORKID
// a Tx output ({value,script}) paying a pkh
const payOut = (sats: number, pkh: Uint8Array) => ({ value: sats, script: paymentOutput(sats, pkh).script });
const RH = rulesHash(new Uint8Array(32).fill(7));               // a game-bound covenant rules hash
const covOut = (sats: number) => ({ value: sats, script: covenantOutput(sats, RH).script });

function signP2pkh(tx: Tx, i: number, prevout: { value: number; script: Uint8Array }, priv: Uint8Array, pub: Uint8Array): Tx {
  const h = sighash(tx, i, prevout, HASHTYPE);
  const der = compactToDer(secp.sign(h, priv).toCompactRawBytes());
  const sig = new Uint8Array([...der, HASHTYPE]);
  const inputs = tx.inputs.map((inp, j) => j === i ? { ...inp, scriptSig: serializeScript([push(sig), push(pub)]) } : inp);
  return { ...tx, inputs };
}

test('a real ECDSA-signed P2PKH input satisfies its prevout (BIP-143 sighash + OP_CHECKSIG)', () => {
  const priv = secp.utils.randomPrivateKey();
  const pub = secp.getPublicKey(priv, true);
  const prevout = { value: 2000, script: paymentOutput(2000, hash160(pub)).script };
  let tx: Tx = {
    version: 1,
    inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [payOut(1500, hash160(secp.getPublicKey(secp.utils.randomPrivateKey(), true)))],
    lockTime: 0,
  };
  tx = signP2pkh(tx, 0, prevout, priv, pub);
  assert.ok(verifyInput(tx, 0, prevout).ok, 'valid signature satisfies the script');
  const vt = verifyTx(tx, [prevout]);
  assert.ok(vt.ok, vt.reason);
  assert.equal(vt.fee, 500, 'fee = inputs − outputs');
});

test('a WRONG key / tampered sig does NOT satisfy the prevout', () => {
  const priv = secp.utils.randomPrivateKey();
  const pub = secp.getPublicKey(priv, true);
  const prevout = { value: 2000, script: paymentOutput(2000, hash160(pub)).script };
  let tx: Tx = { version: 1, inputs: [{ prevTxid: 'cd'.repeat(32), prevVout: 1, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [payOut(1000, hash160(pub))], lockTime: 0 };
  // sign with a DIFFERENT key than the prevout's pkh
  const wrong = secp.utils.randomPrivateKey();
  tx = signP2pkh(tx, 0, prevout, wrong, secp.getPublicKey(wrong, true));
  assert.equal(verifyInput(tx, 0, prevout).ok, false, 'signature by the wrong key fails OP_CHECKSIG / EQUALVERIFY');
});

test('a signature over a DIFFERENT amount fails (BIP-143 binds the prevout value)', () => {
  const priv = secp.utils.randomPrivateKey(); const pub = secp.getPublicKey(priv, true);
  const prevout = { value: 2000, script: paymentOutput(2000, hash160(pub)).script };
  let tx: Tx = { version: 1, inputs: [{ prevTxid: 'ef'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [payOut(1000, hash160(pub))], lockTime: 0 };
  // sign as if the prevout were worth 9999, then verify against the real 2000
  tx = signP2pkh(tx, 0, { value: 9999, script: prevout.script }, priv, pub);
  assert.equal(verifyInput(tx, 0, prevout).ok, false, 'amount mismatch breaks the sighash');
});

test('the bank covenant output (OP_TRUE predicate) is spendable with an empty scriptSig', () => {
  const prevout = { value: 1_000_000, script: covenantOutput(1_000_000, RH).script };
  const tx: Tx = { version: 1, inputs: [{ prevTxid: 'aa'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [covOut(999_500)], lockTime: 0 };
  assert.ok(verifyInput(tx, 0, prevout).ok, 'covenant script evaluates true (payout predicate enforced separately)');
});

test('verifyTx rejects a NEGATIVE fee and a BANNED opcode in an output', () => {
  const priv = secp.utils.randomPrivateKey(); const pub = secp.getPublicKey(priv, true);
  const prevout = { value: 1000, script: paymentOutput(1000, hash160(pub)).script };
  // outputs exceed inputs → negative fee
  let tx: Tx = { version: 1, inputs: [{ prevTxid: 'ba'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [payOut(2000, hash160(pub))], lockTime: 0 };
  tx = signP2pkh(tx, 0, prevout, priv, pub);
  assert.equal(verifyTx(tx, [prevout]).ok, false, 'negative fee rejected');

  // a banned OP_RETURN in an output is rejected. serializeScript REFUSES to build
  // one, so a malicious raw output is crafted by hand: OP_RETURN <push 3> 01 02 03
  const badOut = { value: 100, script: new Uint8Array([OP.OP_RETURN, 0x03, 1, 2, 3]) };
  let tx2: Tx = { version: 1, inputs: [{ prevTxid: 'bb'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [badOut], lockTime: 0 };
  tx2 = signP2pkh(tx2, 0, prevout, priv, pub);
  assert.equal(verifyTx(tx2, [prevout]).ok, false, 'banned opcode in output rejected');
});

// ---- the interpreter is fed UNTRUSTED scripts: verifyInput/verifyTx are total ----
// A scriptSig and a prevout script are attacker-controlled bytes. The boundary
// (verifyInput/verifyTx) must NEVER throw — every parse/exec failure is a clean
// `{ok:false}`, never an exception, and never an unbounded loop.
const mkTx = (scriptSig: Uint8Array): Tx => ({ version: 1, inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig, sequence: 0xffffffff }], outputs: [payOut(500, new Uint8Array(20))], lockTime: 0 });

test('verifyInput is FAIL-CLOSED on hostile scripts (truncated push, non-push sig, banned op, bad DER)', () => {
  const pkhScript = paymentOutput(1000, new Uint8Array(20)).script;
  for (const [sig, lock] of [
    [new Uint8Array([0x05, 1, 2]), pkhScript],                       // truncated push (claims 5, has 2)
    [new Uint8Array([OP.OP_PUSHDATA1, 0xff, 1]), pkhScript],         // truncated pushdata1
    [new Uint8Array([OP.OP_PUSHDATA2, 0xff, 0xff, 1]), pkhScript],   // truncated pushdata2 (claims 65535)
    [new Uint8Array([OP.OP_DUP]), pkhScript],                        // scriptSig not push-only
    [new Uint8Array([0x47, ...new Uint8Array(0x47)]), pkhScript],    // push of garbage "sig+pub" → bad DER, no throw
    [new Uint8Array(0), new Uint8Array([0x6a, 0x01, 0x01])],         // lock = OP_RETURN (banned) → caught, not thrown
  ] as const) {
    let out: unknown = 'unset';
    assert.doesNotThrow(() => { out = verifyInput(mkTx(sig as Uint8Array), 0, { value: 1000, script: lock as Uint8Array }); });
    assert.equal((out as { ok: boolean }).ok, false);
  }
  // parseScript itself throws by contract on a truncated push — the boundary catches it
  assert.throws(() => parseScript(new Uint8Array([0x05, 1, 2])));
});

test('verifyInput / verifyTx are FUZZ-PROOF: 50k random scriptSig+prevout pairs never throw or hang', () => {
  let rng = 0x7a1cf00d >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const rbytes = (max: number) => { const n = rand() % max; const b = new Uint8Array(n); for (let k = 0; k < n; k++) b[k] = rand() & 0xff; return b; };
  const t0 = Date.now();
  for (let i = 0; i < 50_000; i++) {
    const sig = rbytes(80); const lock = rbytes(80);
    assert.doesNotThrow(() => {
      verifyInput(mkTx(sig), 0, { value: 1000, script: lock });
      verifyTx({ version: 1, inputs: [{ prevTxid: 'cd'.repeat(32), prevVout: 0, scriptSig: sig, sequence: 0 }], outputs: [{ value: 100, script: lock }], lockTime: 0 }, [{ value: 1000, script: lock }]);
    });
  }
  assert.ok(Date.now() - t0 < 10000, 'bounded work — no hang');
});
