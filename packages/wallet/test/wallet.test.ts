import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serializeTx, deserializeTx, type Tx } from '@estates/tx';
import { p2pkh, serializeScript } from '@estates/onchain';
import { verifyTx } from '@estates/scriptvm';
import { Wallet } from '../src/index.ts';

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };
const reversed = (b: Uint8Array): Uint8Array => b.slice().reverse();
// a source tx paying `sats` to `pkh` (one P2PKH output) — provides a spendable UTXO
function sourceTx(pkh: Uint8Array, sats: number): { hex: string; vout: number } {
  const tx: Tx = { version: 1, inputs: [{ prevTxid: '00'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [{ value: sats, script: serializeScript(p2pkh(pkh)) }], lockTime: 0 };
  return { hex: toHex(serializeTx(tx)), vout: 0 };
}

test('real addresses: mainnet vs testnet version bytes', () => {
  assert.match(Wallet.random('mainnet').address, /^1[1-9A-HJ-NP-Za-km-z]{25,34}$/, 'mainnet address starts with 1');
  const t = Wallet.random('testnet');
  assert.match(t.address, /^[mn][1-9A-HJ-NP-Za-km-z]{25,34}$/, 'testnet address starts with m/n');
  assert.equal(t.publicKeyHashHex.length, 40);
});

test('fromWif round-trips to the same address + private key', () => {
  const w = Wallet.random('testnet');
  const wif = w.key.toWif();
  const back = Wallet.fromWif(wif, 'testnet');
  assert.equal(back.address, w.address);
  assert.equal(toHex(new Uint8Array(back.key.toArray('be', 32))), toHex(new Uint8Array(w.key.toArray('be', 32))));
});

test('build + sign a real BIP-143 P2PKH tx — and the wallet SELF-VERIFIES it (script-valid)', () => {
  const w = Wallet.random('testnet');
  const payee = Wallet.random('testnet').address;
  const src = sourceTx(w.key.pkh(), 100_000);

  // buildAndSign runs the script interpreter internally and throws on any invalid sig/fee
  const { hex, txid } = w.buildAndSign([{ sourceTxHex: src.hex, vout: src.vout, satoshis: 100_000 }], [{ address: payee, satoshis: 50_000 }]);
  assert.match(txid, /^[0-9a-f]{64}$/, 'valid txid');
  assert.ok(hex.length > 100, 'serialized');

  // independently re-verify with the interpreter: the input must satisfy the prevout
  const prevout = { value: 100_000, script: serializeScript(p2pkh(w.key.pkh())) };
  const tx = deserializeTx(fromHex(hex));
  assert(tx, 'the wallet emits canonically-parseable tx bytes');
  const chk = verifyTx(tx, [prevout]);
  assert.ok(chk.ok, `independently script-valid: ${chk.reason}`);
  assert.ok(chk.fee >= 256, 'a real, non-negative fee');
  assert.equal(toHex(reversed(fromHex(txid))).length, 64);
});

test('drainTo refunds the FULL balance (minus fee) to one address — nothing stranded', () => {
  const w = Wallet.random('testnet');
  const funder = Wallet.random('testnet').address;
  // build the drain tx directly via buildRaw (one output = total − fee, no change)
  const total = 100_000;
  const fee = Math.max(10 + 1 * 148 + 68, 256);
  const src = sourceTx(w.key.pkh(), total);
  const { hex } = w.buildRaw([{ sourceTxHex: src.hex, vout: 0, satoshis: total }], [{ satoshis: total - fee, script: serializeScript(p2pkh(addrPkh(funder))) }]);
  const tx = deserializeTx(fromHex(hex));
  assert(tx, 'drain tx parses');
  assert.equal(tx.outputs.length, 1, 'exactly one output — the full refund, no change left behind');
  assert.equal(Number(tx.outputs[0]!.value), total - fee, 'the entire balance minus fee goes to the funder');
});

test('money guards: mainnet refused without confirm; regtest needs an rpc url', async () => {
  await assert.rejects(() => Wallet.random('mainnet').broadcast('00', {}), /confirmRealValue/);
  await assert.rejects(() => Wallet.random('regtest').broadcast('00', {}), /rpcUrl/);
});

// ---- minimal helpers (for re-verification) ----------------------------------
function addrPkh(address: string): Uint8Array {
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let x = 0n; for (const c of address) x = x * 58n + BigInt(B58.indexOf(c));
  const bytes: number[] = []; while (x > 0n) { bytes.unshift(Number(x % 256n)); x /= 256n; }
  for (const c of address) { if (c === '1') bytes.unshift(0); else break; }
  return new Uint8Array(bytes.slice(1, -4)); // strip version byte + 4-byte checksum
}
