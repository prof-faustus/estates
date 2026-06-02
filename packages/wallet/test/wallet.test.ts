import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Wallet, P2PKH, Transaction } from '../src/index.ts';

/** A source tx (no inputs needed) carrying a P2PKH output to `address`. */
function sourceTxHex(address: string, satoshis: number): string {
  const tx = new Transaction();
  tx.addOutput({ lockingScript: new P2PKH().lock(address), satoshis });
  return tx.toHex();
}

test('real addresses: mainnet vs testnet version bytes', () => {
  const main = Wallet.random('mainnet').address;
  const testWallet = Wallet.random('testnet');
  assert.match(main, /^1[1-9A-HJ-NP-Za-km-z]{25,34}$/, 'mainnet address starts with 1');
  assert.match(testWallet.address, /^[mn][1-9A-HJ-NP-Za-km-z]{25,34}$/, 'testnet address starts with m/n');
  assert.equal(testWallet.publicKeyHashHex.length, 40);
});

test('build + sign a real BSV transaction (BIP-143)', async () => {
  const w = Wallet.random('testnet');
  const payee = Wallet.random('testnet').address;
  const src = sourceTxHex(w.address, 100_000);

  const { hex, txid } = await w.buildAndSign(
    [{ sourceTxHex: src, vout: 0, satoshis: 100_000 }],
    [{ address: payee, satoshis: 50_000 }],
  );

  assert.match(txid, /^[0-9a-f]{64}$/, 'valid txid');
  assert.ok(hex.length > 100, 'serialized tx');
  const parsed = Transaction.fromHex(hex);
  assert.equal(parsed.inputs.length, 1);
  assert.equal(parsed.outputs.length, 2);                 // payee + change
  assert.ok((parsed.inputs[0]!.unlockingScript?.toHex().length ?? 0) > 0, 'input is signed');
  // value conserved minus fee: payee + change < 100000
  const out = parsed.outputs.reduce((s, o) => s + (o.satoshis ?? 0), 0);
  assert.ok(out <= 100_000 && out >= 100_000 - 2000, `outputs ${out} = inputs - fee`);
  assert.equal(parsed.outputs[0]!.satoshis, 50_000);
});

test('mainnet broadcast is refused without explicit confirmation (money guard)', async () => {
  const w = Wallet.random('mainnet');
  await assert.rejects(() => w.broadcast('00', {}), /confirmRealValue/);
});

test('regtest broadcast requires an rpc url', async () => {
  const w = Wallet.random('regtest');
  await assert.rejects(() => w.broadcast('00', {}), /rpcUrl/);
});

test('fromWif round-trips to the same address', () => {
  const w = Wallet.random('testnet');
  const wif = w.key.toWif();
  assert.equal(Wallet.fromWif(wif, 'testnet').address, w.address);
});
