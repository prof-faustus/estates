import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serializeTx, txHex, txid, varint, hash256, type Tx } from '../src/index.ts';

const fromHex = (h: string): Uint8Array => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// The Bitcoin genesis coinbase — the canonical real-world serialization vector.
// (The arbitrary scriptSig bytes are split only to keep them obviously opaque.)
const COINBASE_SIG = '04ffff001d0104' + '455468652054696d65732030332f4a616e2f32303039' +
  '204368' + '616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73';
const PUBKEY_SCRIPT = '4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac';
const GENESIS_RAW =
  '01000000' + '01' +
  '0000000000000000000000000000000000000000000000000000000000000000' + 'ffffffff' +
  '4d' + COINBASE_SIG + 'ffffffff' +
  '01' + '00f2052a01000000' + '43' + PUBKEY_SCRIPT +
  '00000000';
const GENESIS_TXID = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b';

const genesis: Tx = {
  version: 1,
  inputs: [{ prevTxid: '00'.repeat(32), prevVout: 0xffffffff, scriptSig: fromHex(COINBASE_SIG), sequence: 0xffffffff }],
  outputs: [{ value: 5_000_000_000n, script: fromHex(PUBKEY_SCRIPT) }],
  lockTime: 0,
};

test('serializes the genesis coinbase byte-for-byte', () => {
  assert.equal(txHex(genesis), GENESIS_RAW);
});

test('computes the real genesis txid (display byte order, reversed hash256)', () => {
  assert.equal(txid(genesis), GENESIS_TXID);
  // txid is the reverse of hash256(rawtx)
  assert.equal(toHex(hash256(fromHex(GENESIS_RAW)).reverse()), GENESIS_TXID);
});

test('varint (CompactSize) boundaries', () => {
  assert.equal(toHex(varint(0)), '00');
  assert.equal(toHex(varint(0xfc)), 'fc');
  assert.equal(toHex(varint(0xfd)), 'fdfd00');
  assert.equal(toHex(varint(0xffff)), 'fdffff');
  assert.equal(toHex(varint(0x10000)), 'fe00000100');
  assert.equal(toHex(varint(0xffffffff)), 'feffffffff');
});

test('whole-sat values up to 8 bytes serialize little-endian', () => {
  const tx: Tx = { version: 1, inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [{ value: 1n, script: new Uint8Array([0x51]) }], lockTime: 0 };
  const hex = txHex(tx);
  assert.ok(hex.includes('0100000000000000' + '01' + '51'), 'value 1 sat LE + 1-byte script');
  assert.equal(txid(tx).length, 64);
});

test('a 1-sat NFT-style multi-output tx is deterministic + unique per content', () => {
  const mk = (sat: bigint): Tx => ({ version: 1, inputs: [{ prevTxid: 'cd'.repeat(32), prevVout: 1, scriptSig: new Uint8Array(0), sequence: 0xfffffffe }], outputs: [{ value: 1n, script: new Uint8Array([0x6a === 0x6a ? 0x51 : 0]) }, { value: sat, script: new Uint8Array([0x76]) }], lockTime: 7 });
  assert.equal(txid(mk(1000n)), txid(mk(1000n)), 'deterministic');
  assert.notEqual(txid(mk(1000n)), txid(mk(1001n)), 'content-addressed');
  assert.equal(serializeTx(mk(1000n)).length > 0, true);
});
