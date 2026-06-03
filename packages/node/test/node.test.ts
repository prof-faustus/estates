import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { merkleRoot, serializeHeader, verifyInclusion, bytesEqual, type BlockHeader } from '@estates/spv';
import { buildPartialMerkleTree } from '@estates/merkleblock';
import { parseHeader, packFlags, unpackFlags, serializeMerkleBlock, parseMerkleBlock, proofFromMerkleBlockHex } from '../src/index.ts';

const leaf = (n: number): Uint8Array => new Uint8Array(createHash('sha256').update(new Uint8Array([n & 0xff, (n >>> 8) & 0xff])).digest());
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

test('block header round-trips through serialize/parse', () => {
  const h: BlockHeader = { version: 0x20000000, prevHash: new Uint8Array(32).fill(0xab), merkleRoot: new Uint8Array(32).fill(0xcd), time: 1_700_000_000, bits: 0x207fffff, nonce: 12345 };
  const p = parseHeader(serializeHeader(h));
  assert.equal(p.version, h.version); assert.equal(p.time, h.time); assert.equal(p.bits, h.bits); assert.equal(p.nonce, h.nonce);
  assert.ok(bytesEqual(p.prevHash, h.prevHash) && bytesEqual(p.merkleRoot, h.merkleRoot));
});

test('flag bits pack/unpack (LSB-first) round-trip', () => {
  const bits = [1, 0, 1, 1, 0, 0, 0, 1, 1, 0];
  const packed = packFlags(bits);
  assert.equal(packed.length, 2);
  assert.deepEqual(unpackFlags(packed, bits.length), bits);
});

test('CMerkleBlock serialize→parse→proof verifies against the header (native node SPV)', () => {
  for (const n of [1, 4, 7, 16, 28]) {
    const leaves = Array.from({ length: n }, (_, i) => leaf(i));
    const root = merkleRoot(leaves);
    const header: BlockHeader = { version: 1, prevHash: new Uint8Array(32), merkleRoot: root, time: 1, bits: 0x207fffff, nonce: 0 };
    for (let idx = 0; idx < n; idx++) {
      const pmt = buildPartialMerkleTree(leaves, [idx]);
      const hex = toHex(serializeMerkleBlock({ header, pmt }));
      const parsed = parseMerkleBlock(serializeMerkleBlock({ header, pmt }));
      assert.equal(parsed.pmt.txCount, n);
      // txid display order = reverse of the internal leaf hash
      const txidDisplay = toHex(leaves[idx]!.slice().reverse());
      const got = proofFromMerkleBlockHex(hex, txidDisplay);
      assert.ok(got, `n=${n} idx=${idx} proof found`);
      assert.ok(verifyInclusion(leaves[idx]!, got!.proof, got!.header.merkleRoot), 'node-supplied proof verifies');
      assert.ok(bytesEqual(got!.header.merkleRoot, root));
    }
  }
});

test('proofFromMerkleBlockHex returns null for a txid not in the block', () => {
  const leaves = Array.from({ length: 8 }, (_, i) => leaf(i));
  const header: BlockHeader = { version: 1, prevHash: new Uint8Array(32), merkleRoot: merkleRoot(leaves), time: 1, bits: 0, nonce: 0 };
  const hex = toHex(serializeMerkleBlock({ header, pmt: buildPartialMerkleTree(leaves, [2]) }));
  assert.equal(proofFromMerkleBlockHex(hex, toHex(leaf(99).slice().reverse())), null);
});
