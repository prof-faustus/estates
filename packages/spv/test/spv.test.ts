import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@estates/keys';
import {
  hash256, merkleRoot, buildProof, rootFromProof, verifyInclusion,
  serializeHeader, blockHash, verifyAgainstHeader, bytesEqual, type BlockHeader,
} from '../src/index.ts';

const leaf = (n: number): Uint8Array => sha256(new Uint8Array([n]));

test('hash256 = double sha256', () => {
  const x = new Uint8Array([1, 2, 3]);
  assert.ok(bytesEqual(hash256(x), sha256(sha256(x))));
});

test('single-leaf tree: root is the leaf; trivial proof verifies', () => {
  const leaves = [leaf(0)];
  assert.ok(bytesEqual(merkleRoot(leaves), leaf(0)));
  const proof = buildProof(leaves, 0);
  assert.equal(proof.branch.length, 0);
  assert.ok(verifyInclusion(leaf(0), proof, merkleRoot(leaves)));
});

test('every leaf in trees of many sizes (incl. odd) proves inclusion', () => {
  for (const n of [2, 3, 4, 5, 7, 8, 16, 28, 100]) {
    const leaves = Array.from({ length: n }, (_, i) => leaf(i));
    const root = merkleRoot(leaves);
    for (let i = 0; i < n; i++) {
      const proof = buildProof(leaves, i);
      assert.ok(verifyInclusion(leaves[i]!, proof, root), `n=${n} index=${i} proves`);
      assert.ok(bytesEqual(rootFromProof(leaves[i]!, proof), root));
    }
  }
});

test('a forged/tampered proof is rejected (no trust in the supplier)', () => {
  const leaves = Array.from({ length: 8 }, (_, i) => leaf(i));
  const root = merkleRoot(leaves);
  const proof = buildProof(leaves, 3);
  // wrong txid
  assert.equal(verifyInclusion(leaf(99), proof, root), false);
  // tampered sibling
  const bad = { index: proof.index, branch: proof.branch.map((b, k) => (k === 0 ? leaf(123) : b)) };
  assert.equal(verifyInclusion(leaves[3]!, bad, root), false);
  // wrong index (claims a different position)
  assert.equal(verifyInclusion(leaves[3]!, { ...proof, index: 4 }, root), false);
  // a leaf that isn't in the tree cannot be proven for any index
  assert.equal(verifyInclusion(leaf(50), buildProof(leaves, 0), root), false);
});

test('odd-node duplication matches Bitcoin (3 leaves)', () => {
  const [a, b, c] = [leaf(1), leaf(2), leaf(3)];
  // level1: H(a|b), H(c|c); root: H( H(a|b) | H(c|c) )
  const h_ab = hash256(new Uint8Array([...a, ...b]));
  const h_cc = hash256(new Uint8Array([...c, ...c]));
  const expect = hash256(new Uint8Array([...h_ab, ...h_cc]));
  assert.ok(bytesEqual(merkleRoot([a, b, c]), expect));
  assert.ok(verifyInclusion(c, buildProof([a, b, c], 2), expect), 'the duplicated leaf still proves');
});

test('header serializes to 80 bytes and binds the merkleRoot a proof checks against', () => {
  const leaves = Array.from({ length: 5 }, (_, i) => leaf(i));
  const header: BlockHeader = {
    version: 0x20000000, prevHash: new Uint8Array(32).fill(0xaa),
    merkleRoot: merkleRoot(leaves), time: 1_700_000_000, bits: 0x207fffff, nonce: 42,
  };
  assert.equal(serializeHeader(header).length, 80);
  assert.equal(blockHash(header).length, 32);
  for (let i = 0; i < 5; i++) assert.ok(verifyAgainstHeader(leaves[i]!, buildProof(leaves, i), header));
  // a tx not in this block fails against the header
  assert.equal(verifyAgainstHeader(leaf(77), buildProof(leaves, 0), header), false);
});
