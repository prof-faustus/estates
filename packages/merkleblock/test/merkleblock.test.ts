import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha256';
import { merkleRoot, buildProof, verifyInclusion, bytesEqual } from '@estates/spv';
import { buildPartialMerkleTree, parsePartialMerkleTree } from '../src/index.ts';

const leaf = (n: number): Uint8Array => sha256(new Uint8Array([n & 0xff, (n >>> 8) & 0xff]));

test('build→parse round-trips: root matches and the matched leaf’s proof verifies', () => {
  for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 16, 28, 100]) {
    const leaves = Array.from({ length: n }, (_, i) => leaf(i));
    const root = merkleRoot(leaves);
    for (let idx = 0; idx < n; idx++) {
      const pmt = buildPartialMerkleTree(leaves, [idx]);
      const parsed = parsePartialMerkleTree(pmt);
      assert.ok(bytesEqual(parsed.root, root), `n=${n} idx=${idx} root`);
      assert.equal(parsed.matched.length, 1);
      const m = parsed.matched[0]!;
      assert.equal(m.index, idx, 'matched index');
      assert.ok(bytesEqual(m.hash, leaves[idx]!), 'matched leaf hash');
      // the node-style proof verifies against the recomputed root (native SPV)
      assert.ok(verifyInclusion(leaves[idx]!, m.proof, root), `n=${n} idx=${idx} proof verifies`);
      // and agrees with @estates/spv's own proof for that leaf
      assert.deepEqual(m.proof, buildProof(leaves, idx));
    }
  }
});

test('multiple matched leaves each get a correct proof', () => {
  const leaves = Array.from({ length: 12 }, (_, i) => leaf(i));
  const root = merkleRoot(leaves);
  const pmt = buildPartialMerkleTree(leaves, [1, 4, 11]);
  const parsed = parsePartialMerkleTree(pmt);
  assert.deepEqual(parsed.matched.map((m) => m.index).sort((a, b) => a - b), [1, 4, 11]);
  for (const m of parsed.matched) assert.ok(verifyInclusion(m.hash, m.proof, root));
});

test('the partial tree carries only the hashes needed (compactness)', () => {
  const leaves = Array.from({ length: 16 }, (_, i) => leaf(i));
  const pmt = buildPartialMerkleTree(leaves, [5]);
  // a proof for 1 of 16 leaves needs ~4 sibling hashes, not all 16
  assert.ok(pmt.hashes.length <= 5, `compact: ${pmt.hashes.length} hashes`);
  assert.ok(parsePartialMerkleTree(pmt).matched[0]!.proof.branch.length === 4, 'depth-4 branch');
});

test('a malformed partial tree (leftover hashes) is rejected', () => {
  const leaves = Array.from({ length: 8 }, (_, i) => leaf(i));
  const pmt = buildPartialMerkleTree(leaves, [2]);
  assert.throws(() => parsePartialMerkleTree({ ...pmt, hashes: [...pmt.hashes, leaf(99)] }), /malformed/);
});
