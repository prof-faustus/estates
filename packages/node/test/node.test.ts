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
      assert.ok(parsed, `n=${n} idx=${idx} parses`);
      assert.equal(parsed!.pmt.txCount, n);
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

// ---- gettxoutproof bytes are UNTRUSTED: parse is total, bounded, fuzz-proof ----
// Threat: a hostile / MITM'd node returns a crafted CMerkleBlock. parseMerkleBlock
// must never throw, never allocate on an attacker-chosen count, never hang.
test('parseMerkleBlock rejects hostile CMerkleBlocks without throwing or allocating', () => {
  const hdr = new Uint8Array(80); // a syntactically-fine 80-byte header
  const u32 = (n: number) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  const cat = (...a: Uint8Array[]) => { let L = 0; for (const x of a) L += x.length; const o = new Uint8Array(L); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  for (const bad of [
    new Uint8Array(0), new Uint8Array(40), new Uint8Array(84),                 // too short
    cat(hdr, u32(0), new Uint8Array([0x00])),                                  // txCount 0
    cat(hdr, u32(99), new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])), // hashCount varint = huge, no bytes → no billion-slice
    cat(hdr, u32(4), new Uint8Array([0xfe, 0x00, 0x00, 0x00, 0x10]), new Uint8Array(32)), // hashCount 2^28 ≫ txCount
    cat(hdr, u32(4), new Uint8Array([0x01]), new Uint8Array(16)),              // one hash claimed, only 16 bytes present
    cat(hdr, u32(4), new Uint8Array([0x00]), new Uint8Array([0xfe, 0xff, 0xff, 0xff, 0x7f])), // flag count huge, no bytes
    cat(hdr, u32(4), new Uint8Array([0x00]), new Uint8Array([0x00]), new Uint8Array([0xde, 0xad])), // trailing garbage
  ]) {
    let out: unknown = 'unset';
    assert.doesNotThrow(() => { out = parseMerkleBlock(bad); });
    assert.equal(out, null);
  }
});

test('parseMerkleBlock with a 2^31 txCount does not hang or stack-overflow', () => {
  const hdr = new Uint8Array(80);
  const big = new Uint8Array([...hdr, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00]); // txCount = 0x80000000
  const t0 = Date.now();
  assert.doesNotThrow(() => { assert.equal(parseMerkleBlock(big), null); });
  assert.ok(Date.now() - t0 < 200, 'rejected immediately — no treeHeight spin');
});

test('parseMerkleBlock / proofFromMerkleBlockHex are FUZZ-PROOF: 50k random blobs never throw', () => {
  let rng = 0x9e3779b1 >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const t0 = Date.now();
  for (let i = 0; i < 50_000; i++) {
    const len = rand() % 200; const b = new Uint8Array(len);
    for (let k = 0; k < len; k++) b[k] = rand() & 0xff;
    assert.doesNotThrow(() => { parseMerkleBlock(b); proofFromMerkleBlockHex(toHex(b), '00'.repeat(32)); });
  }
  assert.ok(Date.now() - t0 < 8000, 'bounded work — no hang');
});
