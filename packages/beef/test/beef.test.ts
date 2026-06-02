import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { txid, type Tx } from '@estates/tx';
import { merkleRoot, buildProof, type BlockHeader } from '@estates/spv';
import { txLeaf, verifyEnvelope, verifyPaymentToKey, verifySpendChain, type Envelope } from '../src/index.ts';

const otherLeaf = (n: number): Uint8Array => new Uint8Array(createHash('sha256').update(new Uint8Array([n, 0xee])).digest());
const script = (b: number): Uint8Array => new Uint8Array([0x76, 0xa9, 0x14, b]); // p2pkh-ish marker

// a confirmed 1-sat-NFT-style tx
const confirmed: Tx = {
  version: 1,
  inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
  outputs: [{ value: 1n, script: script(0x11) }, { value: 1500n, script: script(0x22) }],
  lockTime: 0,
};

/** Put `confirmed` among other leaves in a block and build its envelope. */
function envelopeFor(tx: Tx, index: number, others: number): Envelope {
  const leaves = [];
  for (let i = 0; i < others; i++) leaves.push(otherLeaf(i));
  leaves.splice(index, 0, txLeaf(tx)); // insert the tx's leaf at `index`
  const root = merkleRoot(leaves);
  const header: BlockHeader = { version: 1, prevHash: new Uint8Array(32), merkleRoot: root, time: 1, bits: 0x207fffff, nonce: 0 };
  return { tx, proof: buildProof(leaves, index), header };
}

test('verifyEnvelope: a confirmed tx proves inclusion under its header (no node)', () => {
  const env = envelopeFor(confirmed, 3, 9);
  assert.ok(verifyEnvelope(env));
});

test('a tampered header root or proof is rejected', () => {
  const env = envelopeFor(confirmed, 2, 6);
  assert.equal(verifyEnvelope({ ...env, header: { ...env.header, merkleRoot: new Uint8Array(32).fill(7) } }), false);
  assert.equal(verifyEnvelope({ ...env, proof: { ...env.proof, index: env.proof.index + 1 } }), false);
  // a different tx with the same proof fails (leaf mismatch)
  const evil: Tx = { ...confirmed, lockTime: 9 };
  assert.equal(verifyEnvelope({ ...env, tx: evil }), false);
});

test('verifyPaymentToKey: confirms a specific on-chain payment (the 1-sat NFT)', () => {
  const env = envelopeFor(confirmed, 0, 4);
  assert.ok(verifyPaymentToKey(env, { value: 1n, script: script(0x11) }), 'the 1-sat NFT output is proven');
  assert.ok(verifyPaymentToKey(env, { value: 1500n, script: script(0x22) }), 'the funding output is proven');
  assert.equal(verifyPaymentToKey(env, { value: 1n, script: script(0x99) }), false, 'wrong script not proven');
  assert.equal(verifyPaymentToKey(env, { value: 2n, script: script(0x11) }), false, 'wrong amount not proven');
});

test('verifySpendChain: an unconfirmed move traces to SPV-confirmed outputs', () => {
  const env = envelopeFor(confirmed, 1, 5);
  const spend: Tx = {
    version: 1,
    inputs: [{ prevTxid: txid(confirmed), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [{ value: 1n, script: script(0x33) }],
    lockTime: 0,
  };
  assert.ok(verifySpendChain(spend, [env]).ok, 'input traces to a confirmed output');

  // spends a non-existent output
  const badVout: Tx = { ...spend, inputs: [{ ...spend.inputs[0]!, prevVout: 5 }] };
  assert.equal(verifySpendChain(badVout, [env]).ok, false);
  // spends an unknown (not SPV-proven) source
  const badSrc: Tx = { ...spend, inputs: [{ ...spend.inputs[0]!, prevTxid: 'cd'.repeat(32) }] };
  assert.equal(verifySpendChain(badSrc, [env]).ok, false);
  // a forged input envelope is rejected
  const forged: Envelope = { ...env, header: { ...env.header, merkleRoot: new Uint8Array(32).fill(1) } };
  assert.equal(verifySpendChain(spend, [forged]).ok, false);
});
