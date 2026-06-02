import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as secp from '@noble/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { genMaster, pubOf, deriveChildPriv, deriveChildPub, deriveSelf, KeyChain } from '../src/index.ts';

const hex = (b: Uint8Array) => bytesToHex(b);

// ---- Alice + Bob: sender derives pub, recipient derives priv, they MATCH ------
test('BRC-42 shared derivation: sender pubkey == recipient privkey’s pubkey', () => {
  const alice = genMaster();   // sender
  const bob = genMaster();     // recipient
  const invoice = 'estates/rent/table7/turn42';
  const childPub = deriveChildPub(bob.pub, alice.priv, invoice);   // Alice pays Bob
  const childPriv = deriveChildPriv(bob.priv, alice.pub, invoice); // Bob spends
  assert.equal(hex(pubOf(childPriv)), hex(childPub), 'both parties land on the same one-use key');
  // the one-use key is NOT Bob's identity key (unlinkable without the shared secret)
  assert.notEqual(hex(childPub), hex(bob.pub));
});

test('shared derivation is deterministic and per-invoice unique (a hash chain)', () => {
  const alice = genMaster(); const bob = genMaster();
  const a = deriveChildPub(bob.pub, alice.priv, 'inv/1');
  const a2 = deriveChildPub(bob.pub, alice.priv, 'inv/1');
  const b = deriveChildPub(bob.pub, alice.priv, 'inv/2');
  assert.equal(hex(a), hex(a2), 'deterministic for the same invoice');
  assert.notEqual(hex(a), hex(b), 'different invoice → different one-use key');
});

test('an outsider (wrong counterparty) cannot derive the same key', () => {
  const alice = genMaster(); const bob = genMaster(); const eve = genMaster();
  const real = deriveChildPub(bob.pub, alice.priv, 'inv/1');
  const evePub = deriveChildPub(bob.pub, eve.priv, 'inv/1'); // Eve uses her own key
  assert.notEqual(hex(real), hex(evePub), 'the shared secret binds the two real parties');
});

// ---- Alice only: deterministic indexed one-use keys, only she can derive ------
test('deriveSelf: indexed one-use keys, deterministic, all distinct, none is the master', () => {
  const alice = genMaster();
  const keys = Array.from({ length: 50 }, (_, i) => deriveSelf(alice, i));
  const pubs = keys.map((k) => hex(k.pub));
  assert.equal(new Set(pubs).size, 50, 'every indexed self key is unique (one-use)');
  assert.equal(hex(deriveSelf(alice, 7).pub), hex(keys[7]!.pub), 'deterministic per index');
  for (const k of keys) {
    assert.equal(hex(pubOf(k.priv)), hex(k.pub), 'priv/pub consistent');
    assert.notEqual(hex(k.pub), hex(alice.pub), 'never the reused identity key');
  }
});

// ---- KeyChain: monotonic issuance, never reuses --------------------------------
test('KeyChain.next() issues a fresh one-use key every time (no reuse)', () => {
  const chain = new KeyChain(genMaster());
  const seen = new Set<string>();
  for (let i = 0; i < 100; i++) {
    const { key, index } = chain.next();
    assert.equal(index, i, 'monotonic index');
    assert.equal(seen.has(hex(key.pub)), false, 'never reissues a key');
    seen.add(hex(key.pub));
  }
});

test('KeyChain pay/receive round-trips between two parties', () => {
  const alice = new KeyChain(genMaster());
  const bob = new KeyChain(genMaster());
  const invoice = 'estates/buy/prop12';
  const payPub = alice.payTo(bob.pub, invoice);          // Alice computes Bob's one-use addr
  const recv = bob.receiveFrom(alice.pub, invoice);      // Bob derives the spendable key
  assert.equal(hex(recv.pub), hex(payPub), 'Alice paid exactly the key Bob can spend');
});

// ---- child keys are valid scalars in [1, n) -----------------------------------
test('derived private keys are valid secp256k1 scalars', () => {
  const a = genMaster(); const b = genMaster();
  for (let i = 0; i < 20; i++) {
    const k = deriveChildPriv(b.priv, a.pub, `inv/${i}`);
    assert.doesNotThrow(() => secp.getPublicKey(k, true), 'valid private key');
  }
});
