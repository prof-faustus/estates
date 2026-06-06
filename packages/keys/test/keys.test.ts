import { test } from 'node:test';
import assert from 'node:assert/strict';
import { genMaster, pubOf, deriveChildPriv, deriveChildPub, deriveSelf, KeyChain, walletChain, verifyChain, genesisLink } from '../src/index.ts';
import { isValidScalar } from '../src/secp256k1.ts';

const hex = (b: Uint8Array) => { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };

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

// ---- MANDATORY hash chain (index‖ECDH‖HMAC) — TS twin of native KeyChain.cs ----
test('walletChain verifies, every key is unique, root is never a sub-key', () => {
  const root = genMaster();
  const chain = walletChain(root.priv, 16);
  assert.ok(verifyChain(root.pub, chain), 'the hash-chained Type-42 chain verifies');
  const pubs = new Set(chain.map((c) => hex(c.pub)));
  assert.equal(pubs.size, chain.length, 'every sub-key is unique (one-use)');
  assert.equal(pubs.has(hex(root.pub)), false, 'root is never a sub-key');
  for (const ck of chain) assert.equal(hex(pubOf(ck.priv)), hex(ck.pub), 'priv/pub consistent');
});

test('tampering ANY earlier link breaks chain verification', () => {
  const root = genMaster();
  const chain = walletChain(root.priv, 8);
  const broken = chain.map((c) => ({ ...c }));
  broken[3] = { ...broken[3], link: Uint8Array.from(broken[3].link).map((b, i) => (i === 0 ? b ^ 0xff : b)) };
  assert.equal(verifyChain(root.pub, broken), false);
});

test('the genesis link binds the root pubkey (different roots ⇒ different chains)', () => {
  const a = genMaster(); const b = genMaster();
  assert.notEqual(hex(genesisLink(a.pub)), hex(genesisLink(b.pub)));
  assert.notEqual(hex(walletChain(a.priv, 1)[0].pub), hex(walletChain(b.priv, 1)[0].pub));
});

// ---- child keys are valid scalars in [1, n) -----------------------------------
test('derived private keys are valid secp256k1 scalars', () => {
  const a = genMaster(); const b = genMaster();
  for (let i = 0; i < 20; i++) {
    const k = deriveChildPriv(b.priv, a.pub, `inv/${i}`);
    assert.ok(isValidScalar(k), 'valid private key');
  }
});

// ---- on-chain spend keys: fresh, ECDH-derived, recoverable, context-bound -----
test('pkhOf + spendContext: a payer-derived output pkh is recoverable by the recipient', async () => {
  const { pkhOf, spendContext } = await import('../src/index.ts');
  const payer = genMaster();       // the actor building the tx
  const recip = genMaster();       // a seat being paid
  const ctx = spendContext({ gameId: 'ab'.repeat(32), network: 'regtest', purpose: 'move', role: 1, turnIndex: 7, outputIndex: 1 });

  // payer derives the recipient's one-use child PUB → output pkh
  const childPub = deriveChildPub(recip.pub, payer.priv, ctx);
  const outPkh = pkhOf(childPub);

  // recipient recovers the matching PRIVATE key and its pkh — proves spendability
  const childPriv = deriveChildPriv(recip.priv, payer.pub, ctx);
  assert.equal(hex(pubOf(childPriv)), hex(childPub), 'recipient derives the same child key');
  assert.equal(hex(pkhOf(pubOf(childPriv))), hex(outPkh), 'recipient can spend the exact output');
  assert.equal(outPkh.length, 20, 'pkh is a 20-byte hash160');
});

test('spendContext binds each output: different purpose/role/turn/output ⇒ different key (no reuse)', async () => {
  const { spendContext } = await import('../src/index.ts');
  const m = genMaster();
  const base = { gameId: 'cd'.repeat(32), network: 'regtest', purpose: 'move', role: 0, turnIndex: 3, outputIndex: 0 };
  const k = (o: Partial<typeof base>) => hex(deriveSelf(m, spendContext({ ...base, ...o })).pub);
  const keys = new Set([k({}), k({ role: 1 }), k({ turnIndex: 4 }), k({ outputIndex: 1 }), k({ purpose: 'reserve' }), k({ network: 'testnet' })]);
  assert.equal(keys.size, 6, 'every distinct on-chain context yields a distinct one-use key');
});
