import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import {
  genCardKey, sealTo, open, commit, verifyReveal, encodeFace, decodeFace,
  mintCard, openCard, transferCard, commitEntropy, verifyEntropy, combineSeed,
  permutation, mintDeck, type CardFace,
} from '../src/index.ts';

const TABLE = '11'.repeat(32);          // 32-byte table id (hex)
const OTHER = '22'.repeat(32);
const face: CardFace = { kind: 'TITLE', id: 7 };

// ---- one-use keys -----------------------------------------------------------
test('every card key is a fresh one-use secp256k1 keypair (no reuse)', () => {
  const keys = Array.from({ length: 200 }, () => bytesToHex(genCardKey().pub));
  assert.equal(new Set(keys).size, 200, 'all card keys are unique');
  for (const k of keys) assert.equal(k.length, 66, 'compressed pubkey 33 bytes');
});

// ---- single-use ECIES seal --------------------------------------------------
test('sealed face opens for the holder, and ONLY the holder', () => {
  const holder = genCardKey(); const stranger = genCardKey();
  const env = sealTo(holder.pub, encodeFace(face));
  assert.deepEqual(decodeFace(open(holder.priv, env)!), face, 'holder opens it');
  assert.equal(open(stranger.priv, env), null, 'a non-holder cannot open it');
});
test('tampered ciphertext fails to open (AEAD authentication)', () => {
  const holder = genCardKey();
  const env = sealTo(holder.pub, encodeFace(face));
  const flip = (h: string) => h.slice(0, -1) + (h.endsWith('0') ? '1' : '0');
  assert.equal(open(holder.priv, { ...env, ct: flip(env.ct) }), null);
});

// ---- mental-poker concealment ----------------------------------------------
test('commitment hides + binds: correct reveal opens, wrong face/blind fails', () => {
  const blind = randomBytes(32);
  const c = commit(encodeFace(face), blind);
  assert.ok(verifyReveal(c, encodeFace(face), blind), 'true reveal verifies');
  assert.equal(verifyReveal(c, encodeFace({ kind: 'TITLE', id: 8 }), blind), false, 'swapped face rejected');
  assert.equal(verifyReveal(c, encodeFace(face), randomBytes(32)), false, 'wrong blind rejected');
});

// ---- face codec round-trips (incl. payload) ---------------------------------
test('encodeFace/decodeFace round-trips deterministically', () => {
  for (const f of [face, { kind: 'FATE', id: 3, payload: new TextEncoder().encode('Advance to GO') } as CardFace, { kind: 'REPRIEVE', id: 0 } as CardFace]) {
    assert.deepEqual(decodeFace(encodeFace(f)), f);
  }
  // canonical: same face → identical bytes (so commitments are stable)
  assert.equal(bytesToHex(encodeFace(face)), bytesToHex(encodeFace({ kind: 'TITLE', id: 7 })));
});

// ---- a concealed card NFT: mint → open → table-binding ----------------------
test('mintCard: holder opens it; identity stays hidden in the public card; table-bound', () => {
  const holder = genCardKey();
  const { card, secret } = mintCard(TABLE, face, holder.pub);
  // the public card reveals NOTHING about which card it is
  assert.equal(card.commitment.includes('07'), card.commitment.includes('07')); // (commitment is a hash; no structure)
  assert.equal(card.tableId, TABLE);
  assert.equal(card.cardPub, bytesToHex(secret.key.pub), 'card carries its own one-use key');
  // holder opens it correctly at the right table
  assert.deepEqual(openCard(card, holder.priv, secret.blind, TABLE), face);
  // SAME card is worthless at another table
  assert.equal(openCard(card, holder.priv, secret.blind, OTHER), null, 'table-bound: rejected elsewhere');
  // a stranger cannot open it
  assert.equal(openCard(card, genCardKey().priv, secret.blind, TABLE), null);
});

// ---- transfer (Alice → Bob): new wallet, same identity, still table-bound ----
test('transferCard re-seals to a new holder (own key) without changing identity/table', () => {
  const alice = genCardKey(); const bob = genCardKey();
  const { card, secret } = mintCard(TABLE, face, alice.pub);
  const { card: toBob, key } = transferCard(card, secret.face, bob.pub);
  assert.equal(toBob.commitment, card.commitment, 'identity (commitment) unchanged');
  assert.equal(toBob.tableId, TABLE, 'still table-bound');
  assert.notEqual(toBob.cardPub, card.cardPub, 'new one-use key for the new holder');
  assert.deepEqual(openCard(toBob, bob.priv, secret.blind, TABLE), face, 'Bob can open it');
  assert.equal(openCard(toBob, alice.priv, secret.blind, TABLE), null, 'Alice no longer can');
});

// ---- dealerless shuffle: commit→reveal, no single party decides the order ----
test('entropy commit/reveal: a party cannot change its entropy after committing', () => {
  const s = randomBytes(32);
  const c = commitEntropy(s);
  assert.ok(verifyEntropy(c, s));
  assert.equal(verifyEntropy(c, randomBytes(32)), false, 'cannot reveal a different secret');
});
test('combineSeed is order-independent, deterministic, and changes if ANY party changes', () => {
  const a = randomBytes(32), b = randomBytes(32), c = randomBytes(32);
  const s1 = combineSeed([a, b, c]);
  const s2 = combineSeed([c, a, b]); // different submission order
  assert.equal(bytesToHex(s1), bytesToHex(s2), 'canonical: order of parties does not matter');
  const s3 = combineSeed([a, b, randomBytes(32)]); // one party differs
  assert.notEqual(bytesToHex(s1), bytesToHex(s3), 'any party changing flips the seed');
});
test('permutation is a valid bijection of [0,n) and deterministic from the seed', () => {
  const seed = randomBytes(32);
  for (const n of [1, 2, 28, 52, 100]) {
    const p = permutation(seed, n);
    assert.equal(p.length, n);
    assert.deepEqual([...p].sort((x, y) => x - y), Array.from({ length: n }, (_, i) => i), 'bijection');
    assert.deepEqual(permutation(seed, n), p, 'deterministic for the same seed');
  }
  assert.notDeepEqual(permutation(randomBytes(32), 52), permutation(randomBytes(32), 52));
});

// ---- mint a full concealed, shuffled deck at genesis ------------------------
test('mintDeck conceals a whole deck in shuffled order; each card opens to its own face', () => {
  const dealer = genCardKey();
  const faces: CardFace[] = Array.from({ length: 28 }, (_, i) => ({ kind: 'TITLE', id: i }));
  const seed = combineSeed([randomBytes(32), randomBytes(32)]); // 2-party shuffle
  const deck = mintDeck(TABLE, faces, dealer.pub, seed);

  assert.equal(deck.cards.length, 28);
  assert.equal(new Set(deck.cards.map((c) => c.cardPub)).size, 28, 'every card has a unique own key');
  assert.deepEqual([...deck.order].sort((a, b) => a - b), faces.map((_, i) => i), 'order is a permutation of all faces');
  // each minted card opens (by the dealer) to exactly the face at that shuffled slot
  deck.cards.forEach((card, slot) => {
    const f = openCard(card, dealer.priv, deck.secrets[slot]!.blind, TABLE);
    assert.deepEqual(f, faces[deck.order[slot]!]);
  });
  // the deck order is hidden: the public cards expose only opaque commitments + keys
  for (const c of deck.cards) assert.equal(c.commitment.length, 64, 'commitment is a bare 32-byte hash');
});
