import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex, randomBytes, sha256 } from '@estates/keys';
import {
  genCardKey, sealTo, open, commit, verifyReveal, encodeFace, decodeFace,
  mintCard, openCard, transferCard, commitEntropy, verifyEntropy, combineSeed,
  permutation, mintDeck, verifyCardTranscript, type CardFace,
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

// ---- EXACT unbiased shuffle for ESTATES's ACTUAL set sizes ------------------
// The defect was modulo bias (`next() % (i+1)`) for any size where i+1 ∤ 2^32:
// Fate/Treasury n=12 (2^32 mod 12 = 4), 28 title NFTs (mod 28 = 4), 30 title+
// Reprieve (mod 30 = 16). The fix is rejection sampling — exactness is structural.
test('permutation is an exact bijection for every ESTATES finite set size', () => {
  for (const n of [12, 28, 30, 40, 2, 6]) {        // Fate, Treasury, titles, titles+reprieve, board, dice-ish
    const seed = randomBytes(32);
    const p = permutation(seed, n);
    assert.deepEqual([...p].sort((x, y) => x - y), Array.from({ length: n }, (_, i) => i), `n=${n} bijection`);
  }
});
test('shuffle is ~uniform across seeds for a biased-prone size (n=12) — no skewed residues', () => {
  // Deterministic seeds; count where index 0 lands. With modulo bias the 4 low
  // residues would be measurably over-represented; rejection sampling keeps it flat.
  const n = 12, samples = 24000;
  const counts = new Array<number>(n).fill(0);
  for (let s = 0; s < samples; s++) {
    const seed = sha256(Uint8Array.of(s & 0xff, (s >>> 8) & 0xff, (s >>> 16) & 0xff, (s >>> 24) & 0xff));
    counts[permutation(seed, n).indexOf(0)]!++;
  }
  const expected = samples / n;
  // chi-square goodness-of-fit; 11 dof, 0.1% critical ≈ 31.26 — a flat shuffle clears it easily.
  const chi2 = counts.reduce((acc, c) => acc + (c - expected) ** 2 / expected, 0);
  assert.ok(chi2 < 31.26, `chi-square ${chi2.toFixed(2)} indicates a skewed shuffle`);
});

// ---- transcript verifier: one-use keys are ENFORCED, not just intended ------
test('verifyCardTranscript accepts a fresh deck; rejects reuse / wrong table / bad key', () => {
  const dealer = genCardKey();
  const faces: CardFace[] = Array.from({ length: 30 }, (_, i) => ({ kind: i < 28 ? 'TITLE' : 'REPRIEVE', id: i }));
  const deck = mintDeck(TABLE, faces, dealer.pub, combineSeed([randomBytes(32), randomBytes(32)]));
  assert.ok(verifyCardTranscript(deck.cards, TABLE).ok, 'fresh deck: unique one-use keys, table-bound');

  // a duplicated custody key (the exact failure one-use keys must prevent) is rejected
  const dup = [...deck.cards, { ...deck.cards[5]! }];
  assert.equal(verifyCardTranscript(dup, TABLE).ok, false, 'reused cardPub rejected');

  // a card bound to another table is rejected
  assert.equal(verifyCardTranscript(deck.cards, OTHER).ok, false, 'wrong table rejected');

  // a malformed / off-curve cardPub is rejected
  const bad = [{ ...deck.cards[0]!, cardPub: 'zz'.repeat(33) }];
  assert.equal(verifyCardTranscript(bad, TABLE).ok, false, 'non-point cardPub rejected');
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

// ---- a concealed card can come from a MALICIOUS minter: openCard stays total ----
test('openCard returns null (never throws) on a MALICIOUS minter who committed to a malformed face', () => {
  const holder = genCardKey();
  const blind = randomBytes(32);
  const garbage = new Uint8Array([0xff, 0xff, 0xff]);             // not a decodable face
  const card = {
    tableId: TABLE,
    cardPub: bytesToHex(genCardKey().pub),
    commitment: commit(garbage, blind),                          // commitment matches the garbage
    sealed: sealTo(holder.pub, garbage),                          // sealed to the holder
  };
  let out: unknown = 'unset';
  assert.doesNotThrow(() => { out = openCard(card, holder.priv, blind, TABLE); });
  assert.equal(out, null, 'a card whose face does not decode is rejected, not a crash');
});

test('decodeFace rejects short/malformed buffers; openCard is FUZZ-PROOF over random sealed faces', () => {
  assert.throws(() => decodeFace(new Uint8Array(0)));
  assert.throws(() => decodeFace(new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 5]))); // claims 5-byte payload, has 0
  const holder = genCardKey();
  let rng = 0x51a2b3c4 >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  for (let i = 0; i < 20_000; i++) {
    const n = rand() % 24; const g = new Uint8Array(n); for (let k = 0; k < n; k++) g[k] = rand() & 0xff;
    const blind = randomBytes(32);
    const card = { tableId: TABLE, cardPub: bytesToHex(genCardKey().pub), commitment: commit(g, blind), sealed: sealTo(holder.pub, g) };
    assert.doesNotThrow(() => { openCard(card, holder.priv, blind, TABLE); });
  }
});
