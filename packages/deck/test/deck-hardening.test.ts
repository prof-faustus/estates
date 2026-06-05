// Audit-required hardening: runtime face validation, participant-bound seed
// combination, permutation size guard, AEAD/domain binding, transfer retirement.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils';
import {
  validateFace, encodeFace, permutation, MAX_DECK_SIZE,
  combineSeedBound, commitEntropy, genCardKey, mintCard, openCard, transferCard,
  isValidPub, type CardFace, type SeedParty,
} from '../src/index.ts';

const TABLE = 'a1'.repeat(32);

test('validateFace / encodeFace reject hostile runtime faces', () => {
  for (const bad of [null, 42, {}, { kind: 'EVIL', id: 0 }, { kind: 'TITLE', id: -1 }, { kind: 'TITLE', id: 1.5 },
    { kind: 'TITLE', id: 2 ** 33 }, { kind: 'TITLE', id: 0, payload: 'x' }, { kind: 'TITLE', id: 0, payload: new Uint8Array(70000) }]) {
    assert.throws(() => validateFace(bad), `validateFace should reject ${JSON.stringify(bad)}`);
    assert.throws(() => encodeFace(bad as unknown as CardFace));
  }
  // a valid face round-trips
  assert.ok(encodeFace({ kind: 'TITLE', id: 7 }).length === 9);
});

test('permutation rejects out-of-range n (no unbounded alloc / infinite loop)', () => {
  for (const bad of [-1, 1.5, NaN, Infinity, MAX_DECK_SIZE + 1, 2 ** 40]) {
    assert.throws(() => permutation(new Uint8Array(32), bad));
  }
  assert.equal(permutation(new Uint8Array(32), 0).length, 0);
  assert.equal(permutation(new Uint8Array(32), 12).length, 12);
});

test('combineSeedBound binds the participant set: reveals must open their commitments', () => {
  const mk = (seat: number, n: number): SeedParty => {
    const reveal = new Uint8Array(32).fill(n);
    const k = genCardKey();
    return { seat, pub: bytesToHex(k.pub), commitment: commitEntropy(reveal), reveal };
  };
  const parties = [mk(0, 1), mk(1, 2), mk(2, 3)];
  const seed = combineSeedBound(parties, TABLE);
  assert.ok(seed instanceof Uint8Array, 'valid parties → seed');
  // order-independent (sorted by seat internally)
  assert.deepEqual(combineSeedBound([parties[2]!, parties[0]!, parties[1]!], TABLE), seed);
  // a reveal that does NOT open its commitment → null
  const forged: SeedParty = { ...parties[0]!, commitment: commitEntropy(new Uint8Array(32).fill(9)) };
  assert.equal(combineSeedBound([forged, parties[1]!, parties[2]!], TABLE), null);
  // duplicate seat → null
  assert.equal(combineSeedBound([parties[0]!, { ...parties[1]!, seat: 0 }], TABLE), null);
  // changing any party changes the seed (no missing/substituted party undetected)
  assert.notDeepEqual(combineSeedBound([mk(0, 1), mk(1, 2)], TABLE), seed);
  // bad gameId → null
  assert.equal(combineSeedBound(parties, 'zz'.repeat(32)), null);
  assert.equal(combineSeedBound(parties, 'short'), null);
});

test('AEAD binding: a sealed card opens only under its own table + key (wrong table fails)', () => {
  const holder = genCardKey();
  const { card, secret } = mintCard(TABLE, { kind: 'FATE', id: 3 }, holder.pub);
  // correct open
  assert.deepEqual(openCard(card, holder.priv, secret.blind, TABLE), { kind: 'FATE', id: 3 });
  // wrong expected table → null (and the aad would not match either)
  assert.equal(openCard(card, holder.priv, secret.blind, 'b2'.repeat(32)), null);
  // a card whose cardPub is swapped (aad no longer matches the seal) → null
  const swapped = { ...card, cardPub: bytesToHex(genCardKey().pub) };
  assert.equal(openCard(swapped, holder.priv, secret.blind, TABLE), null);
});

test('transferCard rotates the key, re-binds the AEAD, and emits a RETIREMENT event', () => {
  const a = genCardKey(), b = genCardKey();
  const { card, secret } = mintCard(TABLE, { kind: 'TITLE', id: 5 }, a.pub);
  const { card: card2, key: bKey, event } = transferCard(card, secret.face, b.pub);
  assert.equal(event.retired, card.cardPub, 'old key retired');
  assert.equal(event.newCardPub, card2.cardPub);
  assert.notEqual(card2.cardPub, card.cardPub, 'fresh one-use key');
  // new holder opens it under the new key's aad; old holder cannot
  assert.deepEqual(openCard(card2, b.priv, secret.blind, TABLE), { kind: 'TITLE', id: 5 });
  assert.equal(openCard(card2, a.priv, secret.blind, TABLE), null);
  void bKey;
});

test('isValidPub / sealTo / mintCard reject off-curve holder keys', () => {
  const offCurve = new Uint8Array(33); offCurve[0] = 0x02; offCurve.fill(0xff, 1);
  assert.equal(isValidPub(offCurve), false);
  assert.equal(isValidPub(genCardKey().pub), true);
  assert.throws(() => mintCard(TABLE, { kind: 'TITLE', id: 1 }, offCurve));
});
