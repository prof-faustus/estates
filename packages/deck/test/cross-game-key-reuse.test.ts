// Mandated test: a card key is valid for AT MOST ONE GAME. A cardPub used in a
// prior game must be rejected when it reappears in a later game's transcript.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintCard, verifyCardTranscript, type ConcealedCard, type CardFace } from '../src/index.ts';
import { genCardKey } from '../src/index.ts';
import { bytesToHex } from '@noble/hashes/utils';

const TABLE_A = 'a1'.repeat(32);
const TABLE_B = 'b2'.repeat(32);
const face: CardFace = { kind: 'TITLE', id: 1 };

function deckFor(tableId: string, n: number): ConcealedCard[] {
  const holder = genCardKey();
  return Array.from({ length: n }, () => mintCard(tableId, face, holder.pub).card);
}

test('a fresh per-game deck verifies, and its keys are unique within the game', () => {
  const cards = deckFor(TABLE_A, 5);
  assert.ok(verifyCardTranscript(cards, TABLE_A).ok);
});

test('CROSS-GAME card-key reuse is REJECTED via the prior-used-key set', () => {
  const gameA = deckFor(TABLE_A, 4);
  const usedInA = gameA.map((c) => c.cardPub);

  // Game B mints its own fresh deck → passes against A's used set.
  const gameBFresh = deckFor(TABLE_B, 4);
  assert.ok(verifyCardTranscript(gameBFresh, TABLE_B, usedInA).ok, 'fresh keys in game B pass');

  // Now game B illegally reuses one of game A's card keys (same cardPub) →
  // rejected because that key already served game A.
  const reused: ConcealedCard = { ...gameBFresh[0]!, cardPub: usedInA[0]! };
  const gameBReuse = [reused, ...gameBFresh.slice(1)];
  const r = verifyCardTranscript(gameBReuse, TABLE_B, usedInA);
  assert.equal(r.ok, false);
  assert.match(r.reason, /prior game|one game/i);
});

test('within-game duplicate card key is still rejected (independent of cross-game set)', () => {
  const cards = deckFor(TABLE_A, 3);
  const dup = [...cards, { ...cards[0]! }]; // repeat the first cardPub
  assert.equal(verifyCardTranscript(dup, TABLE_A).ok, false);
});

test('a non-hex table id is rejected (not just wrong length)', () => {
  const cards = deckFor(TABLE_A, 2);
  // 64 chars but not hex
  const badTable = 'z'.repeat(64);
  assert.equal(verifyCardTranscript(cards, badTable).ok, false);
  // a card whose own tableId is non-hex
  const badCard: ConcealedCard = { ...cards[0]!, tableId: 'g'.repeat(64) };
  assert.equal(verifyCardTranscript([badCard], TABLE_A).ok, false);
});

test('the cross-game used set composes: union of several prior games rejects any of their keys', () => {
  const g1 = deckFor(TABLE_A, 3);
  const g2 = deckFor(TABLE_B, 3);
  const used = new Set([...g1, ...g2].map((c) => c.cardPub));
  const TABLE_C = 'c3'.repeat(32);
  const g3 = deckFor(TABLE_C, 3);
  assert.ok(verifyCardTranscript(g3, TABLE_C, used).ok, 'all-fresh game C passes');
  const reuseG2Key: ConcealedCard = { ...g3[0]!, cardPub: g2[1]!.cardPub };
  assert.equal(verifyCardTranscript([reuseG2Key, ...g3.slice(1)], TABLE_C, used).ok, false);
  void bytesToHex;
});
