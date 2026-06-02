import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  loadParams, baseRent, propertyRent, stationRent, utilityRent,
  mortgageValue, unmortgageCost, buildCost,
} from '../src/index.ts';

const p = loadParams();

test('params version + unit', () => {
  assert.equal(p.params_version, 'estates.v1');
  assert.equal(p.unit, 'sat');
});

test('board has 40 spaces with sequential ids 0..39', () => {
  assert.equal(p.board.length, 40);
  p.board.forEach((s, i) => assert.equal(s.id, i, `space ${i} id`));
});

test('exactly 28 title-NFT spaces (22 properties + 4 stations + 2 utilities)', () => {
  const titled = p.board.filter((s) => s.type === 'property' || s.type === 'station' || s.type === 'utility');
  assert.equal(titled.length, 28);
  assert.equal(p.board.filter((s) => s.type === 'property').length, 22);
  assert.equal(p.board.filter((s) => s.type === 'station').length, 4);
  assert.equal(p.board.filter((s) => s.type === 'utility').length, 2);
  assert.equal(p.nfts.title_deeds.count, 28);
  assert.equal(p.nfts.title_deeds.satoshis_each, 1);
});

test('group membership references real titled spaces of that group', () => {
  for (const [name, def] of Object.entries(p.groups)) {
    for (const id of def.member_property_ids) {
      const space = p.board[id];
      assert.ok(space, `group ${name} -> space ${id} exists`);
      assert.equal(space!.group, name, `space ${id} belongs to ${name}`);
    }
  }
  // every titled space belongs to exactly one declared group
  const declared = new Set(Object.values(p.groups).flatMap((g) => g.member_property_ids));
  for (const s of p.board) {
    if (s.type === 'property' || s.type === 'station' || s.type === 'utility') {
      assert.ok(declared.has(s.id), `space ${s.id} (${s.name}) is in a group`);
    }
  }
});

test('both card decks have 12 cards and exactly one Reprieve grant each', () => {
  for (const deck of ['Fate', 'Treasury']) {
    const cards = p.decks[deck]!;
    assert.equal(cards.length, 12, `${deck} count`);
    const reprieves = cards.filter((c) => c.effect.kind === 'REPRIEVE_GRANT');
    assert.equal(reprieves.length, 1, `${deck} reprieve count`);
  }
  assert.equal(p.nfts.reprieve_cards.count, 2);
});

test('rent derivation — Tanyard Lane (base 60)', () => {
  const base = 60;
  assert.equal(baseRent(base), 5);                 // round(60*0.08)=round(4.8)=5
  assert.equal(propertyRent(base, 0, false), 5);   // single
  assert.equal(propertyRent(base, 0, true), 10);   // full group, unbuilt: 2x
  assert.equal(propertyRent(base, 1, true), 25);   // 5 * 5
  assert.equal(propertyRent(base, 4, true), 313);  // round(5 * 62.5)
  assert.equal(propertyRent(base, 5, true), 375);  // 5 * 75
});

test('station rent ladder 25/50/100/200', () => {
  assert.deepEqual([1, 2, 3, 4].map((n) => stationRent(n)), [25, 50, 100, 200]);
  assert.equal(stationRent(0), 0);
});

test('utility rent = dice × {4 | 10}', () => {
  assert.equal(utilityRent(7, 1), 28);
  assert.equal(utilityRent(7, 2), 70);
  assert.equal(utilityRent(9, 0), 0);
});

test('mortgage + unmortgage', () => {
  assert.equal(mortgageValue(60), 30);             // round(60*0.5)
  assert.equal(unmortgageCost(60), 33);            // round(30*1.1)
});

test('build cost is per-group and matches the SoT', () => {
  assert.equal(buildCost('Sienna'), 50);
  assert.equal(buildCost('Indigo'), 200);
  assert.equal(buildCost('Rails'), 0);
});

test('starting balance, salary, seat bounds', () => {
  assert.equal(p.scalars.starting_balance_per_seat, 1500);
  assert.equal(p.scalars.salary, 200);
  assert.equal(p.scalars.max_seats, 6);
  assert.equal(p.scalars.min_seats, 2);
});
