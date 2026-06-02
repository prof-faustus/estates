import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  commit, verifyReveal, roll, beaconSeed, honestReveals, ZERO_BEACON, type PartyReveal,
} from '../src/index.ts';

const secret = (n: number): Uint8Array => {
  const b = new Uint8Array(32);
  b[0] = n; b[31] = n ^ 0xa5;
  return b;
};

test('commit / verifyReveal round-trip; forged reveal rejected', () => {
  const s = secret(7);
  const c = commit(s);
  assert.equal(verifyReveal(s, c), true);
  assert.equal(verifyReveal(secret(8), c), false);
});

test('dice are always in [1..6] and total in [2..12]', () => {
  for (let t = 0; t < 50; t++) {
    const r = roll([{ seat: 0, secret: secret(t) }, { seat: 1, secret: secret(t + 100) }], t, ZERO_BEACON);
    assert.ok(r.dice[0] >= 1 && r.dice[0] <= 6, `d1 ${r.dice[0]}`);
    assert.ok(r.dice[1] >= 1 && r.dice[1] <= 6, `d2 ${r.dice[1]}`);
    assert.equal(r.total, r.dice[0] + r.dice[1]);
  }
});

test('determinism: same reveals + turn + prev_beacon yield the same roll', () => {
  const reveals: PartyReveal[] = [{ seat: 0, secret: secret(1) }, { seat: 1, secret: secret(2) }];
  const a = roll(reveals, 3, ZERO_BEACON);
  const b = roll(reveals, 3, ZERO_BEACON);
  assert.deepEqual(a.dice, b.dice);
  assert.deepEqual([...a.beacon], [...b.beacon]);
});

test('reveal order does not matter (canonical by seat)', () => {
  const r1 = roll([{ seat: 0, secret: secret(1) }, { seat: 1, secret: secret(2) }], 5);
  const r2 = roll([{ seat: 1, secret: secret(2) }, { seat: 0, secret: secret(1) }], 5);
  assert.deepEqual(r1.dice, r2.dice);
});

test('unbiasable: changing any single reveal changes the seed (no seat can steer)', () => {
  const base = beaconSeed([{ seat: 0, secret: secret(1) }, { seat: 1, secret: secret(2) }], 0, ZERO_BEACON);
  const altA = beaconSeed([{ seat: 0, secret: secret(9) }, { seat: 1, secret: secret(2) }], 0, ZERO_BEACON);
  const altB = beaconSeed([{ seat: 0, secret: secret(1) }, { seat: 1, secret: secret(9) }], 0, ZERO_BEACON);
  assert.notDeepEqual([...base], [...altA]);
  assert.notDeepEqual([...base], [...altB]);
});

test('prev_beacon chaining: same reveals at the same turn differ across chains', () => {
  const reveals: PartyReveal[] = [{ seat: 0, secret: secret(1) }, { seat: 1, secret: secret(2) }];
  const a = roll(reveals, 1, ZERO_BEACON);
  const b = roll(reveals, 1, a.beacon); // chained from a
  assert.notDeepEqual([...a.beacon], [...b.beacon]);
});

test('turn_index binds the roll (replay across turns differs)', () => {
  const reveals: PartyReveal[] = [{ seat: 0, secret: secret(1) }, { seat: 1, secret: secret(2) }];
  assert.notDeepEqual([...roll(reveals, 1).beacon], [...roll(reveals, 2).beacon]);
});

test('timeout default: a committed non-revealer is dropped; roll stands on the honest reveal', () => {
  const s0 = secret(1), s1 = secret(2);
  const c0 = commit(s0), c1 = commit(s1);
  // seat 1 reveals a wrong secret (or fails); only seat 0 is honest
  const honest = honestReveals([
    { seat: 0, secret: s0, commitment: c0 },
    { seat: 1, secret: secret(99), commitment: c1 }, // mismatch -> dropped
  ]);
  assert.deepEqual(honest.map((r) => r.seat), [0]);
  const r = roll(honest, 4);
  assert.deepEqual(r.contributors, [0]);
  assert.ok(r.dice[0] >= 1 && r.dice[1] <= 6);
});

test('rough uniformity: each face appears across many rolls (no degenerate output)', () => {
  const counts = new Array(7).fill(0);
  for (let t = 0; t < 600; t++) {
    const r = roll([{ seat: 0, secret: secret(t & 0xff) }, { seat: 1, secret: secret((t * 7) & 0xff) }], t);
    counts[r.dice[0]]++; counts[r.dice[1]]++;
  }
  for (let face = 1; face <= 6; face++) {
    assert.ok(counts[face] > 100, `face ${face} appeared ${counts[face]} times (expected ~200)`);
  }
});
