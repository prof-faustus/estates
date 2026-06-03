import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadParams } from '@estates/params';
import type { GameState, Action } from '@estates/engine';
import { recordGame, audit, type GameTranscript, type Entry } from '../src/index.ts';

const P = loadParams();
const genesis = { network: 'regtest' as const, seatCount: 3, bankReserve: 1_000_000 };

// non-roll decisions (a modest heuristic; rolls come from the beacon)
const decide = (s: GameState): Action => {
  switch (s.phase) {
    case 'AWAIT_BUY': {
      const price = P.board[s.pendingTitle!]?.base_price ?? 0;
      return s.seats[s.current]!.balance - price >= 200 ? { type: 'BUY' } : { type: 'DECLINE' };
    }
    case 'AWAIT_TAX': return { type: 'PAY_TAX', choice: 'flat' };
    default: return { type: 'END_TURN' };
  }
};

const secret = (r: number, seat: number): Uint8Array => {
  const b = new Uint8Array(32);
  b[0] = r & 0xff; b[1] = (r >> 8) & 0xff; b[2] = seat & 0xff;
  for (let i = 3; i < 32; i++) b[i] = (r * 7 + seat * 13 + i) & 0xff;
  return b;
};

function record(): GameTranscript {
  return recordGame(genesis, decide, secret, 4000);
}

test('a recorded game audits cleanly and reconstructs the final hash', () => {
  const t = record();
  assert.ok(t.entries.length > 10, 'a real game was recorded');
  const r = audit(t);
  assert.ok(r.ok, r.reason);
  assert.ok(r.rollsVerified > 0, 'rolls were verified against the beacon');
  assert.equal(r.finalHash, t.finalHash);
});

test('audit is deterministic / independent (re-audit gives the same hash)', () => {
  const t = record();
  assert.equal(audit(t).finalHash, audit(t).finalHash);
});

function withEntries(t: GameTranscript, entries: Entry[]): GameTranscript {
  return { ...t, entries };
}
const firstIndex = (t: GameTranscript, kind: Entry['kind']): number => t.entries.findIndex((e) => e.kind === kind);

test('a forged die is rejected', () => {
  const t = record();
  const i = firstIndex(t, 'roll');
  const e = t.entries[i] as Extract<Entry, { kind: 'roll' }>;
  const entries = [...t.entries];
  entries[i] = { ...e, dice: [6, 6] }; // claim a different roll than the reveals produce
  const r = audit(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /forged roll|do not match/);
});

test('a swapped reveal is rejected (it no longer opens its commitment)', () => {
  const t = record();
  const i = firstIndex(t, 'roll');
  const e = t.entries[i] as Extract<Entry, { kind: 'roll' }>;
  const reveals = e.reveals.map((rv, k) => (k === 0 ? { ...rv, secret: 'ff'.repeat(32) } : rv));
  const entries = [...t.entries];
  entries[i] = { ...e, reveals };
  const r = audit(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /does not open its commitment|forged roll|do not match/);
});

// ---- audit #3: commitments, participant set, and binding are verified --------
test('a reveal from a NON-SEAT (or bankrupt) is rejected', () => {
  const t = record();
  const i = firstIndex(t, 'roll');
  const e = t.entries[i] as Extract<Entry, { kind: 'roll' }>;
  const entries = [...t.entries];
  entries[i] = { ...e, commits: [...e.commits, { seat: 99, c: 'ab'.repeat(32) }], reveals: [...e.reveals, { seat: 99, secret: 'cd'.repeat(32) }] };
  const r = audit(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /non-live|non-seat/);
});

test('a reveal with NO prior commitment is rejected', () => {
  const t = record();
  const i = firstIndex(t, 'roll');
  const e = t.entries[i] as Extract<Entry, { kind: 'roll' }>;
  const entries = [...t.entries];
  // drop the commitment but keep the reveal for seat 0
  entries[i] = { ...e, commits: e.commits.filter((c) => c.seat !== e.reveals[0]!.seat) };
  const r = audit(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /no prior commitment|non-live/);
});

test('a duplicate reveal seat is rejected', () => {
  const t = record();
  const i = firstIndex(t, 'roll');
  const e = t.entries[i] as Extract<Entry, { kind: 'roll' }>;
  const entries = [...t.entries];
  entries[i] = { ...e, reveals: [...e.reveals, e.reveals[0]!] };
  const r = audit(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /duplicate reveal/);
});

test('an illegal action is rejected', () => {
  const t = record();
  const i = firstIndex(t, 'action');
  const entries = [...t.entries];
  entries[i] = { kind: 'action', action: { type: 'UNMORTGAGE', propertyId: 1 } }; // illegal at this point
  const r = audit(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /illegal action|rejected/);
});

test('a wrong final hash is rejected', () => {
  const t = record();
  const r = audit({ ...t, finalHash: '0'.repeat(64) });
  assert.equal(r.ok, false);
  assert.match(r.reason, /final state hash mismatch/);
});

test('a params-version mismatch is rejected', () => {
  const t = record();
  const r = audit({ ...t, params_version: 'estates.v999' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /params version/);
});
