import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadParams } from '@estates/params';
import type { GameState, Action } from '@estates/engine';
import { recordGame, audit, type GameTranscript, type Entry } from '../src/index.ts';

const P = loadParams();
const genesis = { network: 'regtest' as const, seatCount: 3, bankReserve: 1_000_000 };

// These tests exercise reconstruction in isolation, so they opt OUT of the now-MANDATORY
// key-lifecycle manifest gate (the production audit requires manifests — proven by the
// manifest tests at the bottom). `auditR` = audit without the manifest requirement.
const auditR = (t: GameTranscript): ReturnType<typeof audit> => audit(t, { requireManifests: false });

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
  const r = auditR(t);
  assert.ok(r.ok, r.reason);
  assert.ok(r.rollsVerified > 0, 'rolls were verified against the beacon');
  assert.equal(r.finalHash, t.finalHash);
});

test('audit is deterministic / independent (re-audit gives the same hash)', () => {
  const t = record();
  assert.equal(auditR(t).finalHash, auditR(t).finalHash);
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
  const r = auditR(withEntries(t, entries));
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
  const r = auditR(withEntries(t, entries));
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
  const r = auditR(withEntries(t, entries));
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
  const r = auditR(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /no prior commitment|non-live/);
});

test('a duplicate reveal seat is rejected', () => {
  const t = record();
  const i = firstIndex(t, 'roll');
  const e = t.entries[i] as Extract<Entry, { kind: 'roll' }>;
  const entries = [...t.entries];
  entries[i] = { ...e, reveals: [...e.reveals, e.reveals[0]!] };
  const r = auditR(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /duplicate reveal/);
});

test('an illegal action is rejected', () => {
  const t = record();
  const i = firstIndex(t, 'action');
  const entries = [...t.entries];
  entries[i] = { kind: 'action', action: { type: 'UNMORTGAGE', propertyId: 1 } }; // illegal at this point
  const r = auditR(withEntries(t, entries));
  assert.equal(r.ok, false);
  assert.match(r.reason, /illegal action|rejected/);
});

test('a wrong final hash is rejected', () => {
  const t = record();
  const r = auditR({ ...t, finalHash: '0'.repeat(64) });
  assert.equal(r.ok, false);
  assert.match(r.reason, /final state hash mismatch/);
});

test('a params-version mismatch is rejected', () => {
  const t = record();
  const r = auditR({ ...t, params_version: 'estates.v999' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /params version/);
});

// ---- a transcript reconstructed "from chain alone" is UNTRUSTED: audit is total --
test('audit is FAIL-CLOSED on hostile transcripts (bad genesis, bad hex, non-arrays) — never throws or OOMs', () => {
  const good = record();
  for (const bad of [
    null, undefined, {}, 42,
    { ...good, genesis: { network: 'regtest', seatCount: 1_000_000_000, bankReserve: 0 } }, // 1e9 seats: must NOT allocate
    { ...good, genesis: { network: 'regtest', seatCount: 0, bankReserve: 0 } },
    { ...good, genesis: { network: 'evil', seatCount: 3, bankReserve: 0 } },
    { ...good, genesis: null },
    { ...good, entries: 'notarray' },
    { ...good, entries: [{ kind: 'roll', commits: 'x', reveals: [], dice: [1, 1] }] },
    { ...good, entries: [{ kind: 'roll', commits: [{ seat: 0, c: 'zz' }], reveals: [], dice: [1, 1] }] }, // bad hex → fromHex throws
    { ...good, entries: [{ kind: 'action', action: { type: '__proto__' } }] },
    { ...good, entries: [{ kind: 'bogus' }] },
  ]) {
    let r: unknown = 'unset';
    assert.doesNotThrow(() => { r = auditR(bad as unknown as GameTranscript); });
    assert.equal((r as { ok: boolean }).ok, false, `rejected: ${JSON.stringify(bad)?.slice(0, 40)}`);
  }
  // the genuine transcript still verifies (regression)
  assert.ok(auditR(good).ok);
});

test('audit is FUZZ-PROOF: 20k mutated transcripts never throw', () => {
  const good = record();
  let rng = 0x6c1e9a3f >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  for (let i = 0; i < 20_000; i++) {
    const t: GameTranscript = { ...good };
    const m = rand() % 4;
    if (m === 0) (t as { genesis: unknown }).genesis = { network: 'regtest', seatCount: (rand() % 2_000_000_000), bankReserve: rand() };
    else if (m === 1) (t as { entries: unknown }).entries = [{ kind: 'roll', commits: [{ seat: rand() % 99, c: (rand() % 2 ? 'zz' : 'ab') }], reveals: [], dice: [rand() % 12, rand() % 12] }];
    else if (m === 2) (t as { entries: unknown }).entries = (rand() % 2 ? 'x' : null);
    else (t as { finalHash: unknown }).finalHash = String(rand());
    assert.doesNotThrow(() => { auditR(t); });
  }
});

// ---- KEY-LIFECYCLE folded into a full game audit (audit verifies key lifecycle) --
import { genIdentity } from '@estates/channel';
import { buildManifest, hashHex, type KeyEntry } from '@estates/keylife';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const PH = hashHex(new TextEncoder().encode('estates.v1'));
function gameManifest(gameId: string, sharedSeat0?: string) {
  const auth = genIdentity(); const s0 = genIdentity(); const s1 = genIdentity();
  const entries: KeyEntry[] = [
    { purpose: 'genesis', pub: hx(auth.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: sharedSeat0 ?? hx(s0.signPub), keyType: 'ed25519', seat: 0 },
    { purpose: 'seat', pub: hx(s1.signPub), keyType: 'ed25519', seat: 1 },
  ];
  return buildManifest(gameId, 'estates-1', PH, entries, auth.signPriv, hx(auth.signPub));
}

test('a full game audit PASSES with fresh per-game key manifests supplied', () => {
  const t = record();
  const manifests = [gameManifest('a1'.repeat(32)), gameManifest('b2'.repeat(32))];
  const r = audit(t, { manifests });
  assert.ok(r.ok, r.reason);
});

test('the SAME game transcript FAILS the audit when its key manifests reuse a key across games', () => {
  const t = record();
  const shared = hx(genIdentity().signPub);
  const manifests = [gameManifest('a1'.repeat(32), shared), gameManifest('b2'.repeat(32), shared)]; // reuse seat-0 key
  const r = audit(t, { manifests });
  assert.equal(r.ok, false);
  assert.match(r.reason, /key lifecycle/i);
});
