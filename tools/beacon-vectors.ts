// Emit dice-beacon VECTORS from @estates/beacon so the native C# Beacon port can be
// cross-validated: same commit/reveal set -> same dice + chained beacon, and a
// reveal that doesn't open its commitment is rejected.
import { writeFileSync } from 'node:fs';
import { commit, verifyRollEntry, ZERO_BEACON } from '../packages/beacon/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const secret = (seat: number, salt: number) => { const b = new Uint8Array(32); b[0] = seat; b[1] = salt; for (let i = 2; i < 32; i++) b[i] = (seat * 31 + salt * 7 + i) & 0xff; return b; };

function entry(turnIndex: number, prevBeacon: Uint8Array, salt: number) {
  const s0 = secret(0, salt), s1 = secret(1, salt);
  const commits = [{ seat: 0, c: commit(s0) }, { seat: 1, c: commit(s1) }];
  const reveals = [{ seat: 0, secret: s0 }, { seat: 1, secret: s1 }];
  const r = verifyRollEntry({ commits, reveals, liveSeats: [0, 1], turnIndex, prevBeacon });
  return { commits, reveals, r, prevBeacon };
}

const e0 = entry(0, ZERO_BEACON, 5);
const e1 = entry(1, e0.r.beacon!, 9); // chained: prevBeacon = the previous roll's beacon

// a tampered reveal (wrong secret) → must FAIL verify
const badReveal = [{ seat: 0, secret: secret(0, 99) }, { seat: 1, secret: secret(1, 5) }];
const eBad = verifyRollEntry({ commits: e0.commits, reveals: badReveal, liveSeats: [0, 1], turnIndex: 0, prevBeacon: ZERO_BEACON });

const enc = (e: ReturnType<typeof entry>) => ({
  turnIndex: e.reveals === e0.reveals ? 0 : 1,
  prevBeacon: hx(e.prevBeacon),
  commits: e.commits.map((c) => ({ seat: c.seat, c: hx(c.c) })),
  reveals: e.reveals.map((r) => ({ seat: r.seat, secret: hx(r.secret) })),
  liveSeats: [0, 1],
  expectOk: e.r.ok,
  expectedDice: e.r.dice,
  expectedBeacon: hx(e.r.beacon!),
});

const vectors = {
  rolls: [enc(e0), { ...enc(e1), turnIndex: 1 }],
  bad: {
    commits: e0.commits.map((c) => ({ seat: c.seat, c: hx(c.c) })),
    reveals: badReveal.map((r) => ({ seat: r.seat, secret: hx(r.secret) })),
    liveSeats: [0, 1], turnIndex: 0, prevBeacon: hx(ZERO_BEACON), expectOk: eBad.ok,
  },
};

const path = 'apps/native/Estates.Conformance/beacon-vectors.json';
writeFileSync(path, JSON.stringify(vectors, null, 2));
console.log(`wrote ${path}: ${vectors.rolls.length} rolls + 1 negative; dice e0=${e0.r.dice} e1=${e1.r.dice} bad.ok=${eBad.ok}`);
