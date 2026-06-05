import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadParams } from '@estates/params';
import type { GameState, Action } from '@estates/engine';
import { recordGame, type GameTranscript } from '@estates/audit';
import { InMemoryRelay, PeerSession, broadcast, decodeEnvelope } from '../src/index.ts';

const P = loadParams();
const genesis = { network: 'regtest' as const, seatCount: 3, bankReserve: 1_000_000 };

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
const game = (): GameTranscript => recordGame(genesis, decide, secret, 4000);

test('network determinism: all connected peers converge to the recorded final state', () => {
  const t = game();
  const relay = new InMemoryRelay();
  const a = new PeerSession(genesis); a.join(relay);
  const b = new PeerSession(genesis); b.join(relay);

  t.entries.forEach((entry, seq) => broadcast(relay, seq, entry));

  assert.equal(a.hash(), t.finalHash, 'peer A converged');
  assert.equal(b.hash(), t.finalHash, 'peer B converged');
  assert.equal(a.hash(), b.hash());
});

test('reconnection: a peer joining late replays history and reaches the same state', () => {
  const t = game();
  const relay = new InMemoryRelay();
  // publish the whole game with no one listening yet
  t.entries.forEach((entry, seq) => broadcast(relay, seq, entry));
  // late peer subscribes -> SSE catch-up replays all of history
  const late = new PeerSession(genesis); late.join(relay);
  assert.equal(late.hash(), t.finalHash);
});

test('an out-of-order envelope is not applied (waits for order)', () => {
  const t = game();
  const relay = new InMemoryRelay();
  const peer = new PeerSession(genesis);
  // hand it seq 5 before seq 0 — must be ignored
  broadcast(relay, 5, t.entries[5]!);
  const before = peer.hash();
  // (peer hasn't joined; feed directly)
  const env = relay.history()[0]!;
  assert.equal(peer.ingest(env), false);
  assert.equal(peer.hash(), before, 'state unchanged on gap');
});

test('a forged roll from the relay is rejected; state cannot be corrupted', () => {
  const t = game();
  const peer = new PeerSession(genesis);
  // find the first roll entry, tamper its claimed dice, feed at the right seq
  const idx = t.entries.findIndex((e) => e.kind === 'roll');
  // apply the legitimate entries up to idx
  const relay = new InMemoryRelay();
  for (let i = 0; i < idx; i++) broadcast(relay, i, t.entries[i]!);
  relay.history().forEach((p) => peer.ingest(p));
  const before = peer.hash();
  const e = t.entries[idx] as Extract<typeof t.entries[number], { kind: 'roll' }>;
  const forged = new TextEncoder().encode(JSON.stringify({ seq: idx, entry: { ...e, dice: [6, 6] } }));
  assert.equal(peer.ingest(forged), false);
  assert.equal(peer.hash(), before, 'forged roll did not advance state');
});

test('the relay is opaque: it stores/fans out bytes and never interprets them', () => {
  const relay = new InMemoryRelay();
  const seq = relay.publish(new TextEncoder().encode('arbitrary opaque bytes'));
  assert.equal(seq, 0);
  assert.equal(relay.history().length, 1);
});

// ---- relay is UNTRUSTED: ingest/decodeEnvelope are total + fuzz-proof ----------
const NE = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const H64 = 'ab'.repeat(32);

test('decodeEnvelope accepts a valid envelope and rejects hostile payloads', () => {
  assert.ok(decodeEnvelope(NE({ seq: 0, entry: { kind: 'action', action: { type: 'END_TURN' } } })));
  assert.ok(decodeEnvelope(NE({ seq: 5, entry: { kind: 'roll', commits: [{ seat: 0, c: H64 }], reveals: [{ seat: 0, secret: H64 }], dice: [3, 4] } })));
  for (const bad of [
    new Uint8Array(0), new Uint8Array([0xff, 0x00]), NE(null), NE(42), NE('x'), NE([]),
    NE({ seq: -1, entry: { kind: 'action', action: { type: 'BUY' } } }),
    NE({ seq: 1e12, entry: { kind: 'action', action: { type: 'BUY' } } }),
    NE({ seq: 0, entry: { kind: 'evil' } }),
    NE({ seq: 0, entry: { kind: 'action', action: { type: '__proto__' } } }),
    NE({ seq: 0, entry: { kind: 'action', action: { type: 'ROLL', dice: [9, 9] } } }),
    NE({ seq: 0, entry: { kind: 'roll', commits: 'notarray', reveals: [], dice: [1, 1] } }),
    NE({ seq: 0, entry: { kind: 'roll', commits: [{ seat: 0, c: 'zz' }], reveals: [], dice: [1, 1] } }), // bad hex → fromHex would throw
    NE({ seq: 0, entry: { kind: 'roll', commits: Array.from({ length: 99 }, () => ({ seat: 0, c: H64 })), reveals: [], dice: [1, 1] } }), // oversized
  ]) assert.equal(decodeEnvelope(bad), null);
});

test('a HOSTILE relay payload never crashes ingest and never advances state', () => {
  const peer = new PeerSession(genesis);
  const before = peer.hash();
  for (const bad of [
    new Uint8Array([1, 2, 3]), NE('x'), NE({ seq: 0, entry: { kind: 'roll', commits: [{ seat: 0, c: 'zz' }], reveals: [], dice: [1, 1] } }),
    NE({ seq: 0, entry: { kind: 'action', action: { type: 'EVIL' } } }), NE({ seq: 1e15, entry: null }),
  ]) assert.doesNotThrow(() => assert.equal(peer.ingest(bad), false));
  assert.equal(peer.hash(), before, 'no hostile payload advanced state');
});

test('a hostile relay payload in the fan-out never breaks delivery to honest peers', () => {
  const relay = new InMemoryRelay();
  const peer = new PeerSession(genesis);
  let crashed = false;
  relay.subscribe(() => { throw new Error('a malicious subscriber'); });   // a bad subscriber
  relay.subscribe((p) => { try { peer.ingest(p); } catch { crashed = true; } });
  assert.doesNotThrow(() => relay.publish(NE({ seq: 99, entry: { kind: 'evil' } }))); // bad subscriber isolated
  assert.equal(crashed, false);
});

test('decodeEnvelope is FUZZ-PROOF: 100k random payloads never throw or hang', () => {
  let rng = 0x51ed270b >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const t0 = Date.now();
  for (let i = 0; i < 100_000; i++) {
    const len = rand() % 200; const b = new Uint8Array(len);
    for (let k = 0; k < len; k++) b[k] = rand() & 0xff;
    let out: unknown = 'unset';
    assert.doesNotThrow(() => { out = decodeEnvelope(b); });
    assert.ok(out === null || typeof out === 'object');
  }
  assert.ok(Date.now() - t0 < 8000, 'bounded work — no hang');
});
