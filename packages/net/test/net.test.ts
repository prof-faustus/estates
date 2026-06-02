import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadParams } from '@estates/params';
import type { GameState, Action } from '@estates/engine';
import { recordGame, type GameTranscript } from '@estates/audit';
import { InMemoryRelay, PeerSession, broadcast } from '../src/index.ts';

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
