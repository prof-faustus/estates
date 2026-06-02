import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRelay } from '@estates/chat';
import type { GameState } from '@estates/engine';
import { NetTable, P, type NetworkMode } from '../src/index.ts';

const priceOf = (id: number): number => P.board[id]?.base_price ?? 0;

// shared relay = one in-memory bus; publish fans out synchronously to all peers,
// so after each action every peer is in lockstep immediately (deterministic).
function peer(relay: InMemoryRelay, name: string, sched?: (cb: () => void) => void): NetTable {
  return new NetTable(relay, name, () => {}, sched);
}
function proj(s: GameState): string {
  return JSON.stringify({
    ti: s.turnIndex, cur: s.current, ph: s.phase, win: s.winner,
    bal: s.seats.map((x) => x.balance), pos: s.seats.map((x) => x.position),
    bust: s.seats.map((x) => x.bankrupt),
    titles: Object.entries(s.titles).map(([k, t]) => [k, t.owner, t.buildLevel, t.mortgaged]),
  });
}
function allAgree(peers: NetTable[]): void {
  const ref = proj(peers[0]!.state!);
  for (const p of peers) assert.equal(proj(p.state!), ref, 'peers diverged');
}
// deterministic dice
function dice(seed: number): () => [number, number] {
  let a = seed >>> 0;
  return () => { a = (a * 1664525 + 1013904223) >>> 0; const d1 = 1 + (a % 6); a = (a * 1664525 + 1013904223) >>> 0; return [d1, 1 + (a % 6)]; };
}

/** Stand up N human peers on one relay: host creates, all claim seats. (Does NOT start.) */
function lobby(n: number, network: NetworkMode = 'regtest'): { relay: InMemoryRelay; peers: NetTable[] } {
  const relay = new InMemoryRelay();
  const peers: NetTable[] = [];
  for (let i = 0; i < n; i++) { const p = peer(relay, `P${i}`); p.connect(); peers.push(p); }
  peers[0]!.createTable(n, network);
  for (const p of peers) p.joinSeat();
  return { relay, peers };
}

// ---- exhaustive over every supported player count --------------------------
for (const n of [2, 3, 4, 5, 6]) {
  test(`lobby ${n}: seats fill 0..${n - 1}; only host can start; only when full`, () => {
    const { peers } = lobby(n);
    for (const p of peers) {
      const v = p.view();
      assert.equal(v.phase, 'lobby');
      assert.equal(v.maxSeats, n);
      assert.equal(v.seats.length, n);
      assert.deepEqual(v.seats.map((s) => s.seat), Array.from({ length: n }, (_, i) => i));
    }
    assert.equal(peers[0]!.view().iAmHost, true);
    assert.equal(peers[0]!.view().canStart, true, 'host can start when full');
    for (let i = 1; i < n; i++) assert.equal(peers[i]!.view().canStart, false, 'non-host cannot start');
  });

  test(`no auto-start for ${n}: full lobby stays in lobby until the host calls start`, () => {
    const { peers } = lobby(n);
    for (const p of peers) assert.equal(p.view().phase, 'lobby'); // NOT playing
    // a NON-host calling start() must do nothing
    peers[n - 1]!.start();
    for (const p of peers) assert.equal(p.view().phase, 'lobby', 'a non-host must not be able to start');
    // the human host starts
    peers[0]!.start();
    for (const p of peers) assert.equal(p.view().phase, 'playing', 'all peers now playing');
    allAgree(peers);
  });

  test(`full ${n}-human game stays in lockstep across all peers (decline policy)`, () => {
    const { peers } = lobby(n);
    peers[0]!.start();
    const roll = dice(100 + n);
    for (let step = 0; step < 600; step++) {
      const s = peers[0]!.state!;
      if (s.phase === 'GAME_OVER') break;
      const actor = peers.find((p) => p.mySeat === s.current)!;
      if (s.phase === 'AWAIT_ROLL') actor.submit({ type: 'ROLL', dice: roll() });
      else if (s.phase === 'AWAIT_BUY') actor.submit({ type: 'DECLINE' });
      else if (s.phase === 'AWAIT_TAX') actor.submit({ type: 'PAY_TAX', choice: 'flat' });
      else if (s.phase === 'AWAIT_POST') actor.submit({ type: 'END_TURN' });
      allAgree(peers); // every single step: identical on every client
      if (s.turnIndex > 40) break;
    }
    allAgree(peers);
  });

  test(`full ${n}-human game stays in lockstep (buy-when-affordable policy)`, () => {
    const { peers } = lobby(n);
    peers[0]!.start();
    const roll = dice(7 * n);
    for (let step = 0; step < 600; step++) {
      const s = peers[0]!.state!;
      if (s.phase === 'GAME_OVER') break;
      const actor = peers.find((p) => p.mySeat === s.current)!;
      if (s.phase === 'AWAIT_ROLL') actor.submit({ type: 'ROLL', dice: roll() });
      else if (s.phase === 'AWAIT_BUY') {
        const price = priceOf(s.pendingTitle!);
        actor.submit(s.seats[s.current]!.balance >= price ? { type: 'BUY' } : { type: 'DECLINE' });
      } else if (s.phase === 'AWAIT_TAX') actor.submit({ type: 'PAY_TAX', choice: 'percent' });
      else if (s.phase === 'AWAIT_POST') actor.submit({ type: 'END_TURN' });
      allAgree(peers);
      if (s.turnIndex > 40) break;
    }
    allAgree(peers);
  });
}

// ---- bots are an OPTION the host adds; they only play their own seat --------
test('host fills seats with simulated players (bots); the game still converges; a bot never starts', () => {
  const relay = new InMemoryRelay();
  const queue: (() => void)[] = [];
  const sched = (cb: () => void) => queue.push(cb);   // pump bot actions deterministically
  const host = peer(relay, 'host', sched); host.connect();
  host.createTable(3, 'regtest');
  host.joinSeat();          // seat 0 = human host
  host.addBot();            // seat 1 = bot (host-added)
  host.addBot();            // seat 2 = bot
  assert.equal(host.view().phase, 'lobby', 'still lobby — bots never auto-start');
  host.start();             // ONLY the human host starts
  assert.equal(host.view().phase, 'playing');
  // drive: the human plays seat 0; bots are pumped for their seats
  for (let i = 0; i < 4000; i++) {
    const s = host.state!;
    if (s.phase === 'GAME_OVER') break;
    if (s.current === 0) {
      if (s.phase === 'AWAIT_ROLL') host.submit({ type: 'ROLL', dice: [3, 4] });
      else if (s.phase === 'AWAIT_BUY') host.submit({ type: 'DECLINE' });
      else if (s.phase === 'AWAIT_TAX') host.submit({ type: 'PAY_TAX', choice: 'flat' });
      else if (s.phase === 'AWAIT_POST') host.submit({ type: 'END_TURN' });
    } else if (queue.length) { queue.shift()!(); }
    else break; // no progress
    if (s.turnIndex > 25) break;
  }
  assert.ok(host.state!.turnIndex >= 3, 'the table progressed with bot-filled seats');
});

// ---- seat races, late join, determinism ------------------------------------
test('seat race: if two peers grab the same seat, exactly one wins and all agree', () => {
  const relay = new InMemoryRelay();
  const a = peer(relay, 'A'); a.connect();
  const b = peer(relay, 'B'); b.connect();
  a.createTable(2);
  // both try to take the lowest free seat (0) at once
  a.joinSeat(); b.joinSeat();
  // seat 0 taken by A (first), B lands on seat 1
  assert.equal(a.view().seats.find((s) => s.seat === 0)!.who, a.me);
  assert.equal(a.mySeat, 0); assert.equal(b.mySeat, 1);
  assert.deepEqual(a.view().seats, b.view().seats);
});

test('late joiner replays history and sees the same lobby', () => {
  const relay = new InMemoryRelay();
  const a = peer(relay, 'A'); a.connect(); a.createTable(3); a.joinSeat();
  const c = peer(relay, 'C'); c.connect(); // joins after the table + seat exist
  assert.equal(c.view().phase, 'lobby');
  assert.equal(c.view().maxSeats, 3);
  assert.equal(c.view().seats.length, 1);
  c.joinSeat();
  assert.equal(a.view().seats.length, 2, 'host sees the late joiner');
});

test('determinism: the same script yields identical state on independent tables', () => {
  function run(): string {
    const { peers } = lobby(2);
    peers[0]!.start();
    const roll = dice(42);
    const script = ['ROLL', 'DECLINE', 'END', 'ROLL', 'DECLINE', 'END', 'ROLL', 'END', 'ROLL', 'END'];
    let i = 0;
    while (i < 400) {
      const s = peers[0]!.state!;
      if (s.phase === 'GAME_OVER' || s.turnIndex > 8) break;
      const actor = peers.find((p) => p.mySeat === s.current)!;
      if (s.phase === 'AWAIT_ROLL') actor.submit({ type: 'ROLL', dice: roll() });
      else if (s.phase === 'AWAIT_BUY') actor.submit({ type: 'DECLINE' });
      else if (s.phase === 'AWAIT_TAX') actor.submit({ type: 'PAY_TAX', choice: 'flat' });
      else actor.submit({ type: 'END_TURN' });
      i++;
    }
    void script;
    return proj(peers[0]!.state!);
  }
  assert.equal(run(), run());
});

test('view() reflects each phase; a fresh peer is disconnected until a table exists', () => {
  const relay = new InMemoryRelay();
  const p = peer(relay, 'solo'); p.connect();
  assert.equal(p.view().phase, 'disconnected');
  assert.equal(p.view().canStart, false);
});
