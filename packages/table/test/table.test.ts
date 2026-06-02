import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRelay } from '@estates/chat';
import { initialState, type GameState } from '@estates/engine';
import {
  NetTable, P, LobbyClient, buildable, mortgageable, unmortgageable, lastCard, newAddress,
  type NetworkMode,
} from '../src/index.ts';

function own(ids: number[], owner: number): GameState {
  const s = initialState({ network: 'regtest', seatCount: 2, bankReserve: 1_000_000 });
  const titles = { ...s.titles };
  for (const id of ids) titles[id] = { ...titles[id]!, owner };
  return { ...s, titles, phase: 'AWAIT_POST' };
}

const priceOf = (id: number): number => P.board[id]?.base_price ?? 0;

// shared relay = one in-memory bus; publish fans out synchronously to all peers,
// so after each action every peer is in lockstep immediately (deterministic).
function peer(relay: InMemoryRelay, name: string, opts?: { autoPlay?: boolean; scheduleBot?: (cb: () => void) => void }): NetTable {
  return new NetTable(relay, name, () => {}, opts);
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

// ---- a bot is a SEPARATE remote player (own peer) connected over the relay ---
// It is NOT controlled from anyone's app (that would be a cheat): it is its own
// NetTable running in auto-play, it claims its own seat, and it plays ONLY that
// seat. Here the human host shares ONE relay (bus) with the simulated player,
// exactly as a second window/daemon would over a real socket.
test('a separate simulated player (its own auto-play peer) joins over the relay and plays only its own seat; the human still starts', () => {
  const relay = new InMemoryRelay();
  const queue: (() => void)[] = [];
  const sched = (cb: () => void) => queue.push(cb);   // pump the bot peer deterministically
  const host = peer(relay, 'host'); host.connect();                          // the human
  const bot = peer(relay, 'sim', { autoPlay: true, scheduleBot: sched });    // a separate remote peer
  bot.connect();
  host.createTable(2, 'regtest');
  host.joinSeat();          // seat 0 = human host
  bot.joinSeat(true);       // seat 1 = the simulated player claims its OWN seat over the relay

  assert.equal(host.view().seats.length, 2, 'both peers claimed seats');
  assert.equal(host.view().seats[1]!.bot, true, 'seat 1 is flagged as a simulated player');
  assert.equal(bot.view().phase, 'lobby', 'still lobby — a bot NEVER starts the game');
  host.start();             // ONLY the human host starts
  assert.equal(host.view().phase, 'playing');
  assert.equal(bot.view().phase, 'playing', 'the simulated peer follows the start over the relay');

  // drive: the human plays seat 0; the bot peer auto-plays seat 1 via its own queue
  for (let i = 0; i < 6000; i++) {
    const s = host.state!;
    if (s.phase === 'GAME_OVER') break;
    if (s.current === 0) {
      if (s.phase === 'AWAIT_ROLL') host.submit({ type: 'ROLL', dice: [3, 4] });
      else if (s.phase === 'AWAIT_BUY') host.submit({ type: 'DECLINE' });
      else if (s.phase === 'AWAIT_TAX') host.submit({ type: 'PAY_TAX', choice: 'flat' });
      else if (s.phase === 'AWAIT_POST') host.submit({ type: 'END_TURN' });
    } else if (queue.length) { queue.shift()!(); }  // the bot's own scheduled move fires
    else break; // no progress
    if (s.turnIndex > 25) break;
  }
  assert.ok(host.state!.turnIndex >= 3, 'the table progressed with a separate simulated player');
  // both peers stay in lockstep — the bot is a real remote participant, not a local puppet
  assert.equal(JSON.stringify(host.state), JSON.stringify(bot.state), 'host and bot peer agree on state');
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

// ---- houses & hotels (build), mortgage, cards, Bitmessage-style discovery ----
test('buildable: full group only, even-build; building advances the level', () => {
  let s = own([6, 8, 9], 0);                 // full Sky group
  assert.deepEqual(buildable(s, 0).sort((a, b) => a - b), [6, 8, 9]);
  assert.deepEqual(buildable(s, 1), []);     // seat 1 owns nothing
  s = { ...s, titles: { ...s.titles, 6: { ...s.titles[6]!, buildLevel: 1 } } };
  assert.deepEqual(buildable(s, 0).sort((a, b) => a - b), [8, 9], 'even-build: only the lagging members');
  // a partial group is never buildable
  assert.deepEqual(buildable(own([6, 8], 0), 0), []);
});

test('mortgageable / unmortgageable reflect ownership + state', () => {
  const s = own([1, 3], 0);
  assert.deepEqual(mortgageable(s, 0).sort((a, b) => a - b), [1, 3]);
  assert.deepEqual(unmortgageable(s, 0), []);
  const m = { ...s, titles: { ...s.titles, 1: { ...s.titles[1]!, mortgaged: true } } };
  assert.deepEqual(unmortgageable(m, 0), [1]);
  assert.deepEqual(mortgageable(m, 0), [3]);
});

test('lastCard surfaces the most recent Fate/Treasury draw for the table', () => {
  const s = initialState({ network: 'regtest', seatCount: 2, bankReserve: 1000 });
  assert.equal(lastCard(s), null);
  const withCard = { ...s, log: [...s.log, 'seat 1 draws Treasury: A bequest arrives. Collect 125.'] };
  assert.equal(lastCard(withCard), 'Treasury — A bequest arrives. Collect 125.');
});

test('newAddress: distinct 40-hex Bitmessage-style addresses', () => {
  const a = newAddress(); const b = newAddress();
  assert.match(a, /^[0-9a-f]{40}$/);
  assert.notEqual(a, b);
});

test('Bitmessage-style lobby discovery: a host announce is listed by other clients (no URL)', () => {
  const relay = new InMemoryRelay();          // the built-in transport — no URL typed
  const host = new LobbyClient(relay, () => {});
  const guest = new LobbyClient(relay, () => {});
  host.connect(); guest.connect();
  const addr = newAddress();
  host.announce({ addr, name: 'Tav', maxSeats: 4, network: 'regtest', host: 'h', ts: 1 });
  assert.equal(guest.list().length, 1);
  assert.equal(guest.list()[0]!.addr, addr);
  assert.equal(guest.list()[0]!.maxSeats, 4);
});
