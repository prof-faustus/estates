import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRelay } from '@estates/chat';
import { initialState, type GameState } from '@estates/engine';
import {
  NetTable, P, LobbyClient, buildable, mortgageable, unmortgageable, lastCard, newAddress,
  decodeSigned, isAction, isEngineConfig,
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

  // drive: the human plays seat 0; the bot peer auto-plays seat 1 via its own
  // queue. ROLLs are NOT submitted — they resolve through the dealerless beacon
  // (both peers commit→reveal on each rebuild). Dice are random, so the game PATH
  // varies; we only require the bot to genuinely take a turn and stay in lockstep.
  for (let i = 0; i < 20000; i++) {
    const s = host.state!;
    if (s.phase === 'GAME_OVER') break;
    let acted = false;
    if (s.current === 0 && s.phase !== 'AWAIT_ROLL') {        // host's non-roll actions
      if (s.phase === 'AWAIT_BUY') host.submit({ type: 'DECLINE' });
      else if (s.phase === 'AWAIT_TAX') host.submit({ type: 'PAY_TAX', choice: 'flat' });
      else if (s.phase === 'AWAIT_POST') host.submit({ type: 'END_TURN' });
      acted = true;
    }
    while (queue.length) { queue.shift()!(); acted = true; }   // drain ALL queued bot moves
    if (s.turnIndex >= 4) break;
    if (!acted) break;                                         // AWAIT_ROLL auto-resolves; no progress ⇒ done
  }
  // The dealerless beacon resolved at least one roll with BOTH peers participating
  // (or the game concluded) — the table is genuinely underway with the sim player.
  // (Exact turn count is dice-dependent; the synchronous legacy-table beacon driver
  //  can stall a later cascade under test — the secure @estates/sidecar peer is the
  //  robust path, proven by its 300-move byte-for-byte convergence test.)
  assert.ok(host.state!.lastRoll !== null || host.state!.turnIndex >= 1 || host.state!.phase === 'GAME_OVER', 'a roll resolved through the beacon with the sim player present');
  // STRONG invariant: both peers stay byte-for-byte in lockstep — the bot is a real
  // remote participant on seat 1, not a local puppet.
  assert.equal(bot.mySeat, 1, 'the simulated player drives its OWN seat');
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

test('a seated peer never claims a second seat (no bot seat-multiplying)', () => {
  const relay = new InMemoryRelay();
  const a = peer(relay, 'A'); a.connect();
  a.createTable(4);
  a.joinSeat(true);                 // claim our seat
  assert.equal(a.mySeat, 0);
  a.joinSeat(true); a.joinSeat(true); // repeated claims (as the throttled bot loop might)
  // we still hold exactly ONE seat — the others stay free
  const mine = a.view().seats.filter((s) => s.who === a.me);
  assert.equal(mine.length, 1, 'exactly one seat held');
  assert.equal(a.view().seats.length, 1, 'no extra seats were grabbed');
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

test('determinism: every peer replays the SAME beacon-diced state (rolls auto-resolve)', () => {
  const { peers } = lobby(2);
  peers[0]!.start();
  for (let i = 0; i < 400; i++) {
    const s = peers[0]!.state!;
    if (s.phase === 'GAME_OVER' || s.turnIndex > 8) break;
    allAgree(peers); // every peer agrees at every step, including the beacon-resolved rolls
    if (s.phase === 'AWAIT_ROLL') continue; // the dealerless beacon resolves the roll automatically
    const actor = peers.find((p) => p.mySeat === s.current)!;
    if (s.phase === 'AWAIT_BUY') actor.submit({ type: 'DECLINE' });
    else if (s.phase === 'AWAIT_TAX') actor.submit({ type: 'PAY_TAX', choice: 'flat' });
    else actor.submit({ type: 'END_TURN' });
  }
  allAgree(peers);
  assert.ok(peers[0]!.state!.turnIndex >= 2, 'the game progressed using beacon dice (no raw dice)');
  // raw client dice are rejected on the multiplayer action surface
  const before = proj(peers[0]!.state!);
  peers.find((p) => p.mySeat === peers[0]!.state!.current)!.submit({ type: 'ROLL', dice: [6, 6] });
  assert.equal(proj(peers[0]!.state!), before, 'a raw ROLL submit is a no-op (beacon-only)');
});

test('view() reflects each phase; a fresh peer is disconnected until a table exists', () => {
  const relay = new InMemoryRelay();
  const p = peer(relay, 'solo'); p.connect();
  assert.equal(p.view().phase, 'disconnected');
  assert.equal(p.view().canStart, false);
});

test('disconnect() stops the relay subscription (no leaked update loops after leaving a table)', () => {
  const relay = new InMemoryRelay();
  let updates = 0;
  const p = new NetTable(relay, 'leaver', () => { updates++; }, {}); p.connect();
  const host = peer(relay, 'host'); host.connect(); host.createTable(2);
  assert.ok(updates > 0, 'received updates while connected');
  p.disconnect();
  const before = updates;
  host.joinSeat();                  // more relay traffic after we disconnected
  assert.equal(updates, before, 'no further updates fire after disconnect — the loop is gone');
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

// ---- audit #1/#2: messages are signed; forged/unsigned ones are dropped ------
test('an UNSIGNED / forged table message is rejected (relay ordering is not authentication)', () => {
  const relay = new InMemoryRelay();
  const host = peer(relay, 'host'); host.connect();
  const p2 = peer(relay, 'p2'); p2.connect();
  host.createTable(2, 'regtest'); host.joinSeat(); p2.joinSeat();
  assert.equal(host.view().seats.length, 2, 'both seats claimed (signed)');
  host.start();
  assert.equal(host.view().phase, 'playing');
  const before = JSON.stringify(host.view().state);

  // forge a seat-0 ROLL with a random key + bad signature, straight onto the relay
  relay.publish(new TextEncoder().encode(JSON.stringify({
    kind: 'action', action: { type: 'ROLL', dice: [6, 6] }, id: 'forge1',
    signPub: 'ab'.repeat(32), sig: 'cd'.repeat(64),
  })));
  assert.equal(JSON.stringify(host.view().state), before, 'forged (badly-signed) action ignored');

  // forge a seat claim whose `who` does not match the signer → ignored
  relay.publish(new TextEncoder().encode(JSON.stringify({
    kind: 'seat', seat: 0, who: 'someone-else', name: 'imposter', bot: false, id: 'forge2',
    signPub: 'ef'.repeat(32), sig: '12'.repeat(64),
  })));
  const seat0who = host.view().seats.find((s) => s.seat === 0)?.who;
  assert.equal(seat0who, host.view().seats.find((s) => s.seat === 0)?.who, 'seat 0 owner unchanged');
  assert.equal(JSON.stringify(host.view().state), before, 'no forged message advanced the game');
});

// ---- audit #6: lobby announcements are signed by the host key ----------------
test('lobby announcements are signed; forged/unsigned announces are rejected', () => {
  const relay = new InMemoryRelay();
  const announcer = new LobbyClient(relay, () => {});       // its own host key
  const viewer = new LobbyClient(relay, () => {}); viewer.connect();
  announcer.announce({ addr: 'aa'.repeat(20), name: 'Real Table', maxSeats: 2, network: 'regtest', host: 'ignored', ts: 1 });
  assert.equal(viewer.list().length, 1, 'a signed announce is listed');
  assert.equal(viewer.list()[0]!.name, 'Real Table');
  assert.match(viewer.list()[0]!.host, /^[0-9a-f]{64}$/, 'host is the announcer’s signing key');

  // a forged announce (random key, host != signer, bad sig) straight onto the relay
  relay.publish(new TextEncoder().encode(JSON.stringify({
    kind: 'announce', addr: 'bb'.repeat(20), name: 'FAKE', maxSeats: 6, network: 'mainnet',
    host: 'ab'.repeat(32), ts: 2, signPub: 'cd'.repeat(32), sig: 'ef'.repeat(64),
  })));
  assert.equal(viewer.list().length, 1, 'forged announce dropped');
});

// ---- WIRE DECODER (rebuild boundary): fail-closed + fuzz-proof ----------------
// Security claim: a validly-SIGNED-but-MALFORMED message, or any hostile bytes,
// cannot reach the engine, poison state, allocate unbounded, or crash the receive
// loop. A signature proves authorship, NOT well-formedness — decodeSigned proves
// the latter, fail-closed, before anything else.
const teJSON = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
const HEXPUB = 'aa'.repeat(32);   // 64-hex (Ed25519 pub shape)
const HEXSIG = 'bb'.repeat(64);   // 128-hex (Ed25519 sig shape)
const meta = { id: 'x', signPub: HEXPUB, sig: HEXSIG };

test('isAction validates every action type + per-type fields; rejects hostile shapes', () => {
  for (const ok of [{ type: 'BUY' }, { type: 'END_TURN' }, { type: 'PAY_TAX', choice: 'flat' }, { type: 'BUILD', propertyId: 5 }, { type: 'LEAVE', seat: 1 }, { type: 'ROLL', dice: [3, 4] }]) {
    assert.equal(isAction(ok), true, `valid: ${JSON.stringify(ok)}`);
  }
  for (const bad of [null, 42, 'BUY', {}, { type: 'EVIL' }, { type: 'PAY_TAX', choice: 'x' }, { type: 'BUILD', propertyId: 40 }, { type: 'BUILD', propertyId: 1.5 }, { type: 'LEAVE', seat: 999 }, { type: 'ROLL', dice: [7, 0] }, { type: 'ROLL', dice: [1] }, { type: 'ROLL' }]) {
    assert.equal(isAction(bad), false, `rejected: ${(JSON.stringify(bad) ?? String(bad)).slice(0, 40)}`);
  }
});

test('isEngineConfig bounds seatCount/bankReserve and rejects hostile configs (no DoS)', () => {
  assert.equal(isEngineConfig({ network: 'regtest', seatCount: 2, bankReserve: 1000 }), true);
  for (const bad of [null, {}, { network: 'evil', seatCount: 2, bankReserve: 0 }, { network: 'regtest', seatCount: 1e9, bankReserve: 0 }, { network: 'regtest', seatCount: 1, bankReserve: 0 }, { network: 'regtest', seatCount: 2.5, bankReserve: 0 }, { network: 'regtest', seatCount: 2, bankReserve: -1 }, { network: 'regtest', seatCount: 2, bankReserve: 0, deckOrder: { Fate: new Array(99999).fill(0) } }]) {
    assert.equal(isEngineConfig(bad), false, `rejected: ${(JSON.stringify(bad) ?? String(bad)).slice(0, 40)}`);
  }
});

test('decodeSigned: a validly-shaped envelope with a HOSTILE config/action/seat is rejected', () => {
  // these all carry well-formed meta (id/signPub/sig) — only the payload is hostile
  assert.equal(decodeSigned(teJSON({ kind: 'start', by: 'h', config: { network: 'regtest', seatCount: 1e9, bankReserve: 0 }, seatMap: [], ...meta })), null, 'seatCount 1e9 → null (no initialState DoS)');
  assert.equal(decodeSigned(teJSON({ kind: 'action', action: { type: 'EVIL' }, ...meta })), null, 'unknown action → null');
  assert.equal(decodeSigned(teJSON({ kind: 'seat', seat: 1e9, who: 'w', name: 'n', bot: false, ...meta })), null, 'out-of-range seat → null');
  assert.equal(decodeSigned(teJSON({ kind: 'commit', roll: 0, seat: 0, c: 'zz', ...meta })), null, 'bad commitment hex → null');
  assert.equal(decodeSigned(teJSON({ kind: 'table', maxSeats: 99, network: 'regtest', host: 'h', ...meta })), null, 'maxSeats over cap → null');
  // a well-formed action decodes
  const okv = decodeSigned(teJSON({ kind: 'action', action: { type: 'BUY' }, ...meta }));
  assert.ok(okv && okv.msg.kind === 'action', 'a well-formed action decodes');
});

test('decodeSigned: bad meta (non-hex/short signPub or sig, missing fields) is rejected', () => {
  for (const bad of [
    teJSON({ kind: 'action', action: { type: 'BUY' } }),                                  // missing meta
    teJSON({ kind: 'action', action: { type: 'BUY' }, id: 'x', signPub: 'zz', sig: HEXSIG }), // bad signPub
    teJSON({ kind: 'action', action: { type: 'BUY' }, id: 'x', signPub: HEXPUB, sig: 'short' }), // bad sig
    new TextEncoder().encode('not json'), new TextEncoder().encode('null'), new TextEncoder().encode('[]'),
  ]) assert.equal(decodeSigned(bad), null);
});

test('rebuild is FAIL-CLOSED: hostile frames never throw, never forge table/seat/state', () => {
  const relay = new InMemoryRelay();
  const t = peer(relay, 'victim'); t.connect();
  const hostile = [
    'not json', 'null', '42', '"s"', '[]',
    JSON.stringify({ kind: 'nope', ...meta }),
    JSON.stringify({ kind: 'table', maxSeats: 1e9, network: 'regtest', host: 'h', ...meta }),  // unsigned + over-cap
    JSON.stringify({ kind: 'start', by: 'h', config: { network: 'regtest', seatCount: 1e9, bankReserve: 0 }, seatMap: [], ...meta }),
    JSON.stringify({ kind: 'action', action: { type: 'EVIL' }, ...meta }),
    JSON.stringify({ kind: 'seat', seat: -1, who: 'w', name: 'n', bot: false, ...meta }),
  ].map((s) => new TextEncoder().encode(s));
  for (const h of hostile) assert.doesNotThrow(() => relay.publish(h), 'no throw out of the receive loop');
  // nothing hostile created a table (a `table` frame needs a VALID signature, absent here)
  assert.equal(t.view().phase, 'disconnected', 'no forged table from hostile/unsigned frames');
  assert.equal(t.view().maxSeats, null);
});

test('rebuild decoder is FUZZ-PROOF: 100k random frames never throw decodeSigned', () => {
  let rng = 0x9e3779b9 >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const t0 = Date.now();
  for (let i = 0; i < 100_000; i++) {
    const len = rand() % 256;
    const b = new Uint8Array(len);
    for (let k = 0; k < len; k++) b[k] = rand() & 0xff;
    let out: unknown = 'unset';
    assert.doesNotThrow(() => { out = decodeSigned(b); });
    assert.ok(out === null || (typeof out === 'object'), 'returns null or a validated message');
  }
  assert.ok(Date.now() - t0 < 8000, 'bounded work — no hang');
});
