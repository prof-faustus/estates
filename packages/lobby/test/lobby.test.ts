import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLobby, applyLobby, type LobbyState, type LobbyAction } from '../src/index.ts';
import { initialState } from '@estates/engine';

function run(s: LobbyState, actions: LobbyAction[]): LobbyState {
  let st = s;
  for (const a of actions) {
    const r = applyLobby(st, a);
    assert.ok(r.ok, `${a.type} failed: ${r.ok ? '' : r.code + ' ' + r.context}`);
    st = r.state;
  }
  return st;
}

const cfg = { network: 'regtest' as const, authority: 'host' };

test('join assigns the lowest free seat; double-join rejected; full lobby rejected', () => {
  let s = createLobby({ ...cfg, maxSeats: 2 });
  s = run(s, [{ type: 'JOIN', playerId: 'host' }, { type: 'JOIN', playerId: 'alice' }]);
  assert.deepEqual(s.seats.map((x) => x.seat), [0, 1]);
  assert.equal(applyLobby(s, { type: 'JOIN', playerId: 'host' }).ok, false);   // already joined
  const full = applyLobby(s, { type: 'JOIN', playerId: 'bob' });
  assert.ok(!full.ok && full.code === 'LOBBY_FULL');
});

test('only the authority may fill a bot, and the policy must be valid', () => {
  let s = createLobby(cfg);
  s = run(s, [{ type: 'JOIN', playerId: 'host' }]);
  assert.ok(!(applyLobby(s, { type: 'FILL_BOT', by: 'alice', policy: 'balanced' }).ok)); // not authority
  const bad = applyLobby(s, { type: 'FILL_BOT', by: 'host', policy: 'reckless' });
  assert.ok(!bad.ok && bad.code === 'BAD_POLICY');
  s = run(s, [{ type: 'FILL_BOT', by: 'host', policy: 'aggressive' }]);
  assert.equal(s.seats[1]!.kind, 'bot');
  assert.equal(s.seats[1]!.ready, true); // bots are ready
});

test('START requires authority, ≥2 seats, ≥1 human, and (non-override) all ready', () => {
  let s = createLobby(cfg);
  s = run(s, [{ type: 'JOIN', playerId: 'host' }]);
  // too few seats
  assert.ok(!(applyLobby(s, { type: 'START', by: 'host' }).ok));
  s = run(s, [{ type: 'FILL_BOT', by: 'host', policy: 'balanced' }]); // 1 human + 1 bot
  // human not ready yet -> non-override rejected
  const notReady = applyLobby(s, { type: 'START', by: 'host' });
  assert.ok(!notReady.ok && notReady.code === 'NOT_ALL_READY');
  // override start (1 human + bot) succeeds
  const over = applyLobby(s, { type: 'START', by: 'host', override: true });
  assert.ok(over.ok && over.state.started);
});

test('all-bots is rejected (need a human); non-authority START rejected', () => {
  let s = createLobby(cfg);
  s = run(s, [{ type: 'FILL_BOT', by: 'host', policy: 'cautious' }, { type: 'FILL_BOT', by: 'host', policy: 'balanced' }]);
  const noHuman = applyLobby(s, { type: 'START', by: 'host', override: true });
  assert.ok(!noHuman.ok && noHuman.code === 'NEED_A_HUMAN');
});

test('START emits an EngineConfig seeded by the banker buy-in — SAME model on regtest', () => {
  let s = createLobby(cfg);
  s = run(s, [
    { type: 'JOIN', playerId: 'host' }, { type: 'READY', playerId: 'host', ready: true },
    { type: 'FILL_BOT', by: 'host', policy: 'balanced' },
  ]);
  const r = applyLobby(s, { type: 'START', by: 'host' });
  assert.ok(r.ok); const g = r.state.genesis!;
  // NO auto-funding on ANY network — funded by the banker's real buy-in.
  assert.match(g.fundLog[0]!, /buy-in/);
  assert.doesNotMatch(g.fundLog[0]!, /auto-fund/);
  assert.equal(g.engineConfig.network, 'regtest');
  assert.equal(g.engineConfig.seatCount, 2);
  assert.ok(g.engineConfig.bankReserve > 0);
  // the emitted config actually seeds the engine
  const gs = initialState(g.engineConfig);
  assert.equal(gs.seats.length, 2);
  assert.equal(gs.bankReserve, g.engineConfig.bankReserve);
});

test('the funding model is IDENTICAL on regtest, testnet, and mainnet (no auto-fund anywhere)', () => {
  const fundLogs = (['regtest', 'testnet', 'mainnet'] as const).map((network) => {
    let s = createLobby({ network, authority: 'host' });
    s = run(s, [
      { type: 'JOIN', playerId: 'host' }, { type: 'READY', playerId: 'host', ready: true },
      { type: 'FILL_BOT', by: 'host', policy: 'balanced' },
    ]);
    const r = applyLobby(s, { type: 'START', by: 'host' });
    assert.ok(r.ok); const g = r.state.genesis!;
    assert.match(g.fundLog[0]!, /buy-in/);
    assert.doesNotMatch(g.fundLog[0]!, /auto-fund/);
    assert.equal(g.engineConfig.network, network);
    return g.fundLog[0]!.replace(`[${network}]`, '[NET]');
  });
  // the funding message (minus the network name) is identical → one model for all
  assert.equal(fundLogs[0], fundLogs[1]);
  assert.equal(fundLogs[1], fundLogs[2]);
});

test('actions after START are rejected', () => {
  let s = createLobby(cfg);
  s = run(s, [{ type: 'JOIN', playerId: 'host' }, { type: 'FILL_BOT', by: 'host', policy: 'balanced' }]);
  const started = applyLobby(s, { type: 'START', by: 'host', override: true });
  assert.ok(started.ok);
  const after = applyLobby(started.state, { type: 'JOIN', playerId: 'late' });
  assert.ok(!after.ok && after.code === 'ALREADY_STARTED');
});
