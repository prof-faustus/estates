import { test } from 'node:test';
import assert from 'node:assert/strict';
import { initialState, apply, type GameState, type Action } from '@estates/engine';
import { loadParams } from '@estates/params';
import { defaultActionFor, maturityFor, applyTimeout, driveTurn, driveGame } from '../src/index.ts';

const cfg = { network: 'regtest' as const, seatCount: 2, bankReserve: 1_000_000 };
const fresh = (): GameState => initialState(cfg);
const P = loadParams();

function step(s: GameState, a: Action): GameState {
  const r = apply(s, a); assert.ok(r.ok, `${a.type}: ${r.ok ? '' : r.code}`); return r.state;
}

test('maturity is a relative nSequence window (no CLTV/CSV), sized from params', () => {
  const m = maturityFor('AWAIT_ROLL');
  assert.equal(m.kind, 'relative');
  assert.equal(m.nSequenceBlocks, P.timeouts.decision_blocks);
});

test('default branch per actionable phase', () => {
  // AWAIT_ROLL -> FORFEIT
  assert.deepEqual(defaultActionFor(fresh()), { type: 'FORFEIT' });
  // AWAIT_BUY -> DECLINE
  const buy = step(fresh(), { type: 'ROLL', dice: [1, 2] });
  assert.deepEqual(defaultActionFor(buy), { type: 'DECLINE' });
  // AWAIT_TAX -> lesser (fresh seat worth 1500 -> percent 150 < flat 200 -> percent)
  const tax = step(fresh(), { type: 'ROLL', dice: [1, 3] });
  assert.deepEqual(defaultActionFor(tax), { type: 'PAY_TAX', choice: 'percent' });
  // AWAIT_POST -> END_TURN
  const post = step(buy, { type: 'DECLINE' });
  assert.deepEqual(defaultActionFor(post), { type: 'END_TURN' });
});

test('income-levy default picks flat when the seat is wealthy', () => {
  // high net worth so 10% exceeds the flat 200
  let s = step(fresh(), { type: 'ROLL', dice: [1, 3] }); // AWAIT_TAX
  s = { ...s, seats: s.seats.map((x) => (x.id === s.current ? { ...x, balance: 3000 } : x)) };
  assert.deepEqual(defaultActionFor(s), { type: 'PAY_TAX', choice: 'flat' }); // 300 > 200
});

test('FORFEIT (AWAIT_ROLL timeout) advances the turn with no move', () => {
  const s = fresh();
  const r = applyTimeout(s); // default in AWAIT_ROLL = FORFEIT
  assert.ok(r.ok);
  assert.equal(r.state.current, 1);          // advanced
  assert.equal(r.state.seats[0]!.position, 0); // did not move
  assert.equal(r.state.turnIndex, 1);
});

test('driveTurn runs a full cooperative turn and advances to the next seat', () => {
  const decide = (s: GameState): Action | null => {
    switch (s.phase) {
      case 'AWAIT_ROLL': return { type: 'ROLL', dice: [1, 2] }; // -> 3 Cinder Alley
      case 'AWAIT_BUY': return { type: 'BUY' };
      case 'AWAIT_POST': return { type: 'END_TURN' };
      default: return null;
    }
  };
  const { state, steps } = driveTurn(fresh(), decide);
  assert.equal(state.current, 1);
  assert.equal(state.titles[3]!.owner, 0);
  assert.deepEqual(steps.map((x) => x.action.type), ['ROLL', 'BUY', 'END_TURN']);
  assert.equal(steps.every((x) => !x.byTimeout), true);
});

test('driveTurn falls back to the default branch on a missing decision (timeout)', () => {
  const { state, steps } = driveTurn(fresh(), () => null); // never decides
  assert.equal(steps.length, 1);
  assert.equal(steps[0]!.byTimeout, true);
  assert.deepEqual(steps[0]!.action, { type: 'FORFEIT' });
  assert.equal(state.current, 1);
});

test('driveTurn falls back when a cooperative action is illegal', () => {
  // propose BUY while in AWAIT_ROLL (illegal) -> default FORFEIT
  const { state, steps } = driveTurn(fresh(), () => ({ type: 'BUY' }));
  assert.equal(steps[0]!.byTimeout, true);
  assert.equal(steps[0]!.action.type, 'FORFEIT');
  assert.equal(state.current, 1);
});

test('driveGame makes progress turn over turn and is bounded', () => {
  const end = driveGame(fresh(), () => null, 10); // all timeouts (forfeits)
  assert.equal(end.turnIndex, 10);
  assert.notEqual(end.phase, 'GAME_OVER'); // forfeits never bankrupt anyone
});

test('driveGame returns immediately when the game is already over', () => {
  const over = { ...fresh(), phase: 'GAME_OVER' as const, winner: 0 };
  assert.equal(driveGame(over, () => null).winner, 0);
});
