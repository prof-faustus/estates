import { test } from 'node:test';
import assert from 'node:assert/strict';
import { initialState, type GameState } from '@estates/engine';
import { driveGame } from '@estates/turn';
import { loadParams } from '@estates/params';
import { makeBotDecider, makeBot, seededDice, type Policy } from '../src/index.ts';

const P = loadParams();
const RESERVE = 1_000_000;
const cfg = { network: 'regtest' as const, seatCount: 2, bankReserve: RESERVE };
const fresh = (): GameState => initialState(cfg);
const dice = seededDice(1);

function setOwner(s: GameState, ids: number[], owner: number): GameState {
  const titles = { ...s.titles };
  for (const id of ids) titles[id] = { ...titles[id]!, owner };
  return { ...s, titles };
}
function setBalance(s: GameState, seatId: number, balance: number): GameState {
  return { ...s, seats: s.seats.map((x) => (x.id === seatId ? { ...x, balance } : x)) };
}

test('ROLL action carries in-range dice', () => {
  const a = makeBotDecider('balanced', dice)(fresh(), 0)!;
  assert.equal(a.type, 'ROLL');
  if (a.type === 'ROLL') {
    assert.ok(a.dice[0] >= 1 && a.dice[0] <= 6 && a.dice[1] >= 1 && a.dice[1] <= 6);
  }
});

test('aggressive buys an affordable property; cautious declines when the buffer breaks', () => {
  // construct AWAIT_BUY on Cinder Alley (3, price 60)
  let s: GameState = { ...fresh(), phase: 'AWAIT_BUY', pendingTitle: 3 };
  assert.deepEqual(makeBotDecider('aggressive', dice)(s, 0), { type: 'BUY' });
  // cautious with a thin balance (keeps a 600 buffer) declines
  s = setBalance(s, 0, 600); // 600 - 60 = 540 < 600 buffer
  assert.deepEqual(makeBotDecider('cautious', dice)(s, 0), { type: 'DECLINE' });
});

test('income levy: bot always picks the cheaper option', () => {
  let s: GameState = { ...fresh(), phase: 'AWAIT_TAX' };
  // low worth -> percent (150) cheaper than flat (200)
  assert.deepEqual(makeBotDecider('balanced', dice)(s, 0), { type: 'PAY_TAX', choice: 'percent' });
  // high worth -> flat cheaper
  s = setBalance(s, 0, 5000);
  assert.deepEqual(makeBotDecider('balanced', dice)(s, 0), { type: 'PAY_TAX', choice: 'flat' });
});

test('aggressive builds evenly on an owned full group; cautious holds when short', () => {
  let s: GameState = { ...setOwner(fresh(), [6, 8, 9], 0), phase: 'AWAIT_POST' }; // full Sky
  const built = makeBotDecider('aggressive', dice)(s, 0)!;
  assert.equal(built.type, 'BUILD');
  if (built.type === 'BUILD') assert.ok([6, 8, 9].includes(built.propertyId));
  // cautious with too little cash ends the turn instead
  s = setBalance(s, 0, 100); // build cost 50, buffer 800 -> won't build
  assert.deepEqual(makeBotDecider('cautious', dice)(s, 0), { type: 'END_TURN' });
});

test('bots have independent signing identities (distinct keys)', () => {
  const a = makeBot('balanced', dice); const b = makeBot('aggressive', dice);
  assert.notDeepEqual([...a.keys.pkh], [...b.keys.pkh]);
});

test('self-play: money is conserved and no balance goes negative over a long game', () => {
  const start = cfg.seatCount * P.scalars.starting_balance_per_seat + RESERVE;
  const decide = makeBotDecider('aggressive', seededDice(12345));
  const end = driveGame(fresh(), decide, 400);

  const total = end.seats.reduce((sum, x) => sum + x.balance, 0) + end.bankReserve;
  assert.equal(total, start, 'sats are conserved across seats + bank reserve');
  for (const seat of end.seats) assert.ok(seat.balance >= 0, `seat ${seat.id} balance ${seat.balance} < 0`);
  assert.ok(['AWAIT_ROLL', 'GAME_OVER'].includes(end.phase), `ended in a clean phase, got ${end.phase}`);
});

test('self-play across all three policies stays consistent', () => {
  const start = cfg.seatCount * P.scalars.starting_balance_per_seat + RESERVE;
  for (const policy of ['cautious', 'balanced', 'aggressive'] as Policy[]) {
    const end = driveGame(fresh(), makeBotDecider(policy, seededDice(7)), 200);
    const total = end.seats.reduce((sum, x) => sum + x.balance, 0) + end.bankReserve;
    assert.equal(total, start, `conserved for ${policy}`);
  }
});
