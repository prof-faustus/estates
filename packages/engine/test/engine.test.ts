import { test } from 'node:test';
import assert from 'node:assert/strict';
import { initialState, apply, legalActions, type GameState, type Action } from '../src/index.ts';

const cfg = { network: 'regtest' as const, seatCount: 2, bankReserve: 1_000_000 };

function fresh(): GameState { return initialState(cfg); }

/** apply a sequence, asserting each step succeeds; returns final state. */
function run(s: GameState, actions: Action[]): GameState {
  let st = s;
  for (const a of actions) {
    const r = apply(st, a);
    assert.ok(r.ok, `action ${a.type} failed: ${r.ok ? '' : r.code + ' ' + r.context}`);
    st = r.state;
  }
  return st;
}

test('initial state: seats funded, all titles with the bank, AWAIT_ROLL', () => {
  const s = fresh();
  assert.equal(s.seats.length, 2);
  assert.equal(s.seats[0]!.balance, 1500);
  assert.equal(s.phase, 'AWAIT_ROLL');
  assert.equal(s.housesRemaining, 32);
  assert.equal(s.estatesRemaining, 12);
  assert.equal(Object.values(s.titles).every((t) => t.owner === null), true);
  assert.deepEqual(legalActions(s), ['ROLL', 'FORFEIT']);
});

test('live-fairness gate: requireFairDecks rejects missing/biased deckOrder, accepts a real permutation', () => {
  const fair = Array.from({ length: 12 }, (_, i) => (i + 5) % 12);   // a non-identity permutation of [0,12)
  // a real game claiming card fairness MUST carry a committed order for EVERY deck
  assert.throws(() => initialState({ ...cfg, requireFairDecks: true }), /requires a fair committed deckOrder/);
  assert.throws(() => initialState({ ...cfg, requireFairDecks: true, deckOrder: { Fate: fair } }), /Treasury/);
  // not a permutation (duplicate / out of range / wrong length) is rejected
  const dup = [0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
  assert.throws(() => initialState({ ...cfg, requireFairDecks: true, deckOrder: { Fate: dup, Treasury: fair } }), /Fate/);
  assert.throws(() => initialState({ ...cfg, requireFairDecks: true, deckOrder: { Fate: fair.slice(0, 11), Treasury: fair } }), /Fate/);
  // a valid committed order for both decks is accepted and used
  const s = initialState({ ...cfg, requireFairDecks: true, deckOrder: { Fate: fair, Treasury: fair } });
  assert.deepEqual(s.deckOrder?.Fate, fair);
  // the public/test path still allows identity order (no gate)
  assert.equal(initialState(cfg).phase, 'AWAIT_ROLL');
});

test('buy flow: roll to a property, BUY transfers deed + sats', () => {
  let s = fresh();
  s = run(s, [{ type: 'ROLL', dice: [1, 2] }]); // 0 -> 3 Cinder Alley (Sienna, 60)
  assert.equal(s.phase, 'AWAIT_BUY');
  assert.equal(s.pendingTitle, 3);
  s = run(s, [{ type: 'BUY' }]);
  assert.equal(s.titles[3]!.owner, 0);
  assert.equal(s.seats[0]!.balance, 1440);
  assert.equal(s.phase, 'AWAIT_POST');
});

test('decline returns the title to the bank (Phase-1 default)', () => {
  let s = fresh();
  s = run(s, [{ type: 'ROLL', dice: [1, 2] }, { type: 'DECLINE' }]);
  assert.equal(s.titles[3]!.owner, null);
  assert.equal(s.phase, 'AWAIT_POST');
});

test('rent: landing on another seat’s property pays derived rent', () => {
  let s = fresh();
  // seat 0 buys Cinder Alley (3), ends turn
  s = run(s, [{ type: 'ROLL', dice: [1, 2] }, { type: 'BUY' }, { type: 'END_TURN' }]);
  assert.equal(s.current, 1);
  // seat 1 lands on 3 -> pays base rent 5 (single owner, not full group)
  s = run(s, [{ type: 'ROLL', dice: [1, 2] }]);
  assert.equal(s.seats[1]!.balance, 1495);
  assert.equal(s.seats[0]!.balance, 1445); // 1440 + 5
});

test('doubles grant another roll; three doubles send the seat to the Holding Yard', () => {
  let s = fresh();
  s = run(s, [{ type: 'ROLL', dice: [3, 3] }, { type: 'DECLINE' }]); // double 1 -> pos 6 (Mill Bridge), decline
  assert.equal(s.doublesPending, true);
  assert.equal(s.seats[0]!.position, 6);
  s = run(s, [{ type: 'END_TURN' }]);            // same seat rolls again
  assert.equal(s.current, 0);
  assert.equal(s.phase, 'AWAIT_ROLL');
  s = run(s, [{ type: 'ROLL', dice: [4, 4] }, { type: 'DECLINE' }]); // double 2 -> pos 14 (Saltmarket), decline
  s = run(s, [{ type: 'END_TURN' }]);
  s = run(s, [{ type: 'ROLL', dice: [2, 2] }]);  // double 3 -> Holding Yard (no landing)
  assert.equal(s.seats[0]!.inHolding, true);
  assert.equal(s.seats[0]!.position, 10);
});

test('salary: a card that advances past The Gate collects salary', () => {
  let s = fresh();
  // land on Fate (7); default deck order draws fate-01 "Advance to The Gate" (collect)
  s = run(s, [{ type: 'ROLL', dice: [3, 4] }]); // 0 -> 7 Fate
  assert.equal(s.seats[0]!.position, 0);        // moved to The Gate
  assert.equal(s.seats[0]!.balance, 1700);      // +200 salary
});

test('income levy: flat vs percent choice', () => {
  let s = fresh();
  s = run(s, [{ type: 'ROLL', dice: [1, 3] }]); // 0 -> 4 Income Levy
  assert.equal(s.phase, 'AWAIT_TAX');
  const flat = apply(s, { type: 'PAY_TAX', choice: 'flat' });
  assert.ok(flat.ok && flat.state.seats[0]!.balance === 1300); // 1500 - 200
});

test('even-build is enforced and consumes house supply', () => {
  // construct: seat 0 owns the full Sky group (6,8,9), AWAIT_POST
  let s = fresh();
  s = setOwner(s, [6, 8, 9], 0);
  s = { ...s, phase: 'AWAIT_POST' };
  // first house on 6 is legal (all at 0)
  let r = apply(s, { type: 'BUILD', propertyId: 6 });
  assert.ok(r.ok); s = r.state;
  assert.equal(s.titles[6]!.buildLevel, 1);
  assert.equal(s.housesRemaining, 31);
  // a second house on 6 now would be uneven (8,9 still at 0)
  r = apply(s, { type: 'BUILD', propertyId: 6 });
  assert.ok(!r.ok && r.code === 'UNEVEN_BUILD');
  // building 8 then 9 is fine
  s = run(s, [{ type: 'BUILD', propertyId: 8 }, { type: 'BUILD', propertyId: 9 }]);
  assert.equal(s.housesRemaining, 29);
});

test('cannot build without the full group', () => {
  let s = fresh();
  s = setOwner(s, [6, 8], 0); // missing 9
  s = { ...s, phase: 'AWAIT_POST' };
  const r = apply(s, { type: 'BUILD', propertyId: 6 });
  assert.ok(!r.ok && r.code === 'NOT_FULL_GROUP');
});

test('mortgage pays out, blocks build, and unmortgage costs the premium', () => {
  let s = fresh();
  s = setOwner(s, [1, 3], 0); // full Sienna
  s = { ...s, phase: 'AWAIT_POST' };
  // mortgage Tanyard (1): base 60 -> +30
  let r = apply(s, { type: 'MORTGAGE', propertyId: 1 });
  assert.ok(r.ok); s = r.state;
  assert.equal(s.titles[1]!.mortgaged, true);
  assert.equal(s.seats[0]!.balance, 1530);
  // cannot build on the group while a member is mortgaged
  r = apply(s, { type: 'BUILD', propertyId: 3 });
  assert.ok(!r.ok && r.code === 'HAS_BUILDINGS');
  // unmortgage costs round(30*1.1)=33
  r = apply(s, { type: 'UNMORTGAGE', propertyId: 1 });
  assert.ok(r.ok); s = r.state;
  assert.equal(s.titles[1]!.mortgaged, false);
  assert.equal(s.seats[0]!.balance, 1497); // 1530 - 33
});

test('raise-funds: a charge beyond cash auto-mortgages rather than bankrupting', () => {
  let s = fresh();
  // seat 0: 50 sats, owns Sovereign Mile (39, base 400 -> mortgage 200), AWAIT_TAX
  s = setOwner(s, [39], 0);
  s = setBalance(s, 0, 50);
  s = { ...s, phase: 'AWAIT_TAX', current: 0 };
  const r = apply(s, { type: 'PAY_TAX', choice: 'flat' }); // owes 200
  assert.ok(r.ok); const st = r.state;
  assert.equal(st.seats[0]!.bankrupt, false);
  assert.equal(st.titles[39]!.mortgaged, true); // auto-mortgaged to cover
  assert.equal(st.seats[0]!.balance, 50);        // 50 + 200 - 200
});

test('bankruptcy: insufficient even after liquidation removes the seat and ends the game', () => {
  let s = fresh();
  // seat 0: 50 sats, owns only Tanyard (1, base 60 -> mortgage 30); owes 200
  s = setOwner(s, [1], 0);
  s = setBalance(s, 0, 50);
  s = { ...s, phase: 'AWAIT_TAX', current: 0 };
  const r = apply(s, { type: 'PAY_TAX', choice: 'flat' });
  assert.ok(r.ok); let st = r.state;
  assert.equal(st.seats[0]!.bankrupt, true);
  assert.equal(st.seats[0]!.balance, 0);
  assert.equal(st.titles[1]!.owner, null); // returned to bank
  // ending the (now one-solvent-seat) turn yields a winner
  st = { ...st, phase: 'AWAIT_POST', current: 1 };
  const end = apply(st, { type: 'END_TURN' });
  assert.ok(end.ok && end.state.phase === 'GAME_OVER' && end.state.winner === 1);
});

test('a player who leaves gives their money + titles to the leading player (who then wins)', () => {
  let s = fresh();
  s = setOwner(s, [1, 3], 1);            // seat 1 owns two titles
  s = setBalance(s, 1, 800);
  s = setBalance(s, 0, 1500);
  const r = apply(s, { type: 'LEAVE', seat: 1 });
  assert.ok(r.ok); const st = r.state;
  assert.equal(st.seats[1]!.bankrupt, true);
  assert.equal(st.seats[1]!.balance, 0);
  assert.equal(st.seats[0]!.balance, 2300, 'leader inherits the leaver’s cash');
  assert.equal(st.titles[1]!.owner, 0, 'leader inherits the leaver’s titles');
  assert.equal(st.titles[3]!.owner, 0);
  assert.equal(st.phase, 'GAME_OVER');
  assert.equal(st.winner, 0, 'last solvent player wins');
});

test('leave in a 3-player game routes assets to the highest-worth remaining player; game continues', () => {
  let s = initialState({ network: 'regtest', seatCount: 3, bankReserve: 1_000_000 });
  s = setBalance(s, 0, 1000);
  s = setBalance(s, 2, 5000);            // seat 2 is the leader
  s = setBalance(s, 1, 700);
  const r = apply(s, { type: 'LEAVE', seat: 1 });
  assert.ok(r.ok); const st = r.state;
  assert.equal(st.seats[2]!.balance, 5700, 'highest-worth player gets the leaver’s money');
  assert.notEqual(st.phase, 'GAME_OVER', 'two players remain — game continues');
});

test('wrong-phase actions are rejected, not applied', () => {
  const s = fresh(); // AWAIT_ROLL
  assert.deepEqual(apply(s, { type: 'BUY' }), { ok: false, code: 'WRONG_PHASE', context: 'cannot BUY in AWAIT_ROLL' });
});

test('determinism: identical action sequences yield identical states', () => {
  const seq: Action[] = [
    { type: 'ROLL', dice: [1, 2] }, { type: 'BUY' }, { type: 'END_TURN' },
    { type: 'ROLL', dice: [2, 4] }, { type: 'DECLINE' }, { type: 'END_TURN' },
  ];
  const a = run(fresh(), seq);
  const b = run(fresh(), seq);
  assert.deepEqual(a, b);
});

// --- state-construction helpers (GameState is a plain readonly interface) ---
function setOwner(s: GameState, ids: number[], owner: number): GameState {
  const titles = { ...s.titles };
  for (const id of ids) titles[id] = { ...titles[id]!, owner };
  return { ...s, titles };
}
function setBalance(s: GameState, seatId: number, balance: number): GameState {
  return { ...s, seats: s.seats.map((x) => (x.id === seatId ? { ...x, balance } : x)) };
}
