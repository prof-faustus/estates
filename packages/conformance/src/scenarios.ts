/**
 * scenarios.ts — builds the conformance vectors by EXECUTING the core.
 *
 * Each scenario produces an input state (via initialState + a prelude of
 * applied actions, and/or direct construction), then records the engine's
 * result of one more action as the expected outcome. The committed vector
 * file is therefore the core's own legality, frozen for cross-implementation
 * checking (the Go verifier re-runs the same vectors — D-CORE).
 */
import { initialState, apply, type GameState, type Action } from '@estates/engine';
import { hashState, type Vector } from './index.ts';

const CFG = { network: 'regtest' as const, seatCount: 2, bankReserve: 1_000_000 };

function fresh(): GameState { return initialState(CFG); }
function prelude(actions: Action[]): GameState {
  let s = fresh();
  for (const a of actions) {
    const r = apply(s, a);
    if (!r.ok) throw new Error(`prelude ${a.type} failed: ${r.code} ${r.context}`);
    s = r.state;
  }
  return s;
}
function setOwner(s: GameState, ids: number[], owner: number): GameState {
  const titles = { ...s.titles };
  for (const id of ids) titles[id] = { ...titles[id]!, owner };
  return { ...s, titles };
}
function setBalance(s: GameState, seatId: number, balance: number): GameState {
  return { ...s, seats: s.seats.map((x) => (x.id === seatId ? { ...x, balance } : x)) };
}

function vec(id: string, description: string, state: GameState, action: Action): Vector {
  const r = apply(state, action);
  const expected = r.ok ? { ok: true as const, stateHash: hashState(r.state) } : { ok: false as const, code: r.code };
  return { id, description, state, action, expected };
}

export function buildVectors(): Vector[] {
  const vectors: Vector[] = [];
  const at3 = prelude([{ type: 'ROLL', dice: [1, 2] }]); // AWAIT_BUY @ Cinder Alley (3)

  vectors.push(vec('v01-buy', 'buy an unowned property from the bank', at3, { type: 'BUY' }));
  vectors.push(vec('v02-decline', 'decline a purchase (returns to bank, Phase-1 default)', at3, { type: 'DECLINE' }));

  // insufficient funds to buy
  const pricey = { ...setBalance(setOwner(fresh(), [], 0), 0, 50), phase: 'AWAIT_BUY' as const, pendingTitle: 39 };
  vectors.push(vec('v03-buy-insufficient', 'buying beyond balance is rejected', pricey, { type: 'BUY' }));

  // rent: seat 0 owns 3, seat 1 lands on it
  const ownsThenSeat1 = prelude([{ type: 'ROLL', dice: [1, 2] }, { type: 'BUY' }, { type: 'END_TURN' }]);
  vectors.push(vec('v04-rent', 'landing on another seat’s property pays derived rent', ownsThenSeat1, { type: 'ROLL', dice: [1, 2] }));

  // salary via card (Fate index 0 = Advance to The Gate)
  vectors.push(vec('v05-salary-card', 'a card advancing past The Gate collects salary', fresh(), { type: 'ROLL', dice: [3, 4] }));

  // income levy choices
  const atTax = prelude([{ type: 'ROLL', dice: [1, 3] }]); // AWAIT_TAX @ Income Levy (4)
  vectors.push(vec('v06-tax-flat', 'income levy paid as the flat amount', atTax, { type: 'PAY_TAX', choice: 'flat' }));
  vectors.push(vec('v07-tax-percent', 'income levy paid as a percent of worth', atTax, { type: 'PAY_TAX', choice: 'percent' }));

  // build: full Sky group, AWAIT_POST
  const fullSky = { ...setOwner(fresh(), [6, 8, 9], 0), phase: 'AWAIT_POST' as const };
  vectors.push(vec('v08-build-ok', 'first house on a full group is legal and consumes supply', fullSky, { type: 'BUILD', propertyId: 6 }));
  const built6 = (() => { const r = apply(fullSky, { type: 'BUILD', propertyId: 6 }); if (!r.ok) throw new Error('setup'); return r.state; })();
  vectors.push(vec('v09-build-uneven', 'a second house on the same property is uneven and rejected', built6, { type: 'BUILD', propertyId: 6 }));

  const partialSky = { ...setOwner(fresh(), [6, 8], 0), phase: 'AWAIT_POST' as const };
  vectors.push(vec('v10-build-not-full-group', 'building without the full group is rejected', partialSky, { type: 'BUILD', propertyId: 6 }));

  // mortgage + blocks build
  const fullSienna = { ...setOwner(fresh(), [1, 3], 0), phase: 'AWAIT_POST' as const };
  vectors.push(vec('v11-mortgage', 'mortgaging pays out the mortgage value', fullSienna, { type: 'MORTGAGE', propertyId: 1 }));
  const mortgaged1 = (() => { const r = apply(fullSienna, { type: 'MORTGAGE', propertyId: 1 }); if (!r.ok) throw new Error('setup'); return r.state; })();
  vectors.push(vec('v12-build-blocked-by-mortgage', 'cannot build on a group with a mortgaged member', mortgaged1, { type: 'BUILD', propertyId: 3 }));

  // raise-funds + bankruptcy
  const raiseState = { ...setBalance(setOwner(fresh(), [39], 0), 0, 50), phase: 'AWAIT_TAX' as const };
  vectors.push(vec('v13-raise-funds', 'a charge beyond cash auto-mortgages instead of bankrupting', raiseState, { type: 'PAY_TAX', choice: 'flat' }));
  const bankruptState = { ...setBalance(setOwner(fresh(), [1], 0), 0, 50), phase: 'AWAIT_TAX' as const };
  vectors.push(vec('v14-bankruptcy', 'insufficient even after liquidation removes the seat', bankruptState, { type: 'PAY_TAX', choice: 'flat' }));

  // guards
  vectors.push(vec('v15-wrong-phase', 'an action for the wrong phase is rejected', fresh(), { type: 'BUY' }));
  vectors.push(vec('v16-invalid-dice', 'out-of-range dice are rejected', fresh(), { type: 'ROLL', dice: [0, 7] }));
  vectors.push(vec('v17-forfeit', 'AWAIT_ROLL timeout default forfeits the turn (no move, next seat)', fresh(), { type: 'FORFEIT' }));

  return vectors;
}
