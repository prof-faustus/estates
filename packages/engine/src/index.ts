/**
 * @estates/engine — the pure deterministic ESTATES core.
 *
 * `apply(state, action)` → new state | typed rejection. No I/O, no clock, no
 * own randomness. Dice come in on ROLL actions and card-deck order is injected
 * at init, so every transition is recomputable from the transcript (R4, R7).
 *
 * Auctions (S3a) and player↔player trades are on-chain multi-party operations
 * built in Phase 3; in this core, DECLINE returns the title to the bank unsold
 * (the all-no-bid timeout default of rules §7), and bankruptcy auto-liquidates
 * deterministically (sell buildings, then mortgage) before removing a seat.
 */
import {
  loadParams, baseRent, propertyRent, stationRent, utilityRent,
  mortgageValue, unmortgageCost, buildCost,
  type EstatesParams, type BoardSpace, type Card, type CardEffect,
} from '@estates/params';
import type {
  GameState, SeatState, TitleState, Action, ApplyResult, Phase, EngineConfig, RejectCode,
} from './types.ts';

export * from './types.ts';

const P: EstatesParams = loadParams();
const BOARD = P.board;
const SIZE = P.scalars.board_size;

const reject = (code: RejectCode, context: string): ApplyResult => ({ ok: false, code, context });
const ok = (state: GameState): ApplyResult => ({ ok: true, state });

// ---------------------------------------------------------------------------
// construction
// ---------------------------------------------------------------------------

/** A draw order is valid iff it is an exact permutation of [0,n). */
function isPermutation(order: readonly number[] | undefined, n: number): boolean {
  if (!order || order.length !== n) return false;
  const seen = new Array<boolean>(n).fill(false);
  for (const v of order) {
    if (!Number.isInteger(v) || v < 0 || v >= n || seen[v]) return false;
    seen[v] = true;
  }
  return true;
}

export function initialState(cfg: EngineConfig): GameState {
  // Live-fairness gate: a game claiming concealed-card fairness MUST ship a
  // committed, jointly-generated order for EVERY deck — never fall back to the
  // public identity order. (Audit: reject missing/biased deckOrder in live mode.)
  if (cfg.requireFairDecks) {
    for (const deck of Object.keys(P.decks)) {
      if (!isPermutation(cfg.deckOrder?.[deck], P.decks[deck]!.length)) {
        throw new Error(`live game requires a fair committed deckOrder for ${deck} (exact permutation of ${P.decks[deck]!.length})`);
      }
    }
  }
  const seats: SeatState[] = [];
  for (let i = 0; i < cfg.seatCount; i++) {
    seats.push({
      id: i, balance: P.scalars.starting_balance_per_seat, position: 0,
      inHolding: false, holdingTurns: 0, reprieveCards: 0, bankrupt: false,
    });
  }
  const titles: Record<number, TitleState> = {};
  for (const s of BOARD) {
    if (s.type === 'property' || s.type === 'station' || s.type === 'utility') {
      titles[s.id] = { owner: null, buildLevel: 0, mortgaged: false };
    }
  }
  return {
    network: cfg.network, seats, titles,
    bankReserve: cfg.bankReserve,
    housesRemaining: P.build_supply.houses,
    estatesRemaining: P.build_supply.estates,
    current: 0, phase: 'AWAIT_ROLL', turnIndex: 0,
    doublesPending: false, doublesCount: 0,
    deckCursor: { Fate: 0, Treasury: 0 },
    ...(cfg.deckOrder ? { deckOrder: cfg.deckOrder } : {}),
    lastRoll: null, pendingTitle: null, winner: null, log: [],
  };
}

export function legalActions(s: GameState): Action['type'][] {
  switch (s.phase) {
    case 'AWAIT_ROLL': return ['ROLL', 'FORFEIT'];
    case 'AWAIT_BUY': return ['BUY', 'DECLINE'];
    case 'AWAIT_TAX': return ['PAY_TAX'];
    case 'AWAIT_POST': return ['BUILD', 'SELL_BUILD', 'MORTGAGE', 'UNMORTGAGE', 'END_TURN'];
    case 'GAME_OVER': return [];
  }
}

// ---------------------------------------------------------------------------
// immutable helpers
// ---------------------------------------------------------------------------

function withSeat(s: GameState, id: number, patch: Partial<SeatState>): GameState {
  return { ...s, seats: s.seats.map((x) => (x.id === id ? { ...x, ...patch } : x)) };
}
function withTitle(s: GameState, id: number, patch: Partial<TitleState>): GameState {
  return { ...s, titles: { ...s.titles, [id]: { ...s.titles[id]!, ...patch } } };
}
function note(s: GameState, line: string): GameState {
  return { ...s, log: [...s.log, line] };
}
const seat = (s: GameState, id: number): SeatState => s.seats[id]!;
const space = (id: number): BoardSpace => BOARD[id]!;
const isTitled = (sp: BoardSpace): boolean => sp.type === 'property' || sp.type === 'station' || sp.type === 'utility';

function membersOf(group: string): readonly number[] {
  return P.groups[group]?.member_property_ids ?? [];
}
function ownsFullGroup(s: GameState, seatId: number, group: string): boolean {
  const m = membersOf(group);
  return m.length > 0 && m.every((id) => s.titles[id]?.owner === seatId);
}
function countCategoryOwned(s: GameState, seatId: number, type: 'station' | 'utility'): number {
  let n = 0;
  for (const sp of BOARD) if (sp.type === type && s.titles[sp.id]?.owner === seatId) n++;
  return n;
}
/** Net worth in sats: cash + unmortgaged build value + mortgage values held. */
export function netWorth(s: GameState, seatId: number): number {
  let w = seat(s, seatId).balance;
  for (const sp of BOARD) {
    if (!isTitled(sp)) continue;
    const t = s.titles[sp.id]!;
    if (t.owner !== seatId) continue;
    w += mortgageValue(sp.base_price ?? 0);
    if (!t.mortgaged && t.buildLevel > 0 && sp.group) {
      w += t.buildLevel * buildCost(sp.group);
    }
  }
  return w;
}

// ---------------------------------------------------------------------------
// money — deterministic raise-funds + bankruptcy
// ---------------------------------------------------------------------------

/** Pay from bank reserve to a seat (salary / card collect). Capped at reserve. */
function bankToSeat(s: GameState, seatId: number, amount: number): GameState {
  const pay = Math.min(amount, s.bankReserve);
  return withSeat({ ...s, bankReserve: s.bankReserve - pay }, seatId, { balance: seat(s, seatId).balance + pay });
}

/**
 * Deterministically liquidate seat assets toward `target`: sell buildings
 * (highest level first, ties by ascending property_id), then mortgage
 * unbuilt unmortgaged titles (ascending property_id). Returns updated state.
 */
function raiseFunds(s: GameState, seatId: number, target: number): GameState {
  let st = s;
  // 1) sell buildings
  while (seat(st, seatId).balance < target) {
    let best = -1, bestLevel = 0;
    for (const sp of BOARD) {
      if (!sp.group) continue;
      const t = st.titles[sp.id];
      if (t && t.owner === seatId && t.buildLevel > bestLevel) { best = sp.id; bestLevel = t.buildLevel; }
    }
    if (best < 0) break;
    st = sellBuildInternal(st, seatId, best);
  }
  // 2) mortgage unbuilt, unmortgaged titles
  for (const sp of BOARD) {
    if (seat(st, seatId).balance >= target) break;
    if (!isTitled(sp)) continue;
    const t = st.titles[sp.id]!;
    if (t.owner === seatId && !t.mortgaged && t.buildLevel === 0) {
      const v = mortgageValue(sp.base_price ?? 0);
      // mortgage value is paid by the bank reserve (bank→seat), same as doMortgage
      st = bankToSeat(withTitle(st, sp.id, { mortgaged: true }), seatId, v);
    }
  }
  return st;
}

/** sell one building level off a title, refund half build cost from reserve. */
function sellBuildInternal(s: GameState, seatId: number, id: number): GameState {
  const sp = space(id); const t = s.titles[id]!;
  if (!sp.group || t.buildLevel <= 0) return s;
  const refund = Math.round(buildCost(sp.group) * P.rent_factors.sell_building_refund_factor);
  let st = s;
  // supply: selling estate (5->4) returns the estate, consumes 4 houses; selling a house (1..4) returns a house
  if (t.buildLevel === 5) st = { ...st, estatesRemaining: st.estatesRemaining + 1, housesRemaining: st.housesRemaining - 4 };
  else st = { ...st, housesRemaining: st.housesRemaining + 1 };
  st = withTitle(st, id, { buildLevel: t.buildLevel - 1 });
  st = bankToSeat(st, seatId, refund);
  return st;
}

/**
 * Charge `amount` from `fromId` to `toId` (null = bank reserve). If short,
 * auto-raise funds; if still short, the seat goes bankrupt — remaining cash +
 * all titles transfer to the creditor (or revert to bank), buildings returned
 * to supply. Returns updated state (recipient credited).
 */
function charge(s: GameState, fromId: number, amount: number, toId: number | null): GameState {
  let st = s;
  if (seat(st, fromId).balance < amount) st = raiseFunds(st, fromId, amount);

  if (seat(st, fromId).balance >= amount) {
    st = withSeat(st, fromId, { balance: seat(st, fromId).balance - amount });
    st = toId === null
      ? { ...st, bankReserve: st.bankReserve + amount }
      : withSeat(st, toId, { balance: seat(st, toId).balance + amount });
    return st;
  }

  // bankruptcy: transfer everything that remains.
  const remaining = seat(st, fromId).balance;
  st = withSeat(st, fromId, { balance: 0, bankrupt: true });
  if (toId === null) st = { ...st, bankReserve: st.bankReserve + remaining };
  else st = withSeat(st, toId, { balance: seat(st, toId).balance + remaining });

  for (const sp of BOARD) {
    if (!isTitled(sp)) continue;
    const t = st.titles[sp.id]!;
    if (t.owner !== fromId) continue;
    // return buildings to supply
    if (t.buildLevel === 5) st = { ...st, estatesRemaining: st.estatesRemaining + 1, housesRemaining: st.housesRemaining - 4 };
    else if (t.buildLevel > 0) st = { ...st, housesRemaining: st.housesRemaining + t.buildLevel };
    st = withTitle(st, sp.id, { owner: toId, buildLevel: 0 });
  }
  // Reprieve cards transfer too
  if (toId !== null) {
    st = withSeat(st, toId, { reprieveCards: seat(st, toId).reprieveCards + seat(st, fromId).reprieveCards });
  }
  st = withSeat(st, fromId, { reprieveCards: 0 });
  st = note(st, `seat ${fromId} bankrupt; assets to ${toId === null ? 'bank' : `seat ${toId}`}`);
  return st;
}

function solventSeats(s: GameState): number[] {
  return s.seats.filter((x) => !x.bankrupt).map((x) => x.id);
}
function maybeGameOver(s: GameState): GameState {
  const alive = solventSeats(s);
  if (alive.length <= 1) return { ...s, phase: 'GAME_OVER', winner: alive[0] ?? null };
  return s;
}

// ---------------------------------------------------------------------------
// rent
// ---------------------------------------------------------------------------

function computeRent(s: GameState, id: number, diceTotal: number): number {
  const sp = space(id); const t = s.titles[id]!;
  if (t.owner === null || t.mortgaged) return 0;
  if (sp.type === 'station') return stationRent(countCategoryOwned(s, t.owner, 'station'));
  if (sp.type === 'utility') return utilityRent(diceTotal, countCategoryOwned(s, t.owner, 'utility'));
  const full = sp.group ? ownsFullGroup(s, t.owner, sp.group) : false;
  return propertyRent(sp.base_price ?? 0, t.buildLevel, full);
}

// ---------------------------------------------------------------------------
// landing resolution
// ---------------------------------------------------------------------------

function goToHolding(s: GameState): GameState {
  const id = seat(s, s.current).id;
  let st = withSeat(s, id, { position: P.holding_yard.space_id, inHolding: true, holdingTurns: 0 });
  st = { ...st, doublesPending: false, doublesCount: 0 };
  return note(st, `seat ${id} sent to the Holding Yard`);
}

/** Resolve the active seat's landing. Returns state with a settled phase. */
function resolveLanding(s: GameState, diceTotal: number): GameState {
  const id = s.current;
  const pos = seat(s, id).position;
  const sp = space(pos);

  if (sp.type === 'corner') {
    if (sp.corner === 'summons') return { ...goToHolding(s), phase: 'AWAIT_POST' };
    return { ...s, phase: 'AWAIT_POST' };
  }
  if (sp.type === 'tax') {
    if (sp.tax === 'income_levy') return { ...s, phase: 'AWAIT_TAX' };
    const flat = P.taxes['luxury_duty']!.flat;
    return { ...note(charge(s, id, flat, null), `seat ${id} pays Luxury Duty ${flat}`), phase: 'AWAIT_POST' };
  }
  if (sp.type === 'card') {
    return resolveCard(s, sp.deck!, diceTotal);
  }
  if (isTitled(sp)) {
    const t = s.titles[pos]!;
    if (t.owner === null) return { ...s, phase: 'AWAIT_BUY', pendingTitle: pos };
    if (t.owner === id || t.mortgaged) return { ...s, phase: 'AWAIT_POST' };
    const rent = computeRent(s, pos, diceTotal);
    return { ...note(charge(s, id, rent, t.owner), `seat ${id} pays rent ${rent} to seat ${t.owner}`), phase: 'AWAIT_POST' };
  }
  return { ...s, phase: 'AWAIT_POST' };
}

function nearest(pos: number, type: 'station' | 'utility'): number {
  for (let d = 1; d <= SIZE; d++) {
    const id = (pos + d) % SIZE;
    if (space(id).type === type) return id;
  }
  return pos;
}

function resolveCard(s: GameState, deck: string, diceTotal: number): GameState {
  const cards = P.decks[deck]!;
  const order = drawOrder(s, deck, cards.length);
  const cursor = s.deckCursor[deck] ?? 0;
  const cardIdx = order[cursor % order.length]!;
  const card: Card = cards[cardIdx]!;
  let st = { ...s, deckCursor: { ...s.deckCursor, [deck]: (cursor + 1) % order.length } };
  st = note(st, `seat ${s.current} draws ${deck}: ${card.text}`);
  return applyCardEffect(st, card.effect, diceTotal);
}

/** Injected per-deck draw order from state; identity (declared order) if absent.
 *  An injected order is accepted ONLY if it is a STRICT permutation of [0,n) — a
 *  malformed order (duplicate/missing/out-of-range index) must never duplicate or
 *  drop a Fate/Treasury effect, so we reject it back to declared order rather than
 *  run a corrupt deck. (Live games additionally gate on requireFairDecks at init.) */
function drawOrder(s: GameState, deck: string, n: number): readonly number[] {
  const inj = s.deckOrder?.[deck];
  if (isPermutation(inj, n)) return inj!;
  return Array.from({ length: n }, (_v, i) => i);
}

function applyCardEffect(s: GameState, e: CardEffect, diceTotal: number): GameState {
  const id = s.current;
  switch (e.kind) {
    case 'COLLECT_BANK': return { ...bankToSeat(s, id, e.amount), phase: 'AWAIT_POST' };
    case 'PAY_BANK': return { ...charge(s, id, e.amount, null), phase: 'AWAIT_POST' };
    case 'COLLECT_EACH': {
      let st = s;
      for (const o of solventSeats(st)) if (o !== id) st = charge(st, o, e.amount, id);
      return { ...st, phase: 'AWAIT_POST' };
    }
    case 'PAY_EACH': {
      let st = s;
      for (const o of solventSeats(st)) if (o !== id) st = charge(st, id, e.amount, o);
      return { ...st, phase: 'AWAIT_POST' };
    }
    case 'REPAIRS': {
      let houses = 0, estates = 0;
      for (const sp of BOARD) {
        const t = s.titles[sp.id];
        if (t && t.owner === id) { if (t.buildLevel === 5) estates++; else houses += t.buildLevel; }
      }
      return { ...charge(s, id, houses * e.per_house + estates * e.per_estate, null), phase: 'AWAIT_POST' };
    }
    case 'REPRIEVE_GRANT':
      return { ...withSeat(s, id, { reprieveCards: seat(s, id).reprieveCards + 1 }), phase: 'AWAIT_POST' };
    case 'GOTO_HOLDING':
      return { ...goToHolding(s), phase: 'AWAIT_POST' };
    case 'MOVE_RELATIVE': {
      const np = ((seat(s, id).position + e.delta) % SIZE + SIZE) % SIZE;
      return resolveLanding(withSeat(s, id, { position: np }), diceTotal);
    }
    case 'MOVE_TO': {
      const from = seat(s, id).position;
      let st = s;
      if (e.collect_if_pass && e.space <= from) st = bankToSeat(st, id, P.scalars.salary);
      st = withSeat(st, id, { position: e.space });
      return resolveLanding(st, diceTotal);
    }
    case 'MOVE_TO_NEAREST': {
      const target = nearest(seat(s, id).position, e.category);
      let st = s;
      if (e.collect_if_pass && target <= seat(s, id).position) st = bankToSeat(st, id, P.scalars.salary);
      st = withSeat(st, id, { position: target });
      return resolveLanding(st, diceTotal);
    }
  }
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

export function apply(s: GameState, a: Action): ApplyResult {
  if (s.phase === 'GAME_OVER') return reject('GAME_OVER', 'game is over');
  if (a.type === 'LEAVE') return doLeave(s, a.seat); // allowed in any phase, on or off turn

  switch (a.type) {
    case 'ROLL': return doRoll(s, a.dice);
    case 'BUY': return doBuy(s);
    case 'DECLINE': return doDecline(s);
    case 'PAY_TAX': return doTax(s, a.choice);
    case 'BUILD': return doBuild(s, a.propertyId);
    case 'SELL_BUILD': return doSellBuild(s, a.propertyId);
    case 'MORTGAGE': return doMortgage(s, a.propertyId);
    case 'UNMORTGAGE': return doUnmortgage(s, a.propertyId);
    case 'FORFEIT': return doForfeit(s);
    case 'END_TURN': return doEndTurn(s);
  }
}

/**
 * A player leaves the table at any time (their choice). Their money + titles
 * default to the LEADING player (highest net worth among the remaining solvent
 * seats) — so if leaving makes one seat the last standing, that player wins with
 * everything. With no one else solvent, the assets simply return to the bank.
 */
function doLeave(s: GameState, seatId: number): ApplyResult {
  const leaver = s.seats[seatId];
  if (!leaver || leaver.bankrupt) return ok(s);
  let st = s;
  const others = solventSeats(st).filter((id) => id !== seatId);
  if (others.length > 0) {
    let winner = others[0]!;
    for (const id of others) if (netWorth(st, id) > netWorth(st, winner)) winner = id;
    st = withSeat(st, winner, {
      balance: seat(st, winner).balance + leaver.balance,
      reprieveCards: seat(st, winner).reprieveCards + leaver.reprieveCards,
    });
    for (const sp of BOARD) {
      if (isTitled(sp) && st.titles[sp.id]!.owner === seatId) st = withTitle(st, sp.id, { owner: winner });
    }
    st = withSeat(st, seatId, { balance: 0, bankrupt: true, reprieveCards: 0 });
    st = note(st, `seat ${seatId} leaves; money + assets default to the leading player (seat ${winner})`);
  } else {
    st = withSeat(st, seatId, { balance: 0, bankrupt: true, reprieveCards: 0 });
    st = note(st, `seat ${seatId} leaves the table`);
  }
  if (st.current === seatId) {
    let next = st.current;
    for (let i = 1; i <= st.seats.length; i++) {
      const cand = (st.current + i) % st.seats.length;
      if (!seat(st, cand).bankrupt) { next = cand; break; }
    }
    st = { ...st, current: next, phase: 'AWAIT_ROLL', doublesPending: false, doublesCount: 0, turnIndex: st.turnIndex + 1 };
  }
  return ok(maybeGameOver(st));
}

function doForfeit(s: GameState): ApplyResult {
  if (s.phase !== 'AWAIT_ROLL') return reject('WRONG_PHASE', `cannot FORFEIT in ${s.phase}`);
  // Turn forfeited (no move). Clear any doubles and advance to the next seat.
  const st = note({ ...s, phase: 'AWAIT_POST', doublesPending: false, doublesCount: 0 }, `seat ${s.current} forfeits the turn`);
  return ok(endTurnTransition(st));
}

function doRoll(s: GameState, dice: readonly [number, number]): ApplyResult {
  if (s.phase !== 'AWAIT_ROLL') return reject('WRONG_PHASE', `cannot ROLL in ${s.phase}`);
  const [d1, d2] = dice;
  if (![d1, d2].every((d) => Number.isInteger(d) && d >= 1 && d <= 6)) return reject('INVALID_DICE', `dice ${d1},${d2}`);
  const id = s.current;
  const total = d1 + d2;
  const isDouble = d1 === d2;
  let st: GameState = { ...s, lastRoll: [d1, d2] };
  const sc = seat(st, id);

  if (sc.inHolding) {
    if (isDouble) {
      st = withSeat(st, id, { inHolding: false, holdingTurns: 0 });
      st = note(st, `seat ${id} rolls doubles and leaves the Holding Yard`);
      return ok(advanceAndLand(st, id, total, false));
    }
    const attempts = sc.holdingTurns + 1;
    if (attempts >= P.holding_yard.max_double_attempts) {
      st = charge(withSeat(st, id, { holdingTurns: 0, inHolding: false }), id, P.holding_yard.pay_to_leave, null);
      st = note(st, `seat ${id} pays ${P.holding_yard.pay_to_leave} to leave the Holding Yard`);
      return ok(advanceAndLand(st, id, total, false));
    }
    st = withSeat(st, id, { holdingTurns: attempts });
    st = note(st, `seat ${id} fails to roll doubles (${attempts}/${P.holding_yard.max_double_attempts})`);
    return ok(endTurnTransition({ ...st, phase: 'AWAIT_POST' })); // no action; advance
  }

  if (isDouble && s.doublesCount + 1 >= P.holding_yard.doubles_to_holding) {
    st = note(st, `seat ${id} rolls a third double`);
    return ok({ ...goToHolding(st), phase: 'AWAIT_POST' });
  }
  const newDoublesCount = isDouble ? s.doublesCount + 1 : 0;
  st = { ...st, doublesCount: newDoublesCount, doublesPending: isDouble };
  return ok(advanceAndLand(st, id, total, true));
}

/** advance the seat `total` spaces (paying salary on Gate pass) then resolve landing. */
function advanceAndLand(s: GameState, id: number, total: number, _normal: boolean): GameState {
  const from = seat(s, id).position;
  const raw = from + total;
  const np = raw % SIZE;
  let st = s;
  if (raw >= SIZE) { st = bankToSeat(st, id, P.scalars.salary); st = note(st, `seat ${id} passes The Gate, collects ${P.scalars.salary}`); }
  st = withSeat(st, id, { position: np });
  return resolveLanding(st, total);
}

function doBuy(s: GameState): ApplyResult {
  if (s.phase !== 'AWAIT_BUY') return reject('WRONG_PHASE', `cannot BUY in ${s.phase}`);
  const id = s.current; const pid = s.pendingTitle!;
  const price = space(pid).base_price ?? 0;
  if (seat(s, id).balance < price) return reject('INSUFFICIENT_FUNDS', `need ${price} for ${space(pid).name}`);
  let st = withSeat(s, id, { balance: seat(s, id).balance - price });
  st = { ...st, bankReserve: st.bankReserve + price };
  st = withTitle(st, pid, { owner: id });
  st = note(st, `seat ${id} buys ${space(pid).name} for ${price}`);
  return ok({ ...st, phase: 'AWAIT_POST', pendingTitle: null });
}

function doDecline(s: GameState): ApplyResult {
  if (s.phase !== 'AWAIT_BUY') return reject('WRONG_PHASE', `cannot DECLINE in ${s.phase}`);
  // Phase-1 core: all-no-bid timeout default — title stays with the bank.
  // (Sealed-bid auction S3a is built in Phase 3.)
  const st = note(s, `seat ${s.current} declines ${space(s.pendingTitle!).name}; returns to bank unsold`);
  return ok({ ...st, phase: 'AWAIT_POST', pendingTitle: null });
}

function doTax(s: GameState, choice: 'flat' | 'percent'): ApplyResult {
  if (s.phase !== 'AWAIT_TAX') return reject('WRONG_PHASE', `cannot PAY_TAX in ${s.phase}`);
  const id = s.current; const t = P.taxes['income_levy']!;
  const amount = choice === 'flat' ? t.flat : Math.round(netWorth(s, id) * (t.percent_of_worth ?? 0));
  const st = note(charge(s, id, amount, null), `seat ${id} pays Income Levy ${amount} (${choice})`);
  return ok({ ...st, phase: 'AWAIT_POST' });
}

function doBuild(s: GameState, pid: number): ApplyResult {
  if (s.phase !== 'AWAIT_POST') return reject('WRONG_PHASE', `cannot BUILD in ${s.phase}`);
  const sp = BOARD[pid]; if (!sp || !isTitled(sp)) return reject('NO_SUCH_TITLE', `${pid}`);
  if (sp.type !== 'property' || !sp.group) return reject('NOT_TITLED_SPACE', `${sp.name} is not buildable`);
  const t = s.titles[pid]!; const id = s.current;
  if (t.owner !== id) return reject('NOT_OWNER', `seat ${id} does not own ${sp.name}`);
  if (!ownsFullGroup(s, id, sp.group)) return reject('NOT_FULL_GROUP', `${sp.group} not fully owned`);
  if (membersOf(sp.group).some((m) => s.titles[m]!.mortgaged)) return reject('HAS_BUILDINGS', `${sp.group} has a mortgaged member`);
  if (t.buildLevel >= 5) return reject('ALREADY_MAX', `${sp.name} at estate`);
  // even build: cannot exceed the group minimum + 1
  const minLevel = Math.min(...membersOf(sp.group).map((m) => s.titles[m]!.buildLevel));
  if (t.buildLevel > minLevel) return reject('UNEVEN_BUILD', `must build evenly across ${sp.group}`);
  const toLevel = t.buildLevel + 1;
  if (toLevel === 5) { if (s.estatesRemaining < 1) return reject('NO_BUILD_SUPPLY', 'no estates left'); }
  else if (s.housesRemaining < 1) return reject('NO_BUILD_SUPPLY', 'no houses left');
  const cost = buildCost(sp.group);
  if (seat(s, id).balance < cost) return reject('INSUFFICIENT_FUNDS', `need ${cost} to build`);
  let st = withSeat(s, id, { balance: seat(s, id).balance - cost });
  st = { ...st, bankReserve: st.bankReserve + cost };
  if (toLevel === 5) st = { ...st, estatesRemaining: st.estatesRemaining - 1, housesRemaining: st.housesRemaining + 4 };
  else st = { ...st, housesRemaining: st.housesRemaining - 1 };
  st = withTitle(st, pid, { buildLevel: toLevel });
  return ok(note(st, `seat ${id} builds ${sp.name} to level ${toLevel}`));
}

function doSellBuild(s: GameState, pid: number): ApplyResult {
  if (s.phase !== 'AWAIT_POST') return reject('WRONG_PHASE', `cannot SELL_BUILD in ${s.phase}`);
  const sp = BOARD[pid]; if (!sp || !sp.group) return reject('NO_SUCH_TITLE', `${pid}`);
  const t = s.titles[pid]; const id = s.current;
  if (!t || t.owner !== id) return reject('NOT_OWNER', `seat ${id} does not own ${sp.name}`);
  if (t.buildLevel <= 0) return reject('NOT_BUILT', `${sp.name} has no buildings`);
  // even sell: cannot drop below group max - 1
  const maxLevel = Math.max(...membersOf(sp.group).map((m) => s.titles[m]!.buildLevel));
  if (t.buildLevel < maxLevel) return reject('UNEVEN_BUILD', `must sell evenly across ${sp.group}`);
  return ok(note(sellBuildInternal(s, id, pid), `seat ${id} sells a building on ${sp.name}`));
}

function doMortgage(s: GameState, pid: number): ApplyResult {
  if (s.phase !== 'AWAIT_POST') return reject('WRONG_PHASE', `cannot MORTGAGE in ${s.phase}`);
  const sp = BOARD[pid]; if (!sp || !isTitled(sp)) return reject('NO_SUCH_TITLE', `${pid}`);
  const t = s.titles[pid]!; const id = s.current;
  if (t.owner !== id) return reject('NOT_OWNER', `seat ${id} does not own ${sp.name}`);
  if (t.mortgaged) return reject('ALREADY_MORTGAGED', `${sp.name}`);
  if (t.buildLevel > 0) return reject('HAS_BUILDINGS', `sell buildings on ${sp.name} first`);
  const v = mortgageValue(sp.base_price ?? 0);
  let st = withTitle(bankToSeat(s, id, v), pid, { mortgaged: true });
  return ok(note(st, `seat ${id} mortgages ${sp.name} for ${v}`));
}

function doUnmortgage(s: GameState, pid: number): ApplyResult {
  if (s.phase !== 'AWAIT_POST') return reject('WRONG_PHASE', `cannot UNMORTGAGE in ${s.phase}`);
  const sp = BOARD[pid]; if (!sp || !isTitled(sp)) return reject('NO_SUCH_TITLE', `${pid}`);
  const t = s.titles[pid]!; const id = s.current;
  if (t.owner !== id) return reject('NOT_OWNER', `seat ${id} does not own ${sp.name}`);
  if (!t.mortgaged) return reject('NOT_MORTGAGED', `${sp.name}`);
  const cost = unmortgageCost(sp.base_price ?? 0);
  if (seat(s, id).balance < cost) return reject('INSUFFICIENT_FUNDS', `need ${cost} to unmortgage`);
  let st = withSeat(s, id, { balance: seat(s, id).balance - cost });
  st = withTitle({ ...st, bankReserve: st.bankReserve + cost }, pid, { mortgaged: false });
  return ok(note(st, `seat ${id} lifts mortgage on ${sp.name} for ${cost}`));
}

function doEndTurn(s: GameState): ApplyResult {
  if (s.phase !== 'AWAIT_POST') return reject('WRONG_PHASE', `cannot END_TURN in ${s.phase}`);
  return ok(endTurnTransition(s));
}

/** Common end-of-turn: another roll if doubles pending, else next solvent seat. */
function endTurnTransition(s: GameState): GameState {
  let st = maybeGameOver(s);
  if (st.phase === 'GAME_OVER') return st;
  const cur = seat(st, st.current);
  if (st.doublesPending && !cur.bankrupt && !cur.inHolding) {
    return { ...st, phase: 'AWAIT_ROLL', doublesPending: false };
  }
  // advance to the next solvent seat
  const order = st.seats.map((x) => x.id);
  let next = st.current;
  for (let i = 1; i <= order.length; i++) {
    const cand = (st.current + i) % order.length;
    if (!seat(st, cand).bankrupt) { next = cand; break; }
  }
  return { ...st, current: next, phase: 'AWAIT_ROLL', doublesPending: false, doublesCount: 0, turnIndex: st.turnIndex + 1 };
}
