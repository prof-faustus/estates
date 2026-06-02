/**
 * Offline-practice game controller for the ESTATES web client.
 *
 * Runs the pure @estates/engine in-browser (keys never leave the client). Dice
 * use Web Crypto here for offline practice; trustless play draws them from the
 * commit→reveal beacon (@estates/beacon) — this mode is explicitly NON-trustless.
 * Bot seats use a simple in-browser heuristic; the canonical bots live in
 * @estates/bot for the trustless/server path.
 */
import { initialState, apply, legalActions, netWorth, type GameState, type Action } from '@estates/engine';
import { loadParams } from '@estates/params';

export const P = loadParams();
export const SEAT_COLORS = ['#e6194b', '#3cb44b', '#4363d8', '#f58231', '#911eb4', '#42d4f4'];
export const HUMAN = 0;

export function newGame(seatCount = 3): GameState {
  return initialState({ network: 'regtest', seatCount, bankReserve: 1_000_000 });
}

export function rollDice(): [number, number] {
  const b = new Uint8Array(2);
  crypto.getRandomValues(b);
  return [1 + (b[0]! % 6), 1 + (b[1]! % 6)];
}

export function legal(s: GameState): Action['type'][] {
  return legalActions(s);
}

/** In-browser bot heuristic (offline practice only). */
function botAction(s: GameState): Action {
  switch (s.phase) {
    case 'AWAIT_ROLL': return { type: 'ROLL', dice: rollDice() };
    case 'AWAIT_BUY': {
      const price = P.board[s.pendingTitle!]?.base_price ?? 0;
      return s.seats[s.current]!.balance - price >= 200 ? { type: 'BUY' } : { type: 'DECLINE' };
    }
    case 'AWAIT_TAX': {
      const t = P.taxes['income_levy']!;
      const pct = Math.round(netWorth(s, s.current) * (t.percent_of_worth ?? 0));
      return { type: 'PAY_TAX', choice: pct < t.flat ? 'percent' : 'flat' };
    }
    default: return { type: 'END_TURN' };
  }
}

/** Advance bot seats until it is the human's turn to roll, or the game ends. */
export function runBots(s: GameState): GameState {
  let st = s;
  let guard = 0;
  while (st.phase !== 'GAME_OVER' && !(st.current === HUMAN && st.phase === 'AWAIT_ROLL') && guard++ < 1000) {
    const r = apply(st, botAction(st));
    if (!r.ok) break;
    st = r.state;
  }
  return st;
}

/** Apply a human action, then let the bots play out their turns. */
export function humanDispatch(s: GameState, a: Action): GameState {
  const r = apply(s, a);
  if (!r.ok) return s;
  let st = r.state;
  if (st.phase !== 'GAME_OVER' && st.current !== HUMAN) st = runBots(st);
  return st;
}

/** Titles owned by a seat, with their board space + on-NFT state. */
export function ownedBy(s: GameState, seatId: number) {
  return P.board
    .filter((sp) => (sp.type === 'property' || sp.type === 'station' || sp.type === 'utility') && s.titles[sp.id]?.owner === seatId)
    .map((sp) => ({ space: sp, title: s.titles[sp.id]! }));
}

export const GROUP_COLOR: Record<string, string> = {
  Sienna: '#8d5524', Sky: '#aee1f9', Rose: '#f7a8c4', Amber: '#f5a623',
  Crimson: '#d0021b', Gold: '#f8e71c', Viridian: '#2e7d32', Indigo: '#283593',
  Rails: '#555', Utilities: '#bbb',
};
