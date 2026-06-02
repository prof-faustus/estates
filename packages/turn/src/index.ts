/**
 * @estates/turn — cooperative/timeout default branches + the turn driver.
 *
 * Every actionable FSM state has a cooperative transition AND a pre-signed
 * default (timeout) branch. The default branch is broadcastable only after a
 * RELATIVE maturity window, expressed purely as `nSequence` (relative
 * locktime) — never CLTV/CSV. The window/`nLockTime` here is the data the
 * Phase-3 tx layer binds into the on-chain default-branch transaction.
 *
 * `defaultActionFor` gives the rules §7 default for the current phase;
 * `driveTurn` runs one full turn cooperatively, falling back to the default
 * when a seat's decision is absent (a timeout).
 */
import { loadParams, type EstatesParams } from '@estates/params';
import { apply, netWorth, type GameState, type Action, type ApplyResult, type Phase } from '@estates/engine';

const P: EstatesParams = loadParams();

/** Relative-locktime maturity for a default branch (nSequence), in blocks. */
export interface Maturity {
  readonly kind: 'relative';
  readonly nSequenceBlocks: number;
}

/** The default (timeout) maturity window for any per-turn actionable state. */
export function maturityFor(_phase: Phase): Maturity {
  return { kind: 'relative', nSequenceBlocks: P.timeouts.decision_blocks };
}

/**
 * The rules §7 default action for the current phase:
 *   AWAIT_ROLL → FORFEIT (turn forfeited, no move)
 *   AWAIT_BUY  → DECLINE (property declined → bank unsold / auction)
 *   AWAIT_TAX  → PAY_TAX with the LESSER of flat vs percent
 *   AWAIT_POST → END_TURN
 */
export function defaultActionFor(s: GameState): Action {
  switch (s.phase) {
    case 'AWAIT_ROLL': return { type: 'FORFEIT' };
    case 'AWAIT_BUY': return { type: 'DECLINE' };
    case 'AWAIT_TAX': {
      const t = P.taxes['income_levy']!;
      const percent = Math.round(netWorth(s, s.current) * (t.percent_of_worth ?? 0));
      return { type: 'PAY_TAX', choice: percent < t.flat ? 'percent' : 'flat' };
    }
    case 'AWAIT_POST': return { type: 'END_TURN' };
    case 'GAME_OVER': throw new Error('no default action in GAME_OVER');
  }
}

/** Apply the current phase's timeout default branch. */
export function applyTimeout(s: GameState): ApplyResult {
  return apply(s, defaultActionFor(s));
}

/**
 * A seat's decision for the current state, or `null` to take the default
 * (a timeout). Receives the current state and the active seat id.
 */
export type Decider = (s: GameState, seat: number) => Action | null;

export interface TurnTrace {
  readonly state: GameState;
  readonly steps: readonly { action: Action; byTimeout: boolean }[];
}

/**
 * Drive the game forward one full turn: repeatedly apply the active seat's
 * cooperative decision (or the default branch on timeout) until the active
 * seat changes or the game ends. Rejected cooperative actions fall back to the
 * default branch so the turn always makes progress (liveness).
 */
export function driveTurn(s: GameState, decide: Decider, maxSteps = 64): TurnTrace {
  const startSeat = s.current;
  const steps: { action: Action; byTimeout: boolean }[] = [];
  let st = s;
  for (let i = 0; i < maxSteps; i++) {
    if (st.phase === 'GAME_OVER') break;
    const proposed = decide(st, st.current);
    let action = proposed;
    let byTimeout = false;
    if (action === null) { action = defaultActionFor(st); byTimeout = true; }
    let r = apply(st, action);
    if (!r.ok) { // illegal cooperative action → fall back to the default branch
      action = defaultActionFor(st); byTimeout = true;
      r = apply(st, action);
      if (!r.ok) break; // default itself illegal (shouldn't happen) — stop
    }
    steps.push({ action, byTimeout });
    st = r.state;
    if (st.current !== startSeat || st.phase === 'GAME_OVER') break;
  }
  return { state: st, steps };
}

/** Drive whole turns until the game ends or `maxTurns` is reached. */
export function driveGame(s: GameState, decide: Decider, maxTurns = 1000): GameState {
  let st = s;
  for (let i = 0; i < maxTurns && st.phase !== 'GAME_OVER'; i++) {
    const before = st.turnIndex;
    st = driveTurn(st, decide).state;
    if (st.turnIndex === before && st.phase !== 'GAME_OVER') break; // no progress guard
  }
  return st;
}
