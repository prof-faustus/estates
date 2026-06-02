/**
 * @estates/bot — bot policies as turn-driver Deciders (rules §8).
 *
 * A policy maps the current state to the active seat's action: roll (dice from
 * the beacon-backed source), buy/decline, choose the cheaper income levy, build
 * on full groups, else end the turn. Deterministic given (state, policy, dice),
 * so bot play is auditable/replayable like everything else.
 *
 * Each bot carries an INDEPENDENT secp256k1 signing identity (own keys). In a
 * trustless game the bot runs as its own process/host; in-process use here is
 * for offline practice only (explicitly non-trustless).
 */
import { loadParams, buildCost, type EstatesParams } from '@estates/params';
import { netWorth, type GameState, type Action } from '@estates/engine';
import { type Decider } from '@estates/turn';
import { genKeyPair, type KeyPair } from '@estates/trade';

const P: EstatesParams = loadParams();

export type Policy = 'cautious' | 'balanced' | 'aggressive';

interface Knobs { readonly buyBuffer: number; readonly buildBuffer: number; }
const KNOBS: Record<Policy, Knobs> = {
  cautious: { buyBuffer: 600, buildBuffer: 800 },
  balanced: { buyBuffer: 300, buildBuffer: 400 },
  aggressive: { buyBuffer: 0, buildBuffer: 0 },
};

/** A source of dice for ROLL actions — the beacon in real play. */
export type DiceSource = (s: GameState) => readonly [number, number];

const seat = (s: GameState) => s.seats[s.current]!;

function ownsFullGroup(s: GameState, seatId: number, group: string): boolean {
  const m = P.groups[group]?.member_property_ids ?? [];
  return m.length > 0 && m.every((id) => s.titles[id]?.owner === seatId);
}

/** Lowest-level buildable property in an owned, unmortgaged full group (even build). */
function buildTarget(s: GameState, seatId: number): number | null {
  for (const [name, g] of Object.entries(P.groups)) {
    if (g.build_cost <= 0) continue;              // rails/utilities don't build
    if (!ownsFullGroup(s, seatId, name)) continue;
    if (g.member_property_ids.some((id) => s.titles[id]!.mortgaged)) continue;
    const levels = g.member_property_ids.map((id) => s.titles[id]!.buildLevel);
    const min = Math.min(...levels);
    if (min >= 5) continue;
    const target = g.member_property_ids.find((id) => s.titles[id]!.buildLevel === min);
    if (target !== undefined) return target;
  }
  return null;
}

/** Build a Decider for a policy, drawing dice from `dice`. */
export function makeBotDecider(policy: Policy, dice: DiceSource): Decider {
  const k = KNOBS[policy];
  return (s: GameState): Action => {
    switch (s.phase) {
      case 'AWAIT_ROLL':
        return { type: 'ROLL', dice: dice(s) };

      case 'AWAIT_BUY': {
        const price = P.board[s.pendingTitle!]?.base_price ?? 0;
        return seat(s).balance - price >= k.buyBuffer ? { type: 'BUY' } : { type: 'DECLINE' };
      }

      case 'AWAIT_TAX': {
        const t = P.taxes['income_levy']!;
        const percent = Math.round(netWorth(s, s.current) * (t.percent_of_worth ?? 0));
        return { type: 'PAY_TAX', choice: percent < t.flat ? 'percent' : 'flat' };
      }

      case 'AWAIT_POST': {
        const target = buildTarget(s, s.current);
        if (target !== null) {
          const cost = buildCost(P.board[target]!.group!);
          if (seat(s).balance - cost >= k.buildBuffer) return { type: 'BUILD', propertyId: target };
        }
        return { type: 'END_TURN' };
      }

      case 'GAME_OVER':
        return { type: 'END_TURN' };
    }
  };
}

/** A bot: a policy + its independent signing identity. */
export interface Bot { readonly policy: Policy; readonly keys: KeyPair; readonly decide: Decider; }

export function makeBot(policy: Policy, dice: DiceSource): Bot {
  return { policy, keys: genKeyPair(), decide: makeBotDecider(policy, dice) };
}

/**
 * Deterministic dice source (mulberry32 PRNG) for offline practice / tests.
 * Real games draw dice from @estates/beacon.
 */
export function seededDice(seed: number): DiceSource {
  let a = seed >>> 0;
  const next = (): number => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return () => [1 + Math.floor(next() * 6), 1 + Math.floor(next() * 6)] as const;
}
