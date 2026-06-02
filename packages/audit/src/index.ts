/**
 * @estates/audit — record + independently verify a whole game (R7).
 *
 * A transcript is the genesis config plus an ordered list of entries: each roll
 * carries the seats' beacon reveals (and the claimed dice); each non-roll entry
 * carries the action. `audit` starts from a fresh engine, RE-DERIVES every dice
 * roll from the reveals (chaining prev_beacon), RE-CHECKS every action through
 * the pure engine, and confirms the final state hash. Any tampering — a forged
 * die, an illegal action, a swapped reveal, a wrong final hash — is rejected.
 *
 * This is the proof that an ESTATES game reconstructs and verifies from chain
 * data alone (design spec R7), with no trust in the player who produced it.
 */
import { initialState, apply, type GameState, type Action, type EngineConfig } from '@estates/engine';
import { roll, ZERO_BEACON, type PartyReveal } from '@estates/beacon';
import { hashState } from '@estates/conformance';
import { loadParams } from '@estates/params';

export type Entry =
  | { readonly kind: 'roll'; readonly reveals: readonly { seat: number; secret: string }[]; readonly dice: readonly [number, number] }
  | { readonly kind: 'action'; readonly action: Action };

export interface GameTranscript {
  readonly params_version: string;
  readonly genesis: EngineConfig;
  readonly entries: readonly Entry[];
  readonly finalHash: string;
}

const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const fromHex = (h: string): Uint8Array => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

/** A non-roll decision for the active seat (rolls are produced by the beacon). */
export type Decide = (s: GameState) => Action;
/** Per-roll secret source: (rollIndex, seat) → ≥32-byte secret. */
export type SecretSource = (rollIndex: number, seat: number) => Uint8Array;

/**
 * Drive a full game, recording a verifiable transcript. Rolls are produced by
 * the beacon from the secret source; non-roll actions come from `decide`.
 */
export function recordGame(genesis: EngineConfig, decide: Decide, secret: SecretSource, maxSteps = 5000): GameTranscript {
  let s = initialState(genesis);
  let prev = ZERO_BEACON;
  let rollIndex = 0;
  const entries: Entry[] = [];

  for (let i = 0; i < maxSteps && s.phase !== 'GAME_OVER'; i++) {
    if (s.phase === 'AWAIT_ROLL') {
      const reveals: PartyReveal[] = s.seats.filter((p) => !p.bankrupt).map((p) => ({ seat: p.id, secret: secret(rollIndex, p.id) }));
      const br = roll(reveals, s.turnIndex, prev);
      const r = apply(s, { type: 'ROLL', dice: br.dice });
      if (!r.ok) break;
      entries.push({ kind: 'roll', reveals: reveals.map((rv) => ({ seat: rv.seat, secret: toHex(rv.secret) })), dice: br.dice });
      prev = br.beacon;
      rollIndex++;
      s = r.state;
    } else {
      const action = decide(s);
      const r = apply(s, action);
      if (!r.ok) break;
      entries.push({ kind: 'action', action });
      s = r.state;
    }
  }
  return { params_version: loadParams().params_version, genesis, entries, finalHash: hashState(s) };
}

export interface AuditResult {
  readonly ok: boolean;
  readonly steps: number;
  readonly rollsVerified: number;
  readonly finalHash: string;
  readonly reason: string;
}

/** Independently reconstruct + verify a transcript. */
export function audit(t: GameTranscript): AuditResult {
  if (t.params_version !== loadParams().params_version) {
    return { ok: false, steps: 0, rollsVerified: 0, finalHash: '', reason: `params version mismatch: ${t.params_version}` };
  }
  let s = initialState(t.genesis);
  let prev = ZERO_BEACON;
  let rolls = 0;

  for (let i = 0; i < t.entries.length; i++) {
    const e = t.entries[i]!;
    if (e.kind === 'roll') {
      // re-derive the dice from the reveals; reject if they don't match the claim
      const reveals: PartyReveal[] = e.reveals.map((rv) => ({ seat: rv.seat, secret: fromHex(rv.secret) }));
      const br = roll(reveals, s.turnIndex, prev);
      if (br.dice[0] !== e.dice[0] || br.dice[1] !== e.dice[1]) {
        return { ok: false, steps: i, rollsVerified: rolls, finalHash: '', reason: `entry ${i}: dice ${e.dice} do not match the beacon (recomputed ${br.dice}) — forged roll` };
      }
      const r = apply(s, { type: 'ROLL', dice: br.dice });
      if (!r.ok) return { ok: false, steps: i, rollsVerified: rolls, finalHash: '', reason: `entry ${i}: ROLL rejected (${r.code})` };
      prev = br.beacon; rolls++; s = r.state;
    } else {
      const r = apply(s, e.action);
      if (!r.ok) return { ok: false, steps: i, rollsVerified: rolls, finalHash: '', reason: `entry ${i}: ${e.action.type} rejected (${r.code}) — illegal action` };
      s = r.state;
    }
  }

  const finalHash = hashState(s);
  if (finalHash !== t.finalHash) {
    return { ok: false, steps: t.entries.length, rollsVerified: rolls, finalHash, reason: 'final state hash mismatch — transcript does not reconstruct the claimed result' };
  }
  return { ok: true, steps: t.entries.length, rollsVerified: rolls, finalHash, reason: `reconstructed ${t.entries.length} entries; ${rolls} rolls verified against the beacon; final hash confirmed` };
}
