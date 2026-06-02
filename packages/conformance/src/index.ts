/**
 * @estates/conformance — vector types + canonical state hashing.
 *
 * A vector is one (state, action) → expected pair. `expected` is either the
 * canonical hash of the resulting state (legality SoT) or a typed rejection
 * code. The `log` field is excluded from the hash (advisory text only).
 */
import { createHash } from 'node:crypto';
import type { GameState, Action, RejectCode } from '@estates/engine';

export interface Vector {
  readonly id: string;
  readonly description: string;
  readonly state: GameState;
  readonly action: Action;
  readonly expected:
    | { readonly ok: true; readonly stateHash: string }
    | { readonly ok: false; readonly code: RejectCode };
}

export interface VectorFile {
  readonly params_version: string;
  readonly generated_by: string;
  readonly vectors: readonly Vector[];
}

/** Stable, key-sorted JSON so hashing is order-independent. */
function stable(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stable(obj[k])}`).join(',')}}`;
}

/** Canonical projection of a state for hashing: drop the advisory `log`. */
export function canonicalState(s: GameState): Omit<GameState, 'log'> {
  const { log: _log, ...rest } = s;
  void _log;
  return rest;
}

export function hashState(s: GameState): string {
  return createHash('sha256').update(stable(canonicalState(s))).digest('hex');
}
