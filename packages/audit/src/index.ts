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
import { roll, commit, verifyRollEntry, ZERO_BEACON, type PartyReveal } from '@estates/beacon';
import { hashState } from '@estates/conformance';
import { loadParams } from '@estates/params';
import { verifyManifest, verifyNoCrossGameReuse, type GameKeyManifest } from '@estates/keylife';

export interface KeyLifecycleResult { readonly ok: boolean; readonly reason: string }

/**
 * KEY-LIFECYCLE AUDIT (audit finding: "every game key valid for at most one
 * game"). Given the signed key manifests of a sequence of games, this rejects:
 *   - any manifest that is malformed / unsigned / tampered (verifyManifest), and
 *   - any key reused across two different games (verifyNoCrossGameReuse).
 * A game's transcript is only auditable if its keys pass this lifecycle check, so
 * a key that outlives its one game makes the whole audit FAIL. Total: never throws.
 */
export function auditKeyLifecycle(manifests: readonly GameKeyManifest[]): KeyLifecycleResult {
  if (!Array.isArray(manifests) || manifests.length === 0) return { ok: false, reason: 'no key manifests provided' };
  for (let i = 0; i < manifests.length; i++) {
    const v = verifyManifest(manifests[i]);
    if (!v.ok) return { ok: false, reason: `manifest ${i}: ${v.reason}` };
  }
  const reuse = verifyNoCrossGameReuse(manifests);
  if (!reuse.ok) return { ok: false, reason: reuse.reason };
  return { ok: true, reason: `key lifecycle verified across ${manifests.length} game(s): every key serves at most one game` };
}

export type Entry =
  | {
      readonly kind: 'roll';
      readonly commits: readonly { seat: number; c: string }[]; // commitments, published BEFORE reveals
      readonly reveals: readonly { seat: number; secret: string }[];
      readonly dice: readonly [number, number];
    }
  | { readonly kind: 'action'; readonly action: Action };

export interface GameTranscript {
  readonly params_version: string;
  readonly genesis: EngineConfig;
  readonly entries: readonly Entry[];
  readonly finalHash: string;
}

const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const fromHex = (h: string): Uint8Array => { if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex'); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

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
      entries.push({
        kind: 'roll',
        commits: reveals.map((rv) => ({ seat: rv.seat, c: toHex(commit(rv.secret)) })), // one per live seat
        reveals: reveals.map((rv) => ({ seat: rv.seat, secret: toHex(rv.secret) })),
        dice: br.dice,
      });
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

// A transcript reconstructed "from chain alone" is UNTRUSTED. audit() must be
// TOTAL — never throw, never allocate on an attacker-chosen genesis. A 1e9-seat
// genesis would make initialState allocate before any try/catch could help, and a
// bad-hex commit/reveal would make fromHex throw out of the loop, so both are
// guarded explicitly here.
const AUDIT_MAX_SEATS = 8;
function validGenesis(g: unknown): g is EngineConfig {
  if (!g || typeof g !== 'object') return false;
  const c = g as Record<string, unknown>;
  return (c.network === 'regtest' || c.network === 'testnet' || c.network === 'mainnet')
    && typeof c.seatCount === 'number' && Number.isInteger(c.seatCount) && c.seatCount >= 2 && c.seatCount <= AUDIT_MAX_SEATS
    && typeof c.bankReserve === 'number' && Number.isInteger(c.bankReserve) && c.bankReserve >= 0 && c.bankReserve <= Number.MAX_SAFE_INTEGER;
}

/** Independently reconstruct + verify a transcript. Total: any malformed /
 *  hostile transcript is a clean {ok:false}, never a throw or an OOM. */
export function audit(t: GameTranscript, opts?: { manifests?: readonly GameKeyManifest[]; requireManifests?: boolean }): AuditResult {
  const fail = (reason: string, steps = 0, rollsVerified = 0, finalHash = ''): AuditResult => ({ ok: false, steps, rollsVerified, finalHash, reason });
  if (!t || typeof t !== 'object') return fail('transcript is not an object');
  if (t.params_version !== loadParams().params_version) return fail(`params version mismatch: ${t.params_version}`);
  if (!validGenesis(t.genesis)) return fail('genesis is malformed or out of range (seatCount/bankReserve/network)');
  if (!Array.isArray(t.entries)) return fail('entries is not an array');
  // KEY-LIFECYCLE GATE — MANDATORY by default. A production audit REQUIRES the game's
  // signed one-game key manifest(s): the audit FAILS unless every key is valid
  // (manifest signed + no cross-game reuse). A game whose keys are unaccounted for, or
  // that outlive their one game, is not auditable. Only reconstruction-only unit tests
  // opt out with requireManifests:false.
  const requireManifests = opts?.requireManifests ?? true;
  if (requireManifests && (!opts?.manifests || opts.manifests.length === 0)) {
    return fail('key lifecycle: a signed one-game key manifest is MANDATORY for a production audit (none supplied)');
  }
  if (opts?.manifests) {
    const kl = auditKeyLifecycle(opts.manifests);
    if (!kl.ok) return fail(`key lifecycle: ${kl.reason}`);
  }

  let s = initialState(t.genesis);
  let prev = ZERO_BEACON;
  let rolls = 0;

  try {
    for (let i = 0; i < t.entries.length; i++) {
      const e = t.entries[i]!;
      if (e && e.kind === 'roll') {
        if (!Array.isArray(e.commits) || !Array.isArray(e.reveals)) return fail(`entry ${i}: roll commits/reveals not arrays`, i, rolls);
        // THE shared roll verifier (same logic @estates/net uses — audit #4).
        // fromHex throws on bad hex; the surrounding try makes that a clean reject.
        const v = verifyRollEntry({
          commits: e.commits.map((c: { seat: number; c: string }) => ({ seat: c.seat, c: fromHex(c.c) })),
          reveals: e.reveals.map((rv: { seat: number; secret: string }) => ({ seat: rv.seat, secret: fromHex(rv.secret) })),
          liveSeats: s.seats.filter((p) => !p.bankrupt).map((p) => p.id),
          turnIndex: s.turnIndex, prevBeacon: prev, claimedDice: e.dice,
        });
        if (!v.ok) return fail(`entry ${i}: ${v.reason}`, i, rolls);
        const r = apply(s, { type: 'ROLL', dice: v.dice! });
        if (!r.ok) return fail(`entry ${i}: ROLL rejected (${r.code})`, i, rolls);
        prev = v.beacon!; rolls++; s = r.state;
      } else if (e && e.kind === 'action') {
        const r = apply(s, e.action);
        if (!r.ok) return fail(`entry ${i}: ${e.action?.type} rejected (${r.code}) — illegal action`, i, rolls);
        s = r.state;
      } else {
        return fail(`entry ${i}: unknown entry kind`, i, rolls);
      }
    }
  } catch (err) {
    return fail(`entry processing failed: ${(err as Error).message}`, rolls, rolls);
  }

  const finalHash = hashState(s);
  if (finalHash !== t.finalHash) {
    return { ok: false, steps: t.entries.length, rollsVerified: rolls, finalHash, reason: 'final state hash mismatch — transcript does not reconstruct the claimed result' };
  }
  return { ok: true, steps: t.entries.length, rollsVerified: rolls, finalHash, reason: `reconstructed ${t.entries.length} entries; ${rolls} rolls verified against the beacon; final hash confirmed` };
}
