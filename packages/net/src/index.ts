/**
 * @estates/net — peer transport (C7) + deterministic peer session.
 *
 * The relay is an UNTRUSTED, opaque fan-out: it orders and rebroadcasts byte
 * payloads and never interprets them. Canonical game state is derived purely by
 * replaying the ordered transcript through the pure engine (the same path
 * @estates/audit verifies), so a malicious relay can at worst censor/reorder —
 * it cannot forge state. Peers reconnect by replaying history.
 *
 * The in-memory relay here models the production HTTP + Server-Sent-Events
 * relay (mirrors @bsv-poker/app-services RelayClient: subscribe replays history
 * then streams live; publish fans out). Wire bytes are JSON-encoded envelopes.
 */
import { initialState, apply, type GameState, type EngineConfig, type Action } from '@estates/engine';
import { verifyRollEntry, ZERO_BEACON } from '@estates/beacon';
import { hashState } from '@estates/conformance';
import type { Entry } from '@estates/audit';

export interface Envelope { readonly seq: number; readonly entry: Entry; }
export type RelayHandler = (e: Envelope) => void;

// ---- fail-closed decode boundary (the relay is fully untrusted) ---------------
// The relay fans out arbitrary bytes from arbitrary peers. A payload may be
// non-JSON, a JSON scalar/null, or a validly-shaped-but-hostile entry (non-array
// commits, non-hex secrets that throw in fromHex, a 1e12 seq, a 10⁶-entry commit
// list to exhaust memory). `decodeEnvelope` validates EVERY field and returns
// null on anything unexpected; it NEVER throws. A signature/seq is no excuse to
// skip it — it runs before any value reaches the engine or fromHex.
const NET_MAX_SEQ = 1_000_000_000;   // ordered-log ceiling (no 1e12 seq)
const NET_MAX_SEATS = 8;             // bounds commit/reveal list length + seat ids
const NET_PROP_MAX = 39;             // board spaces 0..39
const NET_HEX64 = 64;                // 32-byte commitment/secret as hex
const isInt0 = (x: unknown, hi: number): x is number => typeof x === 'number' && Number.isInteger(x) && x >= 0 && x <= hi;
const isHexLen = (x: unknown, n: number): x is string => typeof x === 'string' && x.length === n && /^[0-9a-fA-F]+$/.test(x);

function isAction(x: unknown): x is Action {
  if (!x || typeof x !== 'object') return false;
  const a = x as Record<string, unknown>;
  switch (a.type) {
    case 'BUY': case 'DECLINE': case 'FORFEIT': case 'END_TURN': return true;
    case 'PAY_TAX': return a.choice === 'flat' || a.choice === 'percent';
    case 'BUILD': case 'SELL_BUILD': case 'MORTGAGE': case 'UNMORTGAGE': return isInt0(a.propertyId, NET_PROP_MAX);
    case 'LEAVE': return isInt0(a.seat, NET_MAX_SEATS - 1);
    case 'ROLL': return Array.isArray(a.dice) && a.dice.length === 2 && isInt0(a.dice[0], 6) && (a.dice[0] as number) >= 1 && isInt0(a.dice[1], 6) && (a.dice[1] as number) >= 1;
    default: return false;
  }
}
function isSeatHexList(x: unknown, field: 'c' | 'secret'): boolean {
  if (!Array.isArray(x) || x.length > NET_MAX_SEATS) return false;
  for (const it of x) {
    if (!it || typeof it !== 'object') return false;
    const o = it as Record<string, unknown>;
    if (!isInt0(o.seat, NET_MAX_SEATS - 1) || !isHexLen(o[field], NET_HEX64)) return false;
  }
  return true;
}
function isEntry(x: unknown): x is Entry {
  if (!x || typeof x !== 'object') return false;
  const e = x as Record<string, unknown>;
  if (e.kind === 'action') return isAction(e.action);
  if (e.kind !== 'roll') return false;
  return isSeatHexList(e.commits, 'c') && isSeatHexList(e.reveals, 'secret')
    && Array.isArray(e.dice) && e.dice.length === 2 && isInt0(e.dice[0], 6) && (e.dice[0] as number) >= 1 && isInt0(e.dice[1], 6) && (e.dice[1] as number) >= 1;
}
/** Total: decode a relay payload to a valid Envelope, or null. Never throws. */
export function decodeEnvelope(payload: Uint8Array): Envelope | null {
  if (!(payload instanceof Uint8Array) || payload.length === 0 || payload.length > (1 << 20)) return null;
  let o: unknown;
  try { o = JSON.parse(new TextDecoder().decode(payload)); } catch { return null; }
  if (!o || typeof o !== 'object') return null;
  const env = o as Record<string, unknown>;
  if (!isInt0(env.seq, NET_MAX_SEQ) || !isEntry(env.entry)) return null;
  return { seq: env.seq, entry: env.entry };
}

/** Opaque relay contract: order + fan out byte payloads; never interpret them. */
export interface Relay {
  publish(payload: Uint8Array): number;                       // returns the assigned seq
  subscribe(onMessage: (payload: Uint8Array) => void, fromSeq?: number): () => void;
  history(): Uint8Array[];
}

/** In-memory relay (test double + reference for the HTTP+SSE relay's contract). */
export class InMemoryRelay implements Relay {
  private log: Uint8Array[] = [];
  private subs = new Set<(p: Uint8Array) => void>();

  publish(payload: Uint8Array): number {
    const seq = this.log.length;
    this.log.push(payload);
    // a throwing subscriber must not break fan-out to the others, nor the publisher.
    for (const s of this.subs) { try { s(payload); } catch { /* isolate a bad subscriber */ } }
    return seq;
  }

  /** Replay history from `fromSeq` (SSE catch-up), then stream live. */
  subscribe(onMessage: (p: Uint8Array) => void, fromSeq = 0): () => void {
    const lo = Number.isInteger(fromSeq) && fromSeq >= 0 ? fromSeq : 0; // bound the catch-up cursor
    for (let i = lo; i < this.log.length; i++) { try { onMessage(this.log[i]!); } catch { /* isolate */ } }
    this.subs.add(onMessage);
    return () => this.subs.delete(onMessage);
  }

  history(): Uint8Array[] { return [...this.log]; }
}

const enc = (e: Envelope): Uint8Array => new TextEncoder().encode(JSON.stringify(e));
const fromHex = (h: string): Uint8Array => { if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex'); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

/**
 * A peer's deterministic view. Applies the ordered transcript; a roll's dice
 * are re-derived from its reveals (so every peer computes the same roll), and
 * out-of-order or illegal entries are ignored — state can only advance through
 * the engine.
 */
export class PeerSession {
  state: GameState;
  private prevBeacon = ZERO_BEACON;
  private nextSeq = 0;

  constructor(genesis: EngineConfig) { this.state = initialState(genesis); }

  /** Apply one VALIDATED transcript entry. Total: returns false (state intact)
   *  on anything invalid; never throws (fromHex inputs are pre-validated hex, but
   *  the whole body is guarded for defence in depth). */
  private applyEntry(e: Entry): boolean {
    try {
      if (e.kind === 'roll') {
        // SAME verifier as @estates/audit (audit #4): commitments + participant set
        // + reveal openings + canonical dice — the live path is no longer laxer.
        const v = verifyRollEntry({
          commits: e.commits.map((c) => ({ seat: c.seat, c: fromHex(c.c) })),
          reveals: e.reveals.map((rv) => ({ seat: rv.seat, secret: fromHex(rv.secret) })),
          liveSeats: this.state.seats.filter((p) => !p.bankrupt).map((p) => p.id),
          turnIndex: this.state.turnIndex, prevBeacon: this.prevBeacon, claimedDice: e.dice,
        });
        if (!v.ok) return false; // forged / unverified roll
        const r = apply(this.state, { type: 'ROLL', dice: v.dice! });
        if (!r.ok) return false;
        this.prevBeacon = v.beacon!;
        this.state = r.state;
        return true;
      }
      const r = apply(this.state, e.action);
      if (!r.ok) return false;
      this.state = r.state;
      return true;
    } catch { return false; }
  }

  /** Ingest a relay payload, applying it iff it decodes AND is the next ordered
   *  entry. Total: a malformed / hostile / out-of-order payload returns false and
   *  never throws (so a hostile relay cannot crash the fan-out). */
  ingest(payload: Uint8Array): boolean {
    const env = decodeEnvelope(payload);
    if (!env) return false;                       // non-JSON / scalar / hostile entry
    if (env.seq !== this.nextSeq) return false;   // gap / replay — wait for order
    if (!this.applyEntry(env.entry)) return false;
    this.nextSeq++;
    return true;
  }

  /** Subscribe this peer to a relay (replays history, then streams live). */
  join(relay: Relay): () => void {
    return relay.subscribe((p) => { this.ingest(p); }, 0);
  }

  hash(): string { return hashState(this.state); }
}

/** Publish one entry to the relay as the next ordered envelope. */
export function broadcast(relay: Relay, seq: number, entry: Entry): number {
  return relay.publish(enc({ seq, entry }));
}
