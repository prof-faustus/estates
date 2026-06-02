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
import { initialState, apply, type GameState, type EngineConfig } from '@estates/engine';
import { roll, ZERO_BEACON, type PartyReveal } from '@estates/beacon';
import { hashState } from '@estates/conformance';
import type { Entry } from '@estates/audit';

export interface Envelope { readonly seq: number; readonly entry: Entry; }
export type RelayHandler = (e: Envelope) => void;

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
    for (const s of this.subs) s(payload);
    return seq;
  }

  /** Replay history from `fromSeq` (SSE catch-up), then stream live. */
  subscribe(onMessage: (p: Uint8Array) => void, fromSeq = 0): () => void {
    for (let i = fromSeq; i < this.log.length; i++) onMessage(this.log[i]!);
    this.subs.add(onMessage);
    return () => this.subs.delete(onMessage);
  }

  history(): Uint8Array[] { return [...this.log]; }
}

const enc = (e: Envelope): Uint8Array => new TextEncoder().encode(JSON.stringify(e));
const dec = (p: Uint8Array): Envelope => JSON.parse(new TextDecoder().decode(p)) as Envelope;
const fromHex = (h: string): Uint8Array => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

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

  /** Apply one transcript entry. Returns false (and leaves state) if invalid. */
  private applyEntry(e: Entry): boolean {
    if (e.kind === 'roll') {
      const reveals: PartyReveal[] = e.reveals.map((rv) => ({ seat: rv.seat, secret: fromHex(rv.secret) }));
      const br = roll(reveals, this.state.turnIndex, this.prevBeacon);
      if (br.dice[0] !== e.dice[0] || br.dice[1] !== e.dice[1]) return false; // forged roll
      const r = apply(this.state, { type: 'ROLL', dice: br.dice });
      if (!r.ok) return false;
      this.prevBeacon = br.beacon;
      this.state = r.state;
      return true;
    }
    const r = apply(this.state, e.action);
    if (!r.ok) return false;
    this.state = r.state;
    return true;
  }

  /** Ingest a relay payload, applying it iff it is the next ordered entry. */
  ingest(payload: Uint8Array): boolean {
    const env = dec(payload);
    if (env.seq !== this.nextSeq) return false; // gap / replay — wait for order
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
