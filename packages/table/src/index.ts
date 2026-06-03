/**
 * @estates/table — the multiplayer table controller.
 *
 * Waiting room first. The human host picks the player count + network, then
 * WAITS for real people to claim seats or OPTIONALLY adds a simulated player
 * (test only) to fill a seat. THE GAME STARTS ONLY WHEN THE HUMAN HOST CALLS
 * start() — never automatically, never by a bot. After start, every action is
 * broadcast and applied by ALL peers in the relay's global order, so the pure
 * engine keeps every client in lockstep. Bots only auto-play their OWN seat and
 * never start a game.
 */
import { initialState, apply, netWorth, type GameState, type Action, type EngineConfig } from '@estates/engine';
import { loadParams } from '@estates/params';
import { HttpRelay, InMemoryRelay, type Relay } from '@estates/chat';
import { genIdentity, identityFrom, signData, verifyData, type Identity } from '@estates/channel';

export const P = loadParams();
export { identityFrom, type Identity };

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
function fromHex(h: string): Uint8Array {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}
const encJSON = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
/** The canonical bytes a message signature commits to (the message + the author). */
const signedBytes = (m: Msg, signPub: string): Uint8Array => encJSON({ ...m, signPub });
export type NetworkMode = EngineConfig['network'];

export function rollDice(): [number, number] {
  const b = new Uint8Array(2);
  crypto.getRandomValues(b);
  return [1 + (b[0]! % 6), 1 + (b[1]! % 6)];
}
/** Built-in transport — NO url is ever typed by a user (Bitmessage-style). */
export const DEFAULT_RELAY = 'http://127.0.0.1:8788';
export const LOBBY_CHANNEL = 'estates-lobby-v1';
export function makeRelay(channel: string, url: string = DEFAULT_RELAY): Relay {
  return new HttpRelay(url, channel);
}

/** A Bitmessage-style address (hex) for an identity or a table. */
export function newAddress(): string {
  const b = new Uint8Array(20);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

// --- properties the active seat may build on / mortgage right now ------------
export function buildable(s: GameState, seat: number): number[] {
  const out: number[] = [];
  for (const [name, g] of Object.entries(P.groups)) {
    if (g.build_cost <= 0) continue;
    const ids = g.member_property_ids;
    if (!ids.every((id) => s.titles[id]?.owner === seat)) continue;
    if (ids.some((id) => s.titles[id]!.mortgaged)) continue;
    const min = Math.min(...ids.map((id) => s.titles[id]!.buildLevel));
    for (const id of ids) if (s.titles[id]!.buildLevel === min && min < 5) out.push(id);
  }
  return out;
}
export function mortgageable(s: GameState, seat: number): number[] {
  return P.board.filter((sp) => s.titles[sp.id]?.owner === seat && !s.titles[sp.id]!.mortgaged && s.titles[sp.id]!.buildLevel === 0).map((sp) => sp.id);
}
export function unmortgageable(s: GameState, seat: number): number[] {
  return P.board.filter((sp) => s.titles[sp.id]?.owner === seat && s.titles[sp.id]!.mortgaged).map((sp) => sp.id);
}

/** The most recently drawn Fate/Treasury card text (to show on the table). */
export function lastCard(s: GameState): string | null {
  for (let i = s.log.length - 1; i >= 0; i--) {
    const m = s.log[i]!.match(/draws (Fate|Treasury): (.+)$/);
    if (m) return `${m[1]} — ${m[2]}`;
  }
  return null;
}

// --- Bitmessage-style lobby discovery: hosts announce, clients list ----------
export interface OpenTable { addr: string; name: string; maxSeats: number; network: NetworkMode; host: string; ts: number }
export class LobbyClient {
  readonly tables = new Map<string, OpenTable>();
  private relay: Relay;
  private onUpdate: () => void;
  constructor(relay: Relay, onUpdate: () => void) { this.relay = relay; this.onUpdate = onUpdate; }
  connect(): void {
    this.relay.subscribe((p) => {
      try {
        const m = JSON.parse(new TextDecoder().decode(p)) as { kind: string } & OpenTable;
        if (m.kind === 'announce') { this.tables.set(m.addr, { addr: m.addr, name: m.name, maxSeats: m.maxSeats, network: m.network, host: m.host, ts: m.ts }); this.onUpdate(); }
      } catch { /* opaque */ }
    });
  }
  announce(t: OpenTable): void { this.relay.publish(new TextEncoder().encode(JSON.stringify({ kind: 'announce', ...t }))); }
  list(): OpenTable[] { return [...this.tables.values()].sort((a, b) => b.ts - a.ts); }
}

type Msg =
  | { kind: 'table'; maxSeats: number; network: NetworkMode; host: string }
  | { kind: 'seat'; seat: number; who: string; name: string; bot: boolean }
  | { kind: 'start'; by: string; config: EngineConfig; seatMap: { seat: number; who: string }[] }
  | { kind: 'action'; action: Action };
/** A published, SIGNED message: the player's Ed25519 signing pub + signature over
 *  the canonical message bind the author to the protocol (audit #1/#2). */
type Signed = Msg & { id: string; signPub: string; sig: string };

export interface SeatInfo { seat: number; who: string; name: string; bot: boolean }
export interface TableView {
  phase: 'disconnected' | 'lobby' | 'playing';
  maxSeats: number | null;
  network: NetworkMode;
  seats: SeatInfo[];
  freeSeats: number[];
  mySeat: number | null;
  iAmHost: boolean;
  canStart: boolean;
  state: GameState | null;
  myTurn: boolean;
}

export class NetTable {
  private relay: Relay;
  readonly me: string;
  readonly name: string;
  private onUpdate: () => void;

  private maxSeats: number | null = null;
  private network: NetworkMode = 'regtest';
  private host: string | null = null;
  private started = false;
  state: GameState | null = null;
  private seats = new Map<number, { who: string; name: string; bot: boolean }>();
  mySeat: number | null = null;
  private autoPlay: boolean;          // a SIMULATED player: auto-plays ONLY its own seat
  private lastBotKey = '';            // de-dup auto-play so one state fires one action
  private botTimer: ((cb: () => void) => void) | null;
  private id: Identity;               // the PLAYER's key: signs every table message
  private seatKeys = new Map<number, string>(); // seat → signing pub (who controls it)
  private verified = new Set<string>();         // payloads whose signature already verified (amortise rebuild)

  /**
   * `autoPlay` makes this peer a simulated player that plays ONLY its own seat
   * automatically (it never controls another seat — that would be a cheat). Run
   * such a peer as a separate process/window/daemon; it connects over the relay
   * socket exactly like a remote human. `scheduleBot` lets tests pump it.
   */
  constructor(relay: Relay, name: string, onUpdate: () => void, opts?: { autoPlay?: boolean; scheduleBot?: (cb: () => void) => void; identity?: Identity }) {
    this.relay = relay;
    this.id = opts?.identity ?? genIdentity();      // the player's non-custodial key
    this.me = toHex(this.id.signPub);                // identity = the player's signing pubkey, not a random string
    this.name = name || 'player';
    this.onUpdate = onUpdate;
    this.autoPlay = opts?.autoPlay ?? false;
    this.botTimer = opts?.scheduleBot ?? null;
  }

  connect(): void {
    // Drive state by replaying the relay's TOTAL-ORDER log (no optimistic apply,
    // so peers can never diverge). The transport pushes the ordered log live and
    // heals any gap, so every peer converges on one identical state.
    if (this.relay.subscribeOrdered) this.relay.subscribeOrdered((log) => this.rebuild(log));
  }

  createTable(maxSeats: number, network: NetworkMode = 'regtest'): void {
    this.host = this.me;
    this.send({ kind: 'table', maxSeats, network, host: this.me });
  }
  /** Take a seat. `simulated` marks this peer as a bot to other players (it is a
   *  separate connected peer running in auto-play, NOT controlled from anyone's app). */
  joinSeat(simulated = false): void {
    const seat = this.lowestFree();
    if (seat < 0) return;
    this.send({ kind: 'seat', seat, who: this.me, name: this.name, bot: simulated });
  }
  /** HOST + HUMAN ONLY. Binds the final seat map into the signed start. */
  start(): void {
    if (!this.iAmHost() || this.started || this.maxSeats === null) return;
    const seatMap = [...this.seats.entries()].map(([seat, v]) => ({ seat, who: v.who })).sort((a, b) => a.seat - b.seat);
    this.send({ kind: 'start', by: this.me, config: { network: this.network, seatCount: this.maxSeats, bankReserve: P.scalars.salary * 200 }, seatMap });
  }
  submit(action: Action): void { if (this.myTurn()) this.send({ kind: 'action', action }); }

  /** Leave the table mid-game (any time, on or off turn): your money + assets go
   *  to the leading player. Broadcast so every peer applies it. */
  leaveGame(): void {
    if (this.started && this.state && this.mySeat !== null && !this.state.seats[this.mySeat]!.bankrupt) {
      this.send({ kind: 'action', action: { type: 'LEAVE', seat: this.mySeat } });
    }
  }

  iAmHost(): boolean { return this.host === this.me; }
  myTurn(): boolean {
    return !!this.state && this.mySeat !== null && this.state.phase !== 'GAME_OVER' && this.state.current === this.mySeat;
  }
  private lowestFree(): number {
    if (this.maxSeats === null) return -1;
    for (let i = 0; i < this.maxSeats; i++) if (!this.seats.has(i)) return i;
    return -1;
  }

  view(): TableView {
    const free = this.maxSeats === null ? [] : Array.from({ length: this.maxSeats }, (_, i) => i).filter((i) => !this.seats.has(i));
    return {
      phase: this.started ? 'playing' : this.maxSeats === null ? 'disconnected' : 'lobby',
      maxSeats: this.maxSeats, network: this.network,
      seats: [...this.seats.entries()].map(([seat, v]) => ({ seat, ...v })).sort((a, b) => a.seat - b.seat),
      freeSeats: free, mySeat: this.mySeat, iAmHost: this.iAmHost(),
      canStart: this.iAmHost() && !this.started && this.maxSeats !== null && this.seats.size >= 1 && free.length === 0,
      state: this.state, myTurn: this.myTurn(),
    };
  }

  // Publish only — no optimistic local apply. Our action enters the relay's
  // total-order log; the ordered subscription replays it (live, within ms) so
  // our own UI and every peer update from the SAME canonical order.
  private send(m: Msg): void {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const signPub = toHex(this.id.signPub);
    const sig = toHex(signData(signedBytes(m, signPub), this.id.signPriv)); // sign with the player's Ed25519 key
    this.relay.publish(encJSON({ ...m, id, signPub, sig }));
    this.relay.refresh?.();
  }

  /** Recompute ALL state from the ordered log. Pure + deterministic, so every
   *  peer replaying the same log lands on byte-identical state — never diverges. */
  private rebuild(payloads: Uint8Array[]): void {
    let maxSeats: number | null = null;
    let network: NetworkMode = 'regtest';
    let host: string | null = null;             // the host = the signing key that opened the table
    let started = false;
    let state: GameState | null = null;
    const seats = new Map<number, { who: string; name: string; bot: boolean }>();
    const seatKeys = new Map<number, string>();  // seat → controlling signing pub
    for (const p of payloads) {
      const raw = new TextDecoder().decode(p);
      let o: Signed;
      try { o = JSON.parse(raw) as Signed; } catch { continue; }
      const { id, signPub, sig, ...m } = o;
      // AUTHENTICATE: every message must be signed by its author's key (audit #1).
      // Relay ordering is NOT authentication; an unsigned/forged message is dropped.
      // Each unique payload is verified ONCE (cached) so repeated rebuilds stay O(n).
      if (!this.verified.has(raw)) {
        let signer: Uint8Array, signature: Uint8Array;
        try { signer = fromHex(signPub); signature = fromHex(sig); } catch { continue; }
        if (signer.length !== 32 || !verifyData(signedBytes(m as Msg, signPub), signature, signer)) continue;
        this.verified.add(raw);
      }
      switch ((m as Msg).kind) {
        case 'table':
          if (maxSeats === null) { const t = m as Extract<Msg, { kind: 'table' }>; maxSeats = t.maxSeats; network = t.network; host = signPub; }
          break;
        case 'seat': {
          const sm = m as Extract<Msg, { kind: 'seat' }>;
          // a seat is claimed by the key that SIGNED the claim (no spoofing, audit #2);
          // one key controls at most one seat.
          if (!started && !seats.has(sm.seat) && sm.who === signPub && ![...seatKeys.values()].includes(signPub)) {
            seats.set(sm.seat, { who: signPub, name: sm.name, bot: sm.bot });
            seatKeys.set(sm.seat, signPub);
          }
          break;
        }
        case 'start': {
          const st = m as Extract<Msg, { kind: 'start' }>;
          // host-signed AND the bound seat map must match the claimed seats (audit #2)
          if (!started && signPub === host) {
            const cur = JSON.stringify([...seats.entries()].map(([seat, v]) => ({ seat, who: v.who })).sort((a, b) => a.seat - b.seat));
            const claimed = JSON.stringify([...st.seatMap].sort((a, b) => a.seat - b.seat));
            if (cur === claimed) { started = true; state = initialState(st.config); }
          }
          break;
        }
        case 'action': {
          const am = m as Extract<Msg, { kind: 'action' }>;
          if (started && state) {
            // LEAVE is signed by the leaving seat; every other action by the ACTIVE seat.
            const owner = am.action.type === 'LEAVE' ? am.action.seat : state.current;
            if (seatKeys.get(owner) === signPub) { const r = apply(state, am.action); if (r.ok) state = r.state; }
          }
          break;
        }
      }
    }
    this.seatKeys = seatKeys;
    this.maxSeats = maxSeats;
    this.network = network;
    this.host = host;
    this.started = started;
    this.state = state;
    this.seats = seats;
    this.mySeat = [...seats.entries()].find(([, v]) => v.who === this.me)?.[0] ?? null;
    this.onUpdate();
    this.maybeAutoPlay();
  }

  /** A simulated player auto-plays ONLY its own seat (never another's). Fires at
   *  most once per distinct state, so a re-render never double-sends an action. */
  private maybeAutoPlay(): void {
    if (!this.autoPlay) return;
    const s = this.state;
    if (!this.started || !s || s.phase === 'GAME_OVER' || !this.myTurn()) return;
    const key = `${s.turnIndex}:${s.phase}:${s.current}`;
    if (key === this.lastBotKey) return;
    this.lastBotKey = key;
    const fire = () => {
      if (this.myTurn() && this.state && `${this.state.turnIndex}:${this.state.phase}:${this.state.current}` === key) {
        this.send({ kind: 'action', action: botAction(this.state) });
      }
    };
    if (this.botTimer) this.botTimer(fire);
    else setTimeout(fire, 30);
  }
}

/** The optional simulated player's move (test-only; used only for bot-filled seats). */
export function botAction(s: GameState): Action {
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
