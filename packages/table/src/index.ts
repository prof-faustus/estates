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

export const P = loadParams();
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
  | { kind: 'start'; by: string; config: EngineConfig }
  | { kind: 'action'; action: Action };

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
  private myBots = new Set<number>();
  private seen = new Set<string>();   // de-dup so our own optimistic apply + the relay echo apply once
  private botTimer: ((cb: () => void) => void) | null;

  /** `scheduleBot` lets tests run the optional bot synchronously; default = setTimeout. */
  constructor(relay: Relay, name: string, onUpdate: () => void, scheduleBot?: (cb: () => void) => void) {
    this.relay = relay;
    this.me = `${name || 'player'}-${Math.random().toString(36).slice(2, 8)}`;
    this.name = name || 'player';
    this.onUpdate = onUpdate;
    this.botTimer = scheduleBot ?? null;
  }

  connect(): void { this.relay.subscribe((p) => this.ingest(p)); }

  createTable(maxSeats: number, network: NetworkMode = 'regtest'): void {
    this.host = this.me;
    this.send({ kind: 'table', maxSeats, network, host: this.me });
  }
  joinSeat(): void {
    const seat = this.lowestFree();
    if (seat < 0) return;
    this.send({ kind: 'seat', seat, who: this.me, name: this.name, bot: false });
  }
  /** OPTION (host only): fill the lowest free seat with a simulated player (test). */
  addBot(): void {
    if (!this.iAmHost()) return;
    const seat = this.lowestFree();
    if (seat < 0) return;
    this.myBots.add(seat);
    this.send({ kind: 'seat', seat, who: `bot-${seat}-${Math.random().toString(36).slice(2, 6)}`, name: `Bot ${seat}`, bot: true });
  }
  /** HOST + HUMAN ONLY. */
  start(): void {
    if (!this.iAmHost() || this.started || this.maxSeats === null) return;
    this.send({ kind: 'start', by: this.me, config: { network: this.network, seatCount: this.maxSeats, bankReserve: P.scalars.salary * 200 } });
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

  // Publish to the relay AND apply our own message locally + immediately, so the
  // UI responds without waiting on (or depending on) the relay round-trip. The
  // relay echo and other peers are de-duped by id. Turn-based play means only one
  // seat acts at a time, so local-first apply stays consistent across peers.
  private send(m: Msg): void {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    this.relay.publish(new TextEncoder().encode(JSON.stringify({ ...m, id })));
    this.handle(m, id);
  }

  private ingest(p: Uint8Array): void {
    try {
      const o = JSON.parse(new TextDecoder().decode(p)) as Msg & { id?: string };
      const { id, ...rest } = o;
      this.handle(rest as Msg, id ?? new TextDecoder().decode(p));
    } catch { /* opaque payloads (e.g. lobby/chat) are ignored here */ }
  }

  private handle(m: Msg, id: string): void {
    if (this.seen.has(id)) return;
    this.seen.add(id);
    switch (m.kind) {
      case 'table':
        if (this.maxSeats === null) { this.maxSeats = m.maxSeats; this.network = m.network; this.host = m.host; }
        break;
      case 'seat':
        if (!this.started && !this.seats.has(m.seat) && ![...this.seats.values()].some((v) => v.who === m.who)) {
          this.seats.set(m.seat, { who: m.who, name: m.name, bot: m.bot });
          if (m.who === this.me) this.mySeat = m.seat;
        }
        break;
      case 'start':
        if (!this.started && m.by === this.host) { this.started = true; this.state = initialState(m.config); }
        break;
      case 'action':
        if (this.started && this.state) { const r = apply(this.state, m.action); if (r.ok) this.state = r.state; }
        break;
    }
    this.onUpdate();
    this.maybePlayBot();
  }

  private maybePlayBot(): void {
    const s = this.state;
    if (!this.started || !s || s.phase === 'GAME_OVER') return;
    if (!this.myBots.has(s.current)) return;
    const at = s.current;
    const fire = () => {
      if (this.state && this.state.current === at && this.state.phase !== 'GAME_OVER') {
        this.send({ kind: 'action', action: botAction(this.state) });
      }
    };
    if (this.botTimer) this.botTimer(fire);
    else setTimeout(fire, 400);
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
