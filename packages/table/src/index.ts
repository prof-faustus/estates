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
export function makeRelay(url: string, channel: string): Relay {
  return url.trim() ? new HttpRelay(url.trim(), channel) : new InMemoryRelay();
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

  private send(m: Msg): void { this.relay.publish(new TextEncoder().encode(JSON.stringify(m))); }

  private ingest(p: Uint8Array): void {
    let m: Msg;
    try { m = JSON.parse(new TextDecoder().decode(p)) as Msg; } catch { return; }
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
