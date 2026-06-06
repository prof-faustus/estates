/**
 * @estates/lobby — the waiting room (design spec §5).
 *
 * Pure state machine: join / leave / ready / fill-bot / start. The network mode
 * is fixed at lobby genesis and is immutable. The start-authority (host) may
 * START once there are ≥2 occupied seats including ≥1 human, optionally
 * overriding the all-ready gate ("override start", 1 human + bot … 6). START emits
 * the EngineConfig that seeds @estates/engine. Funding is the SAME on EVERY network
 * (regtest = testnet = real BSV): the banker's REAL buy-in at the genesis tx — there
 * is NO auto-funding anywhere.
 */
import { loadParams, type NetworkMode, type EstatesParams } from '@estates/params';
import type { EngineConfig } from '@estates/engine';

const P: EstatesParams = loadParams();

export type SeatKind = 'human' | 'bot';
export interface LobbySeat {
  readonly seat: number;
  readonly kind: SeatKind;
  readonly playerId: string;        // human player id, or a bot id
  readonly policy?: string;         // bot policy (cautious|balanced|aggressive)
  readonly ready: boolean;
}

export interface SeatMeta {
  readonly kind: SeatKind;
  readonly playerId: string;
  readonly policy?: string;
}

export interface Genesis {
  readonly engineConfig: EngineConfig;
  readonly seats: readonly SeatMeta[];
  readonly fundLog: readonly string[];
}

export interface LobbyState {
  readonly network: NetworkMode;
  readonly maxSeats: number;
  readonly authority: string;       // start-authority (host) player id
  readonly seats: readonly LobbySeat[];
  readonly started: boolean;
  readonly genesis: Genesis | null;
}

export interface LobbyConfig {
  readonly network: NetworkMode;
  readonly authority: string;
  readonly maxSeats?: number;       // ≤ params.max_seats
  /** bank reserve sized as this many salary payments (funded by the banker's real buy-in). */
  readonly reserveSalaryCap?: number;
}

export type LobbyAction =
  | { type: 'JOIN'; playerId: string }
  | { type: 'LEAVE'; playerId: string }
  | { type: 'READY'; playerId: string; ready: boolean }
  | { type: 'FILL_BOT'; by: string; policy: string }
  | { type: 'START'; by: string; override?: boolean };

export type LobbyReject =
  | 'LOBBY_FULL' | 'ALREADY_JOINED' | 'NOT_PRESENT' | 'NOT_AUTHORITY'
  | 'ALREADY_STARTED' | 'TOO_FEW_SEATS' | 'NEED_A_HUMAN' | 'NOT_ALL_READY'
  | 'BAD_POLICY';

export type LobbyResult =
  | { ok: true; state: LobbyState }
  | { ok: false; code: LobbyReject; context: string };

const ok = (state: LobbyState): LobbyResult => ({ ok: true, state });
const no = (code: LobbyReject, context: string): LobbyResult => ({ ok: false, code, context });

export function createLobby(cfg: LobbyConfig): LobbyState {
  const maxSeats = Math.min(cfg.maxSeats ?? P.scalars.max_seats, P.scalars.max_seats);
  return { network: cfg.network, maxSeats, authority: cfg.authority, seats: [], started: false, genesis: null };
}

function lowestFreeSeat(s: LobbyState): number {
  const taken = new Set(s.seats.map((x) => x.seat));
  for (let i = 0; i < s.maxSeats; i++) if (!taken.has(i)) return i;
  return -1;
}
const humans = (s: LobbyState): number => s.seats.filter((x) => x.kind === 'human').length;
const allReady = (s: LobbyState): boolean => s.seats.every((x) => x.ready);

export function applyLobby(s: LobbyState, a: LobbyAction, cfg?: { reserveSalaryCap?: number }): LobbyResult {
  if (s.started) return no('ALREADY_STARTED', 'lobby already started');

  switch (a.type) {
    case 'JOIN': {
      if (s.seats.some((x) => x.playerId === a.playerId)) return no('ALREADY_JOINED', a.playerId);
      const seat = lowestFreeSeat(s);
      if (seat < 0) return no('LOBBY_FULL', `max ${s.maxSeats}`);
      return ok({ ...s, seats: [...s.seats, { seat, kind: 'human', playerId: a.playerId, ready: false }] });
    }
    case 'LEAVE': {
      if (!s.seats.some((x) => x.playerId === a.playerId)) return no('NOT_PRESENT', a.playerId);
      return ok({ ...s, seats: s.seats.filter((x) => x.playerId !== a.playerId) });
    }
    case 'READY': {
      if (!s.seats.some((x) => x.playerId === a.playerId)) return no('NOT_PRESENT', a.playerId);
      return ok({ ...s, seats: s.seats.map((x) => (x.playerId === a.playerId ? { ...x, ready: a.ready } : x)) });
    }
    case 'FILL_BOT': {
      if (a.by !== s.authority) return no('NOT_AUTHORITY', a.by);
      if (!P.bot_policies.includes(a.policy)) return no('BAD_POLICY', a.policy);
      const seat = lowestFreeSeat(s);
      if (seat < 0) return no('LOBBY_FULL', `max ${s.maxSeats}`);
      const playerId = `bot:${a.policy}:${seat}`;
      return ok({ ...s, seats: [...s.seats, { seat, kind: 'bot', playerId, policy: a.policy, ready: true }] });
    }
    case 'START': {
      if (a.by !== s.authority) return no('NOT_AUTHORITY', a.by);
      const occupied = s.seats.length;
      if (occupied < P.scalars.min_seats) return no('TOO_FEW_SEATS', `need ≥${P.scalars.min_seats}, have ${occupied}`);
      if (humans(s) < 1) return no('NEED_A_HUMAN', 'at least one human seat required');
      if (!a.override && !allReady(s)) return no('NOT_ALL_READY', 'use override to start before all seats are ready');
      return ok({ ...s, started: true, genesis: buildGenesis(s, cfg?.reserveSalaryCap) });
    }
  }
}

function buildGenesis(s: LobbyState, reserveSalaryCap = 200): Genesis {
  // compact seats to 0..n-1 in ascending lobby-seat order (canonical)
  const ordered = [...s.seats].sort((a, b) => a.seat - b.seat);
  const seats: SeatMeta[] = ordered.map((x) =>
    x.policy === undefined
      ? { kind: x.kind, playerId: x.playerId }
      : { kind: x.kind, playerId: x.playerId, policy: x.policy },
  );
  const seatCount = seats.length;
  const bankReserve = P.scalars.salary * reserveSalaryCap;

  // SAME MODEL ON EVERY NETWORK — regtest = testnet = real BSV. There is NO
  // auto-funding anywhere: it is a REAL BSV game. The banker funds the seat balances
  // and the bank reserve with a REAL buy-in at the genesis tx (the banker must hold
  // enough sats BEFORE minting), and the engine seeds the agreed reserve once that tx
  // confirms. (A regtest node is the player's OWN external node — same flow, real
  // sats from their own coinbase, not a free grant.)
  const fundLog = [
    `[${s.network}] seat balances + bank reserve (${bankReserve} sats) are funded by the banker's REAL buy-in at the genesis tx — identical on regtest, testnet, and mainnet; no free grant on any network`,
  ];

  const engineConfig: EngineConfig = { network: s.network, seatCount, bankReserve };
  return { engineConfig, seats, fundLog };
}
