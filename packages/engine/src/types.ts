/**
 * ESTATES deterministic core — types.
 *
 * The engine is pure: `apply(state, action)` returns a new state or a typed
 * rejection. It has no I/O, no clock, and no randomness of its own — the dice
 * result and the card-deck order are INJECTED (produced by the verifiable
 * beacon / concealed-deck layer) so every transition is independently
 * recomputable from the transcript.
 */
import type { NetworkMode } from '@estates/params';

export type Phase =
  | 'AWAIT_ROLL'        // S0/S1: active seat must roll (beacon result injected)
  | 'AWAIT_BUY'         // S3: landed on an unowned title — BUY or DECLINE
  | 'AWAIT_TAX'         // S3: landed on income levy — choose flat or percent
  | 'AWAIT_POST'        // S4: optional build/mortgage/trade, then END_TURN
  | 'GAME_OVER';        // terminal

/** Ownership + on-NFT state for one titled space. */
export interface TitleState {
  readonly owner: number | null; // seat index, or null = bank
  readonly buildLevel: number;    // 0–5 (5 = estate); 0 for rails/utilities
  readonly mortgaged: boolean;
}

export interface SeatState {
  readonly id: number;
  readonly balance: number;       // sats
  readonly position: number;      // board index 0–39
  readonly inHolding: boolean;
  readonly holdingTurns: number;  // failed double-attempts while held
  readonly reprieveCards: number; // owned Reprieve NFTs
  readonly bankrupt: boolean;
}

export interface GameState {
  readonly network: NetworkMode;
  readonly seats: readonly SeatState[];
  readonly titles: Readonly<Record<number, TitleState>>; // property_id -> state
  readonly bankReserve: number;   // sats
  readonly housesRemaining: number;
  readonly estatesRemaining: number;
  readonly current: number;       // index into seats of the active seat
  readonly phase: Phase;
  readonly turnIndex: number;
  readonly doublesPending: boolean;
  readonly doublesCount: number;  // consecutive doubles this turn
  readonly deckCursor: Readonly<Record<string, number>>; // deck name -> next card idx
  readonly deckOrder?: Readonly<Record<string, readonly number[]>>; // injected draw order; identity if absent
  readonly lastRoll: readonly [number, number] | null;
  readonly pendingTitle: number | null; // space awaiting BUY/DECLINE
  readonly winner: number | null;
  readonly log: readonly string[];
}

export type Action =
  | { type: 'ROLL'; dice: readonly [number, number] }
  | { type: 'BUY' }
  | { type: 'DECLINE' }
  | { type: 'PAY_TAX'; choice: 'flat' | 'percent' }
  | { type: 'BUILD'; propertyId: number }
  | { type: 'SELL_BUILD'; propertyId: number }
  | { type: 'MORTGAGE'; propertyId: number }
  | { type: 'UNMORTGAGE'; propertyId: number }
  | { type: 'END_TURN' };

export type RejectCode =
  | 'WRONG_PHASE'
  | 'GAME_OVER'
  | 'INVALID_DICE'
  | 'NOT_PURCHASABLE'
  | 'INSUFFICIENT_FUNDS'
  | 'NOT_OWNER'
  | 'NOT_FULL_GROUP'
  | 'UNEVEN_BUILD'
  | 'NO_BUILD_SUPPLY'
  | 'ALREADY_MAX'
  | 'NOT_BUILT'
  | 'ALREADY_MORTGAGED'
  | 'NOT_MORTGAGED'
  | 'HAS_BUILDINGS'
  | 'NO_SUCH_TITLE'
  | 'NOT_TITLED_SPACE';

export type ApplyResult =
  | { ok: true; state: GameState }
  | { ok: false; code: RejectCode; context: string };

export interface EngineConfig {
  readonly network: NetworkMode;
  readonly seatCount: number;
  readonly bankReserve: number;
  /**
   * Deterministic per-deck draw order (indices into the deck array). Injected;
   * produced by the verifiable concealed-deck shuffle (C6). If omitted, decks
   * draw in declared order (identity) — used by conformance vectors.
   */
  readonly deckOrder?: Readonly<Record<string, readonly number[]>>;
}
