/**
 * @estates/params — the ONLY typed accessor for params/estates.v1.json.
 *
 * Every game value derives from here; no number is hard-coded twice. Rents are
 * DERIVED from base_price + rent_factors (rules doc §4) and never stored.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// packages/params/src -> packages/params -> packages -> <root>/params/estates.v1.json
const PARAMS_PATH = join(
  fileURLToPath(new URL('.', import.meta.url)),
  '..', '..', '..', 'params', 'estates.v1.json',
);

export type NetworkMode = 'mainnet' | 'testnet' | 'regtest';
export type SpaceType = 'corner' | 'property' | 'station' | 'utility' | 'card' | 'tax';

export interface BoardSpace {
  readonly id: number;
  readonly name: string;
  readonly type: SpaceType;
  readonly group?: string;
  readonly base_price?: number;
  readonly corner?: string;
  readonly deck?: string;
  readonly tax?: string;
}

export type CardEffect =
  | { kind: 'MOVE_TO'; space: number; collect_if_pass: boolean }
  | { kind: 'MOVE_TO_NEAREST'; category: 'station' | 'utility'; collect_if_pass: boolean; rent_multiplier?: number }
  | { kind: 'MOVE_RELATIVE'; delta: number }
  | { kind: 'PAY_BANK'; amount: number }
  | { kind: 'COLLECT_BANK'; amount: number }
  | { kind: 'PAY_EACH'; amount: number }
  | { kind: 'COLLECT_EACH'; amount: number }
  | { kind: 'GOTO_HOLDING' }
  | { kind: 'REPRIEVE_GRANT' }
  | { kind: 'REPAIRS'; per_house: number; per_estate: number };

export interface Card { readonly id: string; readonly text: string; readonly effect: CardEffect; }

export interface GroupDef { readonly build_cost: number; readonly member_property_ids: readonly number[]; }

export interface RentFactors {
  readonly rent_base_factor: number;
  readonly full_group_unbuilt_multiplier: number;
  readonly build_multipliers: readonly number[];
  readonly estate_multiplier: number;
  readonly station_base: number;
  readonly utility_factor: readonly [number, number];
  readonly mortgage_value_factor: number;
  readonly unmortgage_cost_factor: number;
  readonly sell_building_refund_factor: number;
}

export interface EstatesParams {
  readonly params_version: string;
  readonly unit: 'sat';
  readonly network_modes: readonly NetworkMode[];
  readonly scalars: {
    readonly starting_balance_per_seat: number;
    readonly salary: number;
    readonly max_seats: number;
    readonly min_seats: number;
    readonly board_size: number;
  };
  readonly rent_factors: RentFactors;
  readonly build_supply: { readonly houses: number; readonly estates: number; readonly enforce_scarcity: boolean };
  readonly groups: Readonly<Record<string, GroupDef>>;
  readonly taxes: Readonly<Record<string, { space_id: number; flat: number; percent_of_worth?: number; timeout_default?: string }>>;
  readonly holding_yard: { space_id: number; summons_space_id: number; pay_to_leave: number; max_double_attempts: number; doubles_to_holding: number };
  readonly board: readonly BoardSpace[];
  readonly decks: Readonly<Record<string, readonly Card[]>>;
  readonly nfts: {
    readonly title_deeds: { count: number; satoshis_each: number; note?: string };
    readonly reprieve_cards: { count: number; satoshis_each: number; note?: string };
  };
  readonly bot_policies: readonly string[];
  readonly auction: { format: string };
}

let cached: EstatesParams | null = null;

/** Load (and cache) the single source of truth. */
export function loadParams(): EstatesParams {
  if (cached) return cached;
  cached = JSON.parse(readFileSync(PARAMS_PATH, 'utf8')) as EstatesParams;
  return cached;
}

const round = (n: number): number => Math.round(n);

/** Base rent for a property: round(base_price × rent_base_factor). */
export function baseRent(basePrice: number, p: EstatesParams = loadParams()): number {
  return round(basePrice * p.rent_factors.rent_base_factor);
}

/**
 * Derived property rent in sats given build level (0–5) and whether the owner
 * holds the full colour group (rules doc §4).
 *   level 0 + full group  → 2 × base rent
 *   level 0 single        → base rent
 *   level 1–4 (houses)    → base rent × build_multipliers[level-1]
 *   level 5 (estate)      → base rent × estate_multiplier
 */
export function propertyRent(basePrice: number, level: number, fullGroup: boolean, p: EstatesParams = loadParams()): number {
  const base = baseRent(basePrice, p);
  const f = p.rent_factors;
  if (level <= 0) return fullGroup ? base * f.full_group_unbuilt_multiplier : base;
  if (level >= 5) return round(base * f.estate_multiplier);
  return round(base * f.build_multipliers[level - 1]!);
}

/** Station rent: station_base × 2^(stationsOwned−1) → 25/50/100/200 for 1–4. */
export function stationRent(stationsOwned: number, p: EstatesParams = loadParams()): number {
  if (stationsOwned <= 0) return 0;
  return p.rent_factors.station_base * 2 ** (stationsOwned - 1);
}

/** Utility rent: dice × utility_factor[utilitiesOwned−1] (×4 for one, ×10 for both). */
export function utilityRent(diceTotal: number, utilitiesOwned: number, p: EstatesParams = loadParams()): number {
  if (utilitiesOwned <= 0) return 0;
  const factor = p.rent_factors.utility_factor[Math.min(utilitiesOwned, 2) - 1]!;
  return diceTotal * factor;
}

/** Mortgage value: round(base_price × mortgage_value_factor). */
export function mortgageValue(basePrice: number, p: EstatesParams = loadParams()): number {
  return round(basePrice * p.rent_factors.mortgage_value_factor);
}

/** Cost to lift a mortgage: round(mortgage_value × unmortgage_cost_factor). */
export function unmortgageCost(basePrice: number, p: EstatesParams = loadParams()): number {
  return round(mortgageValue(basePrice, p) * p.rent_factors.unmortgage_cost_factor);
}

/** Build cost per level for a property's colour group. */
export function buildCost(group: string, p: EstatesParams = loadParams()): number {
  return p.groups[group]?.build_cost ?? 0;
}
