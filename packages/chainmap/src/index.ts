/**
 * @estates/chainmap — bridge the pure engine's title state to on-chain 1-sat NFTs.
 *
 * The engine tracks each title as { owner, buildLevel, mortgaged }; on-chain that
 * is a 1-sat NFT whose live-script state blob carries the same fields. This maps
 * one to the other and emits the transaction LEGS for the value-bearing actions:
 * a build/mortgage RE-MINTS the NFT (spend the old 1-sat output, create a new
 * 1-sat output with the updated state) plus a native-sat leg; a purchase moves
 * the NFT bank→buyer and the price→reserve. Pure: returns outputs, signs nothing.
 */
import { loadParams, buildCost, mortgageValue, unmortgageCost, type EstatesParams } from '@estates/params';
import type { GameState } from '@estates/engine';
import {
  nftOutput, paymentOutput, encodeTitleState, decodeTitleState, gameTag,
  type TitleState, type TxOutput, type Outpoint,
} from '@estates/onchain';

const P: EstatesParams = loadParams();
const GROUP_IDS = Object.keys(P.groups);
const groupOrdinal = (g: string | undefined): number => (g ? Math.max(0, GROUP_IDS.indexOf(g)) : 0);

export interface MapContext {
  readonly gameId: Uint8Array;             // 32-byte table id
  readonly genesis: Outpoint;              // provenance root
  readonly seatPkhs: readonly Uint8Array[]; // pkh per seat
  readonly bankPkh: Uint8Array;
}

/** The on-chain NFT state for a board title, reflecting the engine's current view. */
export function titleToNftState(s: GameState, propertyId: number, ctx: MapContext): TitleState {
  const t = s.titles[propertyId]!;
  return {
    kind: 'TITLE', gameTag: gameTag(ctx.gameId, 'TITLE'),
    propertyId, groupId: groupOrdinal(P.board[propertyId]?.group),
    buildLevel: t.buildLevel, mortgaged: t.mortgaged, genesis: ctx.genesis,
  };
}

/** The 1-sat NFT output for a title, owned by its engine owner (or bank if unowned). */
export function titleToNftOutput(s: GameState, propertyId: number, ctx: MapContext): TxOutput {
  const owner = s.titles[propertyId]!.owner;
  const pkh = owner === null ? ctx.bankPkh : ctx.seatPkhs[owner]!;
  return nftOutput(titleToNftState(s, propertyId, ctx), pkh);
}

/**
 * Round-trip check: the NFT state blob decodes back to the engine's title view
 * (buildLevel + mortgaged + property/group), proving the bridge is faithful.
 */
export function nftReflectsEngine(s: GameState, propertyId: number, ctx: MapContext): boolean {
  const t = s.titles[propertyId]!;
  const dec = decodeTitleState(encodeTitleState(titleToNftState(s, propertyId, ctx)));
  return dec.propertyId === propertyId && dec.buildLevel === t.buildLevel && dec.mortgaged === t.mortgaged
    && dec.groupId === groupOrdinal(P.board[propertyId]?.group);
}

export interface SemanticCheck { readonly ok: boolean; readonly reason: string }
/**
 * SEMANTIC NFT validation (audit #9): beyond range-checking, tie the title's
 * groupId to the ACTUAL group of its propertyId, and forbid buildings on
 * stations/utilities. (Structural validation lives in @estates/onchain
 * validateTitleState; semantic validation needs params and lives here.)
 */
export function validateTitleSemantics(s: TitleState): SemanticCheck {
  if (s.kind !== 'TITLE') return { ok: true, reason: 'not a title (no group semantics)' };
  const sp = P.board[s.propertyId];
  if (!sp) return { ok: false, reason: `propertyId ${s.propertyId} is not a board space` };
  if (sp.type !== 'property' && sp.type !== 'station' && sp.type !== 'utility') return { ok: false, reason: `propertyId ${s.propertyId} (${sp.type}) is not a titled space` };
  const expected = groupOrdinal(sp.group);
  if (s.groupId !== expected) return { ok: false, reason: `groupId ${s.groupId} does not match property ${s.propertyId}'s group (${expected})` };
  if ((sp.type === 'station' || sp.type === 'utility') && s.buildLevel !== 0) return { ok: false, reason: `${sp.type} cannot carry buildings (buildLevel ${s.buildLevel})` };
  return { ok: true, reason: 'semantically valid title' };
}

export interface ActionTx {
  readonly outputs: readonly TxOutput[];
  readonly note: string;
}

/**
 * Emit the on-chain tx legs for a value-bearing action, given the POST-action
 * engine state (so re-minted NFTs carry the new build level / mortgage flag).
 */
export function emitForAction(post: GameState, propertyId: number, kind: 'buy' | 'build' | 'sell' | 'mortgage' | 'unmortgage', ctx: MapContext): ActionTx {
  const sp = P.board[propertyId]!;
  const owner = post.titles[propertyId]!.owner!;
  const ownerPkh = ctx.seatPkhs[owner]!;
  const nft = titleToNftOutput(post, propertyId, ctx);
  switch (kind) {
    case 'buy':
      // bank→buyer NFT + buyer→reserve price
      return { outputs: [nft, paymentOutput(sp.base_price ?? 0, ctx.bankPkh)], note: `buy ${sp.name}` };
    case 'build':
      return { outputs: [nft, paymentOutput(buildCost(sp.group!), ctx.bankPkh)], note: `build ${sp.name} -> level ${post.titles[propertyId]!.buildLevel}` };
    case 'sell':
      return { outputs: [nft, paymentOutput(Math.round(buildCost(sp.group!) * P.rent_factors.sell_building_refund_factor), ownerPkh)], note: `sell building on ${sp.name}` };
    case 'mortgage':
      return { outputs: [nft, paymentOutput(mortgageValue(sp.base_price ?? 0), ownerPkh)], note: `mortgage ${sp.name}` };
    case 'unmortgage':
      return { outputs: [nft, paymentOutput(unmortgageCost(sp.base_price ?? 0), ctx.bankPkh)], note: `unmortgage ${sp.name}` };
  }
}
