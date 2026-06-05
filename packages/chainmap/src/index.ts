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
  nftOutput, nftOutputWith, paymentOutput, encodeTitleState, decodeTitleState, gameTag,
  type TitleState, type TxOutput, type Outpoint,
} from '@estates/onchain';
import { covenantOutput, covenantScriptItems, rulesHash, type BankMode } from '@estates/bank';

const P: EstatesParams = loadParams();
const GROUP_IDS = Object.keys(P.groups);
const groupOrdinal = (g: string | undefined): number => (g ? Math.max(0, GROUP_IDS.indexOf(g)) : 0);

/** A one-use spend-key provider: returns a FRESH pkh for (seat role, purpose).
 *  Supplied by the live peer (ECDH/BRC-42 derivation); absent in pure tests. */
export type PkhProvider = (role: number, purpose: string) => Uint8Array;

export interface MapContext {
  readonly gameId: Uint8Array;             // 32-byte table id
  readonly genesis: Outpoint;              // provenance root
  readonly seatPkhs: readonly Uint8Array[]; // pkh per seat (fallback when no provider)
  readonly bankPkh: Uint8Array;            // fallback bank pkh (quorum mode)
  /** Bank custody form. DEFAULT 'covenant' (trustless, self-enforcing script);
   *  'quorum' (M-of-N banker sigs to ctx.bankPkh) is opt-in. */
  readonly bankMode?: BankMode;
  readonly rulesHash?: Uint8Array;         // covenant rules-hash (defaults to the game-bound rulesHash(gameId))
}

const bankModeOf = (ctx: MapContext): BankMode => ctx.bankMode ?? 'covenant';
// the covenant rules hash is bound to THIS game (rulesHash(gameId)) so the reserve
// belongs to one game only — never a game-agnostic params-only hash.
const rhOf = (ctx: MapContext): Uint8Array => ctx.rulesHash ?? rulesHash(ctx.gameId);

/** A value leg paid TO the bank reserve: covenant-locked by default (no reused
 *  pkh), or P2PKH to the banker pkh under the opt-in quorum mode. */
export function bankValueOutput(amount: number, ctx: MapContext): TxOutput {
  return bankModeOf(ctx) === 'covenant' ? covenantOutput(amount, rhOf(ctx)) : paymentOutput(amount, ctx.bankPkh);
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

/**
 * The 1-sat NFT output for a title. An OWNED title is custodied by a FRESH
 * one-use key for the owning seat (ECDH-derived via `oneUsePkh`, never a reused
 * seat pkh); an UNOWNED (bank-held) title is locked under the bank covenant by
 * default (or the banker pkh under quorum). Pure tests with no provider fall
 * back to ctx.seatPkhs.
 */
export function titleToNftOutput(s: GameState, propertyId: number, ctx: MapContext, oneUsePkh?: PkhProvider): TxOutput {
  const owner = s.titles[propertyId]!.owner;
  const state = titleToNftState(s, propertyId, ctx);
  if (owner === null) {
    return bankModeOf(ctx) === 'covenant' ? nftOutputWith(state, covenantScriptItems(rhOf(ctx))) : nftOutput(state, ctx.bankPkh);
  }
  const pkh = oneUsePkh ? oneUsePkh(owner, 'nft') : ctx.seatPkhs[owner]!;
  return nftOutput(state, pkh);
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
export function emitForAction(post: GameState, propertyId: number, kind: 'buy' | 'build' | 'sell' | 'mortgage' | 'unmortgage', ctx: MapContext, oneUsePkh?: PkhProvider): ActionTx {
  const sp = P.board[propertyId]!;
  const owner = post.titles[propertyId]!.owner!;
  const ownerPkh = oneUsePkh ? oneUsePkh(owner, 'refund') : ctx.seatPkhs[owner]!; // fresh key for refunds to the owner
  const nft = titleToNftOutput(post, propertyId, ctx, oneUsePkh);
  switch (kind) {
    case 'buy':
      // bank→buyer NFT + buyer→reserve price (covenant-locked)
      return { outputs: [nft, bankValueOutput(sp.base_price ?? 0, ctx)], note: `buy ${sp.name}` };
    case 'build':
      return { outputs: [nft, bankValueOutput(buildCost(sp.group!), ctx)], note: `build ${sp.name} -> level ${post.titles[propertyId]!.buildLevel}` };
    case 'sell':
      return { outputs: [nft, paymentOutput(Math.round(buildCost(sp.group!) * P.rent_factors.sell_building_refund_factor), ownerPkh)], note: `sell building on ${sp.name}` };
    case 'mortgage':
      return { outputs: [nft, paymentOutput(mortgageValue(sp.base_price ?? 0), ownerPkh)], note: `mortgage ${sp.name}` };
    case 'unmortgage':
      return { outputs: [nft, bankValueOutput(unmortgageCost(sp.base_price ?? 0), ctx)], note: `unmortgage ${sp.name}` };
  }
}
