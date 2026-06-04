/**
 * @estates/txmap — EVERY move is its own on-chain BSV transaction. No exceptions.
 *
 * For any engine transition (pre, action) → post, this emits the transaction:
 *   • a 1-sat ACTION-COMMITMENT output `<commit> OP_DROP <P2PKH(one-use)>` that
 *     records the exact action on chain as pushdata consumed by OP_DROP, and
 *   • the VALUE LEGS: a native-sat output to each seat / the bank whose balance
 *     went UP (paid to a fresh ONE-USE key), funded by those whose balance went
 *     DOWN — so sats move, none are minted (conservation is asserted).
 *   • any TITLE NFT change (ownership / build level / mortgage) re-minted via
 *     @estates/chainmap.
 *
 * Whole sats only. Deterministic and pure (signs nothing). This is the "spam is
 * good" design: a transaction per move, all on chain, all auditable.
 */
import type { GameState, Action } from '@estates/engine';
import { paymentOutput, push, op, OP, p2pkh, serializeScript, NFT_SATS, type TxOutput } from '@estates/onchain';
import { titleToNftOutput, bankValueOutput, type MapContext } from '@estates/chainmap';

const COMMIT_TAG = new TextEncoder().encode('ESTATES-MOVE-v1');
const u32 = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);

const ACTION_CODE: Record<Action['type'], number> = {
  ROLL: 1, BUY: 2, DECLINE: 3, PAY_TAX: 4, BUILD: 5, SELL_BUILD: 6,
  MORTGAGE: 7, UNMORTGAGE: 8, FORFEIT: 9, LEAVE: 10, END_TURN: 11,
};

/** Canonical pushdata commitment to a move: tag ‖ turnIndex ‖ actor ‖ code ‖ params. */
export function encodeActionCommit(action: Action, turnIndex: number, actor: number): Uint8Array {
  const head = [COMMIT_TAG, u32(turnIndex), new Uint8Array([actor & 0xff, ACTION_CODE[action.type]])];
  const params: Uint8Array[] = [];
  switch (action.type) {
    case 'ROLL': params.push(new Uint8Array([action.dice[0]!, action.dice[1]!])); break;
    case 'PAY_TAX': params.push(new Uint8Array([action.choice === 'flat' ? 0 : 1])); break;
    case 'BUILD': case 'SELL_BUILD': case 'MORTGAGE': case 'UNMORTGAGE': params.push(u32(action.propertyId)); break;
    case 'LEAVE': params.push(u32(action.seat)); break;
    default: break;
  }
  const all = [...head, ...params];
  const len = all.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0; for (const a of all) { out.set(a, o); o += a.length; }
  return out;
}

const CODE_ACTION: Record<number, Action['type']> = Object.fromEntries(Object.entries(ACTION_CODE).map(([k, v]) => [v, k as Action['type']]));
const rd32 = (b: Uint8Array, o: number): number => ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0;

export interface DecodedMove { readonly turnIndex: number; readonly actor: number; readonly action: Action }
/** Read an on-chain action commitment back into the move it records (auditable). */
export function decodeActionCommit(blob: Uint8Array): DecodedMove {
  for (let i = 0; i < COMMIT_TAG.length; i++) if (blob[i] !== COMMIT_TAG[i]) throw new Error('not an ESTATES move commitment');
  let o = COMMIT_TAG.length;
  const turnIndex = rd32(blob, o); o += 4;
  const actor = blob[o++]!;
  const type = CODE_ACTION[blob[o++]!];
  if (!type) throw new Error('unknown action code');
  let action: Action;
  switch (type) {
    case 'ROLL': action = { type, dice: [blob[o]!, blob[o + 1]!] as const }; break;
    case 'PAY_TAX': action = { type, choice: blob[o] === 0 ? 'flat' : 'percent' }; break;
    case 'BUILD': case 'SELL_BUILD': case 'MORTGAGE': case 'UNMORTGAGE': action = { type, propertyId: rd32(blob, o) }; break;
    case 'LEAVE': action = { type, seat: rd32(blob, o) }; break;
    default: action = { type } as Action; break;
  }
  return { turnIndex, actor, action };
}

/** The 1-sat on-chain action-commitment output (state in live script, OP_DROP). */
export function commitOutput(commit: Uint8Array, oneUsePkh: Uint8Array): TxOutput {
  return { satoshis: NFT_SATS, script: serializeScript([push(commit), op(OP.OP_DROP), ...p2pkh(oneUsePkh)]) };
}

export interface SeatDelta { readonly seat: number; readonly delta: number }
/** Per-seat balance change pre→post (nonzero only). */
export function balanceDeltas(pre: GameState, post: GameState): SeatDelta[] {
  const out: SeatDelta[] = [];
  for (let i = 0; i < post.seats.length; i++) {
    const d = post.seats[i]!.balance - (pre.seats[i]?.balance ?? 0);
    if (d !== 0) out.push({ seat: i, delta: d });
  }
  return out;
}
/** Bank reserve change pre→post. */
export function reserveDelta(pre: GameState, post: GameState): number {
  return post.bankReserve - pre.bankReserve;
}

/** Title ids whose on-chain-relevant state (owner/buildLevel/mortgaged) changed. */
export function changedTitles(pre: GameState, post: GameState): number[] {
  const ids: number[] = [];
  for (const k of Object.keys(post.titles)) {
    const id = Number(k); const a = pre.titles[id]; const b = post.titles[id]!;
    if (!a || a.owner !== b.owner || a.buildLevel !== b.buildLevel || a.mortgaged !== b.mortgaged) ids.push(id);
  }
  return ids;
}

export interface MoveTx {
  readonly commit: TxOutput;        // the action, on chain
  readonly value: TxOutput[];       // sats paid to whoever gained (one-use keys)
  readonly nft: TxOutput[];         // re-minted title NFTs for changed titles
  readonly conserved: boolean;      // sats in == sats out (none minted)
  readonly note: string;
}

/** Map a single engine transition to its on-chain transaction. `oneUsePkh(role,
 *  purpose)` returns a FRESH one-use key hash for each payee — the `purpose`
 *  ('commit' | 'pay' | 'nft') ensures a seat that both moves AND receives in the
 *  same tx gets DISTINCT one-use keys (no intra-tx reuse). The bank reserve leg is
 *  covenant-locked by default (never a reused pkh). */
export function txForAction(
  pre: GameState, post: GameState, action: Action, turnIndex: number, actor: number,
  ctx: MapContext, oneUsePkh: (role: number, purpose: string) => Uint8Array,
): MoveTx {
  const commit = commitOutput(encodeActionCommit(action, turnIndex, actor), oneUsePkh(actor, 'commit'));

  const seatDeltas = balanceDeltas(pre, post);
  const bankD = reserveDelta(pre, post);
  // value legs: an output for each party whose balance INCREASED (received sats)
  const value: TxOutput[] = [];
  for (const { seat, delta } of seatDeltas) if (delta > 0) value.push(paymentOutput(delta, oneUsePkh(seat, 'pay')));
  if (bankD > 0) value.push(bankValueOutput(bankD, ctx)); // covenant-locked reserve (no reused bankPkh)

  // conservation: total gained == total lost (the game never mints sats)
  const gained = seatDeltas.filter((d) => d.delta > 0).reduce((n, d) => n + d.delta, 0) + Math.max(0, bankD);
  const lost = seatDeltas.filter((d) => d.delta < 0).reduce((n, d) => n - d.delta, 0) + Math.max(0, -bankD);
  const conserved = gained === lost;

  const nft: TxOutput[] = changedTitles(pre, post).map((id) => titleToNftOutput(post, id, ctx, oneUsePkh));

  return { commit, value, nft, conserved, note: `${action.type}@t${turnIndex} seat${actor}` };
}
