/**
 * @estates/replay — reconstruct and verify a WHOLE game from the on-chain move
 * chain alone. A third party with only the transcript (the ordered move
 * transactions) and the rules can: confirm each move links to the previous,
 * decode each move's on-chain commitment back into its action, re-execute it
 * through the deterministic engine, and arrive at the exact final state — or
 * reject an illegal/forged move. With SPV envelopes it additionally proves every
 * move is confirmed under proof-of-work, trusting no node and no operator.
 *
 * This is the auditability guarantee (R7) on the on-chain foundation: the game is
 * fully reconstructable and independently verifiable from chain data.
 */
import { txid, type Tx } from '@estates/tx';
import { decodeActionCommit } from '@estates/txmap';
import { initialState, apply, type GameState, type EngineConfig } from '@estates/engine';
import { verifyEnvelope, type Envelope } from '@estates/beef';

/** Read the action-commitment blob from a move tx's output 0 (the commit output:
 *  `<push blob> OP_DROP <P2PKH>`), supporting direct push and OP_PUSHDATA1. */
export function readCommit(tx: Tx): Uint8Array {
  const s = tx.outputs[0]?.script;
  if (!s || s.length < 2) throw new Error('no commitment output');
  const tag = s[0]!;
  if (tag < 0x4c) return s.slice(1, 1 + tag);
  if (tag === 0x4c) return s.slice(2, 2 + s[1]!);
  throw new Error('unsupported push in commitment output');
}

export interface ReplayResult {
  readonly ok: boolean;
  readonly finalState: GameState | null;
  readonly movesApplied: number;
  readonly reason: string;
}

/** Replay an on-chain move chain through the engine. `genesisTxid` is the cursor
 *  the first move spends; `moveTxs` are the ordered move transactions. */
export function replayChain(config: EngineConfig, genesisTxid: string, moveTxs: readonly Tx[]): ReplayResult {
  let s = initialState(config);
  let prev = genesisTxid;
  let applied = 0;
  for (const tx of moveTxs) {
    if (tx.inputs[0]?.prevTxid !== prev) return { ok: false, finalState: s, movesApplied: applied, reason: `move ${applied} does not link to the prior tx` };
    let action;
    try { action = decodeActionCommit(readCommit(tx)).action; } catch (e) { return { ok: false, finalState: s, movesApplied: applied, reason: `move ${applied}: ${(e as Error).message}` }; }
    const r = apply(s, action);
    if (!r.ok) return { ok: false, finalState: s, movesApplied: applied, reason: `move ${applied} (${action.type}) is illegal: ${r.code}` };
    s = r.state;
    applied++;
    prev = txid(tx);
  }
  return { ok: true, finalState: s, movesApplied: applied, reason: `replayed ${applied} on-chain moves to a verified final state` };
}

/** As replayChain, but ALSO require every move to be SPV-confirmed (no node). */
export function verifyConfirmedChain(config: EngineConfig, genesisTxid: string, moves: readonly { tx: Tx; envelope: Envelope }[]): ReplayResult {
  for (let i = 0; i < moves.length; i++) {
    const m = moves[i]!;
    if (txid(m.envelope.tx) !== txid(m.tx)) return { ok: false, finalState: null, movesApplied: i, reason: `move ${i}: envelope is for a different tx` };
    if (!verifyEnvelope(m.envelope)) return { ok: false, finalState: null, movesApplied: i, reason: `move ${i}: SPV proof failed` };
  }
  return replayChain(config, genesisTxid, moves.map((m) => m.tx));
}
