/**
 * @estates/ledger — the on-chain move chain. Genesis sets up the table in one
 * transaction; thereafter EVERY move is its own real transaction that SPENDS the
 * previous move's commitment output and re-creates a new one — so the sequence of
 * txids is itself the authoritative, on-chain, SPV-provable transcript of the
 * game. Each move carries its action commitment (@estates/txmap, decodable) plus
 * its value legs and any title-NFT changes.
 *
 * Value-leg FUNDING inputs (the payer's UTXOs) and signatures are attached by the
 * wallet/native sidecar at broadcast time; this module builds the canonical,
 * linkable transaction structure (@estates/tx) and the chain linkage.
 */
import { txid, type Tx } from '@estates/tx';
import type { MoveTx } from '@estates/txmap';

export * from './manifest.ts';   // genesis key manifest + verifier (red-team #2)

/** {satoshis, script} (onchain) → {value, script} (tx wire). */
function toRaw(o: { satoshis: number; script: Uint8Array }): { value: number; script: Uint8Array } {
  return { value: o.satoshis, script: o.script };
}

export interface Outpoint { readonly txid: string; readonly vout: number }

export interface GenesisCfg {
  readonly fundingOutpoint: Outpoint;       // the UTXO that funds the table
  readonly cursorScript: Uint8Array;        // 1-sat genesis cursor locking script (e.g. a commit output)
  readonly seatFunds: readonly { satoshis: number; script: Uint8Array }[]; // per-seat starting balance outputs
  readonly mints?: readonly { satoshis: number; script: Uint8Array }[];    // deck NFTs, reserve, params
}

/** The table-setup transaction. Output 0 is the move-chain cursor. */
export function buildGenesis(cfg: GenesisCfg): { tx: Tx; cursor: Outpoint } {
  const tx: Tx = {
    version: 1,
    inputs: [{ prevTxid: cfg.fundingOutpoint.txid, prevVout: cfg.fundingOutpoint.vout, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [{ value: 1, script: cfg.cursorScript }, ...cfg.seatFunds.map(toRaw), ...(cfg.mints ?? []).map(toRaw)],
    lockTime: 0,
  };
  return { tx, cursor: { txid: txid(tx), vout: 0 } };
}

/** Build the next move tx: spend the prior cursor, emit this move's outputs.
 *  Output 0 (the action commitment) becomes the new cursor — the chain link. */
export function buildMove(prevCursor: Outpoint, move: MoveTx, sequence = 0xffffffff, lockTime = 0): { tx: Tx; cursor: Outpoint } {
  const tx: Tx = {
    version: 1,
    inputs: [{ prevTxid: prevCursor.txid, prevVout: prevCursor.vout, scriptSig: new Uint8Array(0), sequence }],
    outputs: [toRaw(move.commit), ...move.value.map(toRaw), ...move.nft.map(toRaw)],
    lockTime,
  };
  return { tx, cursor: { txid: txid(tx), vout: 0 } };
}

/** A running on-chain ledger: append moves, each linked to the last. */
export class MoveChain {
  private cursorOp: Outpoint;
  readonly txs: Tx[] = [];
  constructor(genesis: { tx: Tx; cursor: Outpoint }) { this.cursorOp = genesis.cursor; this.txs.push(genesis.tx); }
  get cursor(): Outpoint { return this.cursorOp; }
  /** Append a move; returns its real txid. */
  append(move: MoveTx, sequence = 0xffffffff, lockTime = 0): string {
    const { tx, cursor } = buildMove(this.cursorOp, move, sequence, lockTime);
    this.cursorOp = cursor;
    this.txs.push(tx);
    return txid(tx);
  }
  /** The ordered txids: the on-chain transcript of the whole game. */
  transcript(): string[] { return this.txs.map((t) => txid(t)); }
}
