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

/**
 * Build the next move tx: spend the prior cursor AND the prior NFT output of every
 * title this move re-mints (a TRUE MOVE — the old NFT is CONSUMED, so the previous
 * owner can never use it again), then emit this move's outputs. Output 0 (the
 * action commitment) becomes the new cursor; the new NFT outputs (vout 1+value+i)
 * become each re-minted title's new outpoint, returned in `nftOutpoints`.
 *
 * `priorNftOutpoints` maps a changed title's property id → its CURRENT on-chain
 * NFT outpoint. A title present here is spent (burned); a title absent (its very
 * first mint) is only created. This is what makes "passed from Alice to Bob" a
 * deletion of Alice's output, not a copy.
 */
export function buildMove(
  prevCursor: Outpoint, move: MoveTx, sequence = 0xffffffff, lockTime = 0,
  priorNftOutpoints?: ReadonlyMap<number, Outpoint>,
): { tx: Tx; cursor: Outpoint; nftOutpoints: Map<number, Outpoint> } {
  const nftInputs = (move.nftTitles ?? [])
    .map((id) => priorNftOutpoints?.get(id))
    .filter((op): op is Outpoint => op !== undefined)
    .map((op) => ({ prevTxid: op.txid, prevVout: op.vout, scriptSig: new Uint8Array(0), sequence }));
  const tx: Tx = {
    version: 1,
    inputs: [{ prevTxid: prevCursor.txid, prevVout: prevCursor.vout, scriptSig: new Uint8Array(0), sequence }, ...nftInputs],
    outputs: [toRaw(move.commit), ...move.value.map(toRaw), ...move.nft.map(toRaw)],
    lockTime,
  };
  const t = txid(tx);
  const nftBase = 1 + move.value.length;           // vout of the first nft output
  const nftOutpoints = new Map<number, Outpoint>();
  (move.nftTitles ?? []).forEach((id, i) => nftOutpoints.set(id, { txid: t, vout: nftBase + i }));
  return { tx, cursor: { txid: t, vout: 0 }, nftOutpoints };
}

/**
 * VERIFY a true move (audit: an NFT passed Alice→Bob must DELETE Alice's output).
 * Given the move tx, the outpoints titles held BEFORE it, and the titles it
 * re-mints, this checks that EVERY re-minted title which had a prior NFT output
 * has that exact outpoint spent as an input of `tx`. A re-mint that fails to burn
 * the old output is a forbidden COPY and is rejected.
 */
export function verifyTrueMove(tx: Tx, priorNftOutpoints: ReadonlyMap<number, Outpoint>, nftTitles: readonly number[]): { ok: boolean; reason: string } {
  const spent = new Set(tx.inputs.map((i) => `${i.prevTxid}:${i.prevVout}`));
  for (const id of nftTitles) {
    const prior = priorNftOutpoints.get(id);
    if (!prior) continue;                            // first mint of this title — nothing to burn
    if (!spent.has(`${prior.txid}:${prior.vout}`))
      return { ok: false, reason: `title ${id} re-minted WITHOUT spending its prior NFT output ${prior.txid.slice(0, 12)}…:${prior.vout} (a copy, not a move)` };
  }
  return { ok: true, reason: `true move: ${nftTitles.length} re-minted title(s) each burn their prior NFT output` };
}

/** A running on-chain ledger: append moves, each linked to the last. Tracks each
 *  title's current NFT outpoint so every re-mint SPENDS (burns) the prior output
 *  (true move — the previous holder's NFT is consumed, never copied). */
export class MoveChain {
  private cursorOp: Outpoint;
  private nftOutpoints = new Map<number, Outpoint>();
  readonly txs: Tx[] = [];
  /** `initialNftOutpoints` seeds each title's genesis NFT outpoint (so the first
   *  transfer of a title burns its genesis output). */
  constructor(genesis: { tx: Tx; cursor: Outpoint }, initialNftOutpoints?: ReadonlyMap<number, Outpoint>) {
    this.cursorOp = genesis.cursor; this.txs.push(genesis.tx);
    if (initialNftOutpoints) for (const [k, v] of initialNftOutpoints) this.nftOutpoints.set(k, v);
  }
  get cursor(): Outpoint { return this.cursorOp; }
  /** The current on-chain NFT outpoint of each title (the live, unspent output). */
  nftOutpoint(propertyId: number): Outpoint | undefined { return this.nftOutpoints.get(propertyId); }
  /** Append a move; returns its real txid. Burns the prior NFT output of every
   *  re-minted title and records the new ones. */
  append(move: MoveTx, sequence = 0xffffffff, lockTime = 0): string {
    const { tx, cursor, nftOutpoints } = buildMove(this.cursorOp, move, sequence, lockTime, this.nftOutpoints);
    this.cursorOp = cursor;
    for (const [id, op] of nftOutpoints) this.nftOutpoints.set(id, op); // prior outpoint now spent + replaced
    this.txs.push(tx);
    return txid(tx);
  }
  /** The ordered txids: the on-chain transcript of the whole game. */
  transcript(): string[] { return this.txs.map((t) => txid(t)); }
}
