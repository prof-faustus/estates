/**
 * @estates/beef — the SPV envelope peers exchange IP-to-IP and verify with NO
 * node and NO third-party API (the BEEF/BRC-62 idea). A move's transaction travels
 * with the Merkle proof + block header that prove it is confirmed; the receiver
 * recomputes the leaf (hash256 of the raw tx), checks the proof recomputes the
 * header's merkleRoot (@estates/spv), and is satisfied of inclusion under PoW —
 * trusting only mathematics, never the sender or any operator.
 */
import { serializeTx, hash256, txid, type Tx } from '@estates/tx';
import {
  verifyInclusion, bytesEqual, type MerkleProof, type BlockHeader,
} from '@estates/spv';

/** The Merkle LEAF of a tx = hash256(rawTx), in internal byte order. */
export function txLeaf(tx: Tx): Uint8Array { return hash256(serializeTx(tx)); }

export interface Envelope {
  readonly tx: Tx;
  readonly proof: MerkleProof;
  readonly header: BlockHeader; // the block the tx is in (PoW-checkable elsewhere)
}

/** Verify a tx is confirmed in `header`'s block, by SPV inclusion alone. Total:
 *  an envelope carrying a malformed tx/proof/header returns false, never throws
 *  (serializeTx would otherwise throw on a non-conforming tx object). */
export function verifyEnvelope(env: Envelope): boolean {
  try {
    if (!env || typeof env !== 'object' || !env.tx || !env.proof || !env.header) return false;
    return verifyInclusion(txLeaf(env.tx), env.proof, env.header.merkleRoot);
  } catch { return false; }
}

export interface ExpectedPayment { readonly value: number | bigint; readonly script: Uint8Array }
/** Verify the confirmed tx actually pays `expected` at some output (e.g. that a
 *  one-use key / 1-sat NFT was funded on chain) — inclusion AND content. Total. */
export function verifyPaymentToKey(env: Envelope, expected: ExpectedPayment): boolean {
  try {
    if (!verifyEnvelope(env)) return false;
    const want = BigInt(expected.value);
    return env.tx.outputs.some((o) => BigInt(o.value) === want && bytesEqual(o.script, expected.script));
  } catch { return false; }
}

export interface SpendCheck { readonly ok: boolean; readonly reason: string }
/** SPV chain of custody for an UNCONFIRMED move: every input must spend an output
 *  of a CONFIRMED tx whose envelope verifies, and that output must exist. The
 *  unconfirmed tx itself needs no proof yet — its provenance is SPV-proven. */
export function verifySpendChain(spend: Tx, inputEnvelopes: readonly Envelope[]): SpendCheck {
  const byId = new Map<string, Envelope>();
  for (const e of inputEnvelopes) {
    // verifyEnvelope is total; compute the txid (serializeTx) under guard too so a
    // malformed input tx is a clean reject, never a throw.
    let id: string;
    try { if (!verifyEnvelope(e)) return { ok: false, reason: 'an input envelope failed SPV' }; id = txid(e.tx); }
    catch { return { ok: false, reason: 'an input envelope tx is malformed' }; }
    byId.set(id, e);
  }
  for (let i = 0; i < spend.inputs.length; i++) {
    const inp = spend.inputs[i]!;
    const src = byId.get(inp.prevTxid);
    if (!src) return { ok: false, reason: `input ${i} spends ${inp.prevTxid.slice(0, 12)}… with no SPV-proven source` };
    if (inp.prevVout < 0 || inp.prevVout >= src.tx.outputs.length) return { ok: false, reason: `input ${i} references a non-existent output vout ${inp.prevVout}` };
  }
  return { ok: true, reason: `all ${spend.inputs.length} input(s) trace to SPV-confirmed outputs` };
}
