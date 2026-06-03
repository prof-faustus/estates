/**
 * Trustless bank covenant (D-BANK-ENFORCE upgrade) — removes the honest-quorum
 * assumption of the M-of-N guard.
 *
 * The reserve sits in a covenant output that pins the rules hash. A spend is
 * valid iff its outputs match the rules-mandated action AND the remainder is
 * re-locked to the SAME covenant — checked WITHOUT any seat signatures. In
 * production this is enforced by Script via sighash-preimage introspection
 * (OP_PUSH_TX); here `verifyCovenantPayout` is the equivalent pure predicate.
 *
 * Because validity is purely structural, ANY party can assemble and broadcast a
 * payout — so the "banker" is just whoever FUNDED the reserve (a seated player
 * or a non-playing bankroller). They hold no spend authority, need not be
 * online, and cannot cheat: the covenant self-enforces.
 */
import { createHash } from 'node:crypto';
import { loadParams } from '@estates/params';
import { paymentOutput, push, op, OP, serializeScript, type TxOutput } from '@estates/onchain';
import type { Tx, KeyPair } from '@estates/trade';

const COVENANT_TAG = new TextEncoder().encode('ESTATES-BANK-COVENANT-v1');

/** Hash of the rule-set (params SoT) pinned by the covenant. */
export function rulesHash(): Uint8Array {
  return new Uint8Array(createHash('sha256').update(JSON.stringify(loadParams())).digest());
}

export interface Covenant { readonly reserve: number; readonly rulesHash: Uint8Array; }

/**
 * The reserve covenant output: `<rulesHash> <COVENANT_TAG> OP_2DROP OP_TRUE`.
 * Spendable by anyone, but only into a tx whose outputs satisfy the covenant
 * (enforced by `verifyCovenantPayout` / OP_PUSH_TX in production).
 */
export function covenantOutput(reserve: number, rh: Uint8Array = rulesHash()): TxOutput {
  return {
    satoshis: reserve,
    script: serializeScript([push(rh), push(COVENANT_TAG), op(OP.OP_2DROP), op(0x51 /* OP_TRUE */)]),
  };
}

const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]!);

/** Who bankrolled the reserve. `seat: null` = a non-playing bankroller. */
export interface Banker { readonly keys: KeyPair; readonly seat: number | null; }
export function makeBanker(keys: KeyPair, seat: number | null = null): Banker { return { keys, seat }; }

export interface CovenantCheck { readonly valid: boolean; readonly reason: string; }

/**
 * Verify a trustless payout from the reserve covenant (salary / payout / card
 * collect-from-bank). VALID iff, with NO signatures:
 *   output[0] = exactly `amount` sats to `recipientPkh`, and
 *   output[1] = the reserve covenant re-locked at `prev.reserve - amount`
 *               with the SAME rules hash.
 * Over-paying, paying the wrong recipient, or failing to re-lock the remainder
 * are all rejected by the covenant.
 */
export function verifyCovenantPayout(prev: Covenant, tx: Tx, recipientPkh: Uint8Array, amount: number): CovenantCheck {
  if (amount <= 0) return { valid: false, reason: 'amount must be positive' };
  if (amount > prev.reserve) return { valid: false, reason: 'payout exceeds the reserve' };
  if (tx.outputs.length !== 2) return { valid: false, reason: `covenant payout must have exactly 2 outputs, got ${tx.outputs.length}` };

  const pay = tx.outputs[0]!;
  const want = paymentOutput(amount, recipientPkh);
  if (pay.satoshis !== amount || !eq(pay.script, want.script)) {
    return { valid: false, reason: 'output[0] does not pay exactly the legal amount to the legal recipient' };
  }

  const residual = tx.outputs[1]!;
  const wantResidual = covenantOutput(prev.reserve - amount, prev.rulesHash);
  if (residual.satoshis !== prev.reserve - amount || !eq(residual.script, wantResidual.script)) {
    return { valid: false, reason: 'remainder is not re-locked to the same covenant (reserve could be drained)' };
  }
  return { valid: true, reason: `trustless payout of ${amount}; ${prev.reserve - amount} re-locked; no signatures required` };
}

/**
 * Audit #8: a FULL covenant-spend check that BINDS the predicate to the chain,
 * not just to caller-supplied recipient/amount. VALID iff:
 *   - the tx actually spends the named covenant outpoint (input[0] === prevOutpoint),
 *   - that input's previous locking script is exactly this covenant's script for
 *     `prev.rulesHash` (so the rules hash / reserve are pinned to the real UTXO),
 *   - and the outputs satisfy the payout predicate (pay exactly `amount` to
 *     `recipientPkh`, re-lock the residual to the SAME covenant).
 * `recipientPkh`/`amount` must be the canonical values the deterministic engine
 * mandates for the current state — the caller derives them from state, and the
 * residual re-lock binds the rules hash so a wrong-rules spend cannot validate.
 */
export function verifyCovenantSpend(
  prev: Covenant,
  prevOutpoint: { txid: string; vout: number },
  prevScript: Uint8Array,
  tx: Tx,
  recipientPkh: Uint8Array,
  amount: number,
): CovenantCheck {
  const inp = tx.inputs[0];
  if (!inp || inp.outpoint.txid !== prevOutpoint.txid || inp.outpoint.vout !== prevOutpoint.vout) {
    return { valid: false, reason: 'tx does not spend the covenant outpoint' };
  }
  const expectedPrev = covenantOutput(prev.reserve, prev.rulesHash).script;
  if (!eq(prevScript, expectedPrev)) {
    return { valid: false, reason: 'spent prevout script is not this covenant (rules hash / reserve mismatch)' };
  }
  return verifyCovenantPayout(prev, tx, recipientPkh, amount);
}

/** Build a well-formed covenant payout tx (the honest path). */
export function buildCovenantPayout(prev: Covenant, prevOutpoint: { txid: string; vout: number }, recipientPkh: Uint8Array, amount: number): Tx {
  return {
    version: 1,
    inputs: [{ outpoint: prevOutpoint, owner: new Uint8Array(20), sequence: 0xffffffff }],
    outputs: [paymentOutput(amount, recipientPkh), covenantOutput(prev.reserve - amount, prev.rulesHash)],
    nLockTime: 0,
  };
}
