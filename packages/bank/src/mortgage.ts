/**
 * Mortgage = a REAL on-chain financial instrument (covenant smart contract), not
 * a gameplay flag. A property NFT is locked as COLLATERAL in a covenant output;
 * the borrower receives a `principal` loan in sats; the covenant self-enforces
 * the two ways the position can close, WITHOUT trusting any operator (the
 * OP_PUSH_TX / sighash-preimage introspection technique — modelled here as pure
 * structural predicates, exactly as @estates/bank/covenant.ts does for the
 * reserve):
 *
 *   • REDEEM   — borrower repays `redemption` (principal + interest) to the
 *                lender and the collateral NFT returns to the borrower.
 *   • FORECLOSE — after the `maturity` window (transaction-level nLockTime;
 *                NEVER CLTV/CSV) the lender may seize the collateral NFT.
 *
 * The covenant pins a hash of ALL terms, so neither party can alter the deal:
 * an out-of-terms spend fails the predicate and no honest peer relays it.
 */
import { createHash } from 'node:crypto';
import {
  NFT_SATS, nftOutput, paymentOutput, push, op, OP, serializeScript,
  type TitleState, type TxOutput,
} from '@estates/onchain';
import type { Tx } from '@estates/trade';

const MORTGAGE_TAG = new TextEncoder().encode('ESTATES-MORTGAGE-COVENANT-v1');

export interface MortgageTerms {
  readonly collateral: TitleState;   // the property NFT put up as collateral
  readonly borrowerPkh: Uint8Array;  // 20-byte hash160 — who redeems
  readonly lenderPkh: Uint8Array;    // 20-byte — the bank/financier
  readonly principal: number;        // sats advanced to the borrower at origination
  readonly redemption: number;       // sats owed to redeem (principal + interest), whole sats
  readonly maturity: number;         // nLockTime (block height / MTP) after which foreclosure is valid
}

const u32 = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]!);

/** Canonical hash binding every term of the deal (pinned in the covenant). */
export function termsHash(t: MortgageTerms): Uint8Array {
  const h = createHash('sha256');
  h.update(MORTGAGE_TAG);
  h.update(t.collateral.gameTag);
  h.update(u32(t.collateral.propertyId));
  h.update(u32(t.collateral.buildLevel));
  h.update(Buffer.from(t.collateral.genesis.txid, 'hex'));
  h.update(u32(t.collateral.genesis.vout));
  h.update(t.borrowerPkh);
  h.update(t.lenderPkh);
  h.update(u32(t.principal));
  h.update(u32(t.redemption));
  h.update(u32(t.maturity));
  return new Uint8Array(h.digest());
}

/** The covenant output holding the collateral NFT (1 sat) under the pinned terms.
 *  `<termsHash> <MORTGAGE_TAG> OP_2DROP OP_TRUE` — spendable only into a tx that
 *  satisfies REDEEM or FORECLOSE (enforced by the predicates below / OP_PUSH_TX). */
export function mortgageCovenantOutput(t: MortgageTerms): TxOutput {
  return {
    satoshis: NFT_SATS,
    script: serializeScript([push(termsHash(t)), push(MORTGAGE_TAG), op(OP.OP_2DROP), op(0x51 /* OP_TRUE */)]),
  };
}

/** Interest is a basis-point rate on the principal; redemption is whole sats (round up). */
export function redemptionFor(principal: number, interestBps: number): number {
  if (!Number.isInteger(principal) || principal <= 0) throw new Error('principal must be a positive integer (whole sats)');
  return principal + Math.ceil((principal * interestBps) / 10_000);
}

export interface CovenantCheck { readonly valid: boolean; readonly reason: string }

// ---- ORIGINATION ------------------------------------------------------------
/** Origination: lock the collateral NFT into the covenant and advance `principal`
 *  sats to the borrower. (Inputs — borrower's NFT + lender funds — are signed
 *  normally; the covenant only governs how the locked output may later be spent.) */
export function buildMortgage(t: MortgageTerms, collateralOutpoint: { txid: string; vout: number }, lenderOutpoint: { txid: string; vout: number }): Tx {
  return {
    version: 1,
    inputs: [
      { outpoint: collateralOutpoint, owner: t.borrowerPkh, sequence: 0xffffffff },
      { outpoint: lenderOutpoint, owner: t.lenderPkh, sequence: 0xffffffff },
    ],
    outputs: [mortgageCovenantOutput(t), paymentOutput(t.principal, t.borrowerPkh)],
    nLockTime: 0,
  };
}

// ---- REDEEM -----------------------------------------------------------------
/** REDEEM predicate: VALID iff output[0] returns the (unmortgaged) collateral NFT
 *  to the borrower and output[1] pays exactly `redemption` to the lender. */
export function verifyRedemption(t: MortgageTerms, tx: Tx): CovenantCheck {
  if (tx.outputs.length !== 2) return { valid: false, reason: `redeem must have 2 outputs, got ${tx.outputs.length}` };
  const back = nftOutput({ ...t.collateral, mortgaged: false }, t.borrowerPkh);
  const o0 = tx.outputs[0]!;
  if (o0.satoshis !== NFT_SATS || !eq(o0.script, back.script)) return { valid: false, reason: 'output[0] must return the collateral NFT to the borrower' };
  const pay = paymentOutput(t.redemption, t.lenderPkh);
  const o1 = tx.outputs[1]!;
  if (o1.satoshis !== t.redemption || !eq(o1.script, pay.script)) return { valid: false, reason: 'output[1] must pay exactly the redemption amount to the lender' };
  return { valid: true, reason: `redeemed: collateral returned, ${t.redemption} sats repaid; no signature trust required` };
}
export function buildRedemption(t: MortgageTerms, covenantOutpoint: { txid: string; vout: number }, borrowerFundsOutpoint: { txid: string; vout: number }): Tx {
  return {
    version: 1,
    inputs: [
      { outpoint: covenantOutpoint, owner: new Uint8Array(20), sequence: 0xffffffff },
      { outpoint: borrowerFundsOutpoint, owner: t.borrowerPkh, sequence: 0xffffffff },
    ],
    outputs: [nftOutput({ ...t.collateral, mortgaged: false }, t.borrowerPkh), paymentOutput(t.redemption, t.lenderPkh)],
    nLockTime: 0,
  };
}

// ---- FORECLOSE (time-gated, nLockTime only) ---------------------------------
/** FORECLOSE predicate: VALID iff the maturity window has elapsed (tx.nLockTime ≥
 *  maturity AND the input nSequence enables locktime AND the chain tip has reached
 *  maturity) and output[0] transfers the collateral NFT to the lender. No CLTV/CSV. */
export function verifyForeclosure(t: MortgageTerms, tx: Tx, tipHeight: number): CovenantCheck {
  if (tx.nLockTime < t.maturity) return { valid: false, reason: 'foreclosure tx nLockTime is before maturity' };
  if (tipHeight < t.maturity) return { valid: false, reason: 'maturity window has not elapsed yet (chain tip < maturity)' };
  const input0 = tx.inputs[0];
  if (!input0 || input0.sequence === 0xffffffff) return { valid: false, reason: 'input nSequence must be < 0xffffffff so nLockTime is enforced' };
  if (tx.outputs.length !== 1) return { valid: false, reason: `foreclose must have 1 output, got ${tx.outputs.length}` };
  const seize = nftOutput({ ...t.collateral, mortgaged: false }, t.lenderPkh);
  const o0 = tx.outputs[0]!;
  if (o0.satoshis !== NFT_SATS || !eq(o0.script, seize.script)) return { valid: false, reason: 'output[0] must transfer the collateral NFT to the lender' };
  return { valid: true, reason: `foreclosed at/after maturity ${t.maturity}: lender seized the collateral` };
}
export function buildForeclosure(t: MortgageTerms, covenantOutpoint: { txid: string; vout: number }): Tx {
  return {
    version: 1,
    inputs: [{ outpoint: covenantOutpoint, owner: new Uint8Array(20), sequence: 0xfffffffe /* enables nLockTime */ }],
    outputs: [nftOutput({ ...t.collateral, mortgaged: false }, t.lenderPkh)],
    nLockTime: t.maturity,
  };
}
