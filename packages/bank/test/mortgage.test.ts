import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nftOutput, paymentOutput, NFT_SATS, type TitleState } from '@estates/onchain';
import {
  termsHash, mortgageCovenantOutput, redemptionFor, verifyRedemption, verifyForeclosure,
  buildMortgage, buildRedemption, buildForeclosure, type MortgageTerms,
} from '../src/mortgage.ts';

const pkh = (b: number) => new Uint8Array(20).fill(b);
const collateral: TitleState = {
  kind: 'TITLE', gameTag: new Uint8Array(32).fill(9), propertyId: 7, groupId: 2,
  buildLevel: 0, mortgaged: true, genesis: { txid: 'ab'.repeat(32), vout: 1 },
};
const terms: MortgageTerms = {
  collateral, borrowerPkh: pkh(0xa1), lenderPkh: pkh(0xb2),
  principal: 1000, redemption: redemptionFor(1000, 1000 /* 10% */), maturity: 500,
};
const OP = { txid: '11'.repeat(32), vout: 0 };

test('redemptionFor: principal + interest, whole sats (round up)', () => {
  assert.equal(redemptionFor(1000, 1000), 1100); // 10%
  assert.equal(redemptionFor(101, 1000), 112);   // 101 + ceil(10.1)=11
  assert.throws(() => redemptionFor(0, 1000));
});

test('termsHash binds every term — change any field, the covenant changes', () => {
  const base = termsHash(terms);
  for (const mut of [
    { ...terms, principal: 1001 },
    { ...terms, redemption: terms.redemption + 1 },
    { ...terms, maturity: 501 },
    { ...terms, borrowerPkh: pkh(0xa2) },
    { ...terms, lenderPkh: pkh(0xb3) },
    { ...terms, collateral: { ...collateral, propertyId: 8 } },
  ] as MortgageTerms[]) {
    assert.notDeepEqual(termsHash(mut), base, 'a different deal yields a different covenant');
  }
  assert.deepEqual(termsHash(terms), base, 'deterministic for the same terms');
  assert.equal(mortgageCovenantOutput(terms).satoshis, NFT_SATS, 'collateral held as a 1-sat NFT covenant');
});

test('REDEEM: borrower repays redemption to lender, gets the (unmortgaged) NFT back', () => {
  const tx = buildRedemption(terms, OP, { txid: '22'.repeat(32), vout: 0 });
  const r = verifyRedemption(terms, tx);
  assert.ok(r.valid, r.reason);
  // exact-match outputs
  assert.deepEqual(tx.outputs[0], nftOutput({ ...collateral, mortgaged: false }, terms.borrowerPkh));
  assert.deepEqual(tx.outputs[1], paymentOutput(terms.redemption, terms.lenderPkh));
});

test('REDEEM rejects underpayment, wrong recipient, or not returning the NFT', () => {
  const good = buildRedemption(terms, OP, { txid: '22'.repeat(32), vout: 0 });
  // underpay
  assert.equal(verifyRedemption(terms, { ...good, outputs: [good.outputs[0]!, paymentOutput(terms.redemption - 1, terms.lenderPkh)] }).valid, false);
  // pay the wrong party
  assert.equal(verifyRedemption(terms, { ...good, outputs: [good.outputs[0]!, paymentOutput(terms.redemption, pkh(0xee))] }).valid, false);
  // keep the NFT instead of returning it
  assert.equal(verifyRedemption(terms, { ...good, outputs: [nftOutput({ ...collateral, mortgaged: false }, pkh(0xee)), good.outputs[1]!] }).valid, false);
  // wrong output count
  assert.equal(verifyRedemption(terms, { ...good, outputs: [good.outputs[0]!] }).valid, false);
});

test('FORECLOSE: only at/after maturity, locktime-enabled, NFT to the lender', () => {
  const tx = buildForeclosure(terms, OP);
  assert.equal(tx.nLockTime, terms.maturity);
  assert.notEqual(tx.inputs[0]!.sequence, 0xffffffff, 'nSequence enables nLockTime (no CLTV/CSV)');
  assert.ok(verifyForeclosure(terms, tx, terms.maturity).valid, 'valid exactly at maturity tip');
  assert.ok(verifyForeclosure(terms, tx, terms.maturity + 10).valid, 'valid after maturity');
  assert.deepEqual(tx.outputs[0], nftOutput({ ...collateral, mortgaged: false }, terms.lenderPkh));
});

test('FORECLOSE rejected before maturity, with finalized sequence, or NFT to non-lender', () => {
  const tx = buildForeclosure(terms, OP);
  assert.equal(verifyForeclosure(terms, tx, terms.maturity - 1).valid, false, 'chain tip before maturity');
  assert.equal(verifyForeclosure(terms, { ...tx, nLockTime: terms.maturity - 1 }, terms.maturity).valid, false, 'nLockTime before maturity');
  assert.equal(verifyForeclosure(terms, { ...tx, inputs: [{ ...tx.inputs[0]!, sequence: 0xffffffff }] }, terms.maturity).valid, false, 'finalized input ignores locktime');
  assert.equal(verifyForeclosure(terms, { ...tx, outputs: [nftOutput({ ...collateral, mortgaged: false }, terms.borrowerPkh)] }, terms.maturity).valid, false, 'NFT must go to lender');
});

test('ORIGINATION builds the covenant + advances principal to the borrower', () => {
  const tx = buildMortgage(terms, OP, { txid: '33'.repeat(32), vout: 2 });
  assert.equal(tx.outputs.length, 2);
  assert.deepEqual(tx.outputs[0], mortgageCovenantOutput(terms));
  assert.deepEqual(tx.outputs[1], paymentOutput(terms.principal, terms.borrowerPkh));
});
