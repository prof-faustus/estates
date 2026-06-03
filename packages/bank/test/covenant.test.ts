import { test } from 'node:test';
import assert from 'node:assert/strict';
import { genKeyPair, type Tx } from '@estates/trade';
import { paymentOutput } from '@estates/onchain';
import {
  rulesHash, covenantOutput, verifyCovenantPayout, verifyCovenantSpend, buildCovenantPayout, makeBanker,
  type Covenant,
} from '../src/index.ts';

const seatPkh = new Uint8Array(20).fill(7);
const attackerPkh = new Uint8Array(20).fill(0xee);
const prevOutpoint = { txid: 'ab'.repeat(32), vout: 0 };
const reserve: Covenant = { reserve: 40_000, rulesHash: rulesHash() };

test('trustless payout: a legal payout verifies with ZERO signatures', () => {
  const tx = buildCovenantPayout(reserve, prevOutpoint, seatPkh, 200);
  const r = verifyCovenantPayout(reserve, tx, seatPkh, 200);
  assert.ok(r.valid, r.reason);
  // the tx carries no signatures at all — validity is purely structural
  assert.equal(tx.inputs[0]!.owner.every((b) => b === 0), true, 'no signer key needed');
});

test('over-draining the reserve is rejected by the covenant', () => {
  // pay 200 but only re-lock as if 0 were spent (try to keep full reserve AND pay out)
  const tx: Tx = {
    version: 1, inputs: [{ outpoint: prevOutpoint, owner: new Uint8Array(20), sequence: 0xffffffff }],
    outputs: [paymentOutput(200, seatPkh), covenantOutput(reserve.reserve, reserve.rulesHash)], // residual NOT reduced
    nLockTime: 0,
  };
  const r = verifyCovenantPayout(reserve, tx, seatPkh, 200);
  assert.equal(r.valid, false);
  assert.match(r.reason, /re-locked|drained/);
});

test('paying the wrong recipient is rejected', () => {
  const tx = buildCovenantPayout(reserve, prevOutpoint, attackerPkh, 200);
  // claim it was a legal 200 payout to the seat, but the tx pays the attacker
  const r = verifyCovenantPayout(reserve, tx, seatPkh, 200);
  assert.equal(r.valid, false);
  assert.match(r.reason, /legal recipient|legal amount/);
});

test('paying more than the legal amount is rejected', () => {
  const tx = buildCovenantPayout(reserve, prevOutpoint, seatPkh, 5000);
  const r = verifyCovenantPayout(reserve, tx, seatPkh, 200); // legal amount was 200
  assert.equal(r.valid, false);
});

test('failing to re-lock the remainder to the covenant is rejected', () => {
  const tx: Tx = {
    version: 1, inputs: [{ outpoint: prevOutpoint, owner: new Uint8Array(20), sequence: 0xffffffff }],
    // residual sent to a plain P2PKH (attacker) instead of the covenant
    outputs: [paymentOutput(200, seatPkh), paymentOutput(reserve.reserve - 200, attackerPkh)],
    nLockTime: 0,
  };
  const r = verifyCovenantPayout(reserve, tx, seatPkh, 200);
  assert.equal(r.valid, false);
  assert.match(r.reason, /re-locked|covenant/);
});

test('a payout exceeding the reserve is rejected', () => {
  const small: Covenant = { reserve: 100, rulesHash: rulesHash() };
  const tx = buildCovenantPayout(small, prevOutpoint, seatPkh, 100);
  assert.equal(verifyCovenantPayout(small, tx, seatPkh, 200).valid, false); // claim 200 > 100
});

test('a non-playing bankroller can be the banker (seat = null) and holds no spend authority', () => {
  const bankroller = makeBanker(genKeyPair(), null);
  assert.equal(bankroller.seat, null);
  // the covenant payout is valid regardless of the banker (banker never signs)
  const tx = buildCovenantPayout(reserve, prevOutpoint, seatPkh, 200);
  assert.ok(verifyCovenantPayout(reserve, tx, seatPkh, 200).valid);
  // a seated player can equally be the banker
  const playerBanker = makeBanker(genKeyPair(), 0);
  assert.equal(playerBanker.seat, 0);
});

test('the covenant pins the rule-set hash (mismatched rules do not re-lock)', () => {
  const tx = buildCovenantPayout(reserve, prevOutpoint, seatPkh, 200);
  const wrongRules: Covenant = { reserve: reserve.reserve, rulesHash: new Uint8Array(32).fill(1) };
  assert.equal(verifyCovenantPayout(wrongRules, tx, seatPkh, 200).valid, false);
});

// ---- audit #8: covenant spend bound to the real outpoint + prev script -------
test('verifyCovenantSpend binds to the spent outpoint AND the prev covenant script', () => {
  const prevScript = covenantOutput(reserve.reserve, reserve.rulesHash).script;
  const tx = buildCovenantPayout(reserve, prevOutpoint, seatPkh, 200);
  assert.ok(verifyCovenantSpend(reserve, prevOutpoint, prevScript, tx, seatPkh, 200).valid, 'legal bound spend verifies');

  // spends a DIFFERENT outpoint than the covenant UTXO → rejected
  const wrongIn = { ...tx, inputs: [{ ...tx.inputs[0]!, outpoint: { txid: 'cd'.repeat(32), vout: 1 } }] };
  assert.equal(verifyCovenantSpend(reserve, prevOutpoint, prevScript, wrongIn, seatPkh, 200).valid, false);

  // the spent prevout script is NOT this covenant (e.g. different rules hash) → rejected
  const otherScript = covenantOutput(reserve.reserve, new Uint8Array(32).fill(1)).script;
  assert.equal(verifyCovenantSpend(reserve, prevOutpoint, otherScript, tx, seatPkh, 200).valid, false);

  // wrong amount / recipient still rejected (delegates to the payout predicate)
  assert.equal(verifyCovenantSpend(reserve, prevOutpoint, prevScript, tx, attackerPkh, 200).valid, false);
});
