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
const GAME = new Uint8Array(32).fill(0x5a);
const reserve: Covenant = { reserve: 40_000, rulesHash: rulesHash(GAME) };

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
  const small: Covenant = { reserve: 100, rulesHash: rulesHash(GAME) };
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

// ---- one-game lifecycle: a reserve belongs to exactly ONE game ---------------
test('the covenant is bound to one game: a different gameId yields a DISTINCT script', () => {
  const other = new Uint8Array(32).fill(0xa5);
  // same params, DIFFERENT game → different rules hash → different covenant script.
  assert.notDeepEqual(rulesHash(GAME), rulesHash(other), 'rules hash binds the gameId');
  assert.notDeepEqual(
    covenantOutput(reserve.reserve, rulesHash(GAME)).script,
    covenantOutput(reserve.reserve, rulesHash(other)).script,
    'two games never share a reserve covenant script',
  );
});

test('a payout assembled for one game does NOT validate against another game reserve', () => {
  const other = new Uint8Array(32).fill(0xa5);
  const otherReserve: Covenant = { reserve: reserve.reserve, rulesHash: rulesHash(other) };
  // a legal-looking payout built against GAME's covenant…
  const tx = buildCovenantPayout(reserve, prevOutpoint, seatPkh, 200);
  const prevScript = covenantOutput(reserve.reserve, reserve.rulesHash).script;
  // …re-locks the residual under GAME's rules, so it cannot re-lock the OTHER
  // game's reserve: bound-spend against the other game's covenant is rejected.
  assert.equal(verifyCovenantSpend(otherReserve, prevOutpoint, prevScript, tx, seatPkh, 200).valid, false,
    'cross-game reserve reuse is rejected');
  // and the structural payout predicate against the other reserve fails to re-lock too
  assert.equal(verifyCovenantPayout(otherReserve, tx, seatPkh, 200).valid, false);
});

test('rulesHash rejects a non-32-byte gameId (fail closed)', () => {
  assert.throws(() => rulesHash(new Uint8Array(31)));
  assert.throws(() => rulesHash(new Uint8Array(0)));
});
