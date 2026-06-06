import { test } from 'node:test';
import assert from 'node:assert/strict';
import { genKeyPair, type Tx } from '@estates/trade';
import { gameTag, type TitleState } from '@estates/onchain';
import { loadParams } from '@estates/params';
import {
  pkhOf, signBankSpend, verifyBankSpend, legalOutputs, certify, buildGenesis,
  verifyReserveSpend, reserveOutput, rulesHash, buildCovenantPayout, bankActionBelongsToGame,
  type BankPolicy, type Covenant,
} from '../src/index.ts';

const P = loadParams();
const GAME = new Uint8Array(32).fill(11);
const op = { txid: 'aa'.repeat(32), vout: 0 };

function bankSpendTx(outputs: { satoshis: number; script: Uint8Array }[]): Tx {
  return { version: 1, inputs: [{ outpoint: op, owner: new Uint8Array(20), sequence: 0xffffffff }], outputs, nLockTime: 0 };
}

test('M-of-N: fewer than threshold signatures is invalid; threshold is valid', () => {
  const seats = [genKeyPair(), genKeyPair(), genKeyPair()];
  const policy: BankPolicy = { seatPubkeys: seats.map((k) => k.publicKey), threshold: 2 };
  const tx = bankSpendTx(legalOutputs({ kind: 'salary', seatPkh: seats[0]!.pkh, amount: 200 }));

  const one = [{ pub: seats[0]!.publicKey, sig: signBankSpend(tx, seats[0]!) }];
  assert.equal(verifyBankSpend(tx, one, policy).valid, false);

  const two = [...one, { pub: seats[1]!.publicKey, sig: signBankSpend(tx, seats[1]!) }];
  const r = verifyBankSpend(tx, two, policy);
  assert.ok(r.valid && r.count === 2);
});

test('a non-seat key and duplicate signers do not count toward the threshold', () => {
  const seats = [genKeyPair(), genKeyPair(), genKeyPair()];
  const intruder = genKeyPair();
  const policy: BankPolicy = { seatPubkeys: seats.map((k) => k.publicKey), threshold: 2 };
  const tx = bankSpendTx(legalOutputs({ kind: 'payout', seatPkh: seats[0]!.pkh, amount: 50 }));

  // one real seat + an intruder + the same seat again -> only 1 distinct valid seat sig
  const sigs = [
    { pub: seats[0]!.publicKey, sig: signBankSpend(tx, seats[0]!) },
    { pub: intruder.publicKey, sig: signBankSpend(tx, intruder) },
    { pub: seats[0]!.publicKey, sig: signBankSpend(tx, seats[0]!) },
  ];
  assert.equal(verifyBankSpend(tx, sigs, policy).count, 1);
});

test('signatures do not transfer across tampered outputs (sign one tx, alter it)', () => {
  const seats = [genKeyPair(), genKeyPair()];
  const policy: BankPolicy = { seatPubkeys: seats.map((k) => k.publicKey), threshold: 2 };
  const tx = bankSpendTx(legalOutputs({ kind: 'salary', seatPkh: seats[0]!.pkh, amount: 200 }));
  const sigs = seats.map((k) => ({ pub: k.publicKey, sig: signBankSpend(tx, k) }));
  // tamper: change the salary to 999 after signing
  const tampered = bankSpendTx(legalOutputs({ kind: 'salary', seatPkh: seats[0]!.pkh, amount: 999 }));
  assert.equal(verifyBankSpend(tampered, sigs, policy).valid, false);
});

test('certify accepts the legal output set and rejects an illegal one', () => {
  const buyer = genKeyPair(); const bank = genKeyPair();
  const nft: TitleState = { kind: 'TITLE', gameTag: gameTag(GAME, 'TITLE'), propertyId: 3, groupId: 0, buildLevel: 0, mortgaged: false, genesis: op };
  const legal = legalOutputs({ kind: 'purchase', buyerPkh: buyer.pkh, bankPkh: bank.pkh, price: 60, nft });
  const tx = bankSpendTx(legal);
  assert.equal(certify(tx, legal), true);
  // an illegal spend: pay the buyer extra instead of the bank
  const illegal = bankSpendTx(legalOutputs({ kind: 'salary', seatPkh: buyer.pkh, amount: 1000 }));
  assert.equal(certify(illegal, legal), false);
});

test('genesis tx mints all 1-sat NFTs and funds seats + reserve', () => {
  const seats = [genKeyPair(), genKeyPair()];
  const bank = genKeyPair();
  const g = buildGenesis({
    network: 'regtest', gameId: GAME, seatPkhs: seats.map((k) => k.pkh), bankPkh: bank.pkh,
    startingBalance: P.scalars.starting_balance_per_seat, bankReserve: 40000,
    fundingInputs: [op], beaconSeed: new Uint8Array(32).fill(1),
  });
  // 28 titles + 2 reprieve + 2 seat balances + reserve + params + beacon
  assert.equal(Object.keys(g.titleVout).length, 28);
  assert.equal(g.reprieveVouts.length, 2);
  // every NFT output is exactly 1 sat
  const nftIdx = [...Object.values(g.titleVout), ...g.reprieveVouts];
  for (const i of nftIdx) assert.equal(g.tx.outputs[i]!.satoshis, 1);
  // reserve + seat balances are native sats
  assert.equal(g.tx.outputs[g.reserveVout]!.satoshis, 40000);
  // total NFTs = 30 (28 + 2)
  assert.equal(nftIdx.length, 30);
});

test('genesis output count is fully accounted for', () => {
  const seats = [genKeyPair(), genKeyPair(), genKeyPair()];
  const bank = genKeyPair();
  const g = buildGenesis({
    network: 'mainnet', gameId: GAME, seatPkhs: seats.map((k) => k.pkh), bankPkh: bank.pkh,
    startingBalance: 1500, bankReserve: 40000, fundingInputs: [op], beaconSeed: new Uint8Array(32),
  });
  // 28 titles + 2 reprieve + 3 seats + 1 reserve + 1 params + 1 beacon = 36
  assert.equal(g.tx.outputs.length, 28 + 2 + 3 + 1 + 1 + 1);
});

// ---- audit #8: the bank reserve has a CHOICE of quorum OR script-covenant -----
test('reserve enforcement choice: quorum (M-of-N) and covenant (trustless) both verify', () => {
  const seats = [genKeyPair(), genKeyPair(), genKeyPair()];
  const policy: BankPolicy = { seatPubkeys: seats.map((k) => k.publicKey), threshold: 2 };

  // QUORUM mode: M-of-N seats co-sign a certified-legal action
  const action = { kind: 'salary', seatPkh: seats[0]!.pkh, amount: 200 } as const;
  const qtx = bankSpendTx(legalOutputs(action));
  const sigs = [
    { pub: seats[0]!.publicKey, sig: signBankSpend(qtx, seats[0]!) },
    { pub: seats[1]!.publicKey, sig: signBankSpend(qtx, seats[1]!) },
  ];
  // quorum is a TRUST ASSUMPTION: refused by default (trustless covenant is the default).
  assert.equal(verifyReserveSpend({ mode: 'quorum', tx: qtx, sigs, policy, action }).valid, false, 'quorum refused without explicit opt-in');
  // with the explicit test/non-production opt-in it verifies the M-of-N signatures.
  assert.ok(verifyReserveSpend({ mode: 'quorum', tx: qtx, sigs, policy, action }, { allowQuorum: true }).valid, 'quorum spend verifies when explicitly opted in');
  // quorum with outputs not matching the certified action → rejected
  const qbad = bankSpendTx(legalOutputs({ kind: 'salary', seatPkh: seats[0]!.pkh, amount: 999 }));
  assert.equal(verifyReserveSpend({ mode: 'quorum', tx: qbad, sigs, policy, action }, { allowQuorum: true }).valid, false);

  // COVENANT mode: trustless, ZERO signatures, bound to the spent outpoint+script
  const reserve: Covenant = { reserve: 40_000, rulesHash: rulesHash(GAME) };
  const prevOutpoint = { txid: 'cd'.repeat(32), vout: 0 };
  const prevScript = reserveOutput('covenant', reserve.reserve, seats[0]!.pkh, reserve.rulesHash).script;
  const ctx = buildCovenantPayout(reserve, prevOutpoint, seats[0]!.pkh, 200);
  assert.ok(verifyReserveSpend({ mode: 'covenant', tx: ctx, covenant: reserve, prevOutpoint, prevScript, recipientPkh: seats[0]!.pkh, amount: 200 }).valid, 'covenant spend verifies');

  // the reserve OUTPUT differs by chosen mode (P2PKH-to-bank vs covenant script)
  assert.notDeepEqual(reserveOutput('quorum', 40_000, seats[0]!.pkh).script, reserveOutput('covenant', 40_000, seats[0]!.pkh, rulesHash(GAME)).script);
});

test('bankActionBelongsToGame: a purchase must move THIS game’s NFT; a foreign-game deed is rejected', () => {
  const OTHER = new Uint8Array(32).fill(0xa5);
  const buyer = pkhOf(genKeyPair().publicKey); const bankPkh = pkhOf(genKeyPair().publicKey);
  const op = { txid: 'cd'.repeat(32), vout: 0 };
  const mine: TitleState = { kind: 'TITLE', gameTag: gameTag(GAME, 'TITLE'), propertyId: 3, groupId: 0, buildLevel: 0, mortgaged: false, genesis: op };
  const foreign: TitleState = { ...mine, gameTag: gameTag(OTHER, 'TITLE') };
  assert.equal(bankActionBelongsToGame({ kind: 'purchase', buyerPkh: buyer, bankPkh, price: 60, nft: mine }, GAME), true);
  assert.equal(bankActionBelongsToGame({ kind: 'purchase', buyerPkh: buyer, bankPkh, price: 60, nft: foreign }, GAME), false);
  // non-NFT actions are bound to the game by the reserve covenant, so they pass this check
  assert.equal(bankActionBelongsToGame({ kind: 'salary', seatPkh: buyer, amount: 200 }, GAME), true);
  assert.equal(bankActionBelongsToGame({ kind: 'collect', bankPkh, amount: 50 }, GAME), true);
  // fail closed on a bad gameId
  assert.equal(bankActionBelongsToGame({ kind: 'purchase', buyerPkh: buyer, bankPkh, price: 60, nft: mine }, new Uint8Array(31)), false);
});
