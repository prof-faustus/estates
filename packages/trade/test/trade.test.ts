import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gameTag, paymentOutput, type TitleState, type Outpoint } from '@estates/onchain';
import { genKeyPair, buildTrade, cosign, verifyTrade, valueConserved, verifyTradeValue, type Leg } from '../src/index.ts';

const GAME = new Uint8Array(32).fill(9);
const outpoint = (tag: string, vout = 0): Outpoint => ({ txid: tag.repeat(32).slice(0, 64), vout });

function titleNft(propertyId: number, genesis: Outpoint): { outpoint: Outpoint; state: TitleState } {
  return {
    outpoint: genesis,
    state: { kind: 'TITLE', gameTag: gameTag(GAME, 'TITLE'), propertyId, groupId: 0, buildLevel: 0, mortgaged: false, genesis },
  };
}

function legs() {
  const A = genKeyPair(), B = genKeyPair();
  const a: Leg = {
    party: A, giveNfts: [titleNft(3, outpoint('a1'))], giveSats: 0,
    satsFundingOutpoint: outpoint('af'), changePkh: A.pkh,
  };
  const b: Leg = {
    party: B, giveNfts: [], giveSats: 100,
    satsFundingOutpoint: outpoint('bf'), changePkh: B.pkh,
  };
  return { A, B, a, b };
}

test('fully co-signed trade is valid; NFT reassigned and sats paid', () => {
  const { a, b } = legs();
  let st = buildTrade(a, b);
  st = cosign(st, a.party);
  st = cosign(st, b.party);
  const v = verifyTrade(st);
  assert.ok(v.valid, v.reason);
  assert.equal(valueConserved(a, b, st), true);
  // the NFT output went to B; a 100-sat payment went to A
  assert.equal(st.tx.outputs.some((o) => o.satoshis === 1), true);   // re-minted NFT (1 sat)
  assert.equal(st.tx.outputs.some((o) => o.satoshis === 100), true); // payment to A
});

test('partial signing (counterparty declines) is invalid — nothing moves', () => {
  const { a, b } = legs();
  let st = buildTrade(a, b);
  st = cosign(st, a.party); // only A signs; B declines
  const v = verifyTrade(st);
  assert.equal(v.valid, false);
  assert.match(v.reason, /unsigned|declined/);
});

test('tampering with an output after signing invalidates the trade (anti-front-running)', () => {
  const { a, b } = legs();
  let st = buildTrade(a, b);
  st = cosign(st, a.party);
  st = cosign(st, b.party);
  assert.ok(verifyTrade(st).valid);
  // adversary rewrites the 100-sat payment to redirect it (more sats / different pkh)
  const tamperedOutputs = st.tx.outputs.map((o) => (o.satoshis === 100 ? paymentOutput(100, new Uint8Array(20).fill(0xee)) : o));
  const tampered = { tx: { ...st.tx, outputs: tamperedOutputs }, sigs: st.sigs, pubkeys: st.pubkeys };
  const v = verifyTrade(tampered);
  assert.equal(v.valid, false);
  assert.match(v.reason, /signature invalid/);
});

test('two-NFT swap: both deeds change hands atomically', () => {
  const A = genKeyPair(), B = genKeyPair();
  const a: Leg = { party: A, giveNfts: [titleNft(3, outpoint('a1'))], giveSats: 0, satsFundingOutpoint: outpoint('af'), changePkh: A.pkh };
  const b: Leg = { party: B, giveNfts: [titleNft(6, outpoint('b1'))], giveSats: 0, satsFundingOutpoint: outpoint('bf'), changePkh: B.pkh };
  let st = buildTrade(a, b);
  st = cosign(st, a.party);
  st = cosign(st, b.party);
  assert.ok(verifyTrade(st).valid);
  // two 1-sat NFT outputs exist (one to each party)
  assert.equal(st.tx.outputs.filter((o) => o.satoshis === 1).length, 2);
});

test('a wrong-key signature does not satisfy an input it does not own', () => {
  const { a, b } = legs();
  const intruder = genKeyPair();
  let st = buildTrade(a, b);
  st = cosign(st, a.party);
  st = cosign(st, intruder); // intruder owns no inputs -> B's input still unsigned
  assert.equal(verifyTrade(st).valid, false);
});

// ---- audit #7: real-value conservation against actual prev UTXO amounts -------
test('verifyTradeValue checks conservation against REAL prev UTXO values + fee', () => {
  const { a, b } = legs();
  let st = buildTrade(a, b); st = cosign(st, a.party); st = cosign(st, b.party);
  const tx = st.tx;
  const totalOut = tx.outputs.reduce((s, o) => s + o.satoshis, 0);
  const fee = 50;
  // real prev UTXO amounts that conserve (toy distribution: all value on input 0)
  const prev = tx.inputs.map((_, i) => (i === 0 ? totalOut + fee : 0));
  assert.ok(verifyTradeValue(tx, prev, fee).valid, 'conserving inputs+fee verify');
  // off-by-one fee → not conserved
  assert.equal(verifyTradeValue(tx, prev, fee + 1).valid, false);
  // prevAmounts length must match inputs
  assert.equal(verifyTradeValue(tx, prev.slice(1), fee).valid, false);
  // negative prev UTXO value rejected
  assert.equal(verifyTradeValue(tx, tx.inputs.map((_, i) => (i === 0 ? -1 : 0)), 0).valid, false);
  // negative fee rejected
  assert.equal(verifyTradeValue(tx, prev, -1).valid, false);
});
