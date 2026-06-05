import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serializeTx, deserializeTx, type Tx } from '@estates/tx';
import { p2pkh, serializeScript } from '@estates/onchain';
import { Wallet } from '@estates/wallet';
import { loadParams } from '@estates/params';
import { covenantOutput, rulesHash } from '@estates/bank';
import { buildTableTx } from '../src/index.ts';

const P = loadParams();
const GAME = new Uint8Array(32).fill(9);                        // the table/game id
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

// a source tx paying `sats` to a P2PKH for `pkh` (provides the funder's UTXO)
function sourceTxHex(pkh: Uint8Array, sats: number): string {
  const tx: Tx = { version: 1, inputs: [{ prevTxid: '00'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }], outputs: [{ value: sats, script: serializeScript(p2pkh(pkh)) }], lockTime: 0 };
  return toHex(serializeTx(tx));
}

test('table genesis: funds N seats + a covenant reserve, signed, real BSV tx', async () => {
  const funder = Wallet.random('regtest');
  const funding = { txid: '', vout: 0, satoshis: 300_000_000, raw: sourceTxHex(funder.key.pkh(), 300_000_000) };

  const built = await buildTableTx({ network: 'regtest', funder, funding, seatCount: 3, reserveSalaryCap: 200, gameId: GAME });

  assert.equal(built.seats.length, 3);
  for (const s of built.seats) assert.equal(s.startingBalance, P.scalars.starting_balance_per_seat);
  const expectReserve = P.scalars.salary * 200;
  assert.equal(built.reserve.satoshis, expectReserve);

  const tx = deserializeTx(fromHex(built.hex));
  assert(tx, "genesis tx parses");
  assert.equal(tx.outputs.length, 5, '3 seats + reserve + change');
  for (let i = 0; i < 3; i++) assert.equal(Number(tx.outputs[i]!.value), P.scalars.starting_balance_per_seat);
  assert.equal(Number(tx.outputs[built.reserve.vout]!.value), expectReserve);
  assert.equal(toHex(tx.outputs[built.reserve.vout]!.script), toHex(covenantOutput(expectReserve, rulesHash(GAME)).script), 'reserve carries the game-bound covenant script');
  assert.ok(tx.inputs[0]!.scriptSig.length > 0, 'input is signed (BIP-143)');
  assert.match(built.genesisTxid, /^[0-9a-f]{64}$/);
});

test('seat count is configurable', async () => {
  const funder = Wallet.random('testnet');
  const funding = { txid: '', vout: 0, satoshis: 300_000_000, raw: sourceTxHex(funder.key.pkh(), 300_000_000) };
  const built = await buildTableTx({ network: 'testnet', funder, funding, seatCount: 6, gameId: GAME });
  assert.equal(built.seats.length, 6);
  const tx2 = deserializeTx(fromHex(built.hex));
  assert(tx2, "parses");
  assert.equal(tx2.outputs.length, 6 + 1 + 1, 'seats + reserve + change');
});
