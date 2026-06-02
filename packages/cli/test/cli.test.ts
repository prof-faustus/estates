import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Transaction, P2PKH } from '@bsv/sdk';
import { Wallet } from '@estates/wallet';
import { loadParams } from '@estates/params';
import { covenantOutput, rulesHash } from '@estates/bank';
import { buildTableTx } from '../src/index.ts';

const P = loadParams();
const bytesToHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function sourceTxHex(address: string, satoshis: number): string {
  const tx = new Transaction();
  tx.addOutput({ lockingScript: new P2PKH().lock(address), satoshis });
  return tx.toHex();
}

test('table genesis: funds N seats + a covenant reserve, signed, real BSV tx', async () => {
  const funder = Wallet.random('regtest');
  const funding = { txid: '', vout: 0, satoshis: 300_000_000, raw: sourceTxHex(funder.address, 300_000_000) };

  const built = await buildTableTx({ network: 'regtest', funder, funding, seatCount: 3, reserveSalaryCap: 200 });

  assert.equal(built.seats.length, 3);
  for (const s of built.seats) assert.equal(s.startingBalance, P.scalars.starting_balance_per_seat); // 1500
  const expectReserve = P.scalars.salary * 200;
  assert.equal(built.reserve.satoshis, expectReserve);

  const tx = Transaction.fromHex(built.hex);
  // 3 seats + reserve + change
  assert.equal(tx.outputs.length, 5);
  for (let i = 0; i < 3; i++) assert.equal(tx.outputs[i]!.satoshis, P.scalars.starting_balance_per_seat);
  // the reserve output carries the covenant script + exact reserve sats
  assert.equal(tx.outputs[built.reserve.vout]!.satoshis, expectReserve);
  assert.equal(tx.outputs[built.reserve.vout]!.lockingScript.toHex(), bytesToHex(covenantOutput(expectReserve, rulesHash()).script));
  // input is signed (BIP-143)
  assert.ok((tx.inputs[0]!.unlockingScript?.toHex().length ?? 0) > 0);
  assert.match(built.genesisTxid, /^[0-9a-f]{64}$/);
});

test('seat count is configurable', async () => {
  const funder = Wallet.random('testnet');
  const funding = { txid: '', vout: 0, satoshis: 300_000_000, raw: sourceTxHex(funder.address, 300_000_000) };
  const built = await buildTableTx({ network: 'testnet', funder, funding, seatCount: 6 });
  assert.equal(built.seats.length, 6);
  assert.equal(Transaction.fromHex(built.hex).outputs.length, 6 + 1 + 1); // seats + reserve + change
});
