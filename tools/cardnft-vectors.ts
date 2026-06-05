// Emit card-NFT transfer VECTORS from the audited @estates/cardnft + @estates/tx
// references, so the native C# CardNftN port can be cross-validated: the SAME card
// NFT output script + the SAME transfer tx (spend Alice's outpoint, create Bob's
// successor) + the SAME txid.
import { writeFileSync } from 'node:fs';
import { cardNftOutput } from '../packages/cardnft/src/index.ts';
import { serializeTx, txid, type Tx } from '../packages/tx/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));

const tableId = 'a1'.repeat(32);
const commitment = 'bb'.repeat(32);
const aliceCardPub = '02' + '11'.repeat(32);
const newCardPub = '03' + '22'.repeat(32);
const bobPkh = 'cc'.repeat(20);
const aliceOutpoint = { txid: 'aa'.repeat(32), vout: 7 };

const out = cardNftOutput(tableId, commitment, newCardPub, fromHex(bobPkh)); // 1-sat successor output
const tx: Tx = {
  version: 1,
  inputs: [{ prevTxid: aliceOutpoint.txid, prevVout: aliceOutpoint.vout, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
  outputs: [{ value: out.satoshis, script: out.script }],
  lockTime: 0,
};

const vector = {
  tableId, commitment, aliceCardPub, newCardPub, bobPkh, aliceOutpoint,
  expectedScript: hx(out.script),
  expectedSerialized: hx(serializeTx(tx)),
  expectedTxid: txid(tx),
};

const path = 'apps/native/Estates.Conformance/cardnft-vectors.json';
writeFileSync(path, JSON.stringify(vector, null, 2));
console.log(`wrote ${path}`);
console.log('  card script bytes:', vector.expectedScript.length / 2, '| transfer txid:', vector.expectedTxid);
