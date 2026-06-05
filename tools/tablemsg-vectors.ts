// Emit SIGNED TABLE-MESSAGE vectors so the native C# port can verify the same
// gameplay frames the web produces. The signature covers signedBytes(msg, signPub)
// = JSON({...msg, signPub}); native must re-derive those exact bytes and verify the
// Ed25519 signature (so a native client can authenticate web messages).
import { writeFileSync } from 'node:fs';
import { gameIdentityFrom, signData } from '../packages/channel/src/index.ts';
import type { Action } from '../packages/engine/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const id = gameIdentityFrom(new Uint8Array(32).fill(7), 'a1'.repeat(32));
const signPub = hx(id.signPub);

const actions: Action[] = [
  { type: 'END_TURN' }, { type: 'ROLL', dice: [3, 4] }, { type: 'BUY' }, { type: 'DECLINE' },
  { type: 'BUILD', propertyId: 5 }, { type: 'PAY_TAX', choice: 'flat' }, { type: 'LEAVE', seat: 1 },
];

const vectors = actions.map((action, i) => {
  const msg = { kind: 'action', action };
  const signed = enc({ ...msg, signPub });
  const sig = hx(signData(signed, id.signPriv));
  return { name: `action-${i}-${action.type}`, action, signPub, signedBytes: hx(signed), sig };
});

const path = 'apps/native/Estates.Conformance/tablemsg-vectors.json';
writeFileSync(path, JSON.stringify(vectors, null, 2));
console.log(`wrote ${path}: ${vectors.length} signed table-message vectors`);
