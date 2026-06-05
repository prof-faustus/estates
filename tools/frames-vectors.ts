// Emit SIGNED-FRAME vectors for EVERY table message kind, so the native replay can
// re-derive the canonical signedBytes (JSON({...msg, signPub})) and verify each —
// the verification layer the native rebuild needs to authenticate the live log.
import { writeFileSync } from 'node:fs';
import { gameIdentityFrom, signData } from '../packages/channel/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const id = gameIdentityFrom(new Uint8Array(32).fill(7), 'a1'.repeat(32));
const signPub = hx(id.signPub);

// one of each message kind (the exact field shapes @estates/table builds).
const msgs: Record<string, unknown>[] = [
  { kind: 'table', maxSeats: 4, network: 'regtest', host: signPub },
  { kind: 'seat', seat: 0, who: signPub, name: 'alice', bot: false },
  { kind: 'start', by: signPub, config: { network: 'regtest', seatCount: 2, bankReserve: 40000 }, seatMap: [{ seat: 0, who: signPub }, { seat: 1, who: 'bb'.repeat(32) }] },
  { kind: 'commit', roll: 0, seat: 0, c: 'aa'.repeat(32) },
  { kind: 'reveal', roll: 0, seat: 0, s: 'cc'.repeat(32) },
  { kind: 'dcommit', seat: 1, c: 'dd'.repeat(32) },
  { kind: 'dreveal', seat: 1, s: 'ee'.repeat(32) },
];

const vectors = msgs.map((msg) => {
  const signed = enc({ ...msg, signPub });
  return { kind: msg.kind, msg, signPub, signedBytes: hx(signed), sig: hx(signData(signed, id.signPriv)) };
});

const path = 'apps/native/Estates.Conformance/frames-vectors.json';
writeFileSync(path, JSON.stringify(vectors, null, 2));
console.log(`wrote ${path}: ${vectors.length} signed frames (${vectors.map((v) => v.kind).join(', ')})`);
