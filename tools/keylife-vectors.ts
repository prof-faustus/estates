// Emit one-game-key-manifest verification VECTORS for cross-validating the native
// C# port against the audited TypeScript reference. Each vector is a manifest (or a
// set) + the verdict @estates/keylife produces, so the C# KeyLife must agree exactly.
import { writeFileSync } from 'node:fs';
import { genIdentity } from '../packages/channel/src/index.ts';
import { buildManifest, hashHex, verifyManifest, verifyNoCrossGameReuse, type KeyEntry } from '../packages/keylife/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const PH = hashHex(new TextEncoder().encode('estates.v1'));

function game(gameId: string, seat0?: string) {
  const auth = genIdentity(), s0 = genIdentity(), s1 = genIdentity(), card = genIdentity();
  const entries: KeyEntry[] = [
    { purpose: 'genesis', pub: hx(auth.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: seat0 ?? hx(s0.signPub), keyType: 'ed25519', seat: 0 },
    { purpose: 'seat', pub: hx(s1.signPub), keyType: 'ed25519', seat: 1 },
    { purpose: 'card', pub: hx(card.pub), keyType: 'secp256k1' },
  ];
  return { manifest: buildManifest(gameId, 'estates-1', PH, entries, auth.signPriv, hx(auth.signPub)), seat0: seat0 ?? hx(s0.signPub) };
}

const A = game('a1'.repeat(32));
const B = game('b2'.repeat(32));
const shared = hx(genIdentity().signPub);
const RA = game('a1'.repeat(32), shared);
const RB = game('b2'.repeat(32), shared);

// a tampered manifest (swap a seat key without re-signing) — must FAIL verify
const tampered = { ...A.manifest, entries: A.manifest.entries.map((e, i) => i === 1 ? { ...e, pub: hx(genIdentity().signPub) } : e) };

const vectors = {
  single: [
    { name: 'valid-A', manifest: A.manifest, expectVerify: verifyManifest(A.manifest).ok },
    { name: 'valid-B', manifest: B.manifest, expectVerify: verifyManifest(B.manifest).ok },
    { name: 'tampered', manifest: tampered, expectVerify: verifyManifest(tampered).ok },
    { name: 'wrong-gameId', manifest: { ...A.manifest, gameId: 'c3'.repeat(32) }, expectVerify: verifyManifest({ ...A.manifest, gameId: 'c3'.repeat(32) }).ok },
  ],
  crossGame: [
    { name: 'fresh-AB', manifests: [A.manifest, B.manifest], expectNoReuse: verifyNoCrossGameReuse([A.manifest, B.manifest]).ok },
    { name: 'reused-AB', manifests: [RA.manifest, RB.manifest], expectNoReuse: verifyNoCrossGameReuse([RA.manifest, RB.manifest]).ok },
  ],
};

const out = 'apps/native/Estates.Conformance/keylife-vectors.json';
writeFileSync(out, JSON.stringify(vectors, null, 2));
console.log(`wrote ${out}: ${vectors.single.length} single + ${vectors.crossGame.length} cross-game vectors`);
console.log('expected:', vectors.single.map((v) => `${v.name}=${v.expectVerify}`).join(', '), '|', vectors.crossGame.map((v) => `${v.name}=${v.expectNoReuse}`).join(', '));
