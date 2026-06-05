// Emit key-derivation + signature VECTORS so the native C# Sign port matches the
// TS reference: the SAME wallet master + gameId must yield the SAME per-game seat
// signing key (so a native player's identity equals the web player's), and a
// native-derivable Ed25519 signature must verify.
import { writeFileSync } from 'node:fs';
import { gameIdentityFrom, signingKeyFromMaster, signData, verifyData } from '../packages/channel/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const masters = [new Uint8Array(32).fill(7), new Uint8Array(32).fill(0x2a), Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff)];
const gameIds = ['a1'.repeat(32), 'b2'.repeat(32)];

const derivations: { master: string; gameId: string | null; expectedSignPub: string }[] = [];
for (const m of masters) {
  // game-independent (legacy) key
  derivations.push({ master: hx(m), gameId: null, expectedSignPub: hx(signingKeyFromMaster(m).pub) });
  // per-game keys
  for (const g of gameIds) derivations.push({ master: hx(m), gameId: g, expectedSignPub: hx(gameIdentityFrom(m, g).signPub) });
}

// a signature the native side must be able to verify (and, once it signs, produce
// a TS-verifiable one): sign a fixed message with a per-game key.
const id = gameIdentityFrom(masters[0]!, gameIds[0]!);
const message = new TextEncoder().encode('estates-native-sign-parity-v1');
const sig = signData(message, id.signPriv);
if (!verifyData(message, sig, id.signPub)) throw new Error('TS self-check failed');

const out = 'apps/native/Estates.Conformance/sign-vectors.json';
writeFileSync(out, JSON.stringify({
  derivations,
  signature: { signPub: hx(id.signPub), message: hx(message), sig: hx(sig) },
}, null, 2));
console.log(`wrote ${out}: ${derivations.length} key derivations + 1 signature`);
