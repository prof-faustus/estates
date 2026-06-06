import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signHash, sha256, bytesToHex, hexToBytes, concatBytes } from '@estates/keys';
import { genIdentity, initiate, respond, complete, seal, openFrame, type Session } from '../src/index.ts';
void hexToBytes;

const td = (b: Uint8Array | null) => (b ? new TextDecoder().decode(b) : null);
const te = (s: string) => new TextEncoder().encode(s);

function handshake(): { a: Session; b: Session; alice: ReturnType<typeof genIdentity>; bob: ReturnType<typeof genIdentity> } {
  const alice = genIdentity(); const bob = genIdentity();
  const { hello, pending } = initiate(alice);
  const r = respond(bob, hello); assert.ok(r, 'responder accepts a valid hello');
  const a = complete(pending, r!.ack); assert.ok(a, 'initiator accepts a valid ack');
  return { a: a!, b: r!.session, alice, bob };
}

test('handshake: both peers derive the SAME session key and learn each other’s identity', () => {
  const { a, b, alice, bob } = handshake();
  assert.equal(bytesToHex(a.key), bytesToHex(b.key), 'identical session key on both sides');
  assert.equal(bytesToHex(a.peerIdPub), bytesToHex(bob.pub), 'initiator learned Bob’s identity');
  assert.equal(bytesToHex(b.peerIdPub), bytesToHex(alice.pub), 'responder learned Alice’s identity');
});

test('authenticated frames round-trip both directions; the relay sees only ciphertext', () => {
  const { a, b } = handshake();
  const f1 = seal(a, te('move: roll 3,4'));
  assert.equal(td(openFrame(b, f1)), 'move: roll 3,4');
  const f2 = seal(b, te('ack: ok'));
  assert.equal(td(openFrame(a, f2)), 'ack: ok');
  assert.equal(f1.ct.includes(Buffer.from('roll').toString('hex')), false, 'plaintext never on the wire');
});

test('a forged/tampered hello is rejected (identity not proven)', () => {
  const alice = genIdentity(); const bob = genIdentity();
  const { hello } = initiate(alice);
  // tamper the signature (flip the last hex char; keep it even-length)
  assert.equal(respond(bob, { ...hello, sig: hello.sig.slice(0, -1) + (hello.sig.endsWith('0') ? '1' : '0') }), null);
  // malformed (odd-length) hex is rejected, not thrown
  assert.equal(respond(bob, { ...hello, sig: hello.sig.slice(0, -1) }), null);
  // claim a different identity than the one that signed
  assert.equal(respond(bob, { ...hello, idPub: bytesToHex(genIdentity().pub) }), null);
});

test('MITM cannot derive the session: substituting the ephemeral key breaks the identity binding', () => {
  const alice = genIdentity(); const bob = genIdentity(); const eve = genIdentity();
  const { hello } = initiate(alice);
  // Eve swaps in her own ephemeral key but cannot re-sign as Alice
  const { hello: eveHello } = initiate(eve);
  const forged = { ...hello, ephPub: eveHello.ephPub }; // Alice's sig no longer matches the eph key
  assert.equal(respond(bob, forged), null, 'binding of identity→ephemeral is enforced');
});

test('an Ack is bound to the initiator’s ephemeral key (no cross-session replay)', () => {
  const alice = genIdentity(); const bob = genIdentity();
  const s1 = initiate(alice);
  const s2 = initiate(alice); // a second, different session
  const r1 = respond(bob, s1.hello)!;
  // Bob's Ack for session 1 must NOT complete session 2 (different initiator ephemeral)
  assert.equal(complete(s2.pending, r1.ack), null, 'replayed ack rejected');
  assert.ok(complete(s1.pending, r1.ack), 'the matching ack completes');
});

test('a frame cannot be opened with the wrong session key', () => {
  const { a } = handshake();
  const other = handshake();
  assert.equal(openFrame(other.a, seal(a, te('secret'))), null);
});

// ---- totality of respond/complete: a hostile handshake never throws -----------
// Reconstruct the exact protocol signing so we can forge a Hello whose signature
// is VALID for our idPub but whose ephPub is an OFF-CURVE point. A valid identity
// signature does not prove ephPub is a curve point; the ECDH inside respond used
// to throw "point not on curve" → an unauthenticated remote crash (DoS). respond
// must now return null, not throw.
const enc = new TextEncoder();
const H = (...p: Uint8Array[]) => sha256(concatBytes(...p));
const proSign = (msg: Uint8Array, priv: Uint8Array) => signHash(priv, msg);

test('a VALIDLY-SIGNED hello carrying an OFF-CURVE ephemeral key returns null, never throws (remote-DoS #1)', () => {
  const eve = genIdentity(); const bob = genIdentity();
  const offCurveEph = new Uint8Array(33); offCurveEph[0] = 0x02; offCurveEph.fill(0xff, 1); // x = 0xff..ff: not on secp256k1
  const nonce = new Uint8Array(32).fill(7);
  const sig = proSign(H(enc.encode('hello'), offCurveEph, nonce, eve.signPub), eve.priv); // a REAL signature by Eve
  const hello = { idPub: bytesToHex(eve.pub), ephPub: bytesToHex(offCurveEph), nonce: bytesToHex(nonce), signPub: bytesToHex(eve.signPub), sig: bytesToHex(sig) };
  let out: unknown = 'unset';
  assert.doesNotThrow(() => { out = respond(bob, hello); });
  assert.equal(out, null, 'off-curve ephemeral key is rejected, not a crash');
});

test('respond/complete are TOTAL: null/array/scalar/garbage handshakes never throw', () => {
  const bob = genIdentity(); const { pending } = initiate(genIdentity());
  for (const bad of [null, undefined, 42, 'x', [], {}, { idPub: 1 }, { idPub: 'zz', ephPub: 'zz', nonce: 'zz', signPub: 'zz', sig: 'zz' }, { idPub: '00', ephPub: '00', nonce: '00', signPub: '00'.repeat(32), sig: '00' }]) {
    assert.doesNotThrow(() => { assert.equal(respond(bob, bad as any), null); });
    assert.doesNotThrow(() => { assert.equal(complete(pending, bad as any), null); });
  }
});

test('respond/complete are FUZZ-PROOF: 50k random hellos never throw', () => {
  const bob = genIdentity(); const { pending } = initiate(genIdentity());
  let rng = 0x2f6e15a3 >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const rhex = () => { const n = rand() % 80; let s = ''; for (let i = 0; i < n; i++) s += (rand() & 0xff).toString(16).padStart(2, '0'); return s; };
  const t0 = Date.now();
  for (let i = 0; i < 50_000; i++) {
    const h = { idPub: rhex(), ephPub: rhex(), nonce: rhex(), signPub: rhex(), sig: rhex() };
    assert.doesNotThrow(() => { respond(bob, h as any); complete(pending, h as any); });
  }
  assert.ok(Date.now() - t0 < 15000, 'bounded work — no hang');
});
