/**
 * In-tree secp256k1 — proof of correctness. Known-answer tests (priv -> pub on the standard
 * curve), then positive + HOSTILE-NEGATIVE round-trips for ECDSA, ECDH, encoding, and DER.
 * No third-party library is imported here or in the module under test (PLAN §1.2).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  N, G, publicKey, compress, decompress, ecdhX, signHash, verifyHash,
  isValidScalar, derEncode, derDecode, hexEncode, hexDecode, mul, to32,
} from '../src/secp256k1.ts';

const big = (h: string) => BigInt('0x' + h);

test('KAT: priv=1 -> pub = G (compressed)', () => {
  const pub = publicKey(hexDecode('0000000000000000000000000000000000000000000000000000000000000001'));
  assert.equal(hexEncode(pub), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
});

test('KAT: priv=2 -> known pub (compressed)', () => {
  const pub = publicKey(hexDecode('0000000000000000000000000000000000000000000000000000000000000002'));
  assert.equal(hexEncode(pub), '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5');
});

test('KAT: priv = n-1 -> pub is G with negated Y (odd prefix flips)', () => {
  const pub = publicKey(to32(N - 1n));
  // (n-1)*G = -G, which has the same X as G and the opposite Y parity.
  assert.equal(hexEncode(pub).slice(2), '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(hexEncode(pub).slice(0, 2), '03');
});

test('compress/decompress round-trips and matches the curve equation', () => {
  for (const d of ['07', '11', 'abcdef', 'deadbeef']) {
    const pub = publicKey(hexDecode(d.padStart(64, '0')));
    const pt = decompress(pub);
    assert.equal(hexEncode(compress(pt)), hexEncode(pub));
    // y^2 == x^3 + 7 (mod p)
    const P = big('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
    assert.equal((pt.y * pt.y) % P, (pt.x * pt.x * pt.x + 7n) % P);
  }
});

test('ECDSA sign/verify round-trips; nonce is non-deterministic; low-S', () => {
  const priv = hexDecode('1111111111111111111111111111111111111111111111111111111111111111');
  const pub = publicKey(priv);
  const h = hexDecode('22'.repeat(32));
  const sig1 = signHash(priv, h);
  const sig2 = signHash(priv, h);
  assert.ok(verifyHash(pub, h, sig1));
  assert.ok(verifyHash(pub, h, sig2));
  assert.notEqual(hexEncode(sig1), hexEncode(sig2), 'two sigs over the same hash MUST differ (random nonce, not RFC-6979)');
  // low-S: s <= n/2
  assert.ok(big(hexEncode(sig1.slice(32))) <= N >> 1n);
});

test('ECDSA rejects a forged hash, a tampered signature, and high-S', () => {
  const priv = hexDecode('33'.repeat(32));
  const pub = publicKey(priv);
  const h = hexDecode('44'.repeat(32));
  const sig = signHash(priv, h);
  const badH = hexDecode('45'.repeat(32));
  assert.equal(verifyHash(pub, badH, sig), false);
  const tampered = Uint8Array.from(sig); tampered[10] ^= 0xff;
  assert.equal(verifyHash(pub, h, tampered), false);
  // forge high-S = n - s (the other valid-curve s) -> must be rejected (malleability guard)
  const r = sig.slice(0, 32); const s = big(hexEncode(sig.slice(32)));
  const highS = Uint8Array.from([...r, ...to32(N - s)]);
  assert.equal(verifyHash(pub, h, highS), false);
});

test('ECDH shared secret is symmetric and key-bound', () => {
  const a = hexDecode('0a'.repeat(32)); const b = hexDecode('0b'.repeat(32)); const c = hexDecode('0c'.repeat(32));
  const A = publicKey(a); const B = publicKey(b);
  assert.equal(hexEncode(ecdhX(a, B)), hexEncode(ecdhX(b, A)));
  assert.notEqual(hexEncode(ecdhX(a, B)), hexEncode(ecdhX(c, A)));
});

test('scalar validation rejects zero, oversize, and wrong length', () => {
  assert.equal(isValidScalar(new Uint8Array(32)), false);
  assert.equal(isValidScalar(to32(N)), false);      // == n is invalid
  assert.equal(isValidScalar(to32(N - 1n)), true);   // n-1 is valid
  assert.equal(isValidScalar(new Uint8Array(31)), false);
  assert.equal(isValidScalar(null), false);
});

test('DER encode/decode round-trips a signature', () => {
  const priv = hexDecode('55'.repeat(32));
  const sig = signHash(priv, hexDecode('66'.repeat(32)));
  const der = derEncode(sig);
  assert.equal(der[0], 0x30);
  assert.equal(hexEncode(derDecode(der)), hexEncode(sig));
});

test('mul by n yields the point at infinity (group order is correct)', () => {
  assert.equal(mul(N, G).inf, true);
});
