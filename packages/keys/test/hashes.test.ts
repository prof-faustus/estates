/**
 * In-tree hashes — known-answer tests against the published standard vectors. No third-party
 * library is imported (PLAN §1.2). Covers SHA-256, SHA-512, RIPEMD-160, HMAC, HKDF, hash160/256.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  sha256, sha512, ripemd160, hmacSha256, hmacSha512, hkdfSha256, hash160, hash256,
} from '../src/hashes.ts';

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };
const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));

test('SHA-256 KATs (FIPS 180-4)', () => {
  assert.equal(hex(sha256(enc(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(hex(sha256(enc('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(hex(sha256(enc('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  // long message crossing multiple blocks
  assert.equal(hex(sha256(enc('a'.repeat(1000000)))), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
});

test('SHA-512 KATs (FIPS 180-4)', () => {
  assert.equal(hex(sha512(enc(''))),
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
  assert.equal(hex(sha512(enc('abc'))),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
});

test('RIPEMD-160 KATs', () => {
  assert.equal(hex(ripemd160(enc(''))), '9c1185a5c5e9fc54612808977ee8f548b2258d31');
  assert.equal(hex(ripemd160(enc('abc'))), '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc');
  assert.equal(hex(ripemd160(enc('message digest'))), '5d0689ef49d2fae572b881b123a85ffa21595f36');
});

test('HMAC-SHA-256 KAT (RFC 4231 case 2)', () => {
  assert.equal(hex(hmacSha256(enc('Jefe'), enc('what do ya want for nothing?'))),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
});

test('HMAC-SHA-512 KAT (RFC 4231 case 2)', () => {
  assert.equal(hex(hmacSha512(enc('Jefe'), enc('what do ya want for nothing?'))),
    '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737');
});

test('HKDF-SHA-256 KAT (RFC 5869 test case 1)', () => {
  const ikm = fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const salt = fromHex('000102030405060708090a0b0c');
  const info = fromHex('f0f1f2f3f4f5f6f7f8f9');
  const okm = hkdfSha256(ikm, salt, info, 42);
  assert.equal(hex(okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

test('hash160 and hash256 compose correctly', () => {
  const pub = fromHex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(hex(hash160(pub)), hex(ripemd160(sha256(pub))));
  assert.equal(hex(hash256(enc('hello'))), hex(sha256(sha256(enc('hello')))));
});
