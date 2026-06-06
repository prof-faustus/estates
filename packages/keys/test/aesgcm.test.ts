/**
 * In-tree AES-256-GCM — known-answer tests against NIST SP 800-38D / CAVP vectors, plus
 * round-trip and HOSTILE-NEGATIVE (tampered ciphertext / tag / AAD ⇒ null). No third-party
 * library is imported (PLAN §1.2).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { seal, open } from '../src/aesgcm.ts';

const hex = (b: Uint8Array) => { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };
const fromHex = (h: string) => (h.length ? Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16))) : new Uint8Array(0));

// NIST GCM test case 13 (AES-256): K=0^256, IV=0^96, P empty, A empty.
test('NIST GCM AES-256 case 13 — empty plaintext, tag only', () => {
  const k = fromHex('00'.repeat(32)), iv = fromHex('00'.repeat(12));
  const out = seal(k, iv, new Uint8Array(0));
  assert.equal(hex(out), '530f8afbc74536b9a963b4f1c4cb738b'); // = expected tag
});

// NIST GCM test case 14 (AES-256): K=0^256, IV=0^96, P=0^128, A empty.
test('NIST GCM AES-256 case 14 — one zero block', () => {
  const k = fromHex('00'.repeat(32)), iv = fromHex('00'.repeat(12));
  const out = seal(k, iv, fromHex('00'.repeat(16)));
  const ct = hex(out.subarray(0, 16)), tag = hex(out.subarray(16));
  assert.equal(ct, 'cea7403d4d606b6e074ec5d3baf39d18');
  assert.equal(tag, 'd0d1c8a799996bf0265b98b5d48ab919');
});

// NIST GCM test case 16 (AES-256): full plaintext + AAD with a non-trivial tag.
test('NIST GCM AES-256 case 16 — plaintext + AAD', () => {
  const k = fromHex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
  const iv = fromHex('cafebabefacedbaddecaf888');
  const p = fromHex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
  const a = fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  const out = seal(k, iv, p, a);
  const ct = hex(out.subarray(0, out.length - 16)), tag = hex(out.subarray(out.length - 16));
  assert.equal(ct, '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662');
  assert.equal(tag, '76fc6ece0f4e1768cddf8853bb2d551b');
});

test('round-trip: open(seal(p)) == p, with AAD', () => {
  const k = fromHex('11'.repeat(32)), iv = fromHex('22'.repeat(12));
  const p = new TextEncoder().encode('Alice -> Bob: the deed is yours, and only yours.');
  const a = new TextEncoder().encode('estates/aad/v1');
  const sealed = seal(k, iv, p, a);
  const opened = open(k, iv, sealed, a);
  assert.ok(opened);
  assert.equal(new TextDecoder().decode(opened!), 'Alice -> Bob: the deed is yours, and only yours.');
});

test('hostile-negative: tampered ciphertext, tag, AAD, key, or nonce ⇒ null', () => {
  const k = fromHex('33'.repeat(32)), iv = fromHex('44'.repeat(12));
  const p = new TextEncoder().encode('scarce'); const a = new TextEncoder().encode('aad');
  const sealed = seal(k, iv, p, a);

  const tCt = Uint8Array.from(sealed); tCt[0] ^= 0xff;
  assert.equal(open(k, iv, tCt, a), null);
  const tTag = Uint8Array.from(sealed); tTag[sealed.length - 1] ^= 0xff;
  assert.equal(open(k, iv, tTag, a), null);
  assert.equal(open(k, iv, sealed, new TextEncoder().encode('AAD')), null); // wrong AAD
  const wrongK = fromHex('34'.repeat(32));
  assert.equal(open(wrongK, iv, sealed, a), null);
  const wrongIv = fromHex('45'.repeat(12));
  assert.equal(open(k, wrongIv, sealed, a), null);
});
