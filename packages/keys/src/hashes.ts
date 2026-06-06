/**
 * @estates/keys/hashes — in-tree, DEPENDENCY-FREE hash primitives: SHA-256, SHA-512, RIPEMD-160,
 * HMAC (generic), and HKDF (extract+expand over HMAC-SHA-256). Synchronous, imports nothing.
 *
 * WHY in-tree (PLAN §1.2): the product depends on NO third-party crypto library (`@noble/hashes`
 * is banned). The browser's only platform hashing (WebCrypto SubtleCrypto) is ASYNC, which would
 * force an async rewrite across the whole synchronous protocol stack; Node's `node:crypto` is sync
 * but absent in the browser. So — exactly as the native core writes RIPEMD-160 in C# — these are
 * implemented here, in-tree, synchronous, and identical in output to the standard algorithms (KAT
 * tested). This file is the single hashing source the rest of the TS stack imports.
 */

// ============================ SHA-256 (FIPS 180-4) ============================
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n));

export function sha256(msg: Uint8Array): Uint8Array {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const ml = msg.length;
  const bitLen = ml * 8;
  const withPad = (((ml + 8) >> 6) + 1) << 6; // multiple of 64, room for 0x80 + 8-byte length
  const buf = new Uint8Array(withPad);
  buf.set(msg);
  buf[ml] = 0x80;
  // 64-bit big-endian length (high 32 bits = bitLen / 2^32)
  const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
  buf[withPad - 8] = (hi >>> 24) & 0xff; buf[withPad - 7] = (hi >>> 16) & 0xff;
  buf[withPad - 6] = (hi >>> 8) & 0xff;  buf[withPad - 5] = hi & 0xff;
  buf[withPad - 4] = (lo >>> 24) & 0xff; buf[withPad - 3] = (lo >>> 16) & 0xff;
  buf[withPad - 2] = (lo >>> 8) & 0xff;  buf[withPad - 1] = lo & 0xff;

  const w = new Uint32Array(64);
  for (let off = 0; off < withPad; off += 64) {
    for (let i = 0; i < 16; i++)
      w[i] = (buf[off + i * 4] << 24) | (buf[off + i * 4 + 1] << 16) | (buf[off + i * 4 + 2] << 8) | buf[off + i * 4 + 3];
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  const out = new Uint8Array(32);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => {
    out[i * 4] = (v >>> 24) & 0xff; out[i * 4 + 1] = (v >>> 16) & 0xff;
    out[i * 4 + 2] = (v >>> 8) & 0xff; out[i * 4 + 3] = v & 0xff;
  });
  return out;
}

// ============================ SHA-512 (FIPS 180-4, 64-bit via BigInt) ============================
const MASK64 = (1n << 64n) - 1n;
const K512 = [
  '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
  '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
  'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
  '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
  'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
  '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
  '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
  'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
  '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
  '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
  'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
  'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
  '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
  '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
  '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
  '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
  'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
  '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
  '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
  '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817',
].map((h) => BigInt('0x' + h));
const rotr64 = (x: bigint, n: bigint): bigint => ((x >> n) | (x << (64n - n))) & MASK64;
const shr64 = (x: bigint, n: bigint): bigint => x >> n;

export function sha512(msg: Uint8Array): Uint8Array {
  let h = [
    '6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1',
    '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179',
  ].map((x) => BigInt('0x' + x));

  const ml = msg.length;
  const withPad = (Math.floor((ml + 16) / 128) + 1) * 128; // multiple of 128, room for 0x80 + 16-byte length
  const buf = new Uint8Array(withPad);
  buf.set(msg);
  buf[ml] = 0x80;
  // 128-bit big-endian length; messages here are well under 2^64 bits so only the low 8 bytes matter
  const bitLen = BigInt(ml) * 8n;
  for (let i = 0; i < 8; i++) buf[withPad - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);

  const w = new Array<bigint>(80);
  for (let off = 0; off < withPad; off += 128) {
    for (let i = 0; i < 16; i++) {
      let v = 0n;
      for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(buf[off + i * 8 + j]);
      w[i] = v;
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ shr64(w[i - 15], 7n);
      const s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ shr64(w[i - 2], 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const ch = (e & f) ^ (~e & MASK64 & g);
      const t1 = (hh + S1 + ch + K512[i] + w[i]) & MASK64;
      const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & MASK64;
      hh = g; g = f; f = e; e = (d + t1) & MASK64; d = c; c = b; b = a; a = (t1 + t2) & MASK64;
    }
    const upd = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) h[i] = (h[i] + upd[i]) & MASK64;
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) for (let j = 0; j < 8; j++) out[i * 8 + j] = Number((h[i] >> BigInt(56 - 8 * j)) & 0xffn);
  return out;
}

// ============================ RIPEMD-160 ============================
const rol = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;
const RL = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RR = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const SL = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const SR = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
function rmdF(j: number, x: number, y: number, z: number): number {
  if (j < 16) return x ^ y ^ z;
  if (j < 32) return (x & y) | (~x & z);
  if (j < 48) return (x | ~y) ^ z;
  if (j < 64) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}

export function ripemd160(msg: Uint8Array): Uint8Array {
  const ml = msg.length;
  const withPad = (((ml + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(withPad);
  buf.set(msg);
  buf[ml] = 0x80;
  const bitLen = ml * 8;
  const lo = bitLen >>> 0, hi = Math.floor(bitLen / 0x100000000);
  buf[withPad - 8] = lo & 0xff; buf[withPad - 7] = (lo >>> 8) & 0xff;
  buf[withPad - 6] = (lo >>> 16) & 0xff; buf[withPad - 5] = (lo >>> 24) & 0xff;
  buf[withPad - 4] = hi & 0xff; buf[withPad - 3] = (hi >>> 8) & 0xff;
  buf[withPad - 2] = (hi >>> 16) & 0xff; buf[withPad - 1] = (hi >>> 24) & 0xff;

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const x = new Int32Array(16);
  for (let off = 0; off < withPad; off += 64) {
    for (let i = 0; i < 16; i++)
      x[i] = buf[off + i * 4] | (buf[off + i * 4 + 1] << 8) | (buf[off + i * 4 + 2] << 16) | (buf[off + i * 4 + 3] << 24);
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      const grp = Math.floor(j / 16);
      let t = (al + rmdF(j, bl, cl, dl) + x[RL[j]] + KL[grp]) | 0;
      t = (rol(t >>> 0, SL[j]) + el) | 0;
      al = el; el = dl; dl = rol(cl >>> 0, 10); cl = bl; bl = t;
      let u = (ar + rmdF(79 - j, br, cr, dr) + x[RR[j]] + KR[grp]) | 0;
      u = (rol(u >>> 0, SR[j]) + er) | 0;
      ar = er; er = dr; dr = rol(cr >>> 0, 10); cr = br; br = u;
    }
    const t = (h1 + cl + dr) | 0;
    h1 = (h2 + dl + er) | 0; h2 = (h3 + el + ar) | 0; h3 = (h4 + al + br) | 0;
    h4 = (h0 + bl + cr) | 0; h0 = t;
  }
  const out = new Uint8Array(20);
  [h0, h1, h2, h3, h4].forEach((v, i) => {
    out[i * 4] = v & 0xff; out[i * 4 + 1] = (v >>> 8) & 0xff;
    out[i * 4 + 2] = (v >>> 16) & 0xff; out[i * 4 + 3] = (v >>> 24) & 0xff;
  });
  return out;
}

// ============================ HMAC (generic) + HKDF ============================
type HashFn = (m: Uint8Array) => Uint8Array;
const concat = (...a: Uint8Array[]): Uint8Array => {
  let n = 0; for (const x of a) n += x.length;
  const o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; }
  return o;
};

/** HMAC over any of the in-tree hashes. `blockSize` = 64 for SHA-256/RIPEMD-160, 128 for SHA-512. */
export function hmac(hash: HashFn, blockSize: number, key: Uint8Array, msg: Uint8Array): Uint8Array {
  let k = key.length > blockSize ? hash(key) : key;
  if (k.length < blockSize) { const p = new Uint8Array(blockSize); p.set(k); k = p; }
  const ipad = new Uint8Array(blockSize), opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  return hash(concat(opad, hash(concat(ipad, msg))));
}
export const hmacSha256 = (key: Uint8Array, msg: Uint8Array): Uint8Array => hmac(sha256, 64, key, msg);
export const hmacSha512 = (key: Uint8Array, msg: Uint8Array): Uint8Array => hmac(sha512, 128, key, msg);

/** HKDF (RFC 5869) over HMAC-SHA-256. Returns `length` bytes of output key material. */
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const prk = hmacSha256(salt.length ? salt : new Uint8Array(32), ikm); // extract
  const out = new Uint8Array(length);
  let t = new Uint8Array(0); let pos = 0; let counter = 1;
  while (pos < length) {
    t = hmacSha256(prk, concat(t, info, Uint8Array.from([counter & 0xff]))); // expand
    const take = Math.min(t.length, length - pos);
    out.set(t.subarray(0, take), pos);
    pos += take; counter++;
  }
  return out;
}

/** P2PKH hash160 = RIPEMD-160(SHA-256(pub)). */
export const hash160 = (pub: Uint8Array): Uint8Array => ripemd160(sha256(pub));
/** Double SHA-256 (Bitcoin's Hash256). */
export const hash256 = (b: Uint8Array): Uint8Array => sha256(sha256(b));
