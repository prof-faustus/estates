/**
 * @estates/keys/aesgcm — in-tree, DEPENDENCY-FREE AES-256-GCM (AEAD). Synchronous, imports nothing.
 *
 * WHY in-tree (PLAN §1.2): no third-party crypto library (`@noble/ciphers` is banned), and the
 * browser's only platform AEAD (WebCrypto) is ASYNC. The native core uses .NET `AesGcm`; the TS
 * twin implements AES-256 + GCM here, in-tree and synchronous, identical to the standard (NIST KAT
 * tested). FIPS-197 AES block cipher + SP 800-38D GCM (GHASH over GF(2^128), 96-bit-IV J0).
 *
 * Layout matches the native `Cipher.Seal`: `seal()` returns ciphertext ‖ tag(16); `open()` takes
 * that concatenation and returns null on any authentication failure (never throws, never leaks).
 */

// ---------------- AES-256 (FIPS-197) ----------------
const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
(function initSbox() {
  // build the S-box from the multiplicative inverse in GF(2^8) + affine transform
  const p = new Uint8Array(256), inv = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) { p[i] = x; x ^= xtime(x); } // x = 3^i generator
  // log/antilog over generator 3
  const log = new Uint8Array(256), alog = new Uint8Array(256);
  let a = 1;
  for (let i = 0; i < 255; i++) { alog[i] = a; log[a] = i; a ^= xtime(a); }
  inv[0] = 0;
  for (let i = 1; i < 256; i++) inv[i] = alog[(255 - log[i]) % 255];
  for (let i = 0; i < 256; i++) {
    let s = inv[i], xf = s;
    for (let k = 0; k < 4; k++) { xf = ((xf << 1) | (xf >>> 7)) & 0xff; s ^= xf; }
    s ^= 0x63;
    SBOX[i] = s; INV_SBOX[s] = i;
  }
  void p;
})();
function xtime(b: number): number { return ((b << 1) ^ ((b & 0x80) ? 0x1b : 0)) & 0xff; }
function mul(a: number, b: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) { if (b & 1) r ^= a; const hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1b; b >>= 1; }
  return r;
}
const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];

function expandKey256(key: Uint8Array): Uint8Array[] {
  // 256-bit key -> 15 round keys (Nr = 14), each 16 bytes
  const Nk = 8, Nr = 14;
  const w = new Uint8Array(16 * (Nr + 1));
  w.set(key);
  for (let i = Nk; i < 4 * (Nr + 1); i++) {
    const t = [w[(i - 1) * 4], w[(i - 1) * 4 + 1], w[(i - 1) * 4 + 2], w[(i - 1) * 4 + 3]];
    if (i % Nk === 0) {
      const tmp = t[0]; t[0] = SBOX[t[1]] ^ RCON[i / Nk - 1]; t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[tmp];
    } else if (i % Nk === 4) {
      for (let j = 0; j < 4; j++) t[j] = SBOX[t[j]];
    }
    for (let j = 0; j < 4; j++) w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ t[j];
  }
  const rks: Uint8Array[] = [];
  for (let r = 0; r <= Nr; r++) rks.push(w.subarray(r * 16, r * 16 + 16));
  return rks;
}

function encryptBlock(rks: Uint8Array[], input: Uint8Array): Uint8Array {
  const Nr = 14;
  let s = Uint8Array.from(input);
  for (let i = 0; i < 16; i++) s[i] ^= rks[0][i];
  for (let round = 1; round < Nr; round++) {
    s = s.map((b) => SBOX[b]);
    s = shiftRows(s);
    s = mixColumns(s);
    for (let i = 0; i < 16; i++) s[i] ^= rks[round][i];
  }
  s = s.map((b) => SBOX[b]);
  s = shiftRows(s);
  for (let i = 0; i < 16; i++) s[i] ^= rks[Nr][i];
  return s;
}
function shiftRows(s: Uint8Array): Uint8Array {
  // state is column-major: byte index = col*4 + row
  const o = new Uint8Array(16);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) o[c * 4 + r] = s[((c + r) % 4) * 4 + r];
  return o;
}
function mixColumns(s: Uint8Array): Uint8Array {
  const o = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    const i = c * 4, a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
    o[i] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
    o[i + 1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
    o[i + 2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
    o[i + 3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
  }
  return o;
}

// ---------------- GHASH (GF(2^128), SP 800-38D) ----------------
function gfMul(X: Uint8Array, Y: Uint8Array): Uint8Array {
  // Z = X·Y in GF(2^128) with reduction poly R = 0xe1||0^120, bit order per the spec.
  const Z = new Uint8Array(16);
  const V = Uint8Array.from(Y);
  for (let i = 0; i < 128; i++) {
    const bit = (X[i >> 3] >> (7 - (i & 7))) & 1;
    if (bit) for (let k = 0; k < 16; k++) Z[k] ^= V[k];
    // V = V >> 1 (big-endian bit shift across the 128-bit block)
    let carry = 0;
    for (let k = 0; k < 16; k++) { const nc = V[k] & 1; V[k] = (V[k] >> 1) | (carry << 7); carry = nc; }
    if (carry) V[0] ^= 0xe1;
  }
  return Z;
}
function ghash(H: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  let Y = new Uint8Array(16);
  const block = (data: Uint8Array) => {
    for (let off = 0; off < data.length; off += 16) {
      const b = new Uint8Array(16);
      b.set(data.subarray(off, Math.min(off + 16, data.length)));
      for (let k = 0; k < 16; k++) Y[k] ^= b[k];
      Y = gfMul(Y, H);
    }
  };
  block(aad);
  block(ct);
  // lengths block: [aadBits(64)] ‖ [ctBits(64)], big-endian
  const lenBlock = new Uint8Array(16);
  const aadBits = BigInt(aad.length) * 8n, ctBits = BigInt(ct.length) * 8n;
  for (let i = 0; i < 8; i++) lenBlock[7 - i] = Number((aadBits >> BigInt(8 * i)) & 0xffn);
  for (let i = 0; i < 8; i++) lenBlock[15 - i] = Number((ctBits >> BigInt(8 * i)) & 0xffn);
  for (let k = 0; k < 16; k++) Y[k] ^= lenBlock[k];
  return gfMul(Y, H);
}

function inc32(counter: Uint8Array): void {
  // increment the rightmost 32 bits, mod 2^32
  for (let i = 15; i >= 12; i--) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) break; }
}

function ctrXor(rks: Uint8Array[], j0: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  const counter = Uint8Array.from(j0);
  for (let off = 0; off < data.length; off += 16) {
    inc32(counter);
    const ks = encryptBlock(rks, counter);
    const n = Math.min(16, data.length - off);
    for (let k = 0; k < n; k++) out[off + k] = data[off + k] ^ ks[k];
  }
  return out;
}

function constantTimeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

const TAG_LEN = 16;

/** AES-256-GCM encrypt. key=32 bytes, nonce=12 bytes. Returns ciphertext ‖ tag(16). */
export function seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
  if (key.length !== 32) throw new Error('aesgcm: AES-256 key must be 32 bytes');
  if (nonce.length !== 12) throw new Error('aesgcm: GCM nonce must be 12 bytes');
  const rks = expandKey256(key);
  const H = encryptBlock(rks, new Uint8Array(16));
  const j0 = new Uint8Array(16); j0.set(nonce); j0[15] = 1; // 96-bit IV ⇒ J0 = IV ‖ 0^31 ‖ 1
  const ct = ctrXor(rks, j0, plaintext);
  const S = ghash(H, aad, ct);
  const ej0 = encryptBlock(rks, j0);
  const tag = new Uint8Array(TAG_LEN);
  for (let k = 0; k < TAG_LEN; k++) tag[k] = S[k] ^ ej0[k];
  const out = new Uint8Array(ct.length + TAG_LEN);
  out.set(ct); out.set(tag, ct.length);
  return out;
}

/** AES-256-GCM decrypt of `ctTag` (ciphertext ‖ tag(16)). Returns null on ANY auth failure. */
export function open(key: Uint8Array, nonce: Uint8Array, ctTag: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array | null {
  if (key.length !== 32 || nonce.length !== 12 || ctTag.length < TAG_LEN) return null;
  try {
    const ct = ctTag.subarray(0, ctTag.length - TAG_LEN);
    const tag = ctTag.subarray(ctTag.length - TAG_LEN);
    const rks = expandKey256(key);
    const H = encryptBlock(rks, new Uint8Array(16));
    const j0 = new Uint8Array(16); j0.set(nonce); j0[15] = 1;
    const S = ghash(H, aad, ct);
    const ej0 = encryptBlock(rks, j0);
    const want = new Uint8Array(TAG_LEN);
    for (let k = 0; k < TAG_LEN; k++) want[k] = S[k] ^ ej0[k];
    if (!constantTimeEq(want, tag)) return null; // fail-closed: bad tag ⇒ nothing
    return ctrXor(rks, j0, ct);
  } catch { return null; }
}
