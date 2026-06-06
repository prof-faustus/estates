/**
 * @estates/keys/secp256k1 — in-tree secp256k1, DEPENDENCY-FREE. The TypeScript twin of the
 * audited native `Secp256k1.cs`: same field arithmetic (mod p), affine point add/double/multiply,
 * compressed point encode/decode, ECDH, and ECDSA (CSPRNG random nonce k, low-S; NO RFC-6979).
 *
 * WHY: PLAN §1.2 — the product depends on NO third-party crypto library (`@noble/*` is banned, as
 * is `elliptic`). The runtime platform (WebCrypto / node:crypto) provides SHA-256/HMAC/HKDF/AES-GCM,
 * but NOT secp256k1, so the curve is implemented here, in-tree, identically to the native core.
 * Randomness is the platform CSPRNG (`crypto.getRandomValues`) — present in both browsers and Node.
 *
 * This file uses native `bigint` only; it imports nothing. It is the single source the rest of the
 * TS stack derives keys, signs protocol messages, and runs ECDH through (no Ed25519 anywhere).
 */

// ---- secp256k1 domain parameters (SEC 2) ----
export const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
export const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const HALF_N = N >> 1n;

export interface Point { readonly x: bigint; readonly y: bigint; readonly inf: boolean }
const IDENTITY: Point = { x: 0n, y: 0n, inf: true };
export const G: Point = { x: Gx, y: Gy, inf: false };

function mod(a: bigint, m: bigint): bigint { const r = a % m; return r < 0n ? r + m : r; }
// modular inverse via Fermat (p, n are prime): a^(m-2) mod m
function powMod(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n; base = mod(base, m);
  while (exp > 0n) { if (exp & 1n) r = (r * base) % m; base = (base * base) % m; exp >>= 1n; }
  return r;
}
function invMod(a: bigint, m: bigint): bigint { return powMod(mod(a, m), m - 2n, m); }

// ---- point arithmetic (affine) ----
export function add(p: Point, q: Point): Point {
  if (p.inf) return q;
  if (q.inf) return p;
  if (p.x === q.x) {
    if (mod(p.y + q.y, P) === 0n) return IDENTITY; // p == -q
    return double(p);
  }
  const s = mod((q.y - p.y) * invMod(q.x - p.x, P), P);
  const rx = mod(s * s - p.x - q.x, P);
  const ry = mod(s * (p.x - rx) - p.y, P);
  return { x: rx, y: ry, inf: false };
}

export function double(p: Point): Point {
  if (p.inf || p.y === 0n) return IDENTITY;
  const s = mod(3n * p.x * p.x * invMod(2n * p.y, P), P); // a = 0
  const rx = mod(s * s - 2n * p.x, P);
  const ry = mod(s * (p.x - rx) - p.y, P);
  return { x: rx, y: ry, inf: false };
}

// Scalar multiplication is the hot path. Doing it in AFFINE coordinates costs a modular
// inversion per add/double (~512 per multiply) — correct but far too slow. So `mul` runs in
// JACOBIAN projective coordinates (a:=0), where add/double are inversion-free, and converts to
// affine ONCE at the end (a single inversion per multiply). The affine result is identical, so
// `compress`/`decompress` and the KATs are unchanged. (a=0 ⇒ the standard "dbl-2009-l" / "add-2007-bl".)
interface Jac { X: bigint; Y: bigint; Z: bigint }
const JID: Jac = { X: 1n, Y: 1n, Z: 0n };

function jDouble(p: Jac): Jac {
  if (p.Z === 0n || p.Y === 0n) return JID;
  const A = mod(p.X * p.X, P);
  const B = mod(p.Y * p.Y, P);
  const C = mod(B * B, P);
  let D = mod((p.X + B) * (p.X + B) - A - C, P); D = mod(D + D, P);
  const E = mod(A + A + A, P);          // a = 0
  const F = mod(E * E, P);
  const X3 = mod(F - D - D, P);
  const Y3 = mod(E * (D - X3) - mod(C + C + C + C + C + C + C + C, P), P); // -8C
  const Z3 = mod((p.Y + p.Y) * p.Z, P);
  return { X: X3, Y: Y3, Z: Z3 };
}

function jAdd(p: Jac, q: Jac): Jac {
  if (p.Z === 0n) return q;
  if (q.Z === 0n) return p;
  const Z1Z1 = mod(p.Z * p.Z, P);
  const Z2Z2 = mod(q.Z * q.Z, P);
  const U1 = mod(p.X * Z2Z2, P);
  const U2 = mod(q.X * Z1Z1, P);
  const S1 = mod(p.Y * q.Z * Z2Z2, P);
  const S2 = mod(q.Y * p.Z * Z1Z1, P);
  if (U1 === U2) { return S1 === S2 ? jDouble(p) : JID; }
  const H = mod(U2 - U1, P);
  const I = mod((H + H) * (H + H), P);
  const J = mod(H * I, P);
  const r = mod((S2 - S1) * 2n, P);
  const V = mod(U1 * I, P);
  const X3 = mod(r * r - J - V - V, P);
  const Y3 = mod(r * (V - X3) - mod(S1 * J * 2n, P), P);
  const Z3 = mod((mod((p.Z + q.Z) * (p.Z + q.Z), P) - Z1Z1 - Z2Z2) * H, P);
  return { X: X3, Y: Y3, Z: Z3 };
}

function fromJac(j: Jac): Point {
  if (j.Z === 0n) return IDENTITY;
  const zinv = invMod(j.Z, P);
  const zinv2 = mod(zinv * zinv, P);
  return { x: mod(j.X * zinv2, P), y: mod(j.Y * zinv2 % P * zinv, P), inf: false };
}

export function mul(k: bigint, p: Point): Point {
  k = mod(k, N);
  if (k === 0n || p.inf) return IDENTITY;
  let r = JID;
  let addend: Jac = { X: p.x, Y: p.y, Z: 1n };
  while (k > 0n) {
    if (k & 1n) r = jAdd(r, addend);
    addend = jDouble(addend);
    k >>= 1n;
  }
  return fromJac(r);
}

// ---- scalars / encoding ----
const toHex = (b: Uint8Array): string => { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };
function fromHexStrict(h: string): Uint8Array {
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error('secp256k1: invalid hex');
  const o = new Uint8Array(h.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return o;
}
const bytesToBig = (b: Uint8Array): bigint => (b.length === 0 ? 0n : BigInt('0x' + toHex(b)));

// the canonical 32-byte big-endian encoder for a scalar/coordinate in [0, 2^256).
function be32(x: bigint): Uint8Array { return fromHexStrict((x & ((1n << 256n) - 1n)).toString(16).padStart(64, '0')); }
/** Canonical 32-byte big-endian encoding of a scalar/coordinate (public alias of be32). */
export function to32(x: bigint): Uint8Array { return be32(x); }

const scalar = (priv: Uint8Array): bigint => mod(bytesToBig(priv), N);

/** Compressed (33-byte) public key for a 32-byte private key. */
export function publicKey(priv: Uint8Array): Uint8Array { return compress(mul(scalar(priv), G)); }

export function compress(p: Point): Uint8Array {
  const o = new Uint8Array(33);
  o[0] = (p.y & 1n) === 0n ? 0x02 : 0x03;
  o.set(be32(p.x), 1);
  return o;
}

export function decompress(pub: Uint8Array): Point {
  if (pub.length === 33 && (pub[0] === 0x02 || pub[0] === 0x03)) {
    const x = bytesToBig(pub.slice(1));
    const y2 = mod(powMod(x, 3n, P) + 7n, P);
    let y = powMod(y2, (P + 1n) / 4n, P); // p ≡ 3 (mod 4)
    const wantEven = pub[0] === 0x02;
    if (((y & 1n) === 0n) !== wantEven) y = P - y;
    return { x, y, inf: false };
  }
  if (pub.length === 65 && pub[0] === 0x04) {
    return { x: bytesToBig(pub.slice(1, 33)), y: bytesToBig(pub.slice(33)), inf: false };
  }
  throw new Error('secp256k1: bad public key encoding');
}

/** ECDH shared secret = compressed point (priv·peerPub). */
export function ecdhCompressed(priv: Uint8Array, peerPub: Uint8Array): Uint8Array {
  return compress(mul(scalar(priv), decompress(peerPub)));
}
/** ECDH shared secret = the X coordinate (32 bytes) of priv·peerPub. */
export function ecdhX(priv: Uint8Array, peerPub: Uint8Array): Uint8Array {
  return be32(mul(scalar(priv), decompress(peerPub)).x);
}

/** True iff `priv` is a valid secp256k1 scalar (32 bytes, in [1, n-1]). */
export function isValidScalar(priv: Uint8Array | null | undefined): boolean {
  if (!priv || priv.length !== 32) return false;
  const d = bytesToBig(priv);
  return d > 0n && d < N;
}

/** True iff `pub` is a valid public key: decodable AND actually on the curve (y² ≡ x³+7 mod p),
 *  with both coordinates in the field. Rejects off-curve / malformed points fail-closed. */
export function isValidPublicKey(pub: Uint8Array): boolean {
  try {
    const pt = decompress(pub);
    if (pt.inf || pt.x <= 0n || pt.x >= P || pt.y <= 0n || pt.y >= P) return false;
    return mod(pt.y * pt.y - (pt.x * pt.x * pt.x + 7n), P) === 0n;
  } catch { return false; }
}

// ---- ECDSA (CSPRNG random nonce k, low-S). NO deterministic/RFC-6979 nonce. ----
function randomK(): bigint {
  // fresh, uniformly-random k in [1, n-1] from the platform CSPRNG, by rejection sampling.
  for (;;) {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    const k = bytesToBig(b);
    if (k >= 1n && k < N) return k;
  }
}

/** Sign a 32-byte hash; returns 64 bytes (r‖s) with low-S. The nonce k is freshly random. */
export function signHash(priv: Uint8Array, hash32: Uint8Array): Uint8Array {
  const d = scalar(priv), z = mod(bytesToBig(hash32), N);
  for (;;) {
    const k = randomK();
    const R = mul(k, G);
    const r = mod(R.x, N);
    if (r === 0n) continue;
    let s = mod(invMod(k, N) * (z + r * d), N);
    if (s === 0n) continue;
    if (s > HALF_N) s = N - s; // low-S
    const o = new Uint8Array(64);
    o.set(be32(r), 0); o.set(be32(s), 32);
    return o;
  }
}

/** Verify a 64-byte (r‖s) signature over a 32-byte hash; rejects high-S. Total: never throws. */
export function verifyHash(pub: Uint8Array, hash32: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (sig.length !== 64) return false;
    const r = bytesToBig(sig.slice(0, 32)), s = bytesToBig(sig.slice(32));
    if (r < 1n || r >= N || s < 1n || s >= N || s > HALF_N) return false;
    const z = mod(bytesToBig(hash32), N);
    const w = invMod(s, N);
    const R = add(mul(mod(z * w, N), G), mul(mod(r * w, N), decompress(pub)));
    if (R.inf) return false;
    return mod(R.x, N) === r;
  } catch { return false; }
}

// ---- DER (strict, minimal) for BSV transaction signatures ----
function derInt(v: bigint): Uint8Array {
  let b = be32(v);
  let i = 0; while (i < b.length - 1 && b[i] === 0) i++;
  b = b.slice(i);
  if (b[0] & 0x80) { const o = new Uint8Array(b.length + 1); o.set(b, 1); return o; }
  return b;
}
/** Encode a 64-byte (r‖s) signature as a strict-DER signature (low-S preserved). */
export function derEncode(sig64: Uint8Array): Uint8Array {
  const r = derInt(bytesToBig(sig64.slice(0, 32))), s = derInt(bytesToBig(sig64.slice(32)));
  const body = [0x02, r.length, ...r, 0x02, s.length, ...s];
  return Uint8Array.from([0x30, body.length, ...body]);
}
/** Decode a strict-DER signature to (r, s) as a 64-byte buffer. Throws on malformed input. */
export function derDecode(der: Uint8Array): Uint8Array {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('der');
  i++; // total length
  if (der[i++] !== 0x02) throw new Error('der');
  const rl = der[i++]; const r = bytesToBig(der.slice(i, i + rl)); i += rl;
  if (der[i++] !== 0x02) throw new Error('der');
  const sl = der[i++]; const s = bytesToBig(der.slice(i, i + sl));
  const o = new Uint8Array(64); o.set(be32(r), 0); o.set(be32(s), 32);
  return o;
}

export const hexEncode = toHex;
export const hexDecode = fromHexStrict;
