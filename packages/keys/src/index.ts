/**
 * @estates/keys — the in-tree, DEPENDENCY-FREE key foundation: one-use Type-42 ECDH key derivation
 * with the MANDATORY index‖ECDH‖HMAC HASH CHAIN, plus a re-export of the in-tree crypto primitives
 * (secp256k1, SHA-256/512, RIPEMD-160, HMAC, HKDF, AES-256-GCM) that the rest of the TS stack uses.
 *
 * NO third-party library (PLAN §1.2): everything here stands on `./secp256k1`, `./hashes`, `./aesgcm`
 * — pure TypeScript, identical in output to the audited native core (`Secp256k1.cs`, `KeyChain.cs`,
 * `Ripemd160.cs`, `Cipher.cs`). NO Ed25519, NO RFC-6979, NO BIP32/39/44.
 *
 * Type-42 (the user's scheme, "number 42"):
 *   shared  S = ECDH(myPriv, theirPub)            (S is symmetric: ECDH(a,B)=ECDH(b,A))
 *   tweak   t = HMAC-SHA256(S.x, invoiceNumber)    mod n
 *   childPriv = (theirPriv? + t) mod n             (recipient derives the secret)
 *   childPub  = recipientPub + t·G                 (sender derives the same pubkey)
 * The ROOT key is never shared or used directly; every key use is a UNIQUE one-use sub-key.
 */
import {
  N, G, add, mul, decompress, compress, publicKey, ecdhX, ecdhCompressed, to32, hexEncode, hexDecode, isValidScalar,
} from './secp256k1.ts';
import { sha256, ripemd160, hmacSha256, hash160 as _hash160 } from './hashes.ts';

// re-export the in-tree crypto core so other packages import ONE library-free source.
export * as secp256k1 from './secp256k1.ts';
export { sha256, sha512, ripemd160, hmac, hmacSha256, hmacSha512, hkdfSha256, hash160, hash256 } from './hashes.ts';
export { seal as aesSeal, open as aesOpen } from './aesgcm.ts';
export {
  signHash, verifyHash, derEncode, derDecode, publicKey as pubFromPriv,
  ecdhCompressed, ecdhX, isValidPublicKey, isValidScalar, decompress, compress, mul as pointMul, add as pointAdd, G as basePoint, N as curveOrder,
} from './secp256k1.ts';

const enc = new TextEncoder();
const bytesToBig = (b: Uint8Array): bigint => (b.length === 0 ? 0n : BigInt('0x' + hexEncode(b)));
const bigToBytes32 = (x: bigint): Uint8Array => to32(x);

// ---- byte utilities (the in-tree replacements for `@noble/hashes/utils`) ----
/** Hex-encode bytes (lowercase, no prefix). */
export const bytesToHex = hexEncode;
/** Strict hex-decode (throws on odd length / non-hex). */
export const hexToBytes = hexDecode;
/** Concatenate byte arrays. */
export function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  let n = 0; for (const a of arrs) n += a.length;
  const o = new Uint8Array(n); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; }
  return o;
}
/** `n` cryptographically-random bytes from the platform CSPRNG. */
export function randomBytes(n: number): Uint8Array { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }

export interface KeyPair { readonly priv: Uint8Array; readonly pub: Uint8Array }

/** P2PKH hash160 of a compressed pubkey: ripemd160(sha256(pub)). */
export function pkhOf(pub: Uint8Array): Uint8Array { return _hash160(pub); }

/** A fresh, uniformly-random secp256k1 private key in [1, n-1] (platform CSPRNG, rejection-sampled). */
export function randomPrivateKey(): Uint8Array {
  for (;;) {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    if (isValidScalar(b)) return b;
  }
}

/**
 * Canonical spend-key derivation context (the Type-42 invoice). Binds a one-use key to EXACTLY one
 * on-chain purpose so a key is never reused across outputs.
 */
export function spendContext(p: {
  gameId: string; network: string; version?: string; purpose: string;
  role: number; turnIndex: number; outputIndex: number; asset?: string;
}): string {
  return [
    'estates-spend-v1', p.version ?? '1', p.gameId, p.network, p.purpose,
    `seat${p.role}`, p.asset ?? '-', `turn${p.turnIndex}`, `out${p.outputIndex}`,
  ].join('/');
}

/** secp256k1 identity keypair (a master; the ONLY long-lived key a party holds). */
export function genMaster(): KeyPair {
  const priv = randomPrivateKey();
  return { priv, pub: publicKey(priv) };
}
export function pubOf(priv: Uint8Array): Uint8Array { return publicKey(priv); }

/** Deterministic tweak t = HMAC-SHA256(sharedX, invoice) mod n, in [1, n). */
function tweak(shared: Uint8Array, invoice: string): bigint {
  const t = bytesToBig(hmacSha256(shared, enc.encode(invoice))) % N;
  return t === 0n ? 1n : t;
}

/** RECIPIENT side: derive the one-use child PRIVATE key for `invoice` paid by `senderPub`. */
export function deriveChildPriv(myPriv: Uint8Array, senderPub: Uint8Array, invoice: string): Uint8Array {
  const t = tweak(ecdhX(myPriv, senderPub), invoice);
  const child = (bytesToBig(myPriv) + t) % N;
  return bigToBytes32(child === 0n ? 1n : child);
}
/** SENDER side: derive the recipient's matching one-use child PUBLIC key for `invoice`. */
export function deriveChildPub(recipientPub: Uint8Array, myPriv: Uint8Array, invoice: string): Uint8Array {
  const t = tweak(ecdhX(myPriv, recipientPub), invoice);
  return compress(add(decompress(recipientPub), mul(t, G)));
}

/** "Alice only": a one-use child keypair derived from her master alone (S = ECDH(a,A)). */
export function deriveSelf(master: KeyPair, index: number | string): KeyPair {
  const priv = deriveChildPriv(master.priv, master.pub, `self/${index}`);
  return { priv, pub: publicKey(priv) };
}

// ============================================================================
//  MANDATORY HASH CHAIN (PLAN §2) — the TS twin of the native `KeyChain.cs`.
//  Every key is a node on a verifiable, ordered chain binding INDEX ‖ ECDH ‖ HMAC,
//  hash-chained to the prior link. The root is never used directly; tamper any earlier
//  link and every later key fails to reproduce (verifyChain ⇒ false).
//    link[0] = SHA256("estates-keychain/v1" ‖ rootPub)
//    link[i] = SHA256(link[i-1] ‖ be32(i))
//    k[i]    = HMAC-SHA256( ECDH(rootPriv, counterpartyPub), link[i] ‖ be32(i) ) mod n
//    childPriv[i] = (rootPriv + k[i]) mod n   childPub[i] = rootPub + k[i]·G
// ============================================================================
const GENESIS_TAG = enc.encode('estates-keychain/v1');
const be32num = (i: number): Uint8Array => Uint8Array.from([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]);
const cat = (a: Uint8Array, b: Uint8Array): Uint8Array => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };

export interface ChainedKey { readonly index: number; readonly link: Uint8Array; readonly priv: Uint8Array; readonly pub: Uint8Array }

/** The genesis link of a chain: SHA256("estates-keychain/v1" ‖ rootPub). */
export function genesisLink(rootPub: Uint8Array): Uint8Array { return sha256(cat(GENESIS_TAG, rootPub)); }

function chainK(shared: Uint8Array, link: Uint8Array, index: number): bigint {
  return bytesToBig(hmacSha256(shared, cat(link, be32num(index)))) % N;
}

/** Derive the chained key at `index`: advances `prevLink`, binds an ECDH secret with `counterpartyPub`
 *  + an HMAC, and returns the unique sub-key and its link. */
export function deriveChained(rootPriv: Uint8Array, counterpartyPub: Uint8Array, index: number, prevLink: Uint8Array): ChainedKey {
  const link = sha256(cat(prevLink, be32num(index)));
  const k = chainK(ecdhCompressed(rootPriv, counterpartyPub), link, index);
  const priv = to32((bytesToBig(rootPriv) + k) % N);
  return { index, link, priv, pub: publicKey(priv) };
}

/** A wallet's own hash-chained sub-keys [0..count) — counterparty is the wallet's own key, so only
 *  the root holder can derive them; the root is never shared. */
export function walletChain(rootPriv: Uint8Array, count: number): ChainedKey[] {
  const rootPub = publicKey(rootPriv);
  const out: ChainedKey[] = [];
  let link = genesisLink(rootPub);
  for (let i = 0; i < count; i++) { const ck = deriveChained(rootPriv, rootPub, i, link); out.push(ck); link = ck.link; }
  return out;
}

/** Verify a chain is intact: each link = SHA256(prevLink ‖ be32(index)) in order from genesis, and
 *  each key's pub matches its priv. Any break ⇒ false. */
export function verifyChain(rootPub: Uint8Array, chain: readonly ChainedKey[]): boolean {
  let link = genesisLink(rootPub);
  for (let i = 0; i < chain.length; i++) {
    const ck = chain[i];
    const expect = sha256(cat(link, be32num(ck.index)));
    if (ck.index !== i || hexEncode(expect) !== hexEncode(ck.link)) return false;
    if (hexEncode(publicKey(ck.priv)) !== hexEncode(ck.pub)) return false;
    link = ck.link;
  }
  return true;
}

/** A monotonic one-use key issuer: each call advances the index — a key is never reused. */
export class KeyChain {
  private master: KeyPair;
  private i = 0;
  constructor(master: KeyPair) { this.master = master; }
  get pub(): Uint8Array { return this.master.pub; }
  next(): { key: KeyPair; index: number } { const index = this.i++; return { key: deriveSelf(this.master, index), index }; }
  receiveFrom(senderPub: Uint8Array, invoice: string): KeyPair {
    const priv = deriveChildPriv(this.master.priv, senderPub, invoice);
    return { priv, pub: publicKey(priv) };
  }
  payTo(recipientPub: Uint8Array, invoice: string): Uint8Array {
    return deriveChildPub(recipientPub, this.master.priv, invoice);
  }
}
