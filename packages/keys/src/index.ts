/**
 * @estates/keys — deterministic, indexed, ONE-USE ECDH key derivation.
 *
 * NO address is ever reused. Every key is derived once, deterministically, from a
 * master key + an indexed "invoice number" (a hash chain), via the BSV BRC-42
 * key-derivation scheme:
 *
 *   shared  S = ECDH(myPriv, theirPub)          (S is symmetric: ECDH(a,B)=ECDH(b,A))
 *   tweak   t = HMAC-SHA256(S.x, invoiceNumber)  mod n
 *   childPriv = (theirPriv? + t) mod n           (the recipient derives the secret)
 *   childPub  = recipientPub + t·G               (the sender derives the same pubkey)
 *
 * - "Alice only — JUST her": derive against her OWN pubkey (S = ECDH(a, A)); only
 *   she holds the master, so only she can produce the child secret. Indexed by
 *   `self/<i>` — a deterministic hash chain of one-use keys.
 * - "Alice AND Bob": Alice derives Bob's one-use child PUBKEY to pay him; Bob
 *   derives the matching child PRIVKEY to spend — neither reuses a key, and the
 *   key is unlinkable to Bob's identity key without the shared secret.
 *
 * Isomorphic (pure @noble).
 */
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const N = secp.CURVE.n;
const enc = new TextEncoder();

export interface KeyPair { readonly priv: Uint8Array; readonly pub: Uint8Array }

/** P2PKH hash160 of a compressed pubkey: ripemd160(sha256(pub)). The on-chain
 *  address material for a derived one-use spend key. */
export function pkhOf(pub: Uint8Array): Uint8Array { return ripemd160(sha256(pub)); }

/**
 * Canonical spend-key derivation context (the BRC-42 invoice). Binds a one-use
 * key to EXACTLY one on-chain purpose so a key is never reused across outputs:
 * game id, network, protocol version, purpose, role/seat, asset, turn, output.
 * Both the payer (who derives the child PUB) and the recipient (who derives the
 * matching child PRIV) build the identical context, so the recipient can always
 * recover the private key for an output addressed to them.
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

const bytesToBig = (b: Uint8Array): bigint => BigInt('0x' + bytesToHex(b));
const bigToBytes32 = (x: bigint): Uint8Array => hexToBytes(x.toString(16).padStart(64, '0'));

/** secp256k1 identity keypair (a master; the ONLY long-lived key a party holds). */
export function genMaster(): KeyPair {
  const priv = secp.utils.randomPrivateKey();
  return { priv, pub: secp.getPublicKey(priv, true) };
}
export function pubOf(priv: Uint8Array): Uint8Array { return secp.getPublicKey(priv, true); }

/** x-coordinate of the ECDH shared secret (symmetric across the two parties). */
function sharedX(myPriv: Uint8Array, theirPub: Uint8Array): Uint8Array {
  return secp.getSharedSecret(myPriv, theirPub, true).slice(1); // drop the 02/03 prefix
}
/** Deterministic tweak t = HMAC-SHA256(sharedX, invoice) mod n, in [1, n). */
function tweak(shared: Uint8Array, invoice: string): bigint {
  const t = bytesToBig(hmac(sha256, shared, enc.encode(invoice))) % N;
  return t === 0n ? 1n : t;
}

/** RECIPIENT side: derive the one-use child PRIVATE key for `invoice` paid by `senderPub`. */
export function deriveChildPriv(myPriv: Uint8Array, senderPub: Uint8Array, invoice: string): Uint8Array {
  const t = tweak(sharedX(myPriv, senderPub), invoice);
  const child = (bytesToBig(myPriv) + t) % N;
  return bigToBytes32(child === 0n ? 1n : child);
}
/** SENDER side: derive the recipient's matching one-use child PUBLIC key for `invoice`. */
export function deriveChildPub(recipientPub: Uint8Array, myPriv: Uint8Array, invoice: string): Uint8Array {
  const t = tweak(sharedX(myPriv, recipientPub), invoice);
  const P = secp.ProjectivePoint.fromHex(bytesToHex(recipientPub)).add(secp.ProjectivePoint.BASE.multiply(t));
  return P.toRawBytes(true);
}

/** "Alice only": a one-use child keypair derived from her master alone (S = ECDH(a,A)). */
export function deriveSelf(master: KeyPair, index: number | string): KeyPair {
  const invoice = `self/${index}`;
  const priv = deriveChildPriv(master.priv, master.pub, invoice);
  return { priv, pub: secp.getPublicKey(priv, true) };
}

/** A monotonic one-use key issuer: each call advances the index — a key is never
 *  reused. `next()` for self-only keys; `nextFor(theirPub)` for a counterparty. */
export class KeyChain {
  private master: KeyPair;
  private i = 0;
  constructor(master: KeyPair) { this.master = master; }
  get pub(): Uint8Array { return this.master.pub; }
  /** Next one-use self key (and its index). */
  next(): { key: KeyPair; index: number } { const index = this.i++; return { key: deriveSelf(this.master, index), index }; }
  /** Next one-use child PRIVATE key to receive a payment from `senderPub` at `invoice`. */
  receiveFrom(senderPub: Uint8Array, invoice: string): KeyPair {
    const priv = deriveChildPriv(this.master.priv, senderPub, invoice);
    return { priv, pub: secp.getPublicKey(priv, true) };
  }
  /** The one-use child PUBLIC key to pay `recipientPub` at `invoice` (sender side). */
  payTo(recipientPub: Uint8Array, invoice: string): Uint8Array {
    return deriveChildPub(recipientPub, this.master.priv, invoice);
  }
}
