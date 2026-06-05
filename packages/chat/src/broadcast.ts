/**
 * Broadcast encryption for ESTATES — multi-recipient ECIES, ISOMORPHIC.
 *
 * Uses @noble/* (pure JS) so it runs identically in Node and the browser
 * (SubtleCrypto has no secp256k1, hence noble). A message is encrypted once
 * under a random content key (AES-256-GCM) and that key is wrapped to each
 * recipient via secp256k1 ECDH → HKDF-SHA256 → AES-256-GCM. Only a holder of a
 * recipient private key can read it. Revocation = recipient-set change; fresh
 * content + ephemeral key per message (per-message forward access control).
 */
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';

export interface Peer {
  readonly priv: Uint8Array;   // 32-byte secp256k1 secret key
  readonly pub: Uint8Array;    // 33-byte compressed public key
  readonly address: string;    // Bitmessage-style address (hex)
}

const HKDF_INFO = new TextEncoder().encode('estates-broadcast-v1');
const EMPTY = new Uint8Array(0);

/** Bitmessage/BSV-style address: ripemd160(sha256(pubkey)), hex. */
export function addressOf(pub: Uint8Array): string {
  return bytesToHex(ripemd160(sha256(pub)));
}

/** Generate a secp256k1 peer identity. */
export function genPeer(): Peer {
  const priv = secp.utils.randomPrivateKey();
  const pub = secp.getPublicKey(priv, true);
  return { priv, pub, address: addressOf(pub) };
}

/** Deterministic peer from an EXISTING secret key — so chat uses the PLAYER's own
 *  wallet key (its Bitmessage address is derived from the same key that signs
 *  moves), never a throwaway. */
export function peerFrom(priv: Uint8Array): Peer {
  const pub = secp.getPublicKey(priv, true);
  return { priv, pub, address: addressOf(pub) };
}

interface WrappedKey { readonly address: string; readonly nonce: string; readonly ct: string; }
export interface Envelope {
  readonly ephPub: string;                   // ephemeral compressed pubkey (hex)
  readonly nonce: string;                    // payload nonce (hex)
  readonly ct: string;                       // payload ciphertext+tag (hex)
  readonly recipients: readonly WrappedKey[];
}

// ---- untrusted-input validators (fail-closed; total — never throw) ----------
// WHY: an Envelope on the wire is attacker-controlled. Before ANY field is read we
// prove its exact shape, so a malformed envelope is REJECTED, never dereferenced or
// allowed to throw out of a receive loop. Sizes are bounded so a hostile peer cannot
// force a huge allocation (DoS) via a giant ct or recipient list.
const HEX_RE = /^[0-9a-f]*$/i;
const MAX_CT_BYTES = 1 << 20;       // 1 MiB ciphertext ceiling (a chat line is tiny)
const MAX_RECIPIENTS = 4096;        // far above any real table; bounds the loop/array

/** True iff `x` is an even-length hex string of `exactBytes` (if given) and ≤ maxBytes. */
export function isHex(x: unknown, exactBytes?: number, maxBytes = MAX_CT_BYTES): x is string {
  if (typeof x !== 'string' || x.length % 2 !== 0) return false;
  const bytes = x.length / 2;
  if (bytes > maxBytes) return false;
  if (exactBytes !== undefined && bytes !== exactBytes) return false;
  return HEX_RE.test(x);
}

/**
 * Structural validator for an Envelope from untrusted bytes. Checks EVERY field's
 * presence, type, hex-ness, exact length where fixed (33-byte ephPub, 12-byte
 * nonces, 20-byte recipient addresses), and bounds the recipient count + ct size.
 * Returns a type guard so callers may safely read fields afterward.
 */
export function isEnvelope(x: unknown): x is Envelope {
  if (typeof x !== 'object' || x === null) return false;
  const e = x as Record<string, unknown>;
  if (!isHex(e.ephPub, 33)) return false;          // compressed secp256k1 point
  if (!isHex(e.nonce, 12)) return false;           // AES-GCM nonce
  if (!isHex(e.ct, undefined, MAX_CT_BYTES)) return false;
  if (!Array.isArray(e.recipients) || e.recipients.length === 0 || e.recipients.length > MAX_RECIPIENTS) return false;
  for (const r of e.recipients) {
    if (typeof r !== 'object' || r === null) return false;
    const w = r as Record<string, unknown>;
    if (!isHex(w.address, 20)) return false;        // ripemd160(sha256(pub)) = 20 bytes
    if (!isHex(w.nonce, 12)) return false;
    if (!isHex(w.ct, undefined, MAX_CT_BYTES)) return false;
  }
  return true;
}

function wrapKey(shared: Uint8Array): Uint8Array {
  return hkdf(sha256, shared, EMPTY, HKDF_INFO, 32);
}

/** Encrypt `plaintext` so exactly `recipients` (compressed pubkeys) can read it. */
export function encryptBroadcast(recipients: readonly Uint8Array[], plaintext: Uint8Array): Envelope {
  if (recipients.length === 0) throw new Error('encryptBroadcast: need at least one recipient');
  const contentKey = randomBytes(32);
  const pnonce = randomBytes(12);
  const ct = gcm(contentKey, pnonce).encrypt(plaintext); // ct includes the GCM tag

  const ephPriv = secp.utils.randomPrivateKey();
  const ephPub = secp.getPublicKey(ephPriv, true);
  const wrapped: WrappedKey[] = recipients.map((rpub) => {
    const shared = secp.getSharedSecret(ephPriv, rpub, true);
    const wk = wrapKey(shared);
    const wnonce = randomBytes(12);
    return { address: addressOf(rpub), nonce: bytesToHex(wnonce), ct: bytesToHex(gcm(wk, wnonce).encrypt(contentKey)) };
  });

  return { ephPub: bytesToHex(ephPub), nonce: bytesToHex(pnonce), ct: bytesToHex(ct), recipients: wrapped };
}

/**
 * Decrypt an envelope with a peer's key. TOTAL and FAIL-CLOSED: returns null if the
 * envelope is malformed, not addressed to this peer, or tampered — it NEVER throws,
 * so it is safe to call directly on untrusted bytes inside a receive loop.
 *
 * WHY total: this runs on every inbound relay frame. A hostile peer that could make
 * it throw (e.g. `recipients` not an array) would crash the receive loop / DoS the
 * client; the @noble AEAD then guarantees a tampered ciphertext fails closed (null),
 * never returns forged plaintext.
 */
export function decryptBroadcast(env: unknown, me: Peer): Uint8Array | null {
  if (!isEnvelope(env)) return null;                 // reject malformed before any field read
  try {
    const slot = env.recipients.find((r) => r.address === me.address);
    if (!slot) return null;                           // not addressed to this peer
    const shared = secp.getSharedSecret(me.priv, hexToBytes(env.ephPub), true);
    const wk = wrapKey(shared);
    const contentKey = gcm(wk, hexToBytes(slot.nonce)).decrypt(hexToBytes(slot.ct)); // AEAD: throws on tamper
    return gcm(contentKey, hexToBytes(env.nonce)).decrypt(hexToBytes(env.ct));        // AEAD: throws on tamper
  } catch {
    return null;                                      // wrong key / tampered ciphertext → fail closed
  }
}
