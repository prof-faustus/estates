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

interface WrappedKey { readonly address: string; readonly nonce: string; readonly ct: string; }
export interface Envelope {
  readonly ephPub: string;                   // ephemeral compressed pubkey (hex)
  readonly nonce: string;                    // payload nonce (hex)
  readonly ct: string;                       // payload ciphertext+tag (hex)
  readonly recipients: readonly WrappedKey[];
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

/** Decrypt an envelope with a peer's key. Returns null if not a recipient or on tamper. */
export function decryptBroadcast(env: Envelope, me: Peer): Uint8Array | null {
  const slot = env.recipients.find((r) => r.address === me.address);
  if (!slot) return null; // not addressed to this peer (revoked / never a member)
  try {
    const shared = secp.getSharedSecret(me.priv, hexToBytes(env.ephPub), true);
    const wk = wrapKey(shared);
    const contentKey = gcm(wk, hexToBytes(slot.nonce)).decrypt(hexToBytes(slot.ct));
    return gcm(contentKey, hexToBytes(env.nonce)).decrypt(hexToBytes(env.ct));
  } catch {
    return null; // tampered ciphertext / wrong key
  }
}
