/**
 * Broadcast encryption for ESTATES — multi-recipient ECIES.
 *
 * A single message is encrypted once under a random content key (AES-256-GCM),
 * and that content key is wrapped to each recipient via secp256k1 ECDH →
 * HKDF-SHA256 → AES-256-GCM. Only a holder of one of the recipient private keys
 * can unwrap the content key and read the payload ("trivial" broadcast
 * encryption — sound and standard for small groups like a ≤6-seat table).
 *
 * Revocation is by recipient-set: leave a peer out of the next envelope and it
 * can no longer read. Each message uses a fresh content key + ephemeral key, so
 * messages are independent (per-message forward access control).
 */
import { createECDH, createHash, randomBytes, createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';

export interface Peer {
  readonly ecdh: import('node:crypto').ECDH; // holds the private key
  readonly pub: Uint8Array;                   // 33-byte compressed public key
  readonly address: string;                   // Bitmessage-style address (hex)
}

const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));

/** Bitmessage/BSV-style address: ripemd160(sha256(pubkey)), hex. */
export function addressOf(pub: Uint8Array): string {
  const s = createHash('sha256').update(pub).digest();
  return createHash('ripemd160').update(s).digest('hex');
}

/** Generate a secp256k1 peer identity. */
export function genPeer(): Peer {
  const ecdh = createECDH('secp256k1');
  ecdh.generateKeys();
  const pub = Uint8Array.from(ecdh.getPublicKey(undefined, 'compressed'));
  return { ecdh, pub, address: addressOf(pub) };
}

interface WrappedKey { readonly address: string; readonly iv: string; readonly ct: string; readonly tag: string; }
export interface Envelope {
  readonly ephPub: string;                  // ephemeral compressed pubkey (hex)
  readonly recipients: readonly WrappedKey[];
  readonly iv: string; readonly ct: string; readonly tag: string; // payload
}

const HKDF_INFO = Buffer.from('estates-broadcast-v1');

function wrapKeyFor(shared: Uint8Array): Uint8Array {
  return new Uint8Array(hkdfSync('sha256', shared, new Uint8Array(0), HKDF_INFO, 32));
}

/** Encrypt `plaintext` so that exactly `recipients` (compressed pubkeys) can read it. */
export function encryptBroadcast(recipients: readonly Uint8Array[], plaintext: Uint8Array): Envelope {
  if (recipients.length === 0) throw new Error('encryptBroadcast: need at least one recipient');
  const contentKey = randomBytes(32);

  // payload, encrypted once under the content key
  const piv = randomBytes(12);
  const pc = createCipheriv('aes-256-gcm', contentKey, piv);
  const ct = Buffer.concat([pc.update(plaintext), pc.final()]);
  const ptag = pc.getAuthTag();

  // one ephemeral key for the whole broadcast; wrap the content key per recipient
  const eph = createECDH('secp256k1');
  eph.generateKeys();
  const ephPub = Uint8Array.from(eph.getPublicKey(undefined, 'compressed'));
  const wrapped: WrappedKey[] = recipients.map((rpub) => {
    const shared = Uint8Array.from(eph.computeSecret(Buffer.from(rpub)));
    const wk = wrapKeyFor(shared);
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', wk, iv);
    const wct = Buffer.concat([c.update(contentKey), c.final()]);
    return { address: addressOf(rpub), iv: toHex(iv), ct: toHex(wct), tag: toHex(c.getAuthTag()) };
  });

  return { ephPub: toHex(ephPub), recipients: wrapped, iv: toHex(piv), ct: toHex(ct), tag: toHex(ptag) };
}

/** Decrypt an envelope with a peer's key. Returns null if the peer is not a recipient. */
export function decryptBroadcast(env: Envelope, me: Peer): Uint8Array | null {
  const slot = env.recipients.find((r) => r.address === me.address);
  if (!slot) return null; // not addressed to this peer (revoked / never a member)
  try {
    const shared = Uint8Array.from(me.ecdh.computeSecret(Buffer.from(fromHex(env.ephPub))));
    const wk = wrapKeyFor(shared);
    const d = createDecipheriv('aes-256-gcm', wk, fromHex(slot.iv));
    d.setAuthTag(fromHex(slot.tag));
    const contentKey = Buffer.concat([d.update(fromHex(slot.ct)), d.final()]);

    const p = createDecipheriv('aes-256-gcm', contentKey, fromHex(env.iv));
    p.setAuthTag(fromHex(env.tag));
    return Uint8Array.from(Buffer.concat([p.update(fromHex(env.ct)), p.final()]));
  } catch {
    return null; // tampered ciphertext / wrong key
  }
}
