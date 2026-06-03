/**
 * @estates/channel — a mutually-authenticated, encrypted IP-to-IP session
 * (BRC-103 style). Two peers prove ownership of their identity keys and agree a
 * forward-secret session key over an EPHEMERAL ECDH exchange, then exchange
 * authenticated frames. This is the SECURE PROTOCOL that runs over the native
 * socket transport (the raw TCP/QUIC link is the sidecar's job); here is the
 * handshake + framing, pure and isomorphic (@noble), so it is fully testable.
 *
 *   initiate() ── Hello{idPub, ephPub, nonce, sig} ─▶ respond()
 *   complete() ◀─ Ack{idPub, ephPub, nonce, sig} ──── (responder)
 *   session = HKDF( ECDH(myEph, theirEph) )   (identical on both sides)
 *
 * Identity signatures bind each party's identity key to its ephemeral key (no
 * MITM); the Ack binds to the initiator's ephemeral key (no cross-session replay).
 */
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes, bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

// @noble/secp256k1 v2 needs an HMAC-SHA256 hook for RFC-6979 deterministic ECDSA.
secp.etc.hmacSha256Sync = (k: Uint8Array, ...m: Uint8Array[]): Uint8Array => hmac(sha256, k, secp.etc.concatBytes(...m));

export interface Identity { readonly priv: Uint8Array; readonly pub: Uint8Array }
export function genIdentity(): Identity { const priv = secp.utils.randomPrivateKey(); return { priv, pub: secp.getPublicKey(priv, true) }; }
/** Use a PLAYER'S existing non-custodial secp256k1 key as the channel identity —
 *  the same key signs moves and addresses chat (no throwaway keys). */
export function identityFrom(priv: Uint8Array): Identity {
  if (priv.length !== 32) throw new Error('identity private key must be 32 bytes');
  return { priv, pub: secp.getPublicKey(priv, true) };
}

export interface Hello { readonly idPub: string; readonly ephPub: string; readonly nonce: string; readonly sig: string }
export type Ack = Hello;
export interface Session { readonly key: Uint8Array; readonly peerIdPub: Uint8Array }
interface Pending { readonly id: Identity; readonly ephPriv: Uint8Array; readonly ephPub: Uint8Array; readonly nonce: Uint8Array }

const enc = new TextEncoder();
const H = (...parts: Uint8Array[]): Uint8Array => sha256(concatBytes(...parts));
const sign = (msg: Uint8Array, priv: Uint8Array): Uint8Array => secp.sign(msg, priv).toCompactRawBytes();
const verify = (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): boolean => { try { return secp.verify(sig, msg, pub); } catch { return false; } };

/** Sign arbitrary data with an identity key (ECDSA over sha256(data)). */
export function signData(data: Uint8Array, priv: Uint8Array): Uint8Array { return sign(sha256(data), priv); }
/** Verify a signature over `data` by `pub`. Safe (false on any error). */
export function verifyData(data: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean { return verify(sig, sha256(data), pub); }

function sessionKey(myEphPriv: Uint8Array, theirEphPub: Uint8Array): Uint8Array {
  const shared = secp.getSharedSecret(myEphPriv, theirEphPub, true).slice(1); // x-coord
  return hkdf(sha256, shared, new Uint8Array(0), enc.encode('estates-channel-v1'), 32);
}

/** Initiator step 1: produce the Hello and keep pending state. */
export function initiate(id: Identity): { hello: Hello; pending: Pending } {
  const ephPriv = secp.utils.randomPrivateKey();
  const ephPub = secp.getPublicKey(ephPriv, true);
  const nonce = randomBytes(32);
  const sig = sign(H(enc.encode('hello'), ephPub, nonce), id.priv);
  return {
    hello: { idPub: bytesToHex(id.pub), ephPub: bytesToHex(ephPub), nonce: bytesToHex(nonce), sig: bytesToHex(sig) },
    pending: { id, ephPriv, ephPub, nonce },
  };
}

/** Responder: verify the Hello, derive the session, and produce the Ack. */
export function respond(id: Identity, hello: Hello): { ack: Ack; session: Session } | null {
  let idPub: Uint8Array, ephPub: Uint8Array, nonce: Uint8Array, sig: Uint8Array;
  try { idPub = hexToBytes(hello.idPub); ephPub = hexToBytes(hello.ephPub); nonce = hexToBytes(hello.nonce); sig = hexToBytes(hello.sig); } catch { return null; }
  if (!verify(sig, H(enc.encode('hello'), ephPub, nonce), idPub)) return null; // identity not proven
  const ephPriv = secp.utils.randomPrivateKey();
  const myEphPub = secp.getPublicKey(ephPriv, true);
  const myNonce = randomBytes(32);
  // bind the Ack to the initiator's ephemeral key (anti-replay)
  const ackSig = sign(H(enc.encode('ack'), myEphPub, myNonce, ephPub), id.priv);
  return {
    ack: { idPub: bytesToHex(id.pub), ephPub: bytesToHex(myEphPub), nonce: bytesToHex(myNonce), sig: bytesToHex(ackSig) },
    session: { key: sessionKey(ephPriv, ephPub), peerIdPub: idPub },
  };
}

/** Initiator step 2: verify the Ack (bound to our ephemeral key) and finish. */
export function complete(pending: Pending, ack: Ack): Session | null {
  let idPub: Uint8Array, ephPub: Uint8Array, nonce: Uint8Array, sig: Uint8Array;
  try { idPub = hexToBytes(ack.idPub); ephPub = hexToBytes(ack.ephPub); nonce = hexToBytes(ack.nonce); sig = hexToBytes(ack.sig); } catch { return null; }
  if (!verify(sig, H(enc.encode('ack'), ephPub, nonce, pending.ephPub), idPub)) return null;
  return { key: sessionKey(pending.ephPriv, ephPub), peerIdPub: idPub };
}

// ---- authenticated framing over the session --------------------------------
export interface Frame { readonly nonce: string; readonly ct: string }
export function seal(session: Session, plaintext: Uint8Array): Frame {
  const nonce = randomBytes(12);
  return { nonce: bytesToHex(nonce), ct: bytesToHex(gcm(session.key, nonce).encrypt(plaintext)) };
}
export function openFrame(session: Session, frame: Frame): Uint8Array | null {
  try { return gcm(session.key, hexToBytes(frame.nonce)).decrypt(hexToBytes(frame.ct)); } catch { return null; }
}
