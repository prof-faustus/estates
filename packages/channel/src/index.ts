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
import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes, bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

// @noble/secp256k1 v2 needs an HMAC-SHA256 hook for RFC-6979 deterministic ECDSA.
secp.etc.hmacSha256Sync = (k: Uint8Array, ...m: Uint8Array[]): Uint8Array => hmac(sha256, k, secp.etc.concatBytes(...m));
// @noble/ed25519 v2 needs a SHA-512 hook for synchronous signing.
ed.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed.etc.concatBytes(...m));

/** The Ed25519 protocol-signing key DERIVED from the player's master secret. The
 *  master (secp256k1) is the wallet key that makes single-use address/payment
 *  keys; the SAME master deterministically yields this Ed25519 key for signing
 *  protocol messages (the wallet does not expose raw ECDSA message signing). */
export function signingKeyFromMaster(masterPriv: Uint8Array): { priv: Uint8Array; pub: Uint8Array } {
  const seed = hkdf(sha256, masterPriv, new Uint8Array(0), new TextEncoder().encode('estates-ed25519-sign-v1'), 32);
  return { priv: seed, pub: ed.getPublicKey(seed) };
}

export interface Identity {
  readonly priv: Uint8Array;     // secp256k1 master (wallet key): ECDH + single-use derivation
  readonly pub: Uint8Array;      // secp256k1 compressed pub (handshake identity + chat address)
  readonly signPriv: Uint8Array; // Ed25519 signing seed, DERIVED from the master
  readonly signPub: Uint8Array;  // Ed25519 signing pub (registered as the seat's signing key)
}
function identityOf(priv: Uint8Array): Identity {
  const sk = signingKeyFromMaster(priv);
  return { priv, pub: secp.getPublicKey(priv, true), signPriv: sk.priv, signPub: sk.pub };
}
export function genIdentity(): Identity { return identityOf(secp.utils.randomPrivateKey()); }
/** Use a PLAYER'S existing non-custodial master key as the identity. The same key
 *  does ECDH (handshake) + single-use payment derivation, and DERIVES the Ed25519
 *  key that signs moves; chat is addressed by the master pub. No throwaway keys. */
export function identityFrom(priv: Uint8Array): Identity {
  if (priv.length !== 32) throw new Error('identity private key must be 32 bytes');
  return identityOf(priv);
}

export interface Hello { readonly idPub: string; readonly ephPub: string; readonly nonce: string; readonly signPub: string; readonly sig: string }
export type Ack = Hello;
export interface Session { readonly key: Uint8Array; readonly peerIdPub: Uint8Array; readonly peerSignPub: Uint8Array }
interface Pending { readonly id: Identity; readonly ephPriv: Uint8Array; readonly ephPub: Uint8Array; readonly nonce: Uint8Array }

const enc = new TextEncoder();
const H = (...parts: Uint8Array[]): Uint8Array => sha256(concatBytes(...parts));
const sign = (msg: Uint8Array, priv: Uint8Array): Uint8Array => secp.sign(msg, priv).toCompactRawBytes();
const verify = (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): boolean => { try { return secp.verify(sig, msg, pub); } catch { return false; } };

/** Sign protocol data with the player's DERIVED Ed25519 signing key (not ECDSA). */
export function signData(data: Uint8Array, signPriv: Uint8Array): Uint8Array { return ed.sign(data, signPriv); }
/** Verify an Ed25519 signature over `data` by an Ed25519 signing pub. Safe. */
export function verifyData(data: Uint8Array, sig: Uint8Array, signPub: Uint8Array): boolean { try { return ed.verify(sig, data, signPub); } catch { return false; } }

function sessionKey(myEphPriv: Uint8Array, theirEphPub: Uint8Array): Uint8Array {
  const shared = secp.getSharedSecret(myEphPriv, theirEphPub, true).slice(1); // x-coord
  return hkdf(sha256, shared, new Uint8Array(0), enc.encode('estates-channel-v1'), 32);
}

/** Initiator step 1: produce the Hello and keep pending state. */
export function initiate(id: Identity): { hello: Hello; pending: Pending } {
  const ephPriv = secp.utils.randomPrivateKey();
  const ephPub = secp.getPublicKey(ephPriv, true);
  const nonce = randomBytes(32);
  // the secp identity sig vouches for BOTH the ephemeral key AND the Ed25519 signing key
  const sig = sign(H(enc.encode('hello'), ephPub, nonce, id.signPub), id.priv);
  return {
    hello: { idPub: bytesToHex(id.pub), ephPub: bytesToHex(ephPub), nonce: bytesToHex(nonce), signPub: bytesToHex(id.signPub), sig: bytesToHex(sig) },
    pending: { id, ephPriv, ephPub, nonce },
  };
}

/** Responder: verify the Hello, derive the session, and produce the Ack. */
export function respond(id: Identity, hello: Hello): { ack: Ack; session: Session } | null {
  let idPub: Uint8Array, ephPub: Uint8Array, nonce: Uint8Array, signPub: Uint8Array, sig: Uint8Array;
  try { idPub = hexToBytes(hello.idPub); ephPub = hexToBytes(hello.ephPub); nonce = hexToBytes(hello.nonce); signPub = hexToBytes(hello.signPub); sig = hexToBytes(hello.sig); } catch { return null; }
  if (signPub.length !== 32) return null;
  if (!verify(sig, H(enc.encode('hello'), ephPub, nonce, signPub), idPub)) return null; // identity + signing key not proven
  const ephPriv = secp.utils.randomPrivateKey();
  const myEphPub = secp.getPublicKey(ephPriv, true);
  const myNonce = randomBytes(32);
  // bind the Ack to the initiator's ephemeral key (anti-replay) + our signing key
  const ackSig = sign(H(enc.encode('ack'), myEphPub, myNonce, ephPub, id.signPub), id.priv);
  return {
    ack: { idPub: bytesToHex(id.pub), ephPub: bytesToHex(myEphPub), nonce: bytesToHex(myNonce), signPub: bytesToHex(id.signPub), sig: bytesToHex(ackSig) },
    session: { key: sessionKey(ephPriv, ephPub), peerIdPub: idPub, peerSignPub: signPub },
  };
}

/** Initiator step 2: verify the Ack (bound to our ephemeral key) and finish. */
export function complete(pending: Pending, ack: Ack): Session | null {
  let idPub: Uint8Array, ephPub: Uint8Array, nonce: Uint8Array, signPub: Uint8Array, sig: Uint8Array;
  try { idPub = hexToBytes(ack.idPub); ephPub = hexToBytes(ack.ephPub); nonce = hexToBytes(ack.nonce); signPub = hexToBytes(ack.signPub); sig = hexToBytes(ack.sig); } catch { return null; }
  if (signPub.length !== 32) return null;
  if (!verify(sig, H(enc.encode('ack'), ephPub, nonce, pending.ephPub, signPub), idPub)) return null;
  return { key: sessionKey(pending.ephPriv, ephPub), peerIdPub: idPub, peerSignPub: signPub };
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
