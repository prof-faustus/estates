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
import {
  randomPrivateKey, pubFromPriv, ecdhX, isValidPublicKey, isValidScalar, signHash, verifyHash,
  sha256, hkdfSha256, aesSeal, aesOpen,
  randomBytes, bytesToHex, hexToBytes, concatBytes,
} from '@estates/keys';

/** The secp256k1 protocol-signing key DERIVED from the player's master secret. The
 *  master (secp256k1) is the wallet key that makes single-use address/payment keys;
 *  the SAME master deterministically yields this secp256k1 signing key for protocol
 *  messages (the wallet does not expose raw master-key message signing).
 *
 *  ONE-GAME KEYS: pass a `gameId` (32-byte hex) to derive a key that is UNIQUE TO
 *  THAT GAME — same master, fresh signing key per game, so a seat key from game A
 *  is cryptographically distinct from the same player's seat key in game B (audit:
 *  every key valid for at most one game). Omitting gameId yields the legacy
 *  game-independent key (handshake/identity contexts that are not per-game). */
export function signingKeyFromMaster(masterPriv: Uint8Array, gameId?: string): { priv: Uint8Array; pub: Uint8Array } {
  const info = gameId === undefined
    ? new TextEncoder().encode('estates-secp256k1-sign-v1')
    : new TextEncoder().encode(`estates-secp256k1-sign-v1|game:${gameId}`);
  // HKDF to 32 bytes, then ensure a valid secp256k1 scalar (re-hash on the astronomically
  // unlikely out-of-range draw — uniform, no modulo bias).
  let seed = hkdfSha256(masterPriv, new Uint8Array(0), info, 32);
  while (!isValidScalar(seed)) seed = sha256(seed);
  return { priv: seed, pub: pubFromPriv(seed) };
}

export interface Identity {
  readonly priv: Uint8Array;     // secp256k1 master (wallet key): ECDH + single-use derivation
  readonly pub: Uint8Array;      // secp256k1 compressed pub (handshake identity + chat address)
  readonly signPriv: Uint8Array; // secp256k1 signing key, DERIVED from the master
  readonly signPub: Uint8Array;  // secp256k1 compressed signing pub (registered as the seat's signing key)
}
function identityOf(priv: Uint8Array): Identity {
  const sk = signingKeyFromMaster(priv);
  return { priv, pub: pubFromPriv(priv), signPriv: sk.priv, signPub: sk.pub };
}
export function genIdentity(): Identity { return identityOf(randomPrivateKey()); }
/** Use a PLAYER'S existing non-custodial master key as the identity. The same key
 *  does ECDH (handshake) + single-use payment derivation, and DERIVES the secp256k1
 *  key that signs moves; chat is addressed by the master pub. No throwaway keys. */
export function identityFrom(priv: Uint8Array): Identity {
  if (priv.length !== 32) throw new Error('identity private key must be 32 bytes');
  return identityOf(priv);
}

/**
 * A PER-GAME identity from the player's non-custodial master key. The secp256k1
 * master (ECDH/handshake) is the player's own key, but the Ed25519 SIGNING key is
 * derived FOR THIS GAME ONLY (gameId in the derivation), so the seat/gameplay key
 * a player uses in one game is distinct from every other game's — satisfying both
 * "use the player's own key" and "every key valid for at most one game". The
 * resulting `signPub` is what the game's key manifest binds (see @estates/keylife).
 */
export function gameIdentityFrom(priv: Uint8Array, gameId: string): Identity {
  if (priv.length !== 32) throw new Error('identity private key must be 32 bytes');
  if (typeof gameId !== 'string' || gameId.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(gameId)) throw new Error('gameId must be 32-byte hex');
  const sk = signingKeyFromMaster(priv, gameId);
  return { priv, pub: pubFromPriv(priv), signPriv: sk.priv, signPub: sk.pub };
}

export interface Hello { readonly idPub: string; readonly ephPub: string; readonly nonce: string; readonly signPub: string; readonly sig: string }
export type Ack = Hello;
export interface Session { readonly key: Uint8Array; readonly peerIdPub: Uint8Array; readonly peerSignPub: Uint8Array }
interface Pending { readonly id: Identity; readonly ephPriv: Uint8Array; readonly ephPub: Uint8Array; readonly nonce: Uint8Array }

const enc = new TextEncoder();
const H = (...parts: Uint8Array[]): Uint8Array => sha256(concatBytes(...parts));
const sign = (msg: Uint8Array, priv: Uint8Array): Uint8Array => signHash(priv, msg);
const verify = (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): boolean => verifyHash(pub, msg, sig);

/** Sign protocol data with the player's DERIVED secp256k1 signing key (ECDSA over SHA-256(data)). */
export function signData(data: Uint8Array, signPriv: Uint8Array): Uint8Array { return signHash(signPriv, sha256(data)); }
/** Verify a secp256k1 ECDSA signature over `data` by a secp256k1 signing pub. Safe (never throws). */
export function verifyData(data: Uint8Array, sig: Uint8Array, signPub: Uint8Array): boolean { return verifyHash(signPub, sha256(data), sig); }

function sessionKey(myEphPriv: Uint8Array, theirEphPub: Uint8Array): Uint8Array {
  const shared = ecdhX(myEphPriv, theirEphPub); // x-coord of the ephemeral ECDH
  return hkdfSha256(shared, new Uint8Array(0), enc.encode('estates-channel-v1'), 32);
}

/** Initiator step 1: produce the Hello and keep pending state. */
export function initiate(id: Identity): { hello: Hello; pending: Pending } {
  const ephPriv = randomPrivateKey();
  const ephPub = pubFromPriv(ephPriv);
  const nonce = randomBytes(32);
  // the secp identity sig vouches for BOTH the ephemeral key AND the secp256k1 signing key
  const sig = sign(H(enc.encode('hello'), ephPub, nonce, id.signPub), id.priv);
  return {
    hello: { idPub: bytesToHex(id.pub), ephPub: bytesToHex(ephPub), nonce: bytesToHex(nonce), signPub: bytesToHex(id.signPub), sig: bytesToHex(sig) },
    pending: { id, ephPriv, ephPub, nonce },
  };
}

// A Hello/Ack is FULLY UNTRUSTED bytes from a possibly-hostile peer. `respond`
// and `complete` are TOTAL: they return null on ANYTHING unexpected and NEVER
// throw, so a single handshake message can never crash a listening node.
//
// The subtle trap: a valid identity signature does NOT prove `ephPub` is a valid
// curve point — the attacker signs the *hash* with their own honest idPub and can
// embed arbitrary (off-curve) ephPub bytes. The in-tree ECDH does NOT throw on an
// off-curve point, so `respond`/`complete` EXPLICITLY validate `ephPub` with
// isValidPublicKey (on-curve) before any ECDH — fail-closed, never a crash.
function asBytes(h: Hello): { idPub: Uint8Array; ephPub: Uint8Array; nonce: Uint8Array; signPub: Uint8Array; sig: Uint8Array } | null {
  if (!h || typeof h !== 'object') return null;
  try {
    const idPub = hexToBytes(h.idPub), ephPub = hexToBytes(h.ephPub), nonce = hexToBytes(h.nonce), signPub = hexToBytes(h.signPub), sig = hexToBytes(h.sig);
    if (signPub.length !== 33) return null;   // secp256k1 compressed signing pub
    return { idPub, ephPub, nonce, signPub, sig };
  } catch { return null; }
}

/** Responder: verify the Hello, derive the session, and produce the Ack. Total. */
export function respond(id: Identity, hello: Hello): { ack: Ack; session: Session } | null {
  const f = asBytes(hello);
  if (!f) return null;
  try {
    if (!verify(f.sig, H(enc.encode('hello'), f.ephPub, f.nonce, f.signPub), f.idPub)) return null; // identity + signing key not proven
    if (!isValidPublicKey(f.ephPub)) return null;   // reject an off-curve ephemeral before ECDH
    const ephPriv = randomPrivateKey();
    const myEphPub = pubFromPriv(ephPriv);
    const myNonce = randomBytes(32);
    const session: Session = { key: sessionKey(ephPriv, f.ephPub), peerIdPub: f.idPub, peerSignPub: f.signPub };
    const ackSig = sign(H(enc.encode('ack'), myEphPub, myNonce, f.ephPub, id.signPub), id.priv);
    return {
      ack: { idPub: bytesToHex(id.pub), ephPub: bytesToHex(myEphPub), nonce: bytesToHex(myNonce), signPub: bytesToHex(id.signPub), sig: bytesToHex(ackSig) },
      session,
    };
  } catch { return null; }
}

/** Initiator step 2: verify the Ack (bound to our ephemeral key) and finish. Total. */
export function complete(pending: Pending, ack: Ack): Session | null {
  const f = asBytes(ack);
  if (!f) return null;
  try {
    if (!verify(f.sig, H(enc.encode('ack'), f.ephPub, f.nonce, pending.ephPub, f.signPub), f.idPub)) return null;
    if (!isValidPublicKey(f.ephPub)) return null;   // reject an off-curve ephemeral before ECDH
    return { key: sessionKey(pending.ephPriv, f.ephPub), peerIdPub: f.idPub, peerSignPub: f.signPub };
  } catch { return null; }
}

// ---- authenticated framing over the session --------------------------------
export interface Frame { readonly nonce: string; readonly ct: string }
export function seal(session: Session, plaintext: Uint8Array): Frame {
  const nonce = randomBytes(12);
  return { nonce: bytesToHex(nonce), ct: bytesToHex(aesSeal(session.key, nonce, plaintext)) };
}
export function openFrame(session: Session, frame: Frame): Uint8Array | null {
  try { return aesOpen(session.key, hexToBytes(frame.nonce), hexToBytes(frame.ct)); } catch { return null; }
}
