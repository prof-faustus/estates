/**
 * @estates/chat — multiparty join + end-to-end-encrypted chat over an untrusted
 * relay. Peers join a table channel by announcing their Bitmessage-style address
 * + public key; messages are broadcast-encrypted to the current member set, so
 * the relay (and non-members) only ever see ciphertext. Fully isomorphic
 * (Node + browser) — the crypto is @noble/* and the relay is fetch/SSE.
 */
import { type Relay, InMemoryRelay, HttpRelay } from './relay.ts';
import {
  genPeer, peerFrom, addressOf, encryptBroadcast, decryptBroadcast, isHex, isEnvelope, type Peer, type Envelope,
} from './broadcast.ts';

export { genPeer, peerFrom, addressOf, encryptBroadcast, decryptBroadcast, isHex, isEnvelope, InMemoryRelay, HttpRelay };
export type { Peer, Envelope, Relay };

type NetMsg =
  | { kind: 'join'; address: string; pub: string; name?: string }
  | { kind: 'leave'; address: string }
  | { kind: 'chat'; from: string; env: Envelope };

export interface ChatMessage { readonly from: string; readonly text: string; }
export interface Member { readonly address: string; readonly pub: Uint8Array; readonly name?: string }

const ADDR_BYTES = 20;       // ripemd160(sha256(pub)) — a Bitmessage-style address
const PUB_BYTES = 33;        // compressed secp256k1 public key
const MAX_NAME = 256;        // display-name ceiling (bounds memory; names are short)
const MAX_MSG_BYTES = 1 << 20; // 1 MiB per wire frame (the relay also caps; defense in depth)

const enc = (m: NetMsg): Uint8Array => new TextEncoder().encode(JSON.stringify(m));

/**
 * Decode ONE inbound relay frame to a NetMsg, or null. FAIL-CLOSED and TOTAL: the
 * bytes are attacker-controlled, so we never `as NetMsg`-cast a parsed blob — we
 * prove `kind` and EVERY field (type, hex-ness, exact length, bounded name) before
 * returning, and reject (null) on anything unexpected. Never throws.
 *
 * WHY: a peer that could smuggle an unvalidated field (a non-string `pub`, a
 * malformed `env`, an oversized `name`) into the receive path could crash the loop,
 * poison the member set, or DoS via allocation. Validation here is the security
 * boundary between the untrusted relay and our state.
 */
function decodeNetMsg(payload: Uint8Array): NetMsg | null {
  if (payload.length > MAX_MSG_BYTES) return null;                  // bound before parse
  let raw: unknown;
  try { raw = JSON.parse(new TextDecoder().decode(payload)); } catch { return null; }
  if (typeof raw !== 'object' || raw === null) return null;
  const m = raw as Record<string, unknown>;
  switch (m.kind) {
    case 'join': {
      if (!isHex(m.address, ADDR_BYTES) || !isHex(m.pub, PUB_BYTES)) return null;
      if (m.name !== undefined && (typeof m.name !== 'string' || m.name.length > MAX_NAME)) return null;
      return m.name !== undefined
        ? { kind: 'join', address: m.address, pub: m.pub, name: m.name }
        : { kind: 'join', address: m.address, pub: m.pub };
    }
    case 'leave':
      return isHex(m.address, ADDR_BYTES) ? { kind: 'leave', address: m.address } : null;
    case 'chat':
      return isHex(m.from, ADDR_BYTES) && isEnvelope(m.env) ? { kind: 'chat', from: m.from, env: m.env } : null;
    default:
      return null;                                                  // unknown kind → reject
  }
}

// ISOMORPHIC hex (NO node:Buffer — this module runs in the browser webview too).
const toHex = (b: Uint8Array): string => { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };
const fromHex = (h: string): Uint8Array => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

/**
 * A chat room on a table channel. The relay is untrusted: it only fans out
 * opaque bytes. Membership is learned from join announcements (with history
 * replay on (re)connect — Bitmessage-style store-and-forward); chat bodies are
 * broadcast-encrypted so only current members can read them.
 */
export class ChatRoom {
  readonly members = new Map<string, Member>();
  readonly me: Peer;
  readonly name: string | undefined;
  private readonly relay: Relay;
  private handlers: ((m: ChatMessage) => void)[] = [];
  private unsub: (() => void) | null = null;

  // NB: explicit fields (no TS parameter properties) — strip-only mode
  // (Node --experimental-strip-types) cannot transform parameter properties.
  constructor(relay: Relay, me: Peer, name?: string) {
    this.relay = relay;
    this.me = me;
    this.name = name;
  }

  /** Subscribe to the channel (replays history, then streams live). */
  connect(): void {
    this.unsub = this.relay.subscribe((p) => this.ingest(p));
  }
  disconnect(): void { this.unsub?.(); this.unsub = null; }

  /** Announce membership (join the channel). */
  join(): void {
    this.members.set(this.me.address, { address: this.me.address, pub: this.me.pub, ...(this.name ? { name: this.name } : {}) });
    const msg: NetMsg = this.name
      ? { kind: 'join', address: this.me.address, pub: toHex(this.me.pub), name: this.name }
      : { kind: 'join', address: this.me.address, pub: toHex(this.me.pub) };
    this.relay.publish(enc(msg));
  }

  /** Leave the channel (announce departure). */
  leave(): void {
    this.relay.publish(enc({ kind: 'leave', address: this.me.address }));
    this.members.delete(this.me.address);
  }

  /** Locally exclude a member from this peer's future broadcasts (revocation). */
  revoke(address: string): void { this.members.delete(address); }

  /** Broadcast-encrypt a message to the whole current member set (Bitmessage-style). */
  post(text: string): void {
    const recipients = [...this.members.values()].map((m) => m.pub);
    if (recipients.length === 0) return;
    const env = encryptBroadcast(recipients, new TextEncoder().encode(text));
    this.relay.publish(enc({ kind: 'chat', from: this.me.address, env }));
  }

  /** 2-party ECDH: encrypt only to one member (+ me, so I see my own copy). */
  postTo(address: string, text: string): void {
    const m = this.members.get(address);
    if (!m) return;
    const env = encryptBroadcast([m.pub, this.me.pub], new TextEncoder().encode(text));
    this.relay.publish(enc({ kind: 'chat', from: this.me.address, env }));
  }

  onMessage(cb: (m: ChatMessage) => void): void { this.handlers.push(cb); }

  /**
   * Handle ONE inbound relay frame. SECURITY BOUNDARY: `payload` is fully untrusted
   * (the relay and peers are hostile). Everything is validated by decodeNetMsg
   * first; this method must never throw (it runs inside the relay receive loop) and
   * must never mutate state on malformed input.
   *
   * Invariants enforced here:
   *  - a `join` is accepted ONLY if address == ripemd160(sha256(pub)) — a peer
   *    cannot claim an address it does not hold the key for.
   *  - a `chat` is delivered ONLY if its AEAD envelope decrypts for us (forged or
   *    tampered ciphertext yields null and is dropped — no forged plaintext).
   */
  private ingest(payload: Uint8Array): void {
    const m = decodeNetMsg(payload);
    if (!m) return;                                      // malformed/hostile → dropped, no mutation
    switch (m.kind) {
      case 'join': {
        const pub = fromHex(m.pub);                       // m.pub is validated 33-byte hex by decodeNetMsg
        if (addressOf(pub) !== m.address) return;         // address MUST bind the pubkey (no spoofed identity)
        this.members.set(m.address, { address: m.address, pub, ...(m.name !== undefined ? { name: m.name } : {}) });
        return;
      }
      case 'leave':
        this.members.delete(m.address);
        return;
      case 'chat': {
        const pt = decryptBroadcast(m.env, this.me);      // total: null if not for us / tampered
        if (pt === null) return;
        const text = new TextDecoder().decode(pt);
        for (const h of this.handlers) h({ from: m.from, text });
        return;
      }
    }
  }
}
