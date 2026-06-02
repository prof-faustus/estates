/**
 * @estates/chat — multiparty join + end-to-end-encrypted chat over the untrusted
 * relay (@estates/net). Peers join a table channel by announcing their
 * Bitmessage-style address + public key; messages are broadcast-encrypted to the
 * current member set, so the relay (and non-members) only ever see ciphertext.
 */
import type { Relay } from '@estates/net';
import {
  genPeer, addressOf, encryptBroadcast, decryptBroadcast, type Peer, type Envelope,
} from './broadcast.ts';

export { genPeer, addressOf, encryptBroadcast, decryptBroadcast };
export type { Peer, Envelope };

type NetMsg =
  | { kind: 'join'; address: string; pub: string; name?: string }
  | { kind: 'leave'; address: string }
  | { kind: 'chat'; from: string; env: Envelope };

export interface ChatMessage { readonly from: string; readonly text: string; }
export interface Member { readonly address: string; readonly pub: Uint8Array; readonly name?: string }

const enc = (m: NetMsg): Uint8Array => new TextEncoder().encode(JSON.stringify(m));
const dec = (p: Uint8Array): NetMsg | null => { try { return JSON.parse(new TextDecoder().decode(p)) as NetMsg; } catch { return null; } };
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));
const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

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
    this.unsub = this.relay.subscribe((p) => this.ingest(p), 0);
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

  /** Post a broadcast-encrypted message to the current member set. */
  post(text: string): void {
    const recipients = [...this.members.values()].map((m) => m.pub);
    if (recipients.length === 0) return;
    const env = encryptBroadcast(recipients, new TextEncoder().encode(text));
    this.relay.publish(enc({ kind: 'chat', from: this.me.address, env }));
  }

  onMessage(cb: (m: ChatMessage) => void): void { this.handlers.push(cb); }

  private ingest(payload: Uint8Array): void {
    const m = dec(payload);
    if (!m) return;
    switch (m.kind) {
      case 'join': {
        const pub = fromHex(m.pub);
        if (addressOf(pub) !== m.address) return; // address must bind the pubkey
        this.members.set(m.address, { address: m.address, pub, ...(m.name ? { name: m.name } : {}) });
        return;
      }
      case 'leave':
        this.members.delete(m.address);
        return;
      case 'chat': {
        const pt = decryptBroadcast(m.env, this.me);
        if (pt === null) return; // not a recipient (revoked / before we joined)
        const text = new TextDecoder().decode(pt);
        for (const h of this.handlers) h({ from: m.from, text });
        return;
      }
    }
  }
}
