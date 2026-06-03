/**
 * @estates/sidecar — a playable peer. It wires the IP-to-IP link (@estates/link)
 * to the deterministic engine and the on-chain move ledger, with TWO security
 * properties the audit requires:
 *
 *  • Authenticated moves (audit #1): every move is SIGNED by the moving seat's
 *    identity key over (table, turn, actor, action). A peer may only move ITS OWN
 *    seat, and a received move is applied ONLY if its signature verifies against
 *    the active seat's registered key. Relay/transport ordering is never trusted
 *    as authentication.
 *  • Bitmessage-style encrypted chat: peers chat over the link with multi-recipient
 *    ECIES (@estates/chat) addressed to Bitmessage-style addresses; the wire only
 *    ever carries ciphertext.
 *
 * Both peers replay the SAME signed moves through the SAME pure engine with
 * DETERMINISTIC one-use keys, so state and on-chain transcript stay byte-identical.
 */
import { createHash } from 'node:crypto';
import type { PeerLink } from '@estates/link';
import { signData, verifyData, type Identity } from '@estates/channel';
import { encryptBroadcast, decryptBroadcast, addressOf, type Peer, type Envelope } from '@estates/chat';
import { initialState, apply, type GameState, type Action, type EngineConfig } from '@estates/engine';
import { txForAction } from '@estates/txmap';
import { type MapContext } from '@estates/chainmap';
import { MoveChain } from '@estates/ledger';
import type { Tx } from '@estates/tx';

const te = (s: string) => new TextEncoder().encode(s);
const td = (b: Uint8Array) => new TextDecoder().decode(b);
const enc = (o: unknown): Uint8Array => te(JSON.stringify(o));
const dec = (b: Uint8Array): any => { try { return JSON.parse(td(b)); } catch { return null; } };
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
function fromHexStrict(h: string): Uint8Array {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('bad hex');
  const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}

/** Deterministic one-use key hash both peers derive identically (table‖turn‖role). */
export function detPkh(tableId: Uint8Array, turnIndex: number, role: number): Uint8Array {
  return new Uint8Array(createHash('sha256').update(tableId).update(new Uint8Array([turnIndex & 0xff, (turnIndex >> 8) & 0xff, role & 0xff])).digest()).slice(0, 20);
}

/** A simple deterministic policy (dice travel inside the signed action). */
export function policy(s: GameState): Action {
  switch (s.phase) {
    case 'AWAIT_ROLL': return { type: 'ROLL', dice: [1 + (s.turnIndex % 6), 1 + ((s.turnIndex * 3 + s.current) % 6)] as const };
    case 'AWAIT_BUY': return s.seats[s.current]!.balance > 600 ? { type: 'BUY' } : { type: 'DECLINE' };
    case 'AWAIT_TAX': return { type: 'PAY_TAX', choice: 'flat' };
    default: return { type: 'END_TURN' };
  }
}

export class GamePeer {
  state: GameState;
  readonly seat: number;
  readonly address: string;                 // Bitmessage-style address
  private id: Identity;
  private peerSeat: number;
  private seatKeys: Map<number, Uint8Array>; // seat → identity pubkey (move authentication)
  private ctx: MapContext;
  private link: PeerLink;
  private chain: MoveChain;
  private chatHandlers: ((text: string, from: string) => void)[] = [];
  onUpdate?: () => void;

  constructor(link: PeerLink, id: Identity, seat: number, peerSeat: number, config: EngineConfig, ctx: MapContext, genesis: { tx: Tx; cursor: { txid: string; vout: number } }) {
    this.link = link; this.id = id; this.seat = seat; this.peerSeat = peerSeat; this.ctx = ctx;
    this.address = addressOf(id.pub);
    this.seatKeys = new Map([[seat, id.pub], [peerSeat, link.peerIdPub]]);
    this.state = initialState(config);
    this.chain = new MoveChain(genesis);
    link.onMessage((m) => this.recv(m));
  }

  myTurn(): boolean { return this.state.phase !== 'GAME_OVER' && this.state.current === this.seat; }

  /** Canonical bytes a move signature commits to. */
  private movePayload(turnIndex: number, actor: number, action: Action): Uint8Array {
    return enc({ k: 'estates-move-v1', g: toHex(this.ctx.gameId), turnIndex, actor, action });
  }

  /** Submit OUR move: sign it, apply locally, chain it, and send it to the peer. */
  submit(action: Action): void {
    const pre = this.state;
    if (pre.current !== this.seat) return;          // only ever move our own seat
    const r = apply(pre, action); if (!r.ok) return;
    const post = r.state;
    const sig = signData(this.movePayload(post.turnIndex, pre.current, action), this.id.priv);
    this.chainMove(pre, post, action, pre.current);
    this.state = post;
    this.link.send(enc({ t: 'move', action, sig: toHex(sig) }));
    this.onUpdate?.();
  }

  takeTurn(): void { if (this.myTurn()) this.submit(policy(this.state)); }

  private recv(m: Uint8Array): void {
    const o = dec(m);
    if (!o) return;
    if (o.t === 'move' && o.action && typeof o.sig === 'string') {
      const pre = this.state;
      const actor = pre.current;
      if (actor !== this.peerSeat) return;          // a peer may ONLY move its own seat
      const r = apply(pre, o.action); if (!r.ok) return;
      const post = r.state;
      const key = this.seatKeys.get(actor);
      let sig: Uint8Array;
      try { sig = fromHexStrict(o.sig); } catch { return; }
      if (!key || !verifyData(this.movePayload(post.turnIndex, actor, o.action), sig, key)) return; // forged/unsigned → rejected
      this.chainMove(pre, post, o.action, actor);
      this.state = post;
      this.onUpdate?.();
    } else if (o.t === 'chat' && o.env) {
      const me: Peer = { priv: this.id.priv, pub: this.id.pub, address: this.address };
      const pt = decryptBroadcast(o.env as Envelope, me);
      if (pt) for (const h of this.chatHandlers) h(td(pt), addressOf(this.link.peerIdPub));
    }
  }

  private chainMove(pre: GameState, post: GameState, action: Action, actor: number): void {
    const move = txForAction(pre, post, action, post.turnIndex, actor, this.ctx, (role) => detPkh(this.ctx.gameId, post.turnIndex, role));
    this.chain.append(move);
  }

  // ---- Bitmessage-style encrypted chat ----
  /** Send an encrypted chat message to the peer (ciphertext only on the wire). */
  chat(text: string): void {
    const env = encryptBroadcast([this.link.peerIdPub], te(text));
    this.link.send(enc({ t: 'chat', env }));
  }
  onChat(cb: (text: string, from: string) => void): void { this.chatHandlers.push(cb); }

  transcript(): string[] { return this.chain.transcript(); }
}
