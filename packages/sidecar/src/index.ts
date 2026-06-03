/**
 * @estates/sidecar — a playable peer. It wires the IP-to-IP link (@estates/link)
 * to the deterministic engine and the on-chain move ledger: when it is this
 * peer's turn it submits a move, builds the move's BSV transaction (@estates/txmap
 * + @estates/ledger), extends its on-chain chain, and sends the move to the peer;
 * on receiving a peer's move it applies and chains it identically. Both peers
 * replay the SAME ordered moves through the SAME pure engine with DETERMINISTIC
 * one-use keys, so their state and their on-chain transcript stay byte-identical —
 * no trusted referee. This is the headless heart of the desktop app.
 */
import { createHash } from 'node:crypto';
import type { PeerLink } from '@estates/link';
import { initialState, apply, type GameState, type Action, type EngineConfig } from '@estates/engine';
import { txForAction, type MapContext } from '@estates/txmap';
import { MoveChain } from '@estates/ledger';

/** Deterministic one-use key hash both peers derive identically (table‖turn‖role). */
export function detPkh(tableId: Uint8Array, turnIndex: number, role: number): Uint8Array {
  return new Uint8Array(createHash('sha256').update(tableId).update(new Uint8Array([turnIndex & 0xff, (turnIndex >> 8) & 0xff, role & 0xff])).digest()).slice(0, 20);
}

/** A simple deterministic policy (dice travel inside the action, so both peers
 *  apply the identical move). Real play uses the mental-poker beacon for dice. */
export function policy(s: GameState): Action {
  switch (s.phase) {
    case 'AWAIT_ROLL': return { type: 'ROLL', dice: [1 + (s.turnIndex % 6), 1 + ((s.turnIndex * 3 + s.current) % 6)] as const };
    case 'AWAIT_BUY': return s.seats[s.current]!.balance > 600 ? { type: 'BUY' } : { type: 'DECLINE' };
    case 'AWAIT_TAX': return { type: 'PAY_TAX', choice: 'flat' };
    default: return { type: 'END_TURN' };
  }
}

const enc = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
const dec = (b: Uint8Array): unknown => JSON.parse(new TextDecoder().decode(b));

export class GamePeer {
  state: GameState;
  readonly seat: number;
  private ctx: MapContext;
  private link: PeerLink;
  private chain: MoveChain;
  onUpdate?: () => void;

  constructor(link: PeerLink, seat: number, config: EngineConfig, ctx: MapContext, genesis: { tx: import('@estates/tx').Tx; cursor: { txid: string; vout: number } }) {
    this.link = link; this.seat = seat; this.ctx = ctx;
    this.state = initialState(config);
    this.chain = new MoveChain(genesis);
    link.onMessage((m) => {
      const o = dec(m) as { t?: string; action?: Action };
      if (o && o.t === 'move' && o.action) { this.applyMove(o.action); this.onUpdate?.(); }
    });
  }

  /** Is it this peer's turn to move? */
  myTurn(): boolean { return this.state.phase !== 'GAME_OVER' && this.state.current === this.seat; }

  /** Submit this peer's move: apply locally, chain it, and send it to the peer. */
  submit(action: Action): void {
    if (!this.applyMove(action)) return;
    this.link.send(enc({ t: 'move', action }));
    this.onUpdate?.();
  }

  /** Take this peer's turn automatically (policy). */
  takeTurn(): void { if (this.myTurn()) this.submit(policy(this.state)); }

  private applyMove(action: Action): boolean {
    const pre = this.state;
    const actor = pre.current;
    const r = apply(pre, action);
    if (!r.ok) return false;
    const post = r.state;
    const move = txForAction(pre, post, action, post.turnIndex, actor, this.ctx, (role) => detPkh(this.ctx.gameId, post.turnIndex, role));
    this.chain.append(move);
    this.state = post;
    return true;
  }

  /** The on-chain transcript (ordered txids) this peer has recorded. */
  transcript(): string[] { return this.chain.transcript(); }
}
