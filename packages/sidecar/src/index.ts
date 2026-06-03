/**
 * @estates/sidecar — a playable peer with the audit's security properties:
 *
 *  • Authenticated moves (#1): every move is SIGNED by the moving seat's identity
 *    key; a peer may only move its own seat; a received move is applied ONLY if
 *    its signature verifies against the active seat's registered key.
 *  • Beacon-backed dice (#2): a ROLL's dice are NOT chosen by the mover. Before a
 *    roll, both peers commit (c=H(secret)) then reveal; the dice are the DEBIASED
 *    @estates/beacon map of both revealed secrets (chained via prev_beacon). The
 *    ROLL carries the commit/reveal transcript; the verifier rejects any ROLL
 *    whose dice are not the beacon of secrets that match the prior commitments.
 *  • Bitmessage-style encrypted chat: multi-recipient ECIES over the link.
 *
 * Both peers replay the SAME signed moves through the SAME pure engine with
 * DETERMINISTIC one-use keys, so state and on-chain transcript stay byte-identical.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { PeerLink } from '@estates/link';
import { signData, verifyData, type Identity } from '@estates/channel';
import { encryptBroadcast, decryptBroadcast, addressOf, type Peer, type Envelope } from '@estates/chat';
import { commit as beaconCommit, verifyReveal, roll as beaconRoll, ZERO_BEACON, type PartyReveal } from '@estates/beacon';
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
const eqBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]!);

export function detPkh(tableId: Uint8Array, turnIndex: number, role: number): Uint8Array {
  return new Uint8Array(createHash('sha256').update(tableId).update(new Uint8Array([turnIndex & 0xff, (turnIndex >> 8) & 0xff, role & 0xff])).digest()).slice(0, 20);
}

/** Non-dice policy (the ROLL is produced by the beacon, not chosen). */
export function policy(s: GameState): Action {
  switch (s.phase) {
    case 'AWAIT_BUY': return s.seats[s.current]!.balance > 600 ? { type: 'BUY' } : { type: 'DECLINE' };
    case 'AWAIT_TAX': return { type: 'PAY_TAX', choice: 'flat' };
    default: return { type: 'END_TURN' };
  }
}

interface BeaconTranscript { cm: string; cp: string; sm: string; sp: string; seatM: number; seatP: number }
interface BeaconRound { turn: number; mySecret?: Uint8Array; myCommit?: Uint8Array; peerCommit?: Uint8Array; peerSecret?: Uint8Array; revealed?: boolean }

export class GamePeer {
  state: GameState;
  readonly seat: number;
  readonly address: string;
  private id: Identity;
  private peerSeat: number;
  private seatKeys: Map<number, Uint8Array>;
  private ctx: MapContext;
  private link: PeerLink;
  private chain: MoveChain;
  private prevBeacon: Uint8Array = ZERO_BEACON;
  private round: BeaconRound | null = null;
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

  private movePayload(turnIndex: number, actor: number, action: Action): Uint8Array {
    return enc({ k: 'estates-move-v1', g: toHex(this.ctx.gameId), turnIndex, actor, action });
  }

  /** Take this peer's turn: a ROLL starts the beacon; everything else is a signed move. */
  takeTurn(): void {
    if (!this.myTurn()) return;
    if (this.state.phase === 'AWAIT_ROLL') this.beaconStart();
    else this.submit(policy(this.state));
  }

  /** Submit a NON-roll signed move. */
  submit(action: Action): void {
    if (action.type === 'ROLL') return; // rolls go through the beacon, never here
    const pre = this.state;
    if (pre.current !== this.seat) return;
    const r = apply(pre, action); if (!r.ok) return;
    const post = r.state;
    const sig = signData(this.movePayload(post.turnIndex, pre.current, action), this.id.priv);
    this.chainMove(pre, post, action, pre.current);
    this.state = post;
    this.link.send(enc({ t: 'move', action, sig: toHex(sig) }));
    this.onUpdate?.();
  }

  // ---- beacon-backed dice (#2): commit → reveal → derive ----
  private beaconStart(): void {
    const turn = this.state.turnIndex;
    const mySecret = new Uint8Array(randomBytes(32));
    this.round = { turn, mySecret, myCommit: beaconCommit(mySecret) };
    this.link.send(enc({ t: 'bc', turn, c: toHex(this.round.myCommit!) }));
    this.maybeReveal();
  }
  private onCommit(turn: number, cHex: string): void {
    if (!this.round || this.round.turn !== turn) this.round = { turn };
    const r = this.round;
    try { r.peerCommit = fromHexStrict(cHex); } catch { return; }
    if (!r.myCommit) { const s = new Uint8Array(randomBytes(32)); r.mySecret = s; r.myCommit = beaconCommit(s); this.link.send(enc({ t: 'bc', turn, c: toHex(r.myCommit) })); }
    this.maybeReveal();
  }
  private maybeReveal(): void {
    const r = this.round;
    if (!r || r.revealed || !r.myCommit || !r.peerCommit || !r.mySecret) return;
    r.revealed = true;
    this.link.send(enc({ t: 'br', turn: r.turn, s: toHex(r.mySecret) }));
  }
  private onReveal(turn: number, sHex: string): void {
    const r = this.round; if (!r || r.turn !== turn || !r.peerCommit) return;
    let sec: Uint8Array; try { sec = fromHexStrict(sHex); } catch { return; }
    if (!verifyReveal(sec, r.peerCommit)) return;          // reveal must match the prior commitment
    r.peerSecret = sec;
    this.maybeFinalize();
  }
  private maybeFinalize(): void {
    const r = this.round;
    if (!r || this.state.current !== this.seat || this.state.phase !== 'AWAIT_ROLL') return; // only the mover finalizes
    if (!r.mySecret || !r.peerSecret || !r.myCommit || !r.peerCommit) return;
    const reveals: PartyReveal[] = [{ seat: this.seat, secret: r.mySecret }, { seat: this.peerSeat, secret: r.peerSecret }];
    const result = beaconRoll(reveals, this.state.turnIndex, this.prevBeacon);
    const action: Action = { type: 'ROLL', dice: result.dice };
    const transcript: BeaconTranscript = { cm: toHex(r.myCommit), cp: toHex(r.peerCommit), sm: toHex(r.mySecret), sp: toHex(r.peerSecret), seatM: this.seat, seatP: this.peerSeat };
    const pre = this.state;
    const ar = apply(pre, action); if (!ar.ok) { this.round = null; return; }
    const post = ar.state;
    const sig = signData(this.movePayload(post.turnIndex, pre.current, action), this.id.priv);
    this.chainMove(pre, post, action, pre.current);
    this.prevBeacon = result.beacon;
    this.state = post;
    this.round = null;
    this.link.send(enc({ t: 'move', action, sig: toHex(sig), beacon: transcript }));
    this.onUpdate?.();
  }

  /** Verify a peer's ROLL: dice MUST be the beacon of secrets matching the prior
   *  commitments (no mover-chosen dice). Returns the beacon result or null. */
  private verifyRollBeacon(pre: GameState, dice: readonly [number, number], b: BeaconTranscript): Uint8Array | null {
    if (!b || b.seatM !== this.peerSeat || b.seatP !== this.seat) return null; // mover must be the peer; us the other
    let cm: Uint8Array, cp: Uint8Array, sm: Uint8Array, sp: Uint8Array;
    try { cm = fromHexStrict(b.cm); cp = fromHexStrict(b.cp); sm = fromHexStrict(b.sm); sp = fromHexStrict(b.sp); } catch { return null; }
    // commit-before-reveal binding: the commitments we stored must match the transcript
    if (this.round && this.round.peerCommit && !eqBytes(this.round.peerCommit, cm)) return null;
    if (this.round && this.round.myCommit && !eqBytes(this.round.myCommit, cp)) return null;
    if (!verifyReveal(sm, cm) || !verifyReveal(sp, cp)) return null; // reveals must open their commitments
    const result = beaconRoll([{ seat: b.seatM, secret: sm }, { seat: b.seatP, secret: sp }], pre.turnIndex, this.prevBeacon);
    if (result.dice[0] !== dice[0] || result.dice[1] !== dice[1]) return null; // dice not beacon-derived → forged
    return result.beacon;
  }

  private recv(m: Uint8Array): void {
    const o = dec(m);
    if (!o) return;
    if (o.t === 'bc' && typeof o.turn === 'number' && typeof o.c === 'string') { this.onCommit(o.turn, o.c); return; }
    if (o.t === 'br' && typeof o.turn === 'number' && typeof o.s === 'string') { this.onReveal(o.turn, o.s); return; }
    if (o.t === 'move' && o.action && typeof o.sig === 'string') {
      const pre = this.state;
      const actor = pre.current;
      if (actor !== this.peerSeat) return;
      const r = apply(pre, o.action); if (!r.ok) return;
      const post = r.state;
      const key = this.seatKeys.get(actor);
      let sig: Uint8Array; try { sig = fromHexStrict(o.sig); } catch { return; }
      if (!key || !verifyData(this.movePayload(post.turnIndex, actor, o.action), sig, key)) return; // unsigned/forged
      if (o.action.type === 'ROLL') {
        const beacon = this.verifyRollBeacon(pre, o.action.dice, o.beacon as BeaconTranscript);
        if (!beacon) return;                       // dice not beacon-derived → REJECT
        this.prevBeacon = beacon;
        this.round = null;
      }
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

  chat(text: string): void { this.link.send(enc({ t: 'chat', env: encryptBroadcast([this.link.peerIdPub], te(text)) })); }
  onChat(cb: (text: string, from: string) => void): void { this.chatHandlers.push(cb); }
  transcript(): string[] { return this.chain.transcript(); }
}
