/**
 * @estates/table — the multiplayer table controller.
 *
 * Waiting room first. The human host picks the player count + network, then
 * WAITS for real people to claim seats or OPTIONALLY adds a simulated player
 * (test only) to fill a seat. THE GAME STARTS ONLY WHEN THE HUMAN HOST CALLS
 * start() — never automatically, never by a bot. After start, every action is
 * broadcast and applied by ALL peers in the relay's global order, so the pure
 * engine keeps every client in lockstep. Bots only auto-play their OWN seat and
 * never start a game.
 */
import { initialState, apply, netWorth, type GameState, type Action, type EngineConfig } from '@estates/engine';
import { loadParams } from '@estates/params';
import { HttpRelay, InMemoryRelay, type Relay } from '@estates/chat';
import { genIdentity, identityFrom, signData, verifyData, type Identity } from '@estates/channel';
import { commit as beaconCommit, verifyRollEntry, ZERO_BEACON } from '@estates/beacon';

export const P = loadParams();
export { identityFrom, type Identity };

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
function fromHex(h: string): Uint8Array {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}
const encJSON = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
/** The canonical bytes a message signature commits to (the message + the author). */
const signedBytes = (m: Msg, signPub: string): Uint8Array => encJSON({ ...m, signPub });
export type NetworkMode = EngineConfig['network'];

export function rollDice(): [number, number] {
  const b = new Uint8Array(2);
  crypto.getRandomValues(b);
  return [1 + (b[0]! % 6), 1 + (b[1]! % 6)];
}
/** Built-in transport — NO url is ever typed by a user (Bitmessage-style). */
export const DEFAULT_RELAY = 'http://127.0.0.1:8788';
export const LOBBY_CHANNEL = 'estates-lobby-v1';
export function makeRelay(channel: string, url: string = DEFAULT_RELAY): Relay {
  return new HttpRelay(url, channel);
}

/** A Bitmessage-style address (hex) for an identity or a table. */
export function newAddress(): string {
  const b = new Uint8Array(20);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

// --- properties the active seat may build on / mortgage right now ------------
export function buildable(s: GameState, seat: number): number[] {
  const out: number[] = [];
  for (const [name, g] of Object.entries(P.groups)) {
    if (g.build_cost <= 0) continue;
    const ids = g.member_property_ids;
    if (!ids.every((id) => s.titles[id]?.owner === seat)) continue;
    if (ids.some((id) => s.titles[id]!.mortgaged)) continue;
    const min = Math.min(...ids.map((id) => s.titles[id]!.buildLevel));
    for (const id of ids) if (s.titles[id]!.buildLevel === min && min < 5) out.push(id);
  }
  return out;
}
export function mortgageable(s: GameState, seat: number): number[] {
  return P.board.filter((sp) => s.titles[sp.id]?.owner === seat && !s.titles[sp.id]!.mortgaged && s.titles[sp.id]!.buildLevel === 0).map((sp) => sp.id);
}
export function unmortgageable(s: GameState, seat: number): number[] {
  return P.board.filter((sp) => s.titles[sp.id]?.owner === seat && s.titles[sp.id]!.mortgaged).map((sp) => sp.id);
}

/** The most recently drawn Fate/Treasury card text (to show on the table). */
export function lastCard(s: GameState): string | null {
  for (let i = s.log.length - 1; i >= 0; i--) {
    const m = s.log[i]!.match(/draws (Fate|Treasury): (.+)$/);
    if (m) return `${m[1]} — ${m[2]}`;
  }
  return null;
}

// --- Bitmessage-style lobby discovery: hosts announce, clients list ----------
export interface OpenTable { addr: string; name: string; maxSeats: number; network: NetworkMode; host: string; ts: number }
export class LobbyClient {
  readonly tables = new Map<string, OpenTable>();
  private relay: Relay;
  private onUpdate: () => void;
  private id: Identity;
  constructor(relay: Relay, onUpdate: () => void, identity?: Identity) { this.relay = relay; this.onUpdate = onUpdate; this.id = identity ?? genIdentity(); }
  connect(): void {
    this.relay.subscribe((p) => {
      // SECURITY BOUNDARY: `p` is untrusted. decodeAnnounce validates every field
      // fail-closed (total — never throws) before the signature is checked.
      const a = decodeAnnounce(p);
      if (!a) return;
      const { table: t, signPub, sig } = a;
      // SIGNED announcements only (audit #6): the host field MUST be the signer's
      // key, and the signature must verify — no fake hosts / tables / labels.
      if (t.host !== signPub) return;
      let signer: Uint8Array, signature: Uint8Array;
      try { signer = fromHex(signPub); signature = fromHex(sig); } catch { return; }
      if (signer.length !== 32 || !verifyData(encJSON(t), signature, signer)) return;
      this.tables.set(t.addr, t); this.onUpdate();
    });
  }
  /** Announce an open table, SIGNED by the host key (host := the signing pubkey). */
  announce(t: OpenTable): void {
    const signed: OpenTable = { ...t, host: toHex(this.id.signPub) };
    const sig = toHex(signData(encJSON(signed), this.id.signPriv));
    this.relay.publish(encJSON({ kind: 'announce', ...signed, signPub: toHex(this.id.signPub), sig }));
  }
  list(): OpenTable[] { return [...this.tables.values()].sort((a, b) => b.ts - a.ts); }
}

type Msg =
  | { kind: 'table'; maxSeats: number; network: NetworkMode; host: string }
  | { kind: 'seat'; seat: number; who: string; name: string; bot: boolean }
  | { kind: 'start'; by: string; config: EngineConfig; seatMap: { seat: number; who: string }[] }
  | { kind: 'commit'; roll: number; seat: number; c: string }   // beacon commitment for roll #roll (audit #3)
  | { kind: 'reveal'; roll: number; seat: number; s: string }   // beacon reveal
  | { kind: 'action'; action: Action };
/** A published, SIGNED message: the player's Ed25519 signing pub + signature over
 *  the canonical message bind the author to the protocol (audit #1/#2). */
type Signed = Msg & { id: string; signPub: string; sig: string };

// ===========================================================================
// UNTRUSTED-MESSAGE VALIDATORS (fail-closed, total — never throw)
//
// WHY THIS EXISTS:
//   Every relay frame is attacker-controlled. A valid SIGNATURE proves only WHO
//   authored a blob — it does NOT prove the blob is well-formed. A peer can sign a
//   `start` whose `config.seatCount` is 1e9 (→ giant allocation in initialState), a
//   `seat` whose `seat` is non-integer (→ poisoned Map key), or an `action` that is
//   an arbitrary object (→ undefined behaviour in apply). So we validate EVERY field
//   — type, integer range, exact hex length, bounded collections — BEFORE the
//   signature is checked and BEFORE any value reaches the engine. decodeSigned
//   returns null on anything unexpected and never throws.
// ===========================================================================
const NETWORKS = new Set<string>(['regtest', 'testnet', 'mainnet']);
const MAX_SEATS = 8;             // the game supports 2..6 seats; hard cap bounds every seat loop/array
const MAX_NAME = 256;            // display-name ceiling (bounds memory)
const MAX_ROLL_SEQ = 1_000_000;  // far more rolls than any real game; bounds the per-roll maps
const PROP_MAX = 39;             // board spaces 0..39
const ED_PUB_HEX = 64;           // Ed25519 public key = 32 bytes
const ED_SIG_HEX = 128;          // Ed25519 signature = 64 bytes
const SHA256_HEX = 64;           // beacon commitment / secret = 32 bytes
const MAX_MSG_BYTES = 1 << 20;   // 1 MiB per frame (the relay also caps; defense in depth)
const HEX_RE = /^[0-9a-f]*$/i;

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isInt = (x: unknown, lo: number, hi: number): x is number => typeof x === 'number' && Number.isInteger(x) && x >= lo && x <= hi;
const isStr = (x: unknown, max = 4096): x is string => typeof x === 'string' && x.length <= max;
const isHexLen = (x: unknown, hexLen: number): x is string => typeof x === 'string' && x.length === hexLen && HEX_RE.test(x);

/** A game Action from untrusted bytes — exact type + per-type field validation. */
export function isAction(x: unknown): x is Action {
  if (!isObj(x)) return false;
  switch (x.type) {
    case 'BUY': case 'DECLINE': case 'FORFEIT': case 'END_TURN': return true;
    case 'PAY_TAX': return x.choice === 'flat' || x.choice === 'percent';
    case 'BUILD': case 'SELL_BUILD': case 'MORTGAGE': case 'UNMORTGAGE': return isInt(x.propertyId, 0, PROP_MAX);
    case 'LEAVE': return isInt(x.seat, 0, MAX_SEATS - 1);
    case 'ROLL': return Array.isArray(x.dice) && x.dice.length === 2 && isInt(x.dice[0], 1, 6) && isInt(x.dice[1], 1, 6);
    default: return false;
  }
}

/** An EngineConfig from untrusted bytes. seatCount/bankReserve are bounded so a
 *  hostile `start` cannot DoS initialState; deckOrder structure is bounded (the
 *  engine separately re-validates it as a strict permutation). */
export function isEngineConfig(x: unknown): x is EngineConfig {
  if (!isObj(x)) return false;
  if (!NETWORKS.has(x.network as string)) return false;
  if (!isInt(x.seatCount, 2, MAX_SEATS)) return false;
  if (!isInt(x.bankReserve, 0, Number.MAX_SAFE_INTEGER)) return false;
  if (x.deckOrder !== undefined) {
    if (!isObj(x.deckOrder)) return false;
    for (const k of Object.keys(x.deckOrder)) {
      const arr = (x.deckOrder as Record<string, unknown>)[k];
      if (!Array.isArray(arr) || arr.length > 1000 || !arr.every((n) => isInt(n, 0, 1000))) return false;
    }
  }
  if (x.requireFairDecks !== undefined && typeof x.requireFairDecks !== 'boolean') return false;
  return true;
}

/**
 * Decode + FULLY VALIDATE one signed relay frame, or null. Total: never throws.
 * Reconstructs the Msg with fields in the canonical order the sender used, so the
 * subsequent signature check over signedBytes(msg, signPub) is exact.
 */
export function decodeSigned(payload: Uint8Array): { msg: Msg; id: string; signPub: string; sig: string } | null {
  if (payload.length > MAX_MSG_BYTES) return null;
  let raw: unknown;
  try { raw = JSON.parse(new TextDecoder().decode(payload)); } catch { return null; }
  if (!isObj(raw)) return null;
  const o = raw;
  if (!isStr(o.id, 128) || !isHexLen(o.signPub, ED_PUB_HEX) || !isHexLen(o.sig, ED_SIG_HEX)) return null;
  const meta = { id: o.id, signPub: o.signPub, sig: o.sig };
  switch (o.kind) {
    case 'table':
      if (!isInt(o.maxSeats, 2, MAX_SEATS) || !NETWORKS.has(o.network as string) || !isStr(o.host)) return null;
      return { msg: { kind: 'table', maxSeats: o.maxSeats, network: o.network as NetworkMode, host: o.host }, ...meta };
    case 'seat':
      if (!isInt(o.seat, 0, MAX_SEATS - 1) || !isStr(o.who) || !isStr(o.name, MAX_NAME) || typeof o.bot !== 'boolean') return null;
      return { msg: { kind: 'seat', seat: o.seat, who: o.who, name: o.name, bot: o.bot }, ...meta };
    case 'start': {
      if (!isStr(o.by) || !isEngineConfig(o.config) || !Array.isArray(o.seatMap) || o.seatMap.length > MAX_SEATS) return null;
      const seatMap: { seat: number; who: string }[] = [];
      for (const e of o.seatMap) { if (!isObj(e) || !isInt(e.seat, 0, MAX_SEATS - 1) || !isStr(e.who)) return null; seatMap.push({ seat: e.seat, who: e.who }); }
      return { msg: { kind: 'start', by: o.by, config: o.config, seatMap }, ...meta };
    }
    case 'commit':
      if (!isInt(o.roll, 0, MAX_ROLL_SEQ) || !isInt(o.seat, 0, MAX_SEATS - 1) || !isHexLen(o.c, SHA256_HEX)) return null;
      return { msg: { kind: 'commit', roll: o.roll, seat: o.seat, c: o.c }, ...meta };
    case 'reveal':
      if (!isInt(o.roll, 0, MAX_ROLL_SEQ) || !isInt(o.seat, 0, MAX_SEATS - 1) || !isHexLen(o.s, SHA256_HEX)) return null;
      return { msg: { kind: 'reveal', roll: o.roll, seat: o.seat, s: o.s }, ...meta };
    case 'action':
      if (!isAction(o.action)) return null;
      return { msg: { kind: 'action', action: o.action }, ...meta };
    default:
      return null;
  }
}

/** Decode + FULLY VALIDATE a signed lobby `announce` frame, or null. Total: never
 *  throws. Same boundary as decodeSigned — a valid signature does not excuse a
 *  malformed/oversized announcement (e.g. a 1e9 maxSeats or a giant name). */
export function decodeAnnounce(payload: Uint8Array): { table: OpenTable; signPub: string; sig: string } | null {
  if (payload.length > MAX_MSG_BYTES) return null;
  let raw: unknown;
  try { raw = JSON.parse(new TextDecoder().decode(payload)); } catch { return null; }
  if (!isObj(raw) || raw.kind !== 'announce') return null;
  if (!isStr(raw.addr, 128) || !isStr(raw.name, MAX_NAME) || !isInt(raw.maxSeats, 2, MAX_SEATS)
    || !NETWORKS.has(raw.network as string) || !isHexLen(raw.host, ED_PUB_HEX)
    || !isInt(raw.ts, 0, Number.MAX_SAFE_INTEGER) || !isHexLen(raw.signPub, ED_PUB_HEX) || !isHexLen(raw.sig, ED_SIG_HEX)) return null;
  return {
    table: { addr: raw.addr, name: raw.name, maxSeats: raw.maxSeats, network: raw.network as NetworkMode, host: raw.host, ts: raw.ts },
    signPub: raw.signPub, sig: raw.sig,
  };
}

export interface SeatInfo { seat: number; who: string; name: string; bot: boolean }
export interface TableView {
  phase: 'disconnected' | 'lobby' | 'playing';
  maxSeats: number | null;
  network: NetworkMode;
  seats: SeatInfo[];
  freeSeats: number[];
  mySeat: number | null;
  iAmHost: boolean;
  canStart: boolean;
  state: GameState | null;
  myTurn: boolean;
}

export class NetTable {
  private relay: Relay;
  readonly me: string;
  readonly name: string;
  private onUpdate: () => void;

  private maxSeats: number | null = null;
  private network: NetworkMode = 'regtest';
  private host: string | null = null;
  private started = false;
  state: GameState | null = null;
  private seats = new Map<number, { who: string; name: string; bot: boolean }>();
  mySeat: number | null = null;
  private autoPlay: boolean;          // a SIMULATED player: auto-plays ONLY its own seat
  private lastBotKey = '';            // de-dup auto-play so one state fires one action
  private botTimer: ((cb: () => void) => void) | null;
  private id: Identity;               // the PLAYER's key: signs every table message
  private seatKeys = new Map<number, string>(); // seat → signing pub (who controls it)
  private verified = new Set<string>();         // payloads whose signature already verified (amortise rebuild)
  private mySecrets = new Map<number, Uint8Array>(); // per-roll beacon secret (mine), keyed by roll seq
  private myCommitSeqs = new Set<number>();      // roll seqs I've already committed for
  private myRevealSeqs = new Set<number>();      // roll seqs I've already revealed for
  private commitsBySeq = new Map<number, Map<number, Uint8Array>>(); // roll seq → seat → commitment
  private revealsBySeq = new Map<number, Map<number, Uint8Array>>(); // roll seq → seat → secret
  private nextRollSeq = 0;                       // how many rolls have been applied (the next to resolve)

  /**
   * `autoPlay` makes this peer a simulated player that plays ONLY its own seat
   * automatically (it never controls another seat — that would be a cheat). Run
   * such a peer as a separate process/window/daemon; it connects over the relay
   * socket exactly like a remote human. `scheduleBot` lets tests pump it.
   */
  constructor(relay: Relay, name: string, onUpdate: () => void, opts?: { autoPlay?: boolean; scheduleBot?: (cb: () => void) => void; identity?: Identity }) {
    this.relay = relay;
    this.id = opts?.identity ?? genIdentity();      // the player's non-custodial key
    this.me = toHex(this.id.signPub);                // identity = the player's signing pubkey, not a random string
    this.name = name || 'player';
    this.onUpdate = onUpdate;
    this.autoPlay = opts?.autoPlay ?? false;
    this.botTimer = opts?.scheduleBot ?? null;
  }

  private unsub: (() => void) | null = null;

  connect(): void {
    // Drive state by replaying the relay's TOTAL-ORDER log (no optimistic apply,
    // so peers can never diverge). The transport pushes the ordered log live and
    // heals any gap, so every peer converges on one identical state.
    if (this.relay.subscribeOrdered) this.unsub = this.relay.subscribeOrdered((log) => this.rebuild(log));
  }

  /** Stop all relay activity for this table. MUST be called when leaving a table
   *  (e.g. returning to the lobby): otherwise the background SSE + poll loops keep
   *  running and firing onUpdate() forever, and they pile up game-after-game until
   *  the app grinds to a halt. */
  disconnect(): void {
    this.unsub?.();
    this.unsub = null;
  }

  createTable(maxSeats: number, network: NetworkMode = 'regtest'): void {
    this.host = this.me;
    this.send({ kind: 'table', maxSeats, network, host: this.me });
  }
  /** Take a seat. `simulated` marks this peer as a bot to other players (it is a
   *  separate connected peer running in auto-play, NOT controlled from anyone's app). */
  joinSeat(simulated = false): void {
    if (this.mySeat !== null) return;          // already seated — never claim a second seat
    const seat = this.lowestFree();
    if (seat < 0) return;
    this.send({ kind: 'seat', seat, who: this.me, name: this.name, bot: simulated });
  }
  /** HOST + HUMAN ONLY. Binds the final seat map into the signed start. */
  start(): void {
    if (!this.iAmHost() || this.started || this.maxSeats === null) return;
    const seatMap = [...this.seats.entries()].map(([seat, v]) => ({ seat, who: v.who })).sort((a, b) => a.seat - b.seat);
    this.send({ kind: 'start', by: this.me, config: { network: this.network, seatCount: this.maxSeats, bankReserve: P.scalars.salary * 200 }, seatMap });
  }
  submit(action: Action): void {
    if (action.type === 'ROLL') return; // raw dice are NOT accepted in multiplayer — rolls come from the beacon (audit #3)
    if (this.myTurn()) this.send({ kind: 'action', action });
  }

  /** Leave the table mid-game (any time, on or off turn): your money + assets go
   *  to the leading player. Broadcast so every peer applies it. */
  leaveGame(): void {
    if (this.started && this.state && this.mySeat !== null && !this.state.seats[this.mySeat]!.bankrupt) {
      this.send({ kind: 'action', action: { type: 'LEAVE', seat: this.mySeat } });
    }
  }

  iAmHost(): boolean { return this.host === this.me; }
  myTurn(): boolean {
    return !!this.state && this.mySeat !== null && this.state.phase !== 'GAME_OVER' && this.state.current === this.mySeat;
  }
  private lowestFree(): number {
    if (this.maxSeats === null) return -1;
    for (let i = 0; i < this.maxSeats; i++) if (!this.seats.has(i)) return i;
    return -1;
  }

  view(): TableView {
    const free = this.maxSeats === null ? [] : Array.from({ length: this.maxSeats }, (_, i) => i).filter((i) => !this.seats.has(i));
    return {
      phase: this.started ? 'playing' : this.maxSeats === null ? 'disconnected' : 'lobby',
      maxSeats: this.maxSeats, network: this.network,
      seats: [...this.seats.entries()].map(([seat, v]) => ({ seat, ...v })).sort((a, b) => a.seat - b.seat),
      freeSeats: free, mySeat: this.mySeat, iAmHost: this.iAmHost(),
      canStart: this.iAmHost() && !this.started && this.maxSeats !== null && this.seats.size >= 1 && free.length === 0,
      state: this.state, myTurn: this.myTurn(),
    };
  }

  // Publish only — no optimistic local apply. Our action enters the relay's
  // total-order log; the ordered subscription replays it (live, within ms) so
  // our own UI and every peer update from the SAME canonical order.
  private send(m: Msg): void {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const signPub = toHex(this.id.signPub);
    const sig = toHex(signData(signedBytes(m, signPub), this.id.signPriv)); // sign with the player's Ed25519 key
    this.relay.publish(encJSON({ ...m, id, signPub, sig }));
    this.relay.refresh?.();
  }

  /** Recompute ALL state from the ordered log. Pure + deterministic, so every
   *  peer replaying the same log lands on byte-identical state — never diverges. */
  private rebuild(payloads: Uint8Array[]): void {
    let maxSeats: number | null = null;
    let network: NetworkMode = 'regtest';
    let host: string | null = null;             // the host = the signing key that opened the table
    let started = false;
    let state: GameState | null = null;
    const seats = new Map<number, { who: string; name: string; bot: boolean }>();
    const seatKeys = new Map<number, string>();  // seat → controlling signing pub
    const commitsBySeq = new Map<number, Map<number, Uint8Array>>();
    const revealsBySeq = new Map<number, Map<number, Uint8Array>>();
    let rollsApplied = 0;
    let prevBeacon = ZERO_BEACON;
    // resolve as many beacon rolls as are complete (handles doubles: each roll has
    // its own seq + its own commit/reveal set, chained via prev_beacon).
    const tryRoll = (): void => {
      while (started && state && state.phase === 'AWAIT_ROLL') {
        const seq = rollsApplied;
        const live = state.seats.filter((q) => !q.bankrupt).map((q) => q.id);
        const cm = commitsBySeq.get(seq); const rv = revealsBySeq.get(seq);
        if (!cm || !rv || !live.every((x) => cm.has(x) && rv.has(x))) break;
        const v = verifyRollEntry({
          commits: live.map((x) => ({ seat: x, c: cm.get(x)! })),
          reveals: live.map((x) => ({ seat: x, secret: rv.get(x)! })),
          liveSeats: live, turnIndex: state.turnIndex, prevBeacon,
        });
        if (!v.ok) break;
        const r = apply(state, { type: 'ROLL', dice: v.dice! });
        if (!r.ok) break;
        state = r.state; prevBeacon = v.beacon!; rollsApplied++;
      }
    };
    for (const p of payloads) {
      // SECURITY BOUNDARY: `p` is fully untrusted (hostile relay/peer). decodeSigned
      // validates EVERY field fail-closed before anything else; a malformed frame is
      // dropped here and never touches signatures or game state.
      const dec = decodeSigned(p);
      if (!dec) continue;
      const { msg: m, signPub, sig } = dec;
      const raw = new TextDecoder().decode(p);   // cache key (only reached for shape-valid frames)
      // AUTHENTICATE: every message must be signed by its author's key (audit #1).
      // Relay ordering is NOT authentication; an unsigned/forged message is dropped.
      // A VALID SIGNATURE proves authorship, NOT well-formedness — decodeSigned proved
      // the latter. Each unique payload is verified ONCE (cached) so rebuilds stay O(n).
      if (!this.verified.has(raw)) {
        let signer: Uint8Array, signature: Uint8Array;
        try { signer = fromHex(signPub); signature = fromHex(sig); } catch { continue; }
        if (signer.length !== 32 || !verifyData(signedBytes(m, signPub), signature, signer)) continue;
        this.verified.add(raw);
      }
      switch (m.kind) {
        case 'table':
          if (maxSeats === null) { maxSeats = m.maxSeats; network = m.network; host = signPub; }
          break;
        case 'seat':
          // a seat is claimed by the key that SIGNED the claim (no spoofing, audit #2);
          // one key controls at most one seat.
          if (!started && !seats.has(m.seat) && m.who === signPub && ![...seatKeys.values()].includes(signPub)) {
            seats.set(m.seat, { who: signPub, name: m.name, bot: m.bot });
            seatKeys.set(m.seat, signPub);
          }
          break;
        case 'start':
          // host-signed AND the bound seat map must match the claimed seats (audit #2)
          if (!started && signPub === host) {
            const cur = JSON.stringify([...seats.entries()].map(([seat, v]) => ({ seat, who: v.who })).sort((a, b) => a.seat - b.seat));
            const claimed = JSON.stringify([...m.seatMap].sort((a, b) => a.seat - b.seat));
            // initialState can throw on a (validly-signed) config that requires fair
            // decks without a valid permutation — keep rebuild TOTAL: fail closed.
            if (cur === claimed) { try { state = initialState(m.config); started = true; tryRoll(); } catch { state = null; started = false; } }
          }
          break;
        case 'commit':
          if (seatKeys.get(m.seat) === signPub) {                   // signed by that seat's key
            let map = commitsBySeq.get(m.roll); if (!map) { map = new Map(); commitsBySeq.set(m.roll, map); }
            if (!map.has(m.seat)) map.set(m.seat, fromHex(m.c));     // m.c validated 32-byte hex → fromHex cannot throw
          }
          break;
        case 'reveal':
          if (seatKeys.get(m.seat) === signPub) {
            let map = revealsBySeq.get(m.roll); if (!map) { map = new Map(); revealsBySeq.set(m.roll, map); }
            if (!map.has(m.seat)) map.set(m.seat, fromHex(m.s));
          }
          tryRoll();
          break;
        case 'action':
          if (started && state) {
            // LEAVE is signed by the leaving seat; every other action by the ACTIVE seat.
            const owner = m.action.type === 'LEAVE' ? m.action.seat : state.current;
            // apply is pure + total (returns {ok:false}); the try is defense-in-depth.
            if (seatKeys.get(owner) === signPub) { try { const r = apply(state, m.action); if (r.ok) { state = r.state; tryRoll(); } } catch { /* reject */ } }
          }
          break;
      }
    }
    this.commitsBySeq = commitsBySeq;
    this.revealsBySeq = revealsBySeq;
    this.nextRollSeq = rollsApplied;
    this.seatKeys = seatKeys;
    this.maxSeats = maxSeats;
    this.network = network;
    this.host = host;
    this.started = started;
    this.state = state;
    this.seats = seats;
    this.mySeat = [...seats.entries()].find(([, v]) => v.who === this.me)?.[0] ?? null;
    this.onUpdate();
    this.maybeBeacon();
    this.maybeAutoPlay();
  }

  /** Drive this seat's part of the dealerless dice beacon (audit #3): when a roll
   *  is pending, every LIVE seat commits, then (once all have committed) reveals.
   *  rebuild() derives + applies the roll once all reveals are in — no raw dice. */
  private maybeBeacon(): void {
    if (!this.started || !this.state || this.state.phase !== 'AWAIT_ROLL' || this.mySeat === null) return;
    const live = this.state.seats.filter((p) => !p.bankrupt).map((p) => p.id);
    if (!live.includes(this.mySeat)) return;
    const seq = this.nextRollSeq;
    if (!this.myCommitSeqs.has(seq)) {
      const secret = new Uint8Array(32); crypto.getRandomValues(secret);
      this.mySecrets.set(seq, secret); this.myCommitSeqs.add(seq);
      this.send({ kind: 'commit', roll: seq, seat: this.mySeat, c: toHex(beaconCommit(secret)) });
      return;
    }
    const cm = this.commitsBySeq.get(seq) ?? new Map<number, Uint8Array>();
    if (live.every((x) => cm.has(x)) && !this.myRevealSeqs.has(seq)) {
      const secret = this.mySecrets.get(seq);
      if (secret) { this.myRevealSeqs.add(seq); this.send({ kind: 'reveal', roll: seq, seat: this.mySeat, s: toHex(secret) }); }
    }
  }

  /** A simulated player auto-plays ONLY its own seat (never another's). Fires at
   *  most once per distinct state, so a re-render never double-sends an action. */
  private maybeAutoPlay(): void {
    if (!this.autoPlay) return;
    const s = this.state;
    if (!this.started || !s || s.phase === 'GAME_OVER' || !this.myTurn()) return;
    const key = `${s.turnIndex}:${s.phase}:${s.current}`;
    if (key === this.lastBotKey) return;
    this.lastBotKey = key;
    const fire = () => {
      if (this.myTurn() && this.state && `${this.state.turnIndex}:${this.state.phase}:${this.state.current}` === key) {
        this.send({ kind: 'action', action: botAction(this.state) });
      }
    };
    if (this.botTimer) this.botTimer(fire);
    else setTimeout(fire, 30);
  }
}

/** The optional simulated player's move (test-only; used only for bot-filled seats). */
export function botAction(s: GameState): Action {
  switch (s.phase) {
    case 'AWAIT_ROLL': return { type: 'ROLL', dice: rollDice() };
    case 'AWAIT_BUY': {
      const price = P.board[s.pendingTitle!]?.base_price ?? 0;
      return s.seats[s.current]!.balance - price >= 200 ? { type: 'BUY' } : { type: 'DECLINE' };
    }
    case 'AWAIT_TAX': {
      const t = P.taxes['income_levy']!;
      const pct = Math.round(netWorth(s, s.current) * (t.percent_of_worth ?? 0));
      return { type: 'PAY_TAX', choice: pct < t.flat ? 'percent' : 'flat' };
    }
    default: return { type: 'END_TURN' };
  }
}
