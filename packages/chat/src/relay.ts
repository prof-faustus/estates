/**
 * In-process transport abstraction for chat AND the game table — NO SERVER.
 *
 * The ONLY transport in this package is `InMemoryRelay`: a single-process, in-memory
 * fan-out used by tests and same-process play. There is no HTTP relay, no
 * store-and-forward server, no `/history` ordering authority — those were a server
 * model and have been deleted. Real cross-machine play is TRUE peer-to-peer over
 * `@estates/link` (direct IP-to-IP TCP sockets, no relay), whose `PeerLink` carries
 * the same signed frames this `Relay` interface describes.
 *
 * Two consumption models (both satisfied in-process by InMemoryRelay; a P2P transport
 * provides the same shape over direct peer sockets):
 * - subscribe(cb): each NEW payload once — for chat, where messages are independent.
 * - subscribeOrdered(cb): the FULL ordered log on every change — for the game's
 *   replicated state machine, which replays one identical total order on every peer.
 */
export interface Relay {
  publish(payload: Uint8Array): void;
  subscribe(onMessage: (p: Uint8Array) => void): () => void;
  /** Full ordered channel log, re-emitted on every change (for total-order replay). */
  subscribeOrdered?(onSnapshot: (ordered: Uint8Array[]) => void): () => void;
  /** Hint to sync now (e.g. just after we published our own action). */
  refresh?(): void;
  history?(): Uint8Array[];
}

export class InMemoryRelay implements Relay {
  private log: Uint8Array[] = [];
  private subs = new Set<(p: Uint8Array) => void>();
  private ordered = new Set<(o: Uint8Array[]) => void>();
  publish(payload: Uint8Array): void {
    this.log.push(payload);
    for (const s of this.subs) s(payload);
    for (const o of this.ordered) o([...this.log]);
  }
  subscribe(onMessage: (p: Uint8Array) => void): () => void {
    for (const m of this.log) onMessage(m);
    this.subs.add(onMessage);
    return () => this.subs.delete(onMessage);
  }
  subscribeOrdered(onSnapshot: (ordered: Uint8Array[]) => void): () => void {
    onSnapshot([...this.log]);
    this.ordered.add(onSnapshot);
    return () => this.ordered.delete(onSnapshot);
  }
  refresh(): void { /* synchronous already */ }
  history(): Uint8Array[] { return [...this.log]; }
}
