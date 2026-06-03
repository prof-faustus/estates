/**
 * Relay transport for chat AND the game table — isomorphic. The relay is an
 * UNTRUSTED, opaque, append-only fan-out of byte payloads per channel; it never
 * sees plaintext (chat bodies are broadcast-encrypted before they reach it).
 *
 * - InMemoryRelay: single-process (tests / offline).
 * - HttpRelay: a live HTTP relay (Node 24 + browser via global fetch). It is
 *   STORE-AND-FORWARD: every payload is appended to a per-channel log. Clients
 *   sync by POLLing /history (plain fetch — the one transport a desktop WebView2
 *   reliably supports) and de-dup, so a dropped live frame self-heals.
 *
 * Two consumption models:
 * - subscribe(cb): each NEW payload once (order best-effort) — for chat, where
 *   messages are independent.
 * - subscribeOrdered(cb): the FULL ordered log on every change — for the game's
 *   replicated state machine, which must replay one identical total order on
 *   every peer (no optimistic apply, so peers can never diverge).
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

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array => { if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex'); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

/** Live relay over plain HTTP. Payloads carried as hex; sync is by polling. */
export class HttpRelay implements Relay {
  readonly base: string;
  readonly channel: string;
  private pollMs: number;
  private pokers: (() => void)[] = [];
  constructor(baseUrl: string, channel: string, opts?: { pollMs?: number }) {
    this.base = baseUrl.replace(/\/$/, '');
    this.channel = channel;
    this.pollMs = opts?.pollMs ?? 70;   // ≤100ms cross-window sync; own actions reflect instantly via the publish poke
  }

  publish(payload: Uint8Array): void {
    void fetch(`${this.base}/publish/${this.channel}`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: toHex(payload),
    }).then(() => this.refresh()).catch(() => { /* untrusted relay: failures are non-fatal */ });
  }

  /** Wake any pending poll so our own just-published action reflects fast. */
  refresh(): void { const ps = this.pokers; this.pokers = []; for (const p of ps) p(); }
  private nap(ms: number): Promise<void> {
    return new Promise((res) => {
      const t = setTimeout(() => res(), ms);
      (t as { unref?: () => void }).unref?.(); // a background poll must not keep the process alive
      this.pokers.push(() => { clearTimeout(t); res(); });
    });
  }

  // --- per-message (chat): SSE + history poll, de-duped by payload ---
  subscribe(onMessage: (p: Uint8Array) => void): () => void {
    const ctrl = new AbortController();
    const seen = new Set<string>();
    const deliver = (hex: string): void => { if (hex && !seen.has(hex)) { seen.add(hex); onMessage(fromHex(hex)); } };
    void this.stream(deliver, ctrl.signal);
    void this.pollLoop((hexes) => { for (const h of hexes) deliver(h); }, ctrl.signal);
    return () => ctrl.abort();
  }

  // --- ordered (game): the FULL ordered log from /history is the SINGLE source
  // of total order (audit #4). The server's append order is authoritative; we
  // NEVER append live frames into the local order (that could reorder after a
  // dropped frame). The SSE stream only POKES an immediate re-poll, so updates
  // are near-instant while the order is always exactly the server's. We re-emit
  // the full ordered snapshot whenever the log grows.
  subscribeOrdered(onSnapshot: (ordered: Uint8Array[]) => void): () => void {
    const ctrl = new AbortController();
    let lastLen = -1;
    void this.streamForever(() => this.refresh(), ctrl.signal); // SSE = a poke to re-poll now
    void this.pollLoop((hexes) => {
      if (hexes.length !== lastLen) { lastLen = hexes.length; onSnapshot(hexes.map(fromHex)); }
    }, ctrl.signal);
    return () => ctrl.abort();
  }

  /** Keep a live SSE connection open; auto-reconnect if it drops (keep-alive). */
  private async streamForever(onHex: (hex: string) => void, signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      await this.stream(onHex, signal);
      if (signal.aborted) break;
      await this.nap(300); // brief backoff, then reconnect — the poll covers the gap
    }
  }

  private async pollLoop(onHexes: (hexes: string[]) => void, signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      try {
        const res = await fetch(`${this.base}/history/${this.channel}`, { signal });
        const text = (await res.text()).trim();
        onHexes(text ? text.split('\n').map((l) => l.trim()).filter(Boolean) : []);
      } catch { /* relay down/aborted: retry next tick */ }
      await this.nap(this.pollMs);
    }
  }

  private async stream(onHex: (hex: string) => void, signal: AbortSignal): Promise<void> {
    try {
      const res = await fetch(`${this.base}/subscribe/${this.channel}`, { signal, headers: { accept: 'text/event-stream' } });
      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (line.startsWith('data:')) onHex(line.slice(5).trim());
        }
      }
    } catch { /* aborted or relay down */ }
  }
}
