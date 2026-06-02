/**
 * Relay transport for chat — isomorphic. The relay is an UNTRUSTED, opaque
 * fan-out of byte payloads; it never sees plaintext (chat bodies are
 * broadcast-encrypted before they reach it).
 *
 * - InMemoryRelay: single-process (tests / offline).
 * - HttpRelay: connects to a live HTTP + Server-Sent-Events relay (works in
 *   Node 24 and the browser via global fetch). subscribe() replays history
 *   then streams live (Bitmessage-style store-and-forward catch-up).
 */
export interface Relay {
  publish(payload: Uint8Array): void;
  subscribe(onMessage: (p: Uint8Array) => void): () => void;
  history?(): Uint8Array[];
}

export class InMemoryRelay implements Relay {
  private log: Uint8Array[] = [];
  private subs = new Set<(p: Uint8Array) => void>();
  publish(payload: Uint8Array): void {
    this.log.push(payload);
    for (const s of this.subs) s(payload);
  }
  subscribe(onMessage: (p: Uint8Array) => void): () => void {
    for (const m of this.log) onMessage(m);
    this.subs.add(onMessage);
    return () => this.subs.delete(onMessage);
  }
  history(): Uint8Array[] { return [...this.log]; }
}

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };

/** Live relay over HTTP + SSE. Payloads are carried as hex in SSE `data:` lines. */
export class HttpRelay implements Relay {
  readonly base: string;
  readonly channel: string;
  constructor(baseUrl: string, channel: string) {
    this.base = baseUrl.replace(/\/$/, '');
    this.channel = channel;
  }

  publish(payload: Uint8Array): void {
    void fetch(`${this.base}/publish/${this.channel}`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: toHex(payload),
    }).catch(() => { /* untrusted relay: failures are non-fatal, retry by re-publishing */ });
  }

  subscribe(onMessage: (p: Uint8Array) => void): () => void {
    const ctrl = new AbortController();
    void this.stream(onMessage, ctrl.signal);
    return () => ctrl.abort();
  }

  private async stream(onMessage: (p: Uint8Array) => void, signal: AbortSignal): Promise<void> {
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
          if (line.startsWith('data:')) {
            const hex = line.slice(5).trim();
            if (hex) onMessage(fromHex(hex));
          }
        }
      }
    } catch { /* aborted or relay down */ }
  }
}
