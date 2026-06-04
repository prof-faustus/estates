/**
 * Minimal HTTP + Server-Sent-Events relay server for ESTATES (Node-only).
 *
 * The relay is UNTRUSTED: it stores and fans out opaque hex payloads per
 * channel and never interprets them (chat bodies arrive already
 * broadcast-encrypted). `POST /publish/:channel` appends + fans out;
 * `GET /subscribe/:channel` replays history (store-and-forward catch-up) then
 * streams live. Pairs with HttpRelay in ./relay.ts.
 */
import { createServer, type Server, type ServerResponse } from 'node:http';

interface Channel { log: string[]; clients: Set<ServerResponse>; }

export interface RelayServer { url: string; port: number; close: () => Promise<void>; channelCount: () => number; }

/**
 * @param dropRate test-only [0,1): probability a LIVE SSE frame is skipped
 *        (the payload still lands in the log, so the client's history poll heals
 *        it). Lets tests prove sync survives a lossy at-least-once transport.
 */
export function startRelayServer(port = 0, opts?: { dropRate?: number; maxBody?: number; maxLog?: number; maxChannels?: number; token?: string }): Promise<RelayServer> {
  const dropRate = opts?.dropRate ?? 0;
  // DoS bounds (audit #5): treat the relay as hostile even on loopback.
  const MAX_BODY = opts?.maxBody ?? 256 * 1024;       // bytes per published message
  const MAX_LOG = opts?.maxLog ?? 200_000;            // messages retained per channel
  const MAX_CHANNELS = opts?.maxChannels ?? 10_000;   // distinct channels
  // Optional per-relay capability token (audit #5): a high-entropy secret carried
  // in a NON-SIMPLE custom header, so a random local page/process cannot poison a
  // table channel even before message-signature checks. Defense-in-depth, not the
  // sole auth (messages are signed at the protocol layer).
  const TOKEN = opts?.token;
  const channels = new Map<string, Channel>();
  /** Get/create a channel; returns null if a NEW channel would exceed the cap. */
  const chan = (name: string): Channel | null => {
    let c = channels.get(name);
    if (!c) { if (channels.size >= MAX_CHANNELS) return null; c = { log: [], clients: new Set() }; channels.set(name, c); }
    return c;
  };

  const CORS = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': '*',
  } as const;

  const server: Server = createServer((req, res) => {
    const url = req.url ?? '';
    const pub = url.match(/^\/publish\/([\w.-]+)/);
    const sub = url.match(/^\/subscribe\/([\w.-]+)/);
    const hist = url.match(/^\/history\/([\w.-]+)/);

    // CORS preflight (so the desktop/browser webview can POST + stream)
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS).end(); return; }

    // capability token (audit #5): if configured, a non-simple custom header must
    // carry the secret — a random cross-origin page can't even attempt a POST.
    if (TOKEN && req.headers['x-estates-cap'] !== TOKEN) { res.writeHead(401, CORS).end(); return; }
    // the relay binds loopback; reject a mismatched Host (rebinding/confusion).
    const reqHost = (req.headers.host ?? '').split(':')[0];
    if (reqHost && reqHost !== '127.0.0.1' && reqHost !== 'localhost') { res.writeHead(421, CORS).end(); return; }

    // Loopback JSON-RPC PROXY to the player's OWN node (regtest balance/spend).
    // A browser/webview cannot fetch bitcoind directly — bitcoind sends no CORS
    // headers, so the call dies as "Failed to fetch". This Node-side proxy (same
    // loopback origin the webview already reaches) forwards the call to the user's
    // own node and returns the result. Target is restricted to LOOPBACK (no SSRF):
    // it is strictly "the local interface to your own node", nothing else.
    if (req.method === 'POST' && url === '/rpc') {
      let body = ''; let over = false;
      req.on('data', (d) => { if (over) return; body += d; if (body.length > MAX_BODY) { over = true; res.writeHead(413, CORS).end(); req.destroy(); } });
      req.on('end', () => {
        if (over) return;
        let q: { url?: string; user?: string; pass?: string; method?: string; params?: unknown[] };
        try { q = JSON.parse(body); } catch { res.writeHead(400, { 'content-type': 'application/json', ...CORS }).end('{"error":{"message":"bad json"}}'); return; }
        let target: URL;
        try { target = new URL(q.url ?? ''); } catch { res.writeHead(400, { 'content-type': 'application/json', ...CORS }).end('{"error":{"message":"bad rpc url"}}'); return; }
        if (target.hostname !== '127.0.0.1' && target.hostname !== 'localhost') {
          res.writeHead(403, { 'content-type': 'application/json', ...CORS }).end('{"error":{"message":"rpc proxy is loopback-only (your own node)"}}'); return;
        }
        const auth = 'Basic ' + btoa(`${q.user ?? ''}:${q.pass ?? ''}`);
        fetch(target.toString(), {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: auth },
          body: JSON.stringify({ jsonrpc: '1.0', id: 'estates', method: q.method, params: q.params ?? [] }),
        })
          .then(async (r) => { const text = await r.text(); res.writeHead(r.status, { 'content-type': 'application/json', ...CORS }).end(text); })
          .catch((e) => { res.writeHead(502, { 'content-type': 'application/json', ...CORS }).end(JSON.stringify({ error: { message: `node unreachable: ${e instanceof Error ? e.message : String(e)}` } })); });
      });
      return;
    }

    // Full ordered history as newline-separated hex. Clients poll this to HEAL
    // any SSE frame that was dropped in flight (live store-and-forward catch-up),
    // so a single lost packet can never permanently desync a turn-based game.
    if (req.method === 'GET' && hist) {
      const c = chan(hist[1]!);
      if (!c) { res.writeHead(503, CORS).end(); return; }
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-cache', ...CORS });
      res.end(c.log.join('\n'));
      return;
    }

    if (req.method === 'POST' && pub) {
      const ct = (req.headers['content-type'] ?? '').toString();
      if (ct && !ct.startsWith('text/plain')) { res.writeHead(415, CORS).end(); return; } // opaque hex only
      const c = chan(pub[1]!);
      if (!c) { res.writeHead(503, CORS).end(); return; } // channel cap reached
      let body = '';
      let over = false;
      req.on('data', (d) => {
        if (over) return;
        body += d;
        if (body.length > MAX_BODY) { over = true; res.writeHead(413, CORS).end(); req.destroy(); }
      });
      req.on('end', () => {
        if (over) return;
        const hex = body.trim();
        if (hex && c.log.length >= MAX_LOG) { res.writeHead(503, CORS).end(); return; } // channel log full
        if (hex) {
          c.log.push(hex);
          // Always logged; live fan-out may "drop" frames (test-only) — the
          // client's history poll then heals the gap. dropRate 0 = perfect.
          for (const client of c.clients) if (dropRate === 0 || Math.random() >= dropRate) client.write(`data: ${hex}\n\n`);
        }
        res.writeHead(204, CORS).end();
      });
      return;
    }

    if (req.method === 'GET' && sub) {
      const c = chan(sub[1]!);
      if (!c) { res.writeHead(503, CORS).end(); return; }
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', ...CORS });
      for (const hex of c.log) res.write(`data: ${hex}\n\n`); // history catch-up
      c.clients.add(res);
      req.on('close', () => c.clients.delete(res));
      return;
    }

    res.writeHead(404, CORS).end();
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      const p = typeof addr === 'object' && addr ? addr.port : port;
      resolve({
        url: `http://127.0.0.1:${p}`,
        port: p,
        channelCount: () => channels.size,
        close: () => new Promise<void>((r) => {
          for (const c of channels.values()) for (const cl of c.clients) cl.end();
          server.close(() => r());
        }),
      });
    });
  });
}
