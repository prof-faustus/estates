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

export function startRelayServer(port = 0): Promise<RelayServer> {
  const channels = new Map<string, Channel>();
  const chan = (name: string): Channel => {
    let c = channels.get(name);
    if (!c) { c = { log: [], clients: new Set() }; channels.set(name, c); }
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

    // CORS preflight (so the desktop/browser webview can POST + stream)
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS).end(); return; }

    if (req.method === 'POST' && pub) {
      const c = chan(pub[1]!);
      let body = '';
      req.on('data', (d) => { body += d; });
      req.on('end', () => {
        const hex = body.trim();
        if (hex) {
          c.log.push(hex);
          for (const client of c.clients) client.write(`data: ${hex}\n\n`);
        }
        res.writeHead(204, CORS).end();
      });
      return;
    }

    if (req.method === 'GET' && sub) {
      const c = chan(sub[1]!);
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
