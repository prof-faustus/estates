// ESTATES local launcher for TESTING — starts everything the web app needs:
//   1) the relay (HTTP+SSE fan-out) on 127.0.0.1:8788  (the app's DEFAULT_RELAY)
//   2) a static server for the production bundle        (open this in your browser)
// Two browser tabs = two players: each generates its own wallet/identity and joins
// the same table over the relay. No accounts, no URLs to share — just localhost.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const ROOT = resolve('apps/client-web/dist-app');
const WEB_PORT = 8080;
const RELAY_PORT = 8788;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };

if (!existsSync(join(ROOT, 'index.html'))) {
  console.error('No build found. Run:  pnpm --filter @estates/client-web build');
  process.exit(1);
}

// 1) relay — but only if one isn't already listening (re-runs must not crash).
const relayUp = () => new Promise((res) => {
  const r = createServer(); // probe by trying to bind; if EADDRINUSE, a relay is up
  r.once('error', () => res(true));
  r.once('listening', () => r.close(() => res(false)));
  r.listen(RELAY_PORT, '127.0.0.1');
});
let relay = null;
if (await relayUp()) {
  console.log(`  relay already running on ${RELAY_PORT} — reusing it.`);
} else {
  relay = spawn(process.execPath, ['--experimental-strip-types', 'packages/chat/src/serve.ts', String(RELAY_PORT)],
    { stdio: 'inherit', env: { ...process.env, NODE_OPTIONS: '--use-system-ca' } });
  relay.on('error', (e) => console.error('relay failed to start:', e));
}

// 2) static server for the built SPA
const web = createServer(async (req, res) => {
  let p = decodeURIComponent((req.url || '/').split('?')[0]);
  if (p === '/' || !extname(p)) p = '/index.html';      // SPA fallback
  const file = join(ROOT, p);
  if (!file.startsWith(ROOT) || !existsSync(file)) { res.writeHead(404).end('not found'); return; }
  res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
  res.end(await readFile(file));
});
web.listen(WEB_PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  ===========================================================');
  console.log('   ESTATES is live for testing');
  console.log('  ===========================================================');
  console.log(`   WEB APP :  http://127.0.0.1:${WEB_PORT}`);
  console.log(`   relay   :  http://127.0.0.1:${RELAY_PORT}  (started automatically)`);
  console.log('');
  console.log('   Open the WEB APP url in your browser. To test multiplayer,');
  console.log('   open it in TWO tabs/windows: create a table in one, Join from');
  console.log('   the other. Each tab is a separate player with its own wallet.');
  console.log('  ===========================================================');
  console.log('');
});

process.on('SIGINT', () => { try { relay?.kill(); } catch {} web.close(); process.exit(0); });
process.on('SIGTERM', () => { try { relay?.kill(); } catch {} web.close(); process.exit(0); });
