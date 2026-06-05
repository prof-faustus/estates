// Headless render proof for the PRODUCTION web bundle.
// Serves apps/client-web/dist-app, drives real headless Chrome at it, and asserts
// that React actually MOUNTED non-empty DOM into #root (the blank-screen TDZ bug
// would leave #root empty). Writes a screenshot + a DOM dump for the human to see.
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

// async Chrome launch — spawnSync would BLOCK this process's event loop, killing
// the in-process HTTP server so Chrome could never load the page. spawn keeps the
// loop free to serve. Resolves with {stdout, stderr} on exit.
const runChrome = (args) => new Promise((res) => {
  const c = spawn(CHROME, args, { windowsHide: true });
  let out = '', err = '';
  c.stdout.on('data', (d) => { out += d; });
  c.stderr.on('data', (d) => { err += d; });
  const t = setTimeout(() => c.kill(), 45000);
  c.on('exit', () => { clearTimeout(t); res({ stdout: out, stderr: err }); });
  c.on('error', (e) => { clearTimeout(t); res({ stdout: out, stderr: String(e) }); });
});

const ROOT = resolve('apps/client-web/dist-app');
const OUT = resolve('tools/render-out');
const PORT = 4319;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

let served = [];
const server = createServer(async (req, res) => {
  try {
    served.push(req.url);
    let p = decodeURIComponent((req.url || '/').split('?')[0]);
    if (p === '/' || !extname(p)) p = '/index.html';            // SPA fallback
    const file = join(ROOT, p);
    if (!file.startsWith(ROOT) || !existsSync(file)) { res.writeHead(404); res.end('not found'); return; }
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
    res.end(body);
  } catch (e) { res.writeHead(500); res.end(String(e)); }
});

const CHROME = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
].find(existsSync);
if (!CHROME) { console.error('FAIL: no Chrome/Edge found'); process.exit(2); }

await mkdir(OUT, { recursive: true });
const winPath = (p) => p.replace(/\//g, '\\'); // Chrome (win binary) needs backslash absolute paths
// A DEDICATED profile dir, so this launch never hands off to the user's already-
// running Chrome (the singleton that silently drops --screenshot/--dump-dom).
const profile = winPath(join(OUT, 'chrome-profile'));
const base = ['--headless', '--disable-gpu', '--no-sandbox', '--no-first-run', '--disable-extensions', `--user-data-dir=${profile}`];

await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
const url = `http://127.0.0.1:${PORT}/`;
console.log(`serving ${ROOT} at ${url} via ${CHROME.split('/').pop()}`);

const shot = join(OUT, 'estates-render.png');
const domFile = join(OUT, 'estates-dom.html');

// classic --headless (not =new): it both writes screenshots and runs JS for
// --dump-dom reliably on this Chrome. --virtual-time-budget lets React mount.
const s1 = await runChrome([...base, '--hide-scrollbars',
  `--virtual-time-budget=8000`, '--window-size=1280,900', `--screenshot=${winPath(shot)}`, url]);
const s2 = await runChrome([...base, `--virtual-time-budget=8000`, '--dump-dom', url]);
if (!existsSync(shot)) console.log('screenshot stderr:', (s1.stderr || '').split('\n').slice(-3).join(' | '));

server.close();

const dom = s2.stdout || '';
await writeFile(domFile, dom);

// assertions: #root must contain real mounted content, not be empty.
const rootMatch = dom.match(/<div id="root">([\s\S]*?)<\/div>\s*<\/body>/i) || dom.match(/<div id="root">([\s\S]*)<\/div>/i);
const inner = rootMatch ? rootMatch[1] : '';
const innerLen = inner.replace(/\s+/g, '').length;
const hasShot = existsSync(shot);
const mentionsEstates = /ESTATES/i.test(dom);

console.log('--- render-check results ---');
console.log('server requests    :', served.join(', ') || '(NONE — Chrome never reached the server)');
console.log('screenshot written :', hasShot, hasShot ? `(${shot})` : '');
console.log('dom dump written   :', existsSync(domFile), `(${domFile})`);
console.log('#root inner length :', innerLen, '(chars, whitespace-stripped)');
console.log('document mentions ESTATES text:', mentionsEstates);
const sample = inner.replace(/\s+/g, ' ').trim().slice(0, 400);
console.log('#root inner sample :', sample || '(EMPTY — blank screen!)');

if (innerLen < 30) { console.error('\nFAIL: #root is empty/near-empty — the app rendered a BLANK SCREEN.'); process.exit(1); }
console.log('\nPASS: production bundle MOUNTED real DOM into #root (not blank).');
