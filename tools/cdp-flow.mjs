// End-to-end UI proof via the Chrome DevTools Protocol with NO third-party deps
// (a minimal raw-WebSocket client). Serves the production bundle, opens it in real
// headless Chrome, captures every console message + uncaught exception, then
// EXERCISES the app: fills the name, clicks "Enter the lobby", and verifies the
// lobby screen actually appears. Screenshots each step for the human to see.
import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { connect as netConnect } from 'node:net';
import { randomBytes, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { extname, join, resolve } from 'node:path';

const ROOT = resolve('apps/client-web/dist-app');
const OUT = resolve('tools/render-out');
const PORT = 4321, DBG = 9333;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const CHROME = ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
const winPath = (p) => p.replace(/\//g, '\\');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await mkdir(OUT, { recursive: true });
let served = [];
const server = createServer(async (req, res) => {
  served.push(req.url);
  let p = decodeURIComponent((req.url || '/').split('?')[0]);
  if (p === '/' || !extname(p)) p = '/index.html';
  const file = join(ROOT, p);
  if (!file.startsWith(ROOT) || !existsSync(file)) { res.writeHead(404); res.end('nf'); return; }
  res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
  res.end(await readFile(file));
});
await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
const url = `http://127.0.0.1:${PORT}/`;

// --- launch Chrome with a remote-debugging port + isolated profile ----------
const chrome = spawn(CHROME, ['--headless', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--user-data-dir=${winPath(join(OUT, 'cdp-profile'))}`, `--remote-debugging-port=${DBG}`,
  '--window-size=1280,900', 'about:blank'], { windowsHide: true });
chrome.on('error', (e) => { console.error('chrome spawn error', e); });

const getJSON = (path) => new Promise((res, rej) => {
  const tryOnce = (n) => {
    const r = httpRequest({ host: '127.0.0.1', port: DBG, path }, (resp) => {
      let d = ''; resp.on('data', (c) => d += c); resp.on('end', () => { try { res(JSON.parse(d)); } catch (e) { rej(e); } });
    });
    r.on('error', (e) => { if (n > 0) setTimeout(() => tryOnce(n - 1), 300); else rej(e); });
    r.end();
  };
  tryOnce(40);
});

// --- minimal raw WebSocket client (RFC-6455, client→server masked) -----------
function wsConnect(wsUrl) {
  const u = new URL(wsUrl);
  return new Promise((res, rej) => {
    const sock = netConnect(Number(u.port), u.hostname, () => {
      const key = randomBytes(16).toString('base64');
      sock.write(`GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    let buf = Buffer.alloc(0); let open = false; const handlers = [];
    const api = {
      onMessage: (cb) => handlers.push(cb),
      send: (obj) => {
        const data = Buffer.from(JSON.stringify(obj));
        const mask = randomBytes(4);
        const masked = Buffer.alloc(data.length);
        for (let i = 0; i < data.length; i++) masked[i] = data[i] ^ mask[i & 3];
        let header;
        if (data.length < 126) header = Buffer.from([0x81, 0x80 | data.length]);
        else { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(data.length, 2); }
        sock.write(Buffer.concat([header, mask, masked]));
      },
      close: () => sock.destroy(),
    };
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!open) {
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        buf = buf.subarray(idx + 4); open = true; res(api);
      }
      for (;;) {
        if (buf.length < 2) return;
        const len0 = buf[1] & 0x7f; let off = 2, len = len0;
        if (len0 === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
        else if (len0 === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
        if (buf.length < off + len) return;
        const payload = buf.subarray(off, off + len); buf = buf.subarray(off + len);
        try { for (const h of handlers) h(JSON.parse(payload.toString())); } catch { /* non-JSON frame */ }
      }
    });
    sock.on('error', rej);
  });
}

const ver = await getJSON('/json/version');
let targets = await getJSON('/json');
let page = targets.find((t) => t.type === 'page');
const ws = await wsConnect(page.webSocketDebuggerUrl);

let id = 0; const pending = new Map(); const consoleMsgs = []; const exceptions = [];
ws.onMessage((m) => {
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  if (m.method === 'Runtime.consoleAPICalled') consoleMsgs.push(`${m.params.type}: ${(m.params.args || []).map((a) => a.value ?? a.description ?? '').join(' ')}`);
  if (m.method === 'Runtime.exceptionThrown') exceptions.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') consoleMsgs.push(`log.error: ${m.params.entry.text}`);
});
const cmd = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send({ id: i, method, params }); });
const evaluate = async (expr) => (await cmd('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
const shoot = async (name) => { const r = await cmd('Page.captureScreenshot', { format: 'png' }); if (r.result?.data) await writeFile(join(OUT, name), Buffer.from(r.result.data, 'base64')); };

await cmd('Page.enable'); await cmd('Runtime.enable'); await cmd('Log.enable');
await cmd('Page.navigate', { url });
await sleep(2500); // let the SPA mount + relay-status settle

const step = {};
step.landingHasEnter = await evaluate(`!!Array.from(document.querySelectorAll('button')).find(b=>/lobby/i.test(b.textContent))`);
step.heading = await evaluate(`document.querySelector('h1') && document.querySelector('h1').textContent`);
await shoot('flow-1-landing.png');

// fill the name + click "Enter the lobby"
await evaluate(`(()=>{const n=document.querySelector('input'); if(n){const set=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set; set.call(n,'redteam'); n.dispatchEvent(new Event('input',{bubbles:true}));}})()`);
await evaluate(`(()=>{const b=Array.from(document.querySelectorAll('button')).find(b=>/lobby/i.test(b.textContent)); if(b) b.click();})()`);
await sleep(2000);
step.afterEnterText = await evaluate(`document.body.innerText.replace(/\\s+/g,' ').slice(0,500)`);
step.leftLanding = await evaluate(`!Array.from(document.querySelectorAll('button')).some(b=>/^Enter the lobby$/i.test(b.textContent.trim()))`);
step.rootChars = await evaluate(`(document.getElementById('root')||{innerHTML:''}).innerHTML.replace(/\\s+/g,'').length`);
await shoot('flow-2-after-enter.png');

ws.close(); chrome.kill(); server.close();

console.log('=== ESTATES web app — live CDP flow ===');
console.log('browser            :', ver['Product']);
console.log('server requests    :', served.join(', '));
console.log('h1 heading         :', JSON.stringify(step.heading));
console.log('landing has Enter  :', step.landingHasEnter);
console.log('left landing after click:', step.leftLanding);
console.log('#root chars (post) :', step.rootChars);
console.log('screen after enter :', JSON.stringify(step.afterEnterText));
console.log('console errors     :', consoleMsgs.filter((m) => /error/i.test(m)).join(' || ') || '(none)');
console.log('uncaught exceptions:', exceptions.join(' || ') || '(NONE)');
console.log('screenshots        :', 'flow-1-landing.png, flow-2-after-enter.png');

const ok = step.landingHasEnter && step.leftLanding && exceptions.length === 0 && (step.rootChars > 100);
console.log(ok ? '\nPASS: app mounted, has NO uncaught exceptions, and NAVIGATED past the landing on a real click.'
               : '\nFAIL: see above.');
process.exit(ok ? 0 : 1);
