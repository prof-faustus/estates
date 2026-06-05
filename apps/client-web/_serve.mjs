import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
const root = './dist-app';
const types = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.json':'application/json' };
createServer(async (req, res) => {
  let p = decodeURIComponent((req.url||'/').split('?')[0]);
  if (p === '/') p = '/index.html';
  try { const buf = await readFile(join(root, normalize(p))); res.writeHead(200, {'content-type': types[extname(p)]||'application/octet-stream'}); res.end(buf); }
  catch { const buf = await readFile(join(root,'index.html')); res.writeHead(200,{'content-type':'text/html'}); res.end(buf); }
}).listen(8099, () => console.log('serving dist-app on 8099'));
