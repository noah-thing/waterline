// Local dev server: serves public/ and the same /api/scan handler Vercel runs.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import handler from './api/scan.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
for (const line of (fs.existsSync(path.join(root, '.env')) ? fs.readFileSync(path.join(root, '.env'), 'utf8') : '').split('\n')) {
  const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim()); if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
}
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.jpg': 'image/jpeg', '.png': 'image/png', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon' };
const port = Number(process.env.PORT || 4321);
http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/api/scan') return handler(req, res);
  const base = u.pathname.startsWith('/testbed/') ? root : path.join(root, 'public');
  let p = path.normalize(path.join(base, decodeURIComponent(u.pathname)));
  if (!p.startsWith(base)) { res.statusCode = 403; return res.end(); }
  if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, 'index.html');
  if (!fs.existsSync(p)) { res.statusCode = 404; return res.end('not found'); }
  res.setHeader('content-type', TYPES[path.extname(p)] || 'application/octet-stream');
  res.setHeader('cache-control', 'no-store');
  fs.createReadStream(p).pipe(res);
}).listen(port, () => console.log('waterline on http://localhost:' + port));
