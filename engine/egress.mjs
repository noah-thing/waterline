// Every byte the sandbox sends leaves through here. Each host is resolved once,
// checked against private ranges, and the connection goes to that exact IP, so
// DNS rebinding and redirects into internal addresses are impossible.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dns from 'node:dns/promises';
import { isPrivateIp } from './intel.mjs';

const PORTS = new Set([80, 443, 8080, 8443]);

export async function resolvePublic(host, allowLocal) {
  host = String(host || '').replace(/^\[|\]$/g, '');
  if (!host) return null;
  if (net.isIP(host)) return allowLocal || !isPrivateIp(host) ? host : null;
  if (!allowLocal && /^localhost$|\.local$|\.internal$|\.localhost$/i.test(host)) return null;
  let addrs;
  try { addrs = await dns.lookup(host, { all: true, verbatim: true }); } catch { return null; }
  if (!addrs.length) return null;
  if (!allowLocal && addrs.some(a => isPrivateIp(a.address))) return null;
  return (addrs.find(a => a.family === 4) || addrs[0]).address;
}

export function startProxy({ allowLocal = false, onBlock = () => {} } = {}) {
  const sockets = new Set();
  const okPort = p => allowLocal || PORTS.has(p);
  const server = http.createServer(async (req, res) => {
    let u; try { u = new URL(req.url); } catch { res.writeHead(400); return res.end(); }
    const port = Number(u.port || 80);
    const ip = u.protocol === 'http:' && okPort(port) ? await resolvePublic(u.hostname, allowLocal) : null;
    if (!ip) { onBlock(u.hostname); res.writeHead(403); return res.end(); }
    const headers = { ...req.headers, host: u.host };
    delete headers['proxy-connection']; delete headers['proxy-authorization'];
    const up = http.request({ host: ip, port, method: req.method, path: u.pathname + u.search, headers, setHost: false, timeout: 15000 }, r => {
      res.writeHead(r.statusCode || 502, r.headers); r.pipe(res);
    });
    up.on('error', () => res.destroy()); up.on('timeout', () => up.destroy());
    req.pipe(up);
  });
  server.on('connect', async (req, sock, head) => {
    sockets.add(sock); sock.on('close', () => sockets.delete(sock)); sock.on('error', () => {});
    const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(req.url || '');
    const port = m ? Number(m[2]) : 0;
    const ip = m && okPort(port) ? await resolvePublic(m[1], allowLocal) : null;
    if (!ip) { onBlock(m?.[1] || req.url); return sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); }
    const up = net.connect(port, ip, () => { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head?.length) up.write(head); up.pipe(sock); sock.pipe(up); });
    sockets.add(up); up.on('close', () => sockets.delete(up));
    up.setTimeout(30000, () => up.destroy());
    up.on('error', () => sock.destroy()); sock.on('close', () => up.destroy());
  });
  // Plain ws:// upgrades are refused; wss:// goes through CONNECT above.
  server.on('upgrade', (req, sock) => { onBlock('ws'); sock.destroy(); });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({
    port: server.address().port,
    close: () => { for (const s of sockets) s.destroy(); server.close(); },
  })));
}

// Server-side fetch with the same rule: one resolution, checked, pinned.
export function safeGet(url, { allowLocal = false, maxBytes = 5_000_000, timeout = 6000 } = {}) {
  return new Promise(resolve => {
    let u; try { u = new URL(url); } catch { return resolve(null); }
    if (!/^https?:$/.test(u.protocol)) return resolve(null);
    const port = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
    if (!allowLocal && !PORTS.has(port)) return resolve(null);
    resolvePublic(u.hostname, allowLocal).then(ip => {
      if (!ip) return resolve(null);
      const mod = u.protocol === 'https:' ? https : http;
      const req = mod.request({ host: ip, servername: net.isIP(u.hostname) ? undefined : u.hostname, port, path: u.pathname + u.search, method: 'GET',
        headers: { host: u.host, 'user-agent': 'Mozilla/5.0 Waterline' }, timeout }, res => {
        if (res.statusCode !== 200) { res.resume(); return resolve(null); }
        if (Number(res.headers['content-length'] || 0) > maxBytes) { res.destroy(); return resolve(null); }
        const chunks = []; let n = 0;
        res.on('data', c => { n += c.length; if (n > maxBytes) { res.destroy(); resolve(null); } else chunks.push(c); });
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', () => resolve(null));
      });
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.on('error', () => resolve(null));
      req.end();
    }, () => resolve(null));
  });
}
