// POST /api/scan  { url }  → streamed NDJSON: stage, log, frame events, then one result.
import { scan } from '../engine/scanner.mjs';
import { normalizeUrl } from '../engine/intel.mjs';
import { stat, storeMissing, clientId, checkHit, reserveScan, lock, unlock, cacheGet, cachePut } from '../engine/guard.mjs';

export const config = { maxDuration: 120 };

const MAX_BODY = 2048;
const SAFE_ERRORS = /^(?:Paste a link first\.|Only http and https links can be checked\.|That address points inside a private network\.|Could not find [\w.-]{1,253}\. Check the link for typos\.|That link redirects into a private network\.)$/;

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body !== undefined) return resolve(typeof req.body === 'string' ? req.body : JSON.stringify(req.body));
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { reject(new Error('too-big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sameOrigin(req) {
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin') return false;
  const origin = req.headers.origin;
  if (!origin) return !!site; // browsers always send one of the two on a POST fetch
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

function fail(res, status, error, extra = {}) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  if (extra.retry) res.setHeader('retry-after', String(extra.retry));
  res.end(JSON.stringify({ error, ...extra }));
}

export default async function handler(req, res) {
  if (req.method !== 'POST') { res.setHeader('allow', 'POST'); return fail(res, 405, 'Use POST.'); }
  if (!sameOrigin(req) || req.headers['x-waterline'] !== '1') { stat('refused_offsite'); return fail(res, 403, 'Scans can only be started from the Waterline page.'); }
  if (!/^application\/json/i.test(req.headers['content-type'] || '')) return fail(res, 415, 'Send JSON.');

  if (storeMissing) return fail(res, 503, 'Waterline is not fully set up yet. Try again soon.');
  const id = clientId(req);
  try { const hit = await checkHit(id); if (hit) { stat('limited_requests', id); return fail(res, 429, 'Too many requests. Slow down a little.', hit); } }
  catch { return fail(res, 503, 'Busy right now. Try again in a minute.'); }

  let url;
  try {
    const raw = await readBody(req);
    const body = JSON.parse(raw || '{}');
    if (typeof body.url !== 'string' || body.url.length > 2048) throw new Error('Paste a link first.');
    url = normalizeUrl(body.url.replace(/[\u0000-\u001f\u007f]/g, '')).href;
  } catch (e) { return fail(res, 400, SAFE_ERRORS.test(e.message) ? e.message : 'That does not look like a link.'); }

  const cached = await cacheGet(url);
  const startStream = () => {
    res.statusCode = 200;
    res.setHeader('content-type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-accel-buffering', 'no');
  };
  const send = o => { try { res.write(JSON.stringify(o) + '\n'); } catch {} };

  if (cached) { stat(['checks', 'cached', `v_${cached.verdict}`], id); startStream(); send({ type: 'result', cached: true, ...cached }); return res.end(); }

  let locked;
  try { locked = await lock(id); } catch { return fail(res, 503, 'Busy right now. Try again in a minute.', { retry: 30 }); }
  if (!locked) { stat('limited_running', id); return fail(res, 429, 'You already have a scan running. Wait for it to finish.', { retry: 15 }); }
  try {
    let limited; try { limited = await reserveScan(id); } catch { limited = { reason: 'Busy right now. Try again in a minute.', retry: 60 }; }
    if (limited) { stat(/budget/.test(limited.reason) ? 'limited_budget' : 'limited_person', id); return fail(res, 429, limited.reason, { retry: limited.retry }); }

    startStream();
    send({ type: 'start', url });
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 100000);
    // If the visitor closes or reloads the page, stop the scan and free their slot.
    res.on('close', () => { if (!res.writableEnded) ac.abort(); });
    let result;
    try { result = await scan(url, { emit: send, signal: ac.signal, allowLocal: process.env.WL_ALLOW_LOCAL === '1' && !process.env.VERCEL }); }
    finally { clearTimeout(timer); }
    if (result.verdict !== 'unknown') await cachePut(url, result);
    stat(['checks', 'scans', `v_${result.verdict}`].concat(result.stats?.partial?.length ? ['partial'] : []), id);
    send({ type: 'result', ...result });
  } catch (e) {
    const msg = SAFE_ERRORS.test(e.message) ? e.message : (e.message === 'scan-timeout' ? 'The page took too long to check.' : 'Something went wrong while checking that link.');
    if (!res.headersSent) fail(res, 400, msg); else send({ type: 'error', error: msg });
    stat(e.message === 'scan-timeout' ? 'timeouts' : 'errors');
    if (!SAFE_ERRORS.test(e.message)) console.error('scan failed', e?.message?.slice(0, 200));
  } finally {
    await unlock(id);
    if (!res.writableEnded) res.end();
  }
}
