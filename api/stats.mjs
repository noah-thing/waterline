// GET /api/stats?key=…  Private usage page. Without the right key it is a plain 404.
import crypto from 'node:crypto';
import { readStats } from '../engine/guard.mjs';

export const config = { maxDuration: 60 };

const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const COLS = [
  ['people', 'People'], ['checks', 'Checks'], ['scans', 'Fresh scans'], ['cached', 'From cache'],
  ['v_safe', 'Safe'], ['v_caution', 'Careful'], ['v_unsafe', 'Unsafe'], ['v_unknown', 'Unclear'], ['partial', 'Partial'],
  ['limited', 'Rate limited'], ['refused_offsite', 'Refused (other sites)'], ['failed', 'Failed'],
];

export default async function handler(req, res) {
  const key = process.env.WL_STATS_KEY;
  const given = new URL(req.url, 'http://x').searchParams.get('key') || '';
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-robots-tag', 'noindex, nofollow');
  if (!key || !same(given, key)) { res.statusCode = 404; return res.end('Not found'); }
  // ?probe=<https url>: open that page exactly as a scan does and show what it could see.
  const probeUrl = new URL(req.url, 'http://x').searchParams.get('probe');
  if (probeUrl) {
    if (!/^https:\/\/[^\s]+$/.test(probeUrl) || probeUrl.length > 300) { res.statusCode = 400; return res.end('Bad probe url'); }
    try {
      const { probe } = await import('../engine/scanner.mjs');
      const out = await probe(probeUrl);
      res.setHeader('content-type', 'application/json; charset=utf-8');
      return res.end(JSON.stringify(out, null, 1));
    } catch (e) { res.statusCode = 500; return res.end('Probe failed'); }
  }
  let rows;
  try { rows = await readStats(30); } catch { res.statusCode = 503; return res.end('Store unavailable'); }
  for (const r of rows) {
    r.limited = (r.limited_person || 0) + (r.limited_running || 0) + (r.limited_requests || 0) + (r.limited_budget || 0);
    r.failed = (r.timeouts || 0) + (r.errors || 0);
  }
  const total = Object.fromEntries(COLS.map(([k]) => [k, rows.reduce((s, r) => s + (r[k] || 0), 0)]));
  const cell = v => `<td>${v ? esc(v) : '<span class="z">0</span>'}</td>`;
  const body = rows.filter(r => COLS.some(([k]) => r[k])).map(r => `<tr><th>${esc(r.day)}</th>${COLS.map(([k]) => cell(r[k])).join('')}</tr>`).join('');
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Waterline stats</title><link rel="stylesheet" href="/stats.css"></head><body>
<header><p class="tag">[ Waterline ] Private stats</p><h1>Last 30 days</h1>
<p class="lede">People are counted by a salted hash of their connection, so everyone on one network counts once. Days run in UTC. "People" across days is not additive.</p></header>
<dl class="sum">${[['Checks', total.checks], ['Fresh scans', total.scans], ['Unsafe found', total.v_unsafe], ['Rate limited', total.limited], ['Refused from other sites', total.refused_offsite]].map(([l, v]) => `<div><dt>${l}</dt><dd>${v}</dd></div>`).join('')}</dl>
<div class="wrap"><table><thead><tr><th>Day</th>${COLS.map(([, l]) => `<th>${l}</th>`).join('')}</tr></thead><tbody>${body || `<tr><td colspan="${COLS.length + 1}">No activity yet.</td></tr>`}</tbody></table></div>
</body></html>`);
}
