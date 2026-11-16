// Abuse protection for the public endpoint.
// Uses Upstash Redis (REST, shared by every function instance) when its env
// vars are present; otherwise an in-memory store, which is per instance.
import crypto from 'node:crypto';

const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
export const sharedStore = !!(RURL && RTOK);
// On Vercel, per-instance memory is not a real limit: refuse to run without the shared store.
export const storeMissing = !!process.env.VERCEL && !sharedStore;

export const LIMITS = {
  burst: { n: Number(process.env.WL_BURST || 6), win: 600 },      // fresh scans per person per 10 min
  daily: { n: Number(process.env.WL_DAILY || 40), win: 86400 },   // fresh scans per person per day
  global: { n: Number(process.env.WL_GLOBAL || 1500), win: 86400 }, // all fresh scans per day (budget cap)
  hits: { n: 40, win: 600 },                                      // any request per person per 10 min
};

async function redis(cmds) {
  const r = await fetch(`${RURL}/pipeline`, { method: 'POST', headers: { authorization: `Bearer ${RTOK}`, 'content-type': 'application/json' },
    body: JSON.stringify(cmds), signal: AbortSignal.timeout(3000) });
  if (!r.ok) throw new Error('store');
  return (await r.json()).map(x => x.result);
}

const mem = new Map();
function memIncr(k, win) {
  const now = Date.now(); let e = mem.get(k);
  if (!e || e.exp < now) { e = { v: 0, exp: now + win * 1000 }; mem.set(k, e); }
  e.v++; if (mem.size > 50000) for (const [kk, ee] of mem) if (ee.exp < now) mem.delete(kk);
  return { v: e.v, ttl: Math.ceil((e.exp - now) / 1000) };
}

async function incr(k, win) {
  if (!sharedStore) return memIncr(k, win);
  const [v, , ttl] = await redis([['INCR', k], ['EXPIRE', k, String(win), 'NX'], ['TTL', k]]);
  return { v, ttl };
}

// Who is asking. Vercel overwrites x-forwarded-for with the real client IP, so
// it can not be spoofed there. Stored only as a salted hash.
export function clientId(req) {
  const h = req.headers;
  const ip = (h['x-vercel-forwarded-for'] || h['x-real-ip'] || (process.env.VERCEL ? h['x-forwarded-for'] : '') || req.socket?.remoteAddress || 'unknown')
    .toString().split(',')[0].trim();
  // Collapse IPv6 to its /48 so one connection can not rotate through addresses.
  const key = ip.includes(':') ? ip.split(':').slice(0, 3).join(':') : ip; // IPv6 keyed on /48
  return crypto.createHmac('sha256', process.env.WL_SALT || 'waterline-v1').update(key).digest('hex').slice(0, 24);
}

export async function checkHit(id) {
  const r = await incr(`wl:h:${id}`, LIMITS.hits.win);
  return r.v <= LIMITS.hits.n ? null : { retry: r.ttl };
}

// Reserve one fresh scan. Returns null when allowed, else { retry, reason }.
export async function reserveScan(id) {
  const b = await incr(`wl:b:${id}`, LIMITS.burst.win);
  if (b.v > LIMITS.burst.n) return { retry: b.ttl, reason: `That is ${LIMITS.burst.n} scans in 10 minutes. Try again in ${Math.ceil(b.ttl / 60)} min.` };
  const d = await incr(`wl:d:${id}`, LIMITS.daily.win);
  if (d.v > LIMITS.daily.n) return { retry: d.ttl, reason: `That is ${LIMITS.daily.n} scans today. Try again tomorrow.` };
  // The shared budget is only spent once this person is within their own limits.
  const g = await incr('wl:g:' + new Date().toISOString().slice(0, 10), LIMITS.global.win);
  if (g.v > LIMITS.global.n) return { retry: g.ttl, reason: 'Waterline has hit its scan budget for today. Try again tomorrow.' };
  return null;
}

// One scan at a time per person.
export async function lock(id, sec = 150) {
  const k = `wl:l:${id}`;
  if (!sharedStore) { const e = mem.get(k); if (e && e.exp > Date.now()) return false; mem.set(k, { v: 1, exp: Date.now() + sec * 1000 }); return true; }
  const [ok] = await redis([['SET', k, '1', 'NX', 'EX', String(sec)]]);
  return ok === 'OK';
}
export async function unlock(id) {
  const k = `wl:l:${id}`;
  if (!sharedStore) return void mem.delete(k);
  await redis([['DEL', k]]).catch(() => {});
}

// Recent results, so the same link pasted by a whole chat costs one scan.
const ckey = url => 'wl:c:' + crypto.createHash('sha256').update(url).digest('hex').slice(0, 32);
export async function cacheGet(url) {
  try {
    if (!sharedStore) { const e = mem.get(ckey(url)); return e && e.exp > Date.now() ? e.v : null; }
    const [v] = await redis([['GET', ckey(url)]]); return v ? JSON.parse(v) : null;
  } catch { return null; }
}
export async function cachePut(url, value, sec = 600) {
  try {
    if (!sharedStore) return void mem.set(ckey(url), { v: value, exp: Date.now() + sec * 1000 });
    await redis([['SET', ckey(url), JSON.stringify(value), 'EX', String(sec)]]);
  } catch {}
}

// Daily usage counters for the private stats page. Only counts and a HyperLogLog of
// the salted visitor hashes are kept (no IPs, no links), for 90 days.
const day = () => new Date().toISOString().slice(0, 10);
export function stat(fields, id) {
  if (!sharedStore) return;
  const k = `wl:s:${day()}`, cmds = [];
  for (const f of [].concat(fields)) cmds.push(['HINCRBY', k, f, '1']);
  cmds.push(['EXPIRE', k, String(90 * 86400)]);
  if (id) cmds.push(['PFADD', `wl:p:${day()}`, id], ['EXPIRE', `wl:p:${day()}`, String(90 * 86400)]);
  redis(cmds).catch(() => {});
}
export async function readStats(days = 30) {
  if (!sharedStore) return [];
  const ds = Array.from({ length: days }, (_, i) => new Date(Date.now() - i * 864e5).toISOString().slice(0, 10));
  const res = await redis(ds.flatMap(d => [['HGETALL', `wl:s:${d}`], ['PFCOUNT', `wl:p:${d}`]]));
  return ds.map((d, i) => {
    const flat = res[i * 2] || [], o = {};
    for (let j = 0; j < flat.length; j += 2) o[flat[j]] = Number(flat[j + 1]);
    return { day: d, people: res[i * 2 + 1] || 0, ...o };
  });
}
