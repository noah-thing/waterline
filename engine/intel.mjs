// URL and domain checks that need no browser: shape of the address, private
// network guard, domain age (RDAP), optional Google Safe Browsing.
import dns from 'node:dns/promises';
import net from 'node:net';
import { isAdultHost } from './rules.mjs';

const SHORTENERS = /^(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|tiny\.cc|ow\.ly|buff\.ly|rebrand\.ly|s\.id|t\.ly|v\.gd|qrco\.de|linktr\.ee)$/i;
const RISKY_TLD = /\.(?:zip|mov|xyz|top|click|country|gq|tk|ml|cf|ga|work|rest|cam|lol|quest|cfd|sbs)$/i;

export function normalizeUrl(input) {
  let s = String(input || '').trim();
  if (!s) throw new Error('Paste a link first.');
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = 'https://' + s;
  const u = new URL(s);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https links can be checked.');
  return u;
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19));
  }
  const v = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
  if (mapped) return isPrivateIp(mapped[1]);
  return v === '::' || v === '::1' || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || /^ff/.test(v) || /^::ffff:/.test(v) || /^64:ff9b:/.test(v) || /^2002:/.test(v);
}

export async function guardHost(host, allowLocal) {
  if (allowLocal) return;
  if (/^localhost$|\.local$|\.internal$/i.test(host)) throw new Error('That address points inside a private network.');
  const ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true }).catch(() => [])).map(r => r.address);
  if (!ips.length) throw new Error(`Could not find ${host}. Check the link for typos.`);
  if (ips.some(isPrivateIp)) throw new Error('That address points inside a private network.');
}

export function urlShape(u) {
  const f = [];
  const host = u.hostname;
  if (net.isIP(host)) f.push({ rule: 'raw-ip', severity: 'warn', category: 'phishing', title: 'Link is a bare IP address', detail: 'Real sites almost always use a name. Bare IPs are common for throwaway malware hosts.', source: 'observed' });
  if (host.startsWith('xn--') || host.includes('.xn--')) f.push({ rule: 'punycode', severity: 'warn', category: 'phishing', title: 'Look-alike characters in the address', detail: `The name uses non-Latin characters (${host}) that can imitate a real site.`, source: 'observed' });
  if (SHORTENERS.test(host)) f.push({ rule: 'shortener', severity: 'info', category: 'context', title: 'Shortened link', detail: 'The real destination was hidden behind a short link; checked where it actually goes.', source: 'observed' });
  if (RISKY_TLD.test(host)) f.push({ rule: 'risky-tld', severity: 'info', category: 'context', title: 'Low-cost domain ending', detail: `.${host.split('.').pop()} domains are cheap and often used for throwaway sites.`, source: 'observed' });
  if (u.protocol === 'http:') f.push({ rule: 'no-tls', severity: 'info', category: 'context', title: 'Not encrypted (http)', detail: 'The page loads without HTTPS.', source: 'observed' });
  if (u.username || /@/.test(u.href.split('?')[0].replace(/^https?:\/\//, '').split('/')[0])) f.push({ rule: 'userinfo', severity: 'warn', category: 'phishing', title: 'Hidden real address', detail: 'The link uses an "@" trick so the part you read is not where it goes.', source: 'observed' });
  if (isAdultHost(host)) f.push({ rule: 'adult-host', severity: 'block', category: 'nsfw', title: 'Adult website', detail: `${host} is a known adult site.`, source: 'observed' });
  return f;
}

function registrable(host) {
  const parts = host.split('.');
  const twoLevel = /^(?:co|com|net|org|gov|ac|edu)\.[a-z]{2}$/i.test(parts.slice(-2).join('.'));
  return parts.slice(twoLevel ? -3 : -2).join('.');
}

// Hosting platforms where the domain age says nothing about the page.
const PLATFORMS = /(?:github\.io|githubusercontent\.com|itch\.io|vercel\.app|netlify\.app|pages\.dev|glitch\.me|replit\.app|repl\.co|web\.app|firebaseapp\.com|surge\.sh|neocities\.org|codepen\.io|onrender\.com|fly\.dev|lovable\.app|claude\.site|claudeusercontent\.com|bolt\.new|v0\.dev)$/i;

export async function domainAge(host) {
  if (net.isIP(host) || PLATFORMS.test(host)) return { platform: PLATFORMS.test(host) };
  const dom = registrable(host);
  try {
    const r = await fetch(`https://rdap.org/domain/${dom}`, { signal: AbortSignal.timeout(6000), redirect: 'follow' });
    if (!r.ok) return { domain: dom };
    const j = await r.json();
    const ev = (j.events || []).find(e => e.eventAction === 'registration');
    if (!ev) return { domain: dom };
    const days = Math.floor((Date.now() - new Date(ev.eventDate)) / 864e5);
    return { domain: dom, days, registered: ev.eventDate.slice(0, 10) };
  } catch { return { domain: dom }; }
}

export async function safeBrowsing(urls) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key || !urls.length) return null;
  try {
    const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`, {
      method: 'POST', signal: AbortSignal.timeout(6000), headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client: { clientId: 'waterline', clientVersion: '1.0' }, threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: urls.slice(0, 50).map(url => ({ url })) } }) });
    const j = await r.json();
    return j.matches || [];
  } catch { return null; }
}

export { registrable };
