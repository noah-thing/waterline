// The scan pipeline. Opens the link in a locked-down headless Chromium, plays
// it like a person would, fast-forwards its timers, and collects everything it
// shows, loads and runs. Rules find candidates; Jev and DeepSeek confirm or
// clear them, so ordinary games do not get flagged.
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import sharp from 'sharp';
import { normalizeUrl, guardHost, urlShape, domainAge, safeBrowsing, isPrivateIp } from './intel.mjs';
import { scanCode, scanText, extractDataImages, extractImageUrls, isAdultHost, maskHost, isExecutable, IP_LOGGERS } from './rules.mjs';
import { classify, pixelThumb } from './nsfw.mjs';
import { startProxy, safeGet } from './egress.mjs';
import { reviewImages, reviewFindings, reviewText, deepRead, hasJev, hasDeepSeek } from './judge.mjs';

const LIMITS = { scripts: 80, scriptBytes: 3_000_000, totalScriptBytes: 14_000_000, images: 70, imageBytes: 5_000_000, requests: 700, frames: 9 };
const sha = b => crypto.createHash('sha1').update(b).digest('hex');

// Only these variables reach the browser process: no API keys, no tokens.
function browserEnv() {
  const keep = ['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'LD_LIBRARY_PATH', 'FONTCONFIG_PATH', 'FONTCONFIG_FILE', 'PLAYWRIGHT_BROWSERS_PATH'];
  const env = {};
  for (const k of keep) if (process.env[k]) env[k] = process.env[k];
  env.HOME ||= '/tmp';
  return env;
}

async function launch(proxyPort) {
  const { chromium } = await import('playwright-core');
  // All traffic goes through the egress proxy, loopback included; no QUIC or raw WebRTC UDP around it.
  const proxy = { server: `http://127.0.0.1:${proxyPort}`, bypass: '<-loopback>' };
  const args = ['--proxy-bypass-list=<-loopback>', '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--disable-dev-shm-usage', '--mute-audio', '--disable-extensions', '--disable-sync', '--no-first-run',
    '--disable-background-networking', '--disable-default-apps', '--disable-component-update', '--autoplay-policy=no-user-gesture-required'];
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    const sp = (await import('@sparticuz/chromium')).default;
    const executablePath = await sp.executablePath();
    return chromium.launch({ executablePath, args: [...sp.args.filter(a => !/disable-web-security/.test(a)), ...args], headless: true, env: browserEnv(), proxy });
  }
  return chromium.launch({ headless: true, args, env: browserEnv(), proxy });
}

// Recorded inside every frame: what the page tries to do to the visitor.
const HOOKS = `(() => {
  const L = (k, v) => { try { (window.__wl ||= []).length < 200 && window.__wl.push([k, String(v ?? '').slice(0, 600)]); } catch {} };
  try { if (navigator.clipboard) { navigator.clipboard.writeText = t => { L('clipboard', t); return Promise.resolve(); }; navigator.clipboard.write = () => { L('clipboard', '[binary]'); return Promise.resolve(); }; } } catch {}
  try { const ec = Document.prototype.execCommand; Document.prototype.execCommand = function (c, ...a) { if (String(c).toLowerCase() === 'copy') { try { L('clipboard', String(getSelection() || document.activeElement?.value || '')); } catch {} } return ec.call(this, c, ...a); }; } catch {}
  try { window.open = function (u) { L('open', u); return null; }; } catch {}
  try { if (navigator.mediaDevices) navigator.mediaDevices.getUserMedia = c => { L('media', JSON.stringify(c)); return Promise.reject(new DOMException('Permission denied', 'NotAllowedError')); }; } catch {}
  try { if (window.Notification) Notification.requestPermission = () => { L('notify', ''); return Promise.resolve('denied'); }; } catch {}
  try { Element.prototype.requestFullscreen = function () { L('fullscreen', ''); return Promise.resolve(); }; } catch {}
  try { if (navigator.geolocation) navigator.geolocation.getCurrentPosition = () => L('geo', ''); } catch {}
  try { if (navigator.serviceWorker) navigator.serviceWorker.register = () => { L('sw', ''); return Promise.reject(new Error('blocked')); }; } catch {}
})();`;

const PLAY_RE = /^\s*(?:play(?: now| game)?|start(?: game)?|begin|go!?|enter|new game|tap to (?:play|start)|click to (?:play|start)|press (?:start|space|any key)|let'?s go|run game|launch)\s*[!>▶►]?\s*$/i;

// Resolve to fallback if a page call hangs (a page can spin forever).
const within = (p, ms, fallback) => Promise.race([Promise.resolve(p).catch(() => fallback), new Promise(r => setTimeout(() => r(fallback), ms))]);

export async function scan(input, { emit = () => {}, allowLocal = false, signal } = {}) {
  const t0 = Date.now();
  const say = (stage, text) => emit({ type: 'log', stage, text, t: Date.now() - t0 });
  const findings = [];
  const add = f => { if (!findings.some(x => x.rule === f.rule && x.where === f.where)) findings.push(f); };
  const stats = { requests: 0, blocked: 0, scripts: 0, scriptBytes: 0, images: 0, frames: 0, hosts: new Set() };

  // 01 — the address itself
  emit({ type: 'stage', id: 'address' });
  const url = normalizeUrl(input);
  await guardHost(url.hostname, allowLocal);
  urlShape(url).forEach(add);
  say('address', `Resolved ${url.hostname}`);
  const agePromise = domainAge(url.hostname);

  // 02 — render in the sandbox
  emit({ type: 'stage', id: 'render' });
  const proxy = await startProxy({ allowLocal, onBlock: () => { stats.blocked++; } });
  let browser;
  try { browser = await launch(proxy.port); } catch (e) { proxy.close(); throw e; }
  const onAbort = () => { browser.close().catch(() => {}); proxy.close(); };
  signal?.addEventListener('abort', onAbort, { once: true });
  const scripts = new Map(); const images = new Map(); const frames = []; const popups = new Set(); const downloads = [];
  const dnsCache = new Map();
  const allowedHost = host => {
    if (allowLocal) return Promise.resolve(true);
    if (/^localhost$|\.local$|\.internal$/i.test(host)) return Promise.resolve(false);
    if (net.isIP(host)) return Promise.resolve(!isPrivateIp(host));
    if (!dnsCache.has(host)) dnsCache.set(host, dns.lookup(host, { all: true }).then(r => r.length > 0 && !r.some(a => isPrivateIp(a.address))).catch(() => false));
    return dnsCache.get(host);
  };
  let page, finalUrl = url.href, loadError = null, title = '';
  try {
    const context = await browser.newContext({
      viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1, serviceWorkers: 'block', acceptDownloads: false,
      permissions: [], locale: 'en-US', ignoreHTTPSErrors: true,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    });
    await context.addInitScript(HOOKS);
    await context.route('**/*', async route => {
      const req = route.request();
      let u; try { u = new URL(req.url()); } catch { return route.abort(); }
      if (u.protocol === 'data:' || u.protocol === 'blob:') return route.continue();
      if (!/^https?:$/.test(u.protocol)) return route.abort();
      if (++stats.requests > LIMITS.requests) return route.abort();
      if (!(await allowedHost(u.hostname))) { stats.blocked++; return route.abort('blockedbyclient'); }
      stats.hosts.add(u.hostname);
      if (stats.requests <= 160) emit({ type: 'req', host: isAdultHost(u.hostname) ? maskHost(u.hostname) : u.hostname, kind: req.resourceType().slice(0, 6), n: stats.requests });
      if (isAdultHost(u.hostname)) add({ rule: 'adult-request', severity: 'block', category: 'nsfw', title: 'Loads content from an adult site', detail: `While running, the page contacted ${maskHost(u.hostname)}.`, where: maskHost(u.hostname), source: 'observed' });
      if (IP_LOGGERS.test(u.hostname)) add({ rule: 'iplogger-request', severity: 'block', category: 'privacy', title: 'Contacted an IP logger', detail: `The page called ${u.hostname}, a service that records visitor IP addresses.`, where: u.hostname, source: 'observed' });
      if (isExecutable(u.pathname)) { downloads.push(u.href); return route.abort(); }
      return route.continue();
    });

    context.on('response', async resp => {
      try {
        const req = resp.request(); const type = req.resourceType(); const rurl = resp.url();
        const len = Number(resp.headers()['content-length'] || 0);
        const ct = resp.headers()['content-type'] || '';
        if (/application\/(?:x-msdownload|x-msdos-program|vnd\.microsoft\.portable-executable|x-dosexec|vnd\.android\.package-archive)/i.test(ct)) downloads.push(rurl);
        if (type === 'script' || type === 'document') {
          if (scripts.has(rurl)) return;
          if (scripts.size >= LIMITS.scripts || stats.scriptBytes >= LIMITS.totalScriptBytes) { stats.capped = true; return; }
          let body = await resp.text().catch(() => '');
          if (!body) return;
          // Oversized files are read up to the limit, never skipped.
          if (body.length > LIMITS.scriptBytes) { body = body.slice(0, LIMITS.scriptBytes); stats.capped = true; }
          scripts.set(rurl, { url: rurl, type, text: body }); stats.scriptBytes += body.length;
        } else if (type === 'image' && images.size >= LIMITS.images) { stats.capped = true;
        } else if (type === 'image' && len <= LIMITS.imageBytes && !/svg/.test(ct)) {
          const buf = await resp.body().catch(() => null);
          if (!buf || buf.length < 600 || buf.length > LIMITS.imageBytes) return;
          const h = sha(buf); if (![...images.values()].some(i => i.hash === h)) images.set(rurl, { url: rurl, buf, hash: h });
        }
      } catch {}
    });
    page = await context.newPage();
    context.on('page', p => { if (p !== page) { popups.add(p.url()); p.close().catch(() => {}); } });
    page.on('dialog', d => { add({ rule: 'dialog', severity: 'info', category: 'context', title: 'Shows pop-up dialogs', detail: `"${d.message().slice(0, 120)}"`, source: 'observed' }); d.dismiss().catch(() => {}); });
    page.on('download', d => downloads.push(d.url()));
    try { await page.clock.install(); } catch {}

    say('render', 'Opening in an isolated browser');
    try {
      const resp = await page.goto(url.href, { waitUntil: 'domcontentloaded', timeout: 20000 });
      if (resp && resp.status() >= 400) say('render', `Server answered ${resp.status()}`);
      await page.waitForLoadState('load', { timeout: 9000 }).catch(() => {});
      await page.waitForTimeout(1200);
    } catch (e) { if (process.env.WL_DEBUG) console.error('goto', e.message.slice(0, 400)); loadError = /timeout/i.test(e.message) ? 'The page took too long to load.' : 'The page could not be opened.'; }
    finalUrl = page.url();
    title = await within(page.title(), 3000, '');
    say('render', `${stats.requests} requests from ${stats.hosts.size} hosts`);
    const final = (() => { try { return new URL(finalUrl); } catch { return null; } })();
    if (final && final.hostname !== url.hostname) {
      say('render', `Redirected to ${final.hostname}`);
      urlShape(final).filter(f => f.rule === 'adult-host').forEach(add);
      if (!(await allowedHost(final.hostname))) throw new Error('That link redirects into a private network.');
    }

    const grab = async label => {
      if (frames.length >= LIMITS.frames) return;
      const buf = await page.screenshot({ type: 'jpeg', quality: 70, timeout: 5000 }).catch(() => null);
      if (!buf) return;
      const small = await sharp(buf, { animated: false, limitInputPixels: 25e6 }).resize(16, 10, { fit: 'fill' }).greyscale().raw().toBuffer();
      if (frames.some(f => f.small.reduce((s, v, i) => s + Math.abs(v - small[i]), 0) / small.length < 3)) return;
      frames.push({ buf, small, label }); stats.frames = frames.length;
      emit({ type: 'frame', label, thumb: await pixelThumb(buf, 32) });
    };

    // 03 — play it like a person
    emit({ type: 'stage', id: 'play' });
    await grab('First screen');
    if (!loadError) {
      const clicked = [];
      for (let round = 0; round < 2; round++) {
        for (const fr of page.frames()) {
          const loc = fr.locator('button, a, [role=button], input[type=button], input[type=submit], div, span, p, h1, h2, h3').filter({ hasText: PLAY_RE });
          const n = Math.min(await within(loc.count(), 2000, 0), 4);
          for (let i = n - 1; i >= 0 && clicked.length < 3; i--) {
            const el = loc.nth(i);
            if (!(await el.isVisible().catch(() => false))) continue;
            const txt = ((await el.innerText().catch(() => '')) || '').trim().slice(0, 30);
            if (await el.click({ timeout: 1500 }).then(() => true).catch(() => false)) { clicked.push(txt); say('play', `Clicked "${txt}"`); await page.waitForTimeout(900); break; }
          }
        }
        await grab(clicked.length ? `After "${clicked.at(-1)}"` : 'Idle');
      }
      // Canvas games: tap the biggest canvas and mash the usual keys.
      const box = await within(page.evaluate(() => {
        const all = [...document.querySelectorAll('canvas, iframe')].map(e => e.getBoundingClientRect()).filter(r => r.width > 120 && r.height > 120);
        all.sort((a, b) => b.width * b.height - a.width * a.height);
        const r = all[0]; return r ? { x: r.x + r.width / 2, y: r.y + r.height / 2 } : null;
      }), 3000, null);
      const target = box || { x: 640, y: 400 };
      say('play', box ? 'Playing the game canvas' : 'Clicking through the page');
      const keys = ['Space', 'Enter', 'ArrowUp', 'Space', 'KeyW', 'ArrowRight', 'Space', 'KeyZ'];
      for (let i = 0; i < 8; i++) {
        await page.mouse.click(target.x, target.y).catch(() => {});
        await page.keyboard.press(keys[i]).catch(() => {});
        await page.waitForTimeout(450);
        if (i % 2 === 1) await grab(`Playing ${Math.round((Date.now() - t0) / 1000)}s`);
      }
      // Payloads that wait (setTimeout 60s, "after 3 deaths"...): jump the clock forward.
      try { await page.clock.fastForward('02:00'); say('play', 'Fast-forwarded 2 minutes of timers'); } catch {}
      await page.waitForTimeout(900);
      await grab('After 2 min (fast-forward)');
      for (let i = 0; i < 4; i++) { await page.mouse.click(target.x, target.y).catch(() => {}); await page.keyboard.press('Space').catch(() => {}); await page.waitForTimeout(250); }
      try { await page.clock.fastForward('05:00'); } catch {}
      await page.waitForTimeout(700);
      await grab('After 7 min (fast-forward)');
    }

    // What the page tried to do while we played.
    const hookLog = [];
    for (const fr of page.frames()) hookLog.push(...((await within(fr.evaluate(() => window.__wl || []), 3000, [])) || []));
    for (const [k, v] of hookLog) {
      if (k === 'clipboard' && /powershell|mshta|cmd(?:\.exe)?\s*\/c|iex\b|Invoke-|curl\s.+\|\s*(?:ba)?sh|bitsadmin|certutil|wscript|rundll32|msiexec/i.test(v))
        add({ rule: 'clipboard-cmd', severity: 'block', category: 'malware', title: 'Put a command on your clipboard', detail: 'The page silently copied a system command, the first step of the ClickFix malware trick.', excerpt: v.slice(0, 140), source: 'observed' });
      else if (k === 'clipboard') add({ rule: 'clipboard', severity: 'info', category: 'context', title: 'Wrote to the clipboard', detail: 'The page copied text without being asked.', excerpt: v.slice(0, 100), source: 'observed' });
      if (k === 'open') { try { popups.add(new URL(v, finalUrl).href); } catch {} }
      if (k === 'media') add({ rule: 'media-req', severity: 'warn', category: 'privacy', title: 'Asked for camera or microphone', detail: 'The page tried to turn on a camera or microphone while playing.', source: 'observed' });
      if (k === 'geo') add({ rule: 'geo', severity: 'warn', category: 'privacy', title: 'Asked for your location', detail: 'The page requested GPS location.', source: 'observed' });
      if (k === 'notify') add({ rule: 'notify', severity: 'info', category: 'context', title: 'Asks to send notifications', detail: 'Notification prompts are a common spam route.', source: 'observed' });
    }
    for (const p of popups) {
      let h = ''; try { h = new URL(p).hostname; } catch {}
      if (h && isAdultHost(h)) add({ rule: 'adult-popup', severity: 'block', category: 'nsfw', title: 'Opens an adult site', detail: `Playing opens ${maskHost(h)} in a new window.`, where: maskHost(h), source: 'observed' });
      else if (h) say('play', `Tried to open ${h}`);
    }
    if (downloads.length) {
      const exe = downloads.find(d => isExecutable(d));
      add({ rule: 'download', severity: exe ? 'block' : 'warn', category: 'malware', title: exe ? 'Tries to download a program' : 'Tries to download a file',
        detail: exe ? 'The page tried to download an executable. A browser game never needs one.' : 'A download started without being asked.', excerpt: (exe || downloads[0]).slice(0, 160), source: 'observed' });
    }

    // 04 — read the code
    emit({ type: 'stage', id: 'code' });
    const visible = [];
    for (const fr of page.frames()) {
      const html = await within(fr.content(), 4000, '');
      if (html) { const k = 'inline:' + fr.url(); scripts.set(k, { url: fr.url() || finalUrl, type: 'inline', text: html }); }
      visible.push(await within(fr.evaluate(() => document.body?.innerText || ''), 3000, ''));
    }
    stats.scripts = scripts.size;
    say('code', `Reading ${scripts.size} files, ${(stats.scriptBytes / 1e6).toFixed(1)} MB`);
    const host = (() => { try { return new URL(finalUrl).hostname.replace(/^www\./, ''); } catch { return url.hostname; } })();
    const codeFindings = [];
    const hiddenImages = []; const laterUrls = new Set();
    for (const s of scripts.values()) {
      const where = s.url.length > 90 ? s.url.slice(0, 87) + '…' : s.url;
      for (const f of scanCode(s.text, { source: where, host })) codeFindings.push({ ...f, _script: s });
      for (const b64 of extractDataImages(s.text, 20)) if (hiddenImages.length < 30) hiddenImages.push({ buf: Buffer.from(b64, 'base64'), where });
      for (const u of extractImageUrls(s.text, s.url, 40)) if (!images.has(u)) laterUrls.add(u);
    }
    const text = visible.join('\n').slice(0, 20000);
    // Jev reads the start of the page plus the area around any explicit match, so padding can not hide it.
    const textWindow = t => { const m = /\b(?:porn|hentai|xxx|nude|nsfw|sex)/i.exec(t); return m && m.index > 3000 ? t.slice(0, 2500) + '\n…\n' + t.slice(Math.max(0, m.index - 1500), m.index + 2000) : t.slice(0, 6000); };
    scanText(text, 'on screen').forEach(add);
    say('code', `${codeFindings.length} pattern matches in code`);

    // Images the code references but the session never showed.
    const fetchList = [...laterUrls].slice(0, 40);
    if (fetchList.length) say('images', `Fetching ${fetchList.length} images the code can load later`);
    await Promise.all(fetchList.map(async u => {
      try {
        const buf = await safeGet(u, { allowLocal, maxBytes: LIMITS.imageBytes });
        if (!buf || buf.length < 600) return;
        const h = sha(buf); if (![...images.values()].some(i => i.hash === h)) images.set(u, { url: u, buf, hash: h, later: true });
      } catch {}
    }));
    for (const hi of hiddenImages) { const h = sha(hi.buf); images.set('data:' + h.slice(0, 10), { url: hi.where, buf: hi.buf, hash: h, hidden: true }); }

    // 05 — look at every picture
    emit({ type: 'stage', id: 'images' });
    stats.images = images.size;
    say('images', `Classifying ${images.size} images and ${frames.length} frames`);
    const imageCands = [];
    for (const im of images.values()) {
      const s = await classify(im.buf, { tiles: false }).catch(() => null);
      if (s && (s.explicit >= 0.3 || s.sexy >= 0.6)) imageCands.push({ ...im, score: s });
    }
    const frameScores = [];
    for (const f of frames) frameScores.push(await classify(f.buf, { tiles: true }).catch(() => null));
    imageCands.sort((a, b) => b.score.explicit - a.score.explicit);
    say('images', imageCands.length ? `${imageCands.length} images need a second look` : 'No image looks explicit to the local model');

    // 06 — the judges
    emit({ type: 'stage', id: 'judge' });
    const judged = [];
    if (hasJev()) say('judge', 'Asking Jev to confirm');
    const [frameJ, imgJ, codeJ, textJ] = await Promise.all([
      reviewImages(frames.map(f => ({ buf: f.buf })), { wide: true }),
      reviewImages(imageCands.slice(0, 12).map(c => ({ buf: c.buf }))),
      reviewFindings(codeFindings.filter(f => f.severity !== 'info').slice(0, 12), finalUrl),
      reviewText(textWindow(text), finalUrl),
    ]);
    // Frames: what was actually on screen.
    const thumbs = await Promise.all(frames.map(f => pixelThumb(f.buf, 40)));
    frames.forEach((f, i) => {
      const j = frameJ[i], s = frameScores[i];
      const nude = j?.nudity ?? null, loc = s?.explicit ?? 0;
      const explicit = nude != null ? (nude >= 0.7 || (nude >= 0.4 && loc >= 0.85)) : loc >= 0.9;
      const maybe = !explicit && (nude != null ? nude >= 0.45 : loc >= 0.6);
      if (explicit || maybe) add({ rule: 'frame-nsfw', severity: explicit ? 'block' : 'warn', category: 'nsfw', title: explicit ? 'Explicit image on screen' : 'Possibly explicit image on screen',
        detail: `Seen ${f.label.toLowerCase()}.`, where: f.label, thumb: thumbs[i], score: Math.max(nude ?? 0, loc), source: 'observed' });
      if (j?.gore >= 0.75) add({ rule: 'frame-gore', severity: 'warn', category: 'stream', title: 'Graphic gore on screen', detail: `Seen ${f.label.toLowerCase()}.`, where: f.label, thumb: thumbs[i], source: 'observed' });
      if (j?.hate >= 0.8) add({ rule: 'frame-hate', severity: 'block', category: 'stream', title: 'Hate symbol on screen', detail: `Seen ${f.label.toLowerCase()}.`, where: f.label, thumb: thumbs[i], source: 'observed' });
    });
    // Images in the files.
    for (let i = 0; i < Math.min(imageCands.length, 12); i++) {
      const c = imageCands[i], j = imgJ[i], loc = c.score.explicit, nude = j?.nudity ?? null;
      const explicit = nude != null ? (nude >= 0.7 || (nude >= 0.4 && loc >= 0.85)) : loc >= 0.9;
      const maybe = !explicit && (nude != null ? nude >= 0.45 : loc >= 0.6);
      const where = c.hidden ? `Hidden inside ${c.url}` : (c.later ? 'Referenced in code, not shown yet' : 'Loaded by the page');
      if (explicit || maybe) add({ rule: 'image-nsfw', severity: explicit ? 'block' : 'warn', category: 'nsfw',
        title: c.hidden ? 'Explicit image hidden in the code' : (explicit ? 'Explicit image in the game files' : 'Possibly explicit image in the files'),
        detail: where + '.', where: c.url.slice(0, 120), thumb: await pixelThumb(c.buf, 32), score: Math.max(nude ?? 0, loc), source: 'images' });
      else judged.push({ kind: 'image', cleared: true });
    }
    // Code matches: Jev decides whether the match is hostile.
    const serious = codeFindings.filter(f => f.severity !== 'info').slice(0, 12);
    serious.forEach((f, i) => {
      const harm = codeJ[i];
      const { _script, ...clean } = f;
      if (harm == null) add(clean);
      else if (harm >= 0.5) add({ ...clean, ai: harm });
      // AI can soften a hard rule to "check", never erase it.
      else if (f.severity === 'block') add({ ...clean, severity: 'warn', ai: harm });
      else { judged.push({ kind: 'code', cleared: true, rule: f.rule }); say('judge', `Cleared "${f.title}" as ordinary code`); }
    });
    codeFindings.filter(f => f.severity === 'info').forEach(({ _script, ...f }) => add(f));
    if (textJ) {
      if (textJ.sexual >= 0.8) add({ rule: 'text-sexual', severity: 'warn', category: 'nsfw', title: 'Sexual text on screen', detail: 'Jev read sexually explicit language on the page.', source: 'observed' });
      if (textJ.hateful >= 0.85) add({ rule: 'text-hate', severity: 'block', category: 'stream', title: 'Hate speech on screen', detail: 'Jev read slurs or hate speech on the page.', source: 'observed' });
      if (textJ.scam >= 0.85) add({ rule: 'text-scam', severity: 'warn', category: 'phishing', title: 'Scam wording', detail: 'The text looks like a fake prize, fake virus warning or a request for logins.', source: 'observed' });
    }
    // Lower the explicit-word rule if Jev read the text and saw nothing sexual.
    const ew = findings.find(f => f.rule === 'explicit-text');
    if (ew && textJ && textJ.sexual < 0.3) findings.splice(findings.indexOf(ew), 1);

    // DeepSeek reads the code only when something is still in question.
    const stillCode = findings.filter(f => f.source === 'code' && f.severity !== 'info');
    const heavy = findings.some(f => f.rule === 'obfuscated');
    if (hasDeepSeek() && (stillCode.length || heavy)) {
      say('judge', 'DeepSeek is reading the suspicious script');
      const targets = serious.filter(f => findings.some(x => x.rule === f.rule && x.where === f.where)).map(f => f._script);
      const pick = [...new Set(targets)].slice(0, 2).map(s => {
        const m = serious.find(f => f._script === s); const idx = Math.max(0, s.text.indexOf((m?.excerpt || '').slice(20, 60)) - 2500);
        return { where: s.url, code: s.text.slice(idx, idx + 6000) };
      });
      const v = pick.length ? await deepRead(pick) : null;
      // DeepSeek can add a finding, never remove one.
      if (v?.verdict === 'benign') say('judge', 'DeepSeek read the script as harmless');
      else if (v?.verdict === 'malicious') {
        add({ rule: 'deepseek', severity: 'block', category: 'malware', title: 'Script reads as malicious', detail: v.reason, source: 'code' });
      } else if (v?.reason) say('judge', `DeepSeek: ${v.reason}`);
    }

    if (stats.capped) add({ rule: 'capped', severity: 'info', category: 'context', title: 'Very large page', detail: 'Some files were read only in part because the page is unusually big.', source: 'observed' });
    const age = await agePromise;
    if (age?.days != null && age.days < 14) add({ rule: 'new-domain', severity: 'info', category: 'context', title: 'Brand-new domain', detail: `${age.domain} was registered ${age.days} day${age.days === 1 ? '' : 's'} ago.`, source: 'observed' });
    const sb = await safeBrowsing([url.href, finalUrl]);
    if (sb?.length) add({ rule: 'safebrowsing', severity: 'block', category: 'malware', title: 'On Google’s unsafe list', detail: `Google Safe Browsing lists this as ${sb[0].threatType.toLowerCase().replace(/_/g, ' ')}.`, source: 'observed' });

    const out = verdict({ findings, loadError, url, finalUrl, title, stats, age, judged, thumbs, frames, t0 });
    return out;
  } finally {
    signal?.removeEventListener('abort', onAbort);
    await browser.close().catch(() => {});
    proxy.close();
    if (signal?.aborted) throw new Error('scan-timeout');
  }
}

const ORDER = { block: 0, warn: 1, info: 2 };
function verdict({ findings, loadError, url, finalUrl, title, stats, age, judged, thumbs, frames, t0 }) {
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const blocks = findings.filter(f => f.severity === 'block'), warns = findings.filter(f => f.severity === 'warn');
  let v, headline, line;
  if (blocks.length) { v = 'unsafe'; headline = 'Do not open this on stream.'; line = blocks[0].title + (blocks.length > 1 ? `, and ${blocks.length - 1} more.` : '.'); }
  else if (loadError) { v = 'unknown'; headline = 'Could not check this link.'; line = loadError; }
  else if (warns.length) { v = 'caution'; headline = 'Look before you open it live.'; line = warns[0].title + (warns.length > 1 ? `, and ${warns.length - 1} more.` : '.'); }
  else { v = 'safe'; headline = 'Safe to open on stream.'; line = 'Nothing explicit, hostile or sneaky turned up after playing it.'; }
  return {
    verdict: v, headline, line, url: url.href, finalUrl, title: (title || '').slice(0, 120),
    findings: findings.map(({ rule, severity, category, title, detail, where, excerpt, thumb, ai, source }) => ({ rule, severity, category, title, detail, where, excerpt, thumb, ai, source })),
    frames: frames.map((f, i) => ({ label: f.label, thumb: thumbs[i] })),
    stats: { requests: stats.requests, blocked: stats.blocked, hosts: stats.hosts.size, scripts: stats.scripts, mb: +(stats.scriptBytes / 1e6).toFixed(2),
      images: stats.images, frames: stats.frames, cleared: judged.filter(j => j.cleared).length, domainDays: age?.days ?? null, seconds: +((Date.now() - t0) / 1000).toFixed(1),
      engines: ['chromium', 'nsfwjs', hasJev() && 'jev', hasDeepSeek() && 'deepseek'].filter(Boolean) },
  };
}
