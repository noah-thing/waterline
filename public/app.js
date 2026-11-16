// Waterline front end: the berg, the sounding, the report.
const $ = s => document.querySelector(s);
const hero = $('#hero');
const photo = $('#photo'), asciiC = $('#ascii');
const pctx = photo.getContext('2d'), actx = asciiC.getContext('2d');
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const input = $('#url');

// Source image (1536 x 1024): waterline and peak tip rows.
const IMG_W = 1536, IMG_H = 1024, WL = 415, TIP = 175;
const RAMP = ' .,:;-=+*#%@';
const CODE = '01{}[]<>/\\=+*#$%&;:~^|';
const STAGES = ['address', 'render', 'play', 'code', 'images', 'judge'];
const STAGE_NAME = { address: 'Address', render: 'Render', play: 'Play', code: 'Code', images: 'Images', judge: 'Judge' };
const TARGET = { address: 0.04, render: 0.2, play: 0.37, code: 0.55, images: 0.72, judge: 0.88 };
const TONES = { safe: '#7ee2b8', caution: '#f2c46b', unsafe: '#ff5d47', unknown: '#9db1c4' };
const WORD = { safe: 'Safe.', caution: 'Careful.', unsafe: 'Unsafe.', unknown: 'Unclear.' };
const VERDICT_TAG = { safe: 'Safe', caution: 'Check first', unsafe: 'Unsafe', unknown: 'Unclear' };

const img = new Image();
img.src = '/assets/berg.jpg';

let W = 0, H = 0, dpr = 1, geo = null, grid = null, dockRect = null;
const S = { state: 'idle', t0: performance.now(), stage: null, stageT: 0, progress: 0, shown: 0, tone: null, toneT: 0, toneRGB: [191, 227, 255], glitch: 0 };

// ── Geometry ───────────────────────────────────────────────
function layout() {
  W = innerWidth; H = hero.clientHeight; dpr = Math.min(devicePixelRatio || 1, 2);
  const phone = W < 760;
  const mark = $('#mark');
  mark.style.fontSize = '';
  let fs = parseFloat(getComputedStyle(mark).fontSize);
  const top = phone ? 116 : 92;  // first free pixel under the bar (phone has the credit row)
  const peak = WL - TIP;         // peak height in image pixels
  // The wordmark sits wholly above the peak: cap top >= top, baseline = tip - gap.
  // Short screens drop the waterline, then shrink the berg, then the wordmark.
  let s = Math.max(W / IMG_W, H / IMG_H) * (phone ? 0.82 : 1);
  let wlY = Math.round(H * (phone ? 0.39 : 0.46));
  const need = () => top + 0.72 * fs + 0.1 * fs;
  if (wlY - peak * s < need()) wlY = Math.min(Math.round(H * (phone ? 0.44 : 0.54)), Math.round(need() + peak * s));
  if (wlY - peak * s < need()) s = Math.max(s * 0.62, (wlY - need()) / peak);
  if (wlY - peak * s < need()) { fs = Math.max(56, (wlY - peak * s - top) / 0.82); mark.style.fontSize = fs + 'px'; }
  const x = (W - IMG_W * s) / 2, y = wlY - WL * s;
  geo = { s, x, y, wlY, tipY: y + TIP * s, phone };
  for (const c of [photo, asciiC]) { c.width = Math.round(W * dpr); c.height = Math.round(H * dpr); }
  hero.style.setProperty('--wl', wlY + 'px');
  // Measure where the baseline falls inside the h1 so it lands just above the tip.
  const probe = document.createElement('i'); probe.style.cssText = 'display:inline-block;width:0;height:0;vertical-align:baseline';
  mark.appendChild(probe);
  const base = probe.getBoundingClientRect().top - mark.getBoundingClientRect().top; probe.remove();
  hero.style.setProperty('--mark-y', Math.max(top - (base - 0.72 * fs), geo.tipY - 0.1 * fs - base) + 'px');
  input.placeholder = phone ? 'Paste a link' : 'Paste a link: game, site, anything';
  if (img.complete && img.naturalWidth) { drawPhoto(); buildGrid(); }
  requestAnimationFrame(measureDock);
}

// Where the peak's left flank dissolves into ASCII (screen x, from fully ASCII to fully photo).
const dissolve = () => ({ x0: geo.x + 470 * geo.s, x1: geo.x + 790 * geo.s });

function drawPhoto() {
  const { s, x, y, wlY } = geo, iw = IMG_W * s, ih = IMG_H * s;
  pctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  pctx.fillStyle = '#04070c'; pctx.fillRect(0, 0, W, H);
  // The photo, its edges faded into the dark ground, its left flank dissolved for the ASCII.
  const off = document.createElement('canvas'); off.width = photo.width; off.height = photo.height;
  const o = off.getContext('2d'); o.setTransform(dpr, 0, 0, dpr, 0, 0);
  o.drawImage(img, x, y, iw, ih);
  o.globalCompositeOperation = 'destination-out';
  const cut = (x0, y0, x1, y1, a0, a1, rx, ry, rw, rh) => {
    const g = o.createLinearGradient(x0, y0, x1, y1); g.addColorStop(0, `rgba(0,0,0,${a0})`); g.addColorStop(1, `rgba(0,0,0,${a1})`);
    o.fillStyle = g; o.fillRect(rx, ry, rw, rh);
  };
  const F = Math.min(220, iw * 0.15);
  cut(x, 0, x + F, 0, 1, 0, x - 1, y, F + 1, ih); cut(x + iw - F, 0, x + iw, 0, 0, 1, x + iw - F, y, F + 1, ih);
  const FT = Math.min(ih * 0.32, 340); cut(0, y, 0, y + FT, 1, 0, x, y - 1, iw, FT + 1); cut(0, y + ih - F, 0, y + ih, 0, 1, x, y + ih - F, iw, F + 1);
  const d = dissolve();
  cut(d.x0, 0, d.x1, 0, 0.92, 0, 0, 0, d.x1, wlY - 1);
  pctx.setTransform(1, 0, 0, 1, 0, 0); pctx.drawImage(off, 0, 0); pctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  // Below the waterline the photo sinks back so the ASCII carries it.
  let g = pctx.createLinearGradient(0, wlY, 0, H); g.addColorStop(0, 'rgba(4,7,12,.8)'); g.addColorStop(1, 'rgba(4,7,12,.94)');
  pctx.fillStyle = g; pctx.fillRect(0, wlY + 1, W, H - wlY);
  // The hero hands over to the page below without a seam.
  g = pctx.createLinearGradient(0, H - 160, 0, H); g.addColorStop(0, 'rgba(4,7,12,0)'); g.addColorStop(1, '#04070c');
  pctx.fillStyle = g; pctx.fillRect(0, H - 160, W, 160);
}

function buildGrid() {
  const { s, x, y, wlY, phone } = geo;
  const cw = phone ? 7 : 8, ch = phone ? 12 : 14;
  const cols = Math.ceil(W / cw), rows = Math.ceil((H - wlY) / ch);
  const off = document.createElement('canvas'); off.width = cols; off.height = rows;
  const o = off.getContext('2d', { willReadFrequently: true });
  o.fillStyle = '#04070c'; o.fillRect(0, 0, cols, rows);
  o.drawImage(img, x / cw, (y - wlY) / ch, IMG_W * s / cw, IMG_H * s / ch);
  const px = o.getImageData(0, 0, cols, rows).data;
  const v = new Float32Array(cols * rows), chars = new Array(cols * rows), flick = new Float32Array(cols * rows);
  for (let i = 0; i < cols * rows; i++) {
    const l = 0.3 * px[i * 4] + 0.59 * px[i * 4 + 1] + 0.11 * px[i * 4 + 2];
    v[i] = Math.pow(Math.min(1, Math.max(0, (l - 26) / 120)), 0.85);
    chars[i] = RAMP[Math.round(v[i] * (RAMP.length - 1))];
  }
  // Above the waterline: the peak's flank, read as ASCII.
  const upTop = Math.max(0, geo.tipY - 16), upRows = Math.max(0, Math.floor((wlY - upTop) / ch));
  const up = { top: wlY - upRows * ch, rows: upRows, v: new Float32Array(cols * upRows), chars: new Array(cols * upRows) };
  if (upRows) {
    const o2 = document.createElement('canvas').getContext('2d', { willReadFrequently: true });
    o2.canvas.width = cols; o2.canvas.height = upRows;
    o2.fillStyle = '#04070c'; o2.fillRect(0, 0, cols, upRows);
    o2.drawImage(img, x / cw, (y - up.top) / ch, IMG_W * s / cw, IMG_H * s / ch);
    const q = o2.getImageData(0, 0, cols, upRows).data;
    for (let i = 0; i < cols * upRows; i++) {
      const l = 0.3 * q[i * 4] + 0.59 * q[i * 4 + 1] + 0.11 * q[i * 4 + 2];
      up.v[i] = Math.pow(Math.min(1, Math.max(0, (l - 40) / 170)), 0.9);
      up.chars[i] = RAMP[Math.round(up.v[i] * (RAMP.length - 1))];
    }
  }
  grid = { cw, ch, cols, rows, v, chars, flick, up, font: `${phone ? 10 : 11}px "Plex Mono", ui-monospace, monospace` };
}

function measureDock() {
  const h = hero.getBoundingClientRect();
  const els = S.state === 'done' ? [$('#report')] : [...document.querySelectorAll('.lede, #form, #log')];
  let l = 1e9, t = 1e9, r = -1e9, b = -1e9;
  for (const k of els) { const q = k.getBoundingClientRect(); if (!q.width) continue; l = Math.min(l, q.left); t = Math.min(t, q.top); r = Math.max(r, q.right); b = Math.max(b, q.bottom); }
  const pad = S.state === 'done' ? 40 : 16;
  dockRect = r > l ? { l: l - h.left - 48, t: t - h.top - pad, r: r - h.left + 48, b: b - h.top + 16 } : null;
}

const lineY = p => geo.wlY + 18 + p * (H - geo.wlY - 60);

// ── Render loop ────────────────────────────────────────────
const ease = t => 1 - Math.pow(1 - t, 3);
const hexRGB = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16));
const goLabel = $('#goLabel');

function frame(now) {
  requestAnimationFrame(frame);
  if (!grid) return;
  const t = (now - S.t0) / 1000;
  if (S.state === 'scanning' && S.stage) {
    const i = STAGES.indexOf(S.stage), a = TARGET[S.stage], b = i < 5 ? TARGET[STAGES[i + 1]] : 0.98;
    S.progress = a + (b - a) * 0.85 * (1 - Math.exp(-(now - S.stageT) / 5000));
  }
  S.shown += (S.progress - S.shown) * (reduce ? 1 : 0.07);
  drawAscii(now, t);
  if (S.state === 'scanning') {
    const depth = String(Math.round(S.shown * 500)).padStart(3, '0');
    goLabel.textContent = 'Depth ' + depth + ' m';
  }
}

function drawAscii(now, t) {
  const { cw, ch, cols, rows, v, chars, flick, font } = grid;
  const wl = geo.wlY;
  actx.setTransform(dpr, 0, 0, dpr, 0, 0);
  actx.clearRect(0, 0, W, H);
  const intro = reduce ? 1 : ease(Math.min(1, t / 1.6));
  actx.fillStyle = 'rgba(238,243,247,.42)';
  actx.fillRect(W / 2 - (W / 2) * intro, wl, W * intro, 1);

  actx.font = font; actx.textBaseline = 'top';
  const scanning = S.state === 'scanning';
  const ly = lineY(S.shown);
  const tone = S.tone ? S.toneRGB : null;
  const toneR = S.tone ? (reduce ? 1e5 : ease(Math.min(1, (now - S.toneT) / 1700)) * Math.hypot(W, H)) : 0;
  const glitch = S.glitch > 0 ? Math.max(0, 1 - (now - S.toneT) / 800) : 0;
  const revealRows = reduce ? rows : rows * ease(Math.min(1, Math.max(0, (t - 0.2) / 1.4)));
  const flickRate = scanning ? 0.014 : 0.003;
  const buckets = new Map();
  const D = dockRect;

  // The dissolving flank above the water.
  const up = grid.up, dz = dissolve();
  if (up.rows && intro > 0.3) {
    const upA = reduce ? 1 : ease(Math.min(1, Math.max(0, (t - 0.6) / 1.2)));
    for (let r = 0; r < up.rows; r++) {
      const y = up.top + r * ch;
      for (let c = 0; c < cols; c++) {
        const x = c * cw; if (x > dz.x1) break;
        const i = r * cols + c; const b = up.v[i]; if (b < 0.06) continue;
        const k = Math.min(1, (dz.x1 - x) / (dz.x1 - dz.x0));
        let a = (0.25 + 0.75 * b) * k * upA; if (a < 0.05) continue;
        let chr = up.chars[i];
        if (!reduce && Math.random() < 0.004) chr = CODE[(Math.random() * CODE.length) | 0];
        let rC = 191 + (238 - 191) * b, gC = 227 + (243 - 227) * b, bC = 255;
        if (tone) { const dist = Math.hypot(x - W / 2, y - wl); if (dist < toneR) { const kk = Math.min(1, (toneR - dist) / 240) * 0.8; rC += (tone[0] - rC) * kk; gC += (tone[1] - gC) * kk; bC += (tone[2] - bC) * kk; } }
        const key = `${rC >> 3},${gC >> 3},${bC >> 3},${Math.round(a * 12)}`;
        let list = buckets.get(key); if (!list) buckets.set(key, list = []);
        list.push(chr, x, y);
      }
    }
  }
  for (let r = 0; r < Math.min(rows, revealRows); r++) {
    const y = wl + 4 + r * ch;
    const dy = y - ly;
    const rowShift = glitch && Math.random() < 0.1 * glitch ? (Math.random() - 0.5) * 48 * glitch : 0;
    for (let c = 0; c < cols; c++) {
      const i = r * cols + c;
      let b = v[i];
      let chr = chars[i];
      if (b < 0.035) continue;
      if (!reduce) {
        if (flick[i] > now) chr = CODE[(i + (now / 90 | 0)) % CODE.length];
        else if (Math.random() < flickRate * b) flick[i] = now + 80 + Math.random() * 220;
        b *= 0.86 + 0.14 * Math.sin(r * 0.22 - t * 0.9 + c * 0.015);
      }
      const x = c * cw;
      let rC = 93, gC = 115, bC = 138;
      let a = 0.22 + 0.78 * b;
      if (scanning) {
        if (dy > 0) a *= 0.5; else a = Math.min(1, a * 1.15);
        const near = Math.abs(dy);
        if (near < 70) {
          const k = 1 - near / 70;
          a = Math.min(1, a + 0.5 * k * (0.3 + b));
          if (!reduce && Math.random() < 0.25 * k) chr = CODE[(Math.random() * CODE.length) | 0];
          rC += (191 - rC) * k; gC += (227 - gC) * k; bC += (255 - bC) * k;
        }
      }
      const m = Math.min(1, b * 1.1);
      rC += (191 - rC) * m * 0.75; gC += (227 - gC) * m * 0.75; bC += (255 - bC) * m * 0.75;
      if (tone) {
        const dist = Math.hypot(x - W / 2, y - wl);
        if (dist < toneR) {
          const k = Math.min(1, (toneR - dist) / 240) * (0.35 + 0.65 * m);
          rC += (tone[0] - rC) * k; gC += (tone[1] - gC) * k; bC += (tone[2] - bC) * k;
          a = Math.min(1, a + 0.12 * k);
        }
      }
      if (D && x > D.l && x < D.r && y > D.t && y < D.b) {
        const ex = Math.min(x - D.l, D.r - x, y - D.t, D.b - y);
        a *= 0.08 + 0.92 * Math.max(0, 1 - ex / 36);
      }
      if (a < 0.04) continue;
      const key = `${rC >> 3},${gC >> 3},${bC >> 3},${Math.round(a * 12)}`;
      let list = buckets.get(key); if (!list) buckets.set(key, list = []);
      list.push(chr, x + rowShift, y);
    }
  }
  for (const [key, list] of buckets) {
    const [r, g, b, a] = key.split(',').map(Number);
    actx.fillStyle = `rgba(${r << 3},${g << 3},${b << 3},${a / 12})`;
    for (let k = 0; k < list.length; k += 3) actx.fillText(list[k], list[k + 1], list[k + 2]);
  }
  if (scanning) {
    const grad = actx.createLinearGradient(0, ly - 90, 0, ly);
    grad.addColorStop(0, 'rgba(191,227,255,0)'); grad.addColorStop(1, 'rgba(191,227,255,.1)');
    actx.fillStyle = grad; actx.fillRect(0, ly - 90, W, 90);
    actx.fillStyle = 'rgba(191,227,255,.85)'; actx.fillRect(0, ly, W, 1);

  }
}

// ── Wordmark ───────────────────────────────────────────────
const markText = $('#markText');
const GLYPHS = 'ABCDEFGHIKLMNOPRSTUVWXYZabcdefhiklmnorstuvwxz';
function introMark() {
  markText.textContent = '';
  [...'Waterline'].forEach((c, i) => {
    const s = document.createElement('span'); s.className = 'ch'; s.textContent = c;
    s.style.animationDelay = reduce ? '0s' : (0.2 + i * 0.05) + 's';
    markText.appendChild(s);
  });
}
let scrambleRun = 0;
function scrambleTo(word, ms = 900) {
  $('#mark').setAttribute('aria-label', word.replace('.', ''));
  if (reduce) { markText.textContent = word; return; }
  const from = markText.textContent, run = ++scrambleRun, t0 = performance.now();
  const step = now => {
    if (run !== scrambleRun) return;
    const k = Math.min(1, (now - t0) / ms);
    const len = Math.round(from.length + (word.length - from.length) * ease(k));
    let out = '';
    for (let i = 0; i < len; i++) out += k >= ((i + 1) / len) * 0.92 ? (word[i] ?? '') : GLYPHS[(Math.random() * GLYPHS.length) | 0];
    markText.textContent = out;
    if (k < 1) requestAnimationFrame(step); else markText.textContent = word;
  };
  requestAnimationFrame(step);
}
// ── Stream (left edge) ─────────────────────────────────────
const stream = $('#stream');
let streamTimer = null;
function hexLine() {
  const off = (Math.random() * 0xfffff | 0).toString(16).padStart(6, '0');
  const bytes = Array.from({ length: 8 }, () => (Math.random() * 256 | 0).toString(16).padStart(2, '0')).join(' ');
  const glyph = Array.from({ length: 10 }, () => CODE[(Math.random() * CODE.length) | 0]).join('');
  return `${off}  ${bytes}  ${glyph}`;
}
function pushStream(text, real = false, stamp = '') {
  const el = document.createElement('span');
  el.className = 'ln' + (real ? ' real' : '');
  if (real) { const i = document.createElement('i'); i.textContent = stamp.padEnd(8); el.append(i, document.createTextNode(text)); }
  else el.textContent = text;
  stream.appendChild(el);
  while (stream.children.length > 64) stream.firstChild.remove();
  stream.scrollTop = stream.scrollHeight;
}
function startStream() { stream.textContent = ''; if (reduce) return; for (let i = 0; i < 30; i++) pushStream(hexLine()); streamTimer = setInterval(() => pushStream(hexLine()), 70); }
function stopStream() { clearInterval(streamTimer); streamTimer = null; }

// ── Wire (right edge): the real hosts the page contacts ──
const wire = $('#wire');
function pushWire(ev) {
  const el = document.createElement('span');
  const t = document.createElement('b'); t.textContent = (ev.kind || 'get').toUpperCase().padEnd(7);
  const h = document.createElement('i'); h.textContent = String(ev.host || '').slice(0, 42);
  el.append(t, h, document.createTextNode('  ' + String(ev.n || '').padStart(3, '0')));
  wire.appendChild(el);
  while (wire.children.length > 48) wire.firstChild.remove();
}

// ── Live log under the field ───────────────────────────────
const log = $('#log');
function logLine(text, stamp, cls = '') {
  const li = document.createElement('div'); if (cls) li.className = cls;
  if (stamp) { const i = document.createElement('i'); i.textContent = stamp; li.appendChild(i); }
  const span = document.createElement('span'); li.appendChild(span);
  log.appendChild(li);
  while (log.children.length > 3) log.firstChild.remove();
  if (reduce) { span.textContent = text; return; }
  let n = 0; const tw = setInterval(() => { n += 2; span.textContent = text.slice(0, n); if (n >= text.length) clearInterval(tw); }, 14);
}
function logReset(text, cls = 'hint') { log.textContent = ''; const li = document.createElement('div'); li.className = cls; li.textContent = text; log.appendChild(li); }

// ── Flow ───────────────────────────────────────────────────
const form = $('#form'), go = $('#go'), report = $('#report');
function setState(st) { S.state = st; hero.dataset.state = st; }
function setStage(id) {
  S.stage = id; S.stageT = performance.now();
}

function toIdle() {
  stopStream();
  setState('idle'); S.stage = null; S.progress = 0; S.tone = null; S.glitch = 0;
  hero.style.removeProperty('--tone');
  input.readOnly = false; go.disabled = false; goLabel.textContent = 'Check';
  if (markText.textContent !== 'Waterline') scrambleTo('Waterline', 700);
  setTimeout(measureDock, 60);
}
function fail(msg) { toIdle(); logReset(msg, 'err'); input.focus(); }

async function run(url) {
  setState('scanning'); S.progress = 0.01; S.shown = 0;
  input.readOnly = true; go.disabled = true;
  wire.textContent = ''; log.textContent = ''; logLine('Sending to the scanner', '+0.0s');
  startStream();
  setTimeout(measureDock, 450);
  const t0 = performance.now();
  const stamp = () => '+' + ((performance.now() - t0) / 1000).toFixed(1) + 's';
  let res;
  try { res = await fetch('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json', 'x-waterline': '1' }, body: JSON.stringify({ url }) }); }
  catch { return fail('Could not reach Waterline. Check your connection.'); }
  if (!res.ok || !res.body) {
    let msg = 'Something went wrong. Try again.';
    try { msg = (await res.json()).error || msg; } catch {}
    return fail(msg);
  }
  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = '', done = false, result = null;
  while (!done) {
    const { value, done: d } = await reader.read().catch(() => ({ done: true }));
    done = d; if (value) buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      let ev; try { ev = JSON.parse(line); } catch { continue; }
      if (ev.type === 'stage' && STAGES.includes(ev.id)) { setStage(ev.id); pushStream(`── ${STAGE_NAME[ev.id].toUpperCase()} ──`, true, stamp()); }
      else if (ev.type === 'log' && typeof ev.text === 'string') { const t = ev.text.slice(0, 90); logLine(t, stamp()); pushStream(t.slice(0, 60), true, stamp()); }
      else if (ev.type === 'frame' && ev.label) pushStream(`── frame · ${String(ev.label).slice(0, 40)}`, true, stamp());
      else if (ev.type === 'req') pushWire(ev);
      else if (ev.type === 'result') result = ev;
      else if (ev.type === 'error') return fail(ev.error || 'Something went wrong.');
    }
  }
  if (!result) return fail('The scan stopped before it finished. Try again.');
  if (result.cached) for (const st of STAGES) { setStage(st); await new Promise(r => setTimeout(r, reduce ? 0 : 150)); }
  S.progress = 1;
  await new Promise(r => setTimeout(r, reduce ? 0 : 700));
  showReport(result);
}

const SEV_COLOR = { block: 'var(--unsafe)', warn: 'var(--caution)', info: 'var(--frost)' };
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// One plain sentence under the headline, written from what was actually found.
function summary(v, fs, s) {
  const blocks = fs.filter(f => f.severity === 'block').length, warns = fs.filter(f => f.severity === 'warn').length;
  const read = `read ${plural(s.scripts || 0, 'file', 'files')} and ${plural(s.images || 0, 'image', 'images')}`;
  if (v === 'safe') return `Waterline played it, ${read}, and ran its timers seven minutes ahead. Nothing explicit, hostile or sneaky turned up.`;
  if (v === 'unsafe') return `${plural(blocks, 'serious problem', 'serious problems')}${warns ? ` and ${plural(warns, 'thing', 'things')} worth a look` : ''}, found after playing it and reading what it loads.`;
  if (v === 'caution') return `Nothing clearly dangerous, but ${plural(warns, 'thing is', 'things are')} worth a look before you open it live.`;
  return null;
}

function showReport(r) {
  stopStream();
  const v = TONES[r.verdict] ? r.verdict : 'unknown';
  S.progress = 1; S.tone = v; S.toneT = performance.now(); S.toneRGB = hexRGB(TONES[v]); S.glitch = v === 'unsafe' ? 1 : 0;
  hero.style.setProperty('--tone', TONES[v]);
  setState('done');
  scrambleTo(WORD[v], 1000);

  const fs = Array.isArray(r.findings) ? r.findings : [];
  const s = r.stats || {};
  $('#rpWord').textContent = VERDICT_TAG[v];
  $('#rpTime').textContent = r.cached ? 'checked in the last 10 min' : (s.seconds != null ? `in ${Math.round(s.seconds)} seconds` : '');
  $('#rHead').textContent = r.headline || '';


  // Findings, grouped by kind, worst first; notes only when nothing serious was found.
  const list = $('#rList'); list.textContent = '';
  const serious = fs.filter(f => f.severity !== 'info');
  const groups = [];
  // Findings that describe the same threat (seen in the code and seen happening) are one item.
  const kind = f => /iplogger/.test(f.rule) ? 'iplogger' : /^adult|nsfw$/.test(f.rule) || f.rule === 'adult-url' ? 'adult' : /clickfix/.test(f.rule) ? 'clickfix' : /^(frame|image)-nsfw/.test(f.rule) ? 'explicit-image' : f.rule;
  for (const f of (v === 'safe' ? [] : serious)) {
    const g = groups.find(x => x.kind === kind(f));
    if (!g) groups.push({ ...f, kind: kind(f) });
  }
  groups.slice(0, 4).forEach((f, i) => {
    const li = document.createElement('li'); li.style.setProperty('--sev', SEV_COLOR[f.severity] || 'var(--frost)');
    const n = document.createElement('span'); n.className = 'n'; n.textContent = String(i + 1).padStart(2, '0');
    const t = document.createElement('span'); t.className = 't'; t.textContent = f.title;
    const d = document.createElement('span'); d.className = 'd'; d.textContent = f.detail || '';
    li.append(n, t, d); list.appendChild(li);
  });
  if (groups.length > 4) {
    const li = document.createElement('li'); const sp = document.createElement('span'); sp.className = 'n';
    const m = document.createElement('span'); m.className = 'more'; m.textContent = `+ ${plural(groups.length - 4, 'more finding', 'more findings')}`;
    li.append(sp, m); list.appendChild(li);
  }
  list.hidden = !list.children.length;
  $('#rLine').textContent = summary(v, groups.filter(g => g.severity === 'block').concat(groups.filter(g => g.severity === 'warn')), s) || r.line || '';

  const bits = [];
  if (s.requests != null) bits.push(plural(s.requests, 'request', 'requests'));
  if (s.hosts) bits.push(plural(s.hosts, 'host', 'hosts'));
  if (s.cleared) bits.push(`${s.cleared} cleared by AI`);
  if (r.finalUrl || r.url) bits.push(String(r.finalUrl || r.url).replace(/^https?:\/\//, '').replace(/\/$/, '').slice(0, 48));
  $('#rMeta').textContent = bits.join('  ·  ');

  // Keep the whole report on screen: drop list items until it fits, and say how many are left.
  report.hidden = false; report.style.visibility = 'hidden';
  const items = () => [...list.querySelectorAll('li:not(.more-li)')];
  let hiddenCount = Math.max(0, groups.length - 4);
  while (report.scrollHeight > report.clientHeight + 2 && items().length > 1) { items().at(-1).remove(); hiddenCount++; }
  list.querySelector('.more')?.closest('li')?.remove();
  if (hiddenCount) {
    const li = document.createElement('li'); li.className = 'more-li'; const sp = document.createElement('span'); sp.className = 'n';
    const m = document.createElement('span'); m.className = 'more'; m.textContent = `+ ${plural(hiddenCount, 'more finding', 'more findings')}`;
    li.append(sp, m); list.appendChild(li);
    if (report.scrollHeight > report.clientHeight + 2 && items().length > 1) { items().at(-1).remove(); m.textContent = `+ ${plural(hiddenCount + 1, 'more finding', 'more findings')}`; }
  }
  report.style.visibility = ''; report.hidden = true;

  const order = [...report.querySelectorAll('.r-top, .r-head, .r-line, #rList > li, .r-meta')];
  order.forEach((el, i) => { el.classList.add('rv'); el.style.transitionDelay = reduce ? '0s' : (0.35 + i * 0.07).toFixed(2) + 's'; });
  setTimeout(() => {
    report.hidden = false; report.scrollTop = 0;
    requestAnimationFrame(() => requestAnimationFrame(() => { report.classList.add('show'); measureDock(); setTimeout(measureDock, 900); }));
  }, reduce ? 0 : 300);
  setTimeout(() => $('#again').focus({ preventScroll: true }), 1300);
}

function closeReport() {
  report.classList.remove('show');
  setTimeout(() => { report.hidden = true; }, reduce ? 0 : 500);
  toIdle(); logReset('Opens it sealed. Plays it. Reads what is under the surface.');
  input.value = '';
  setTimeout(() => input.focus({ preventScroll: true }), 450);
}

form.addEventListener('submit', e => {
  e.preventDefault();
  if (S.state !== 'idle') return;
  const url = input.value.trim();
  if (!url) { logReset('Paste a link first.', 'err'); input.focus(); return; }
  run(url);
});
$('#again').addEventListener('click', closeReport);
addEventListener('keydown', e => { if (e.key === 'Escape' && S.state === 'done') closeReport(); });
addEventListener('paste', e => {
  if (S.state !== 'idle' || document.activeElement === input) return;
  const t = e.clipboardData?.getData('text')?.trim();
  if (t) { input.value = t; input.focus(); }
});
// ?url= pre-fills the field (never auto-runs).
try { const q = new URLSearchParams(location.search).get('url'); if (q && q.length < 2048) input.value = q; } catch {}

// ── Pin: install as an app where the browser allows it, else show the shortcut ──
let installPrompt = null;
addEventListener('beforeinstallprompt', e => { e.preventDefault(); installPrompt = e; });
const pin = $('#pin'), pinTip = $('#pinTip');
let tipTimer;
function tip(key) {
  pinTip.textContent = '';
  const k1 = document.createElement('kbd'), k2 = document.createElement('kbd'); k1.textContent = key; k2.textContent = 'D';
  pinTip.append('Press ', k1, k2, ' to bookmark Waterline.');
  pinTip.hidden = false; requestAnimationFrame(() => pinTip.classList.add('on'));
  clearTimeout(tipTimer); tipTimer = setTimeout(() => { pinTip.classList.remove('on'); setTimeout(() => { pinTip.hidden = true; }, 250); }, 5000);
}
function pinned() { pin.classList.add('done'); pin.querySelector('span').textContent = 'Pinned'; }
pin.addEventListener('click', async () => {
  if (installPrompt) {
    installPrompt.prompt();
    const { outcome } = await installPrompt.userChoice.catch(() => ({}));
    installPrompt = null;
    if (outcome === 'accepted') return pinned();
  }
  tip(/Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent) ? '⌘' : 'Ctrl');
});
addEventListener('appinstalled', pinned);
if (matchMedia('(display-mode: standalone)').matches) pin.closest('.pin-wrap').hidden = true;

// ── Below the hero: cross-section and reveals ─────────────
function buildCrossSection() {
  const pre = $('#crossSection'); if (!pre || !img.naturalWidth) return;
  const phone = innerWidth < 760;
  const cols = phone ? 58 : 84, rows = phone ? 40 : 58;
  const c = document.createElement('canvas'); c.width = cols; c.height = rows;
  const o = c.getContext('2d', { willReadFrequently: true });
  o.drawImage(img, 300, WL + 6, 936, IMG_H - WL - 6, 0, 0, cols, rows);
  const px = o.getImageData(0, 0, cols, rows).data;
  let html = '';
  for (let r = 0; r < rows; r++) {
    let cls = null, run = '';
    const flush = () => { if (!run) return; html += cls ? `<${cls}>${run}</${cls}>` : run; run = ''; };
    for (let k = 0; k < cols; k++) {
      const i = (r * cols + k) * 4, l = 0.3 * px[i] + 0.59 * px[i + 1] + 0.11 * px[i + 2];
      const n = Math.pow(Math.min(1, Math.max(0, (l - 22) / 110)), 0.8);
      const ch = RAMP[Math.round(n * (RAMP.length - 1))];
      const cl = n > 0.62 ? 'b' : n < 0.22 ? 'i' : null;
      if (cl !== cls) { flush(); cls = cl; }
      run += ch;
    }
    flush(); html += '\n';
  }
  pre.innerHTML = html;
}
const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('seen'); io.unobserve(e.target); } }), { threshold: 0.2 });
document.querySelectorAll('.u-head, .section-art, .limits, .foot2').forEach(el => { el.classList.add('reveal'); io.observe(el); });
document.querySelectorAll('.u-list li').forEach((el, i) => { el.classList.add('reveal'); el.style.transitionDelay = (i * 0.06) + 's'; io.observe(el); });

let rz; addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => { layout(); buildCrossSection(); }, 120); });
introMark();
img.decode().catch(() => {}).then(() => { layout(); buildCrossSection(); S.t0 = performance.now(); });
document.fonts?.ready.then(() => layout());
layout();
requestAnimationFrame(frame);
