// Makes the sandbox look like an ordinary desktop Chrome to the page, in every frame and
// worker, and keeps Waterline's own hooks invisible. Everything here runs before page scripts.
//
// The identity claims the real OS family of the machine (Linux on Vercel), because background
// workers report the real platform and a mismatch between page and worker is itself a tell.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// The Chromium version that will run, known before launch so workers get the same identity.
export function chromiumVersion(onVercel) {
  try {
    if (onVercel) { const v = require('@sparticuz/chromium/package.json').version; return `${v.split('.')[0]}.0.0.0`; }
    const b = JSON.parse(fs.readFileSync(path.join(path.dirname(require.resolve('playwright-core/package.json')), 'browsers.json'), 'utf8'));
    return b.browsers.find(x => x.name === 'chromium-headless-shell')?.browserVersion || '131.0.0.0';
  } catch { return '131.0.0.0'; }
}

const OS = {
  linux: { ua: 'X11; Linux x86_64', uaPlatform: 'Linux', platformVersion: '6.8.0', arch: 'x86', gl: ['Google Inc. (Intel)', 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)'] },
  darwin: { ua: 'Macintosh; Intel Mac OS X 10_15_7', uaPlatform: 'macOS', platformVersion: '15.5.0', arch: 'arm', gl: ['Google Inc. (Apple)', 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)'] },
  win32: { ua: 'Windows NT 10.0; Win64; x64', uaPlatform: 'Windows', platformVersion: '15.0.0', arch: 'x86', gl: ['Google Inc. (Intel)', 'ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00005917) Direct3D11 vs_5_0 ps_5_0, D3D11)'] },
};

export function identity(full, platform = process.platform) {
  const os = OS[platform] || OS.linux;
  const major = String(full).split('.')[0];
  const ua = `Mozilla/5.0 (${os.ua}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
  const brands = [{ brand: 'Google Chrome', version: major }, { brand: 'Chromium', version: major }, { brand: 'Not_A Brand', version: '24' }];
  const fullList = [{ brand: 'Google Chrome', version: full }, { brand: 'Chromium', version: full }, { brand: 'Not_A Brand', version: '24.0.0.0' }];
  return {
    ua, major, full, brands, fullList, os,
    headers: {
      'accept-language': 'en-US,en;q=0.9',
      'sec-ch-ua': brands.map(b => `"${b.brand}";v="${b.version}"`).join(', '),
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': `"${os.uaPlatform}"`,
    },
  };
}

export const stealthArgs = id => ['--disable-blink-features=AutomationControlled', '--lang=en-US', `--user-agent=${id.ua}`, '--window-size=1280,920'];

export function contextOptions(id) {
  return { userAgent: id.ua, locale: 'en-US', timezoneId: 'America/New_York', extraHTTPHeaders: id.headers, colorScheme: 'light' };
}

// Runs first inside workers the page creates from in-page scripts, so a worker tells the same
// story as the page: silent console, same browser brands, same graphics card.
export function workerPrelude(id) {
  const high = { architecture: id.os.arch, bitness: '64', brands: id.brands, fullVersionList: id.fullList, mobile: false, model: '', platform: id.os.uaPlatform, platformVersion: id.os.platformVersion, uaFullVersion: id.full, wow64: false, formFactors: ['Desktop'] };
  return `(() => {
  const nativeToString = Function.prototype.toString, masked = new WeakMap();
  const make = (name, impl, len) => { const w = { [name](...a) { return impl.apply(this, a); } }[name]; try { Object.defineProperty(w, 'length', { value: len ?? impl.length }); Object.defineProperty(w, 'name', { value: name }); } catch {} masked.set(w, 'function ' + name + '() { [native code] }'); return w; };
  Object.defineProperty(Function.prototype, 'toString', { value: make('toString', function () { return masked.has(this) ? masked.get(this) : nativeToString.call(this); }, 0), writable: true, configurable: true, enumerable: false });
  const getter = (o, p, v) => { try { Object.defineProperty(o, p, { get: make('get ' + p, function () { return v; }, 0), configurable: true, enumerable: true }); } catch {} };
  const method = (o, p, f, len) => { try { Object.defineProperty(o, p, { value: make(p, f, len), writable: true, configurable: true, enumerable: false }); } catch {} };
  try { for (const k of ['log', 'debug', 'info', 'warn', 'error', 'dir', 'dirxml', 'table', 'trace', 'group', 'groupCollapsed', 'groupEnd', 'count', 'countReset', 'assert', 'time', 'timeLog', 'timeEnd', 'timeStamp', 'clear']) if (typeof console[k] === 'function') method(console, k, function () {}, 0); } catch {}
  try { getter(WorkerNavigator.prototype, 'webdriver', false); } catch {}
  try { if (self.NavigatorUAData) { const high = ${JSON.stringify(high)}; const P = NavigatorUAData.prototype; getter(P, 'brands', high.brands); getter(P, 'platform', high.platform); getter(P, 'mobile', false); method(P, 'getHighEntropyValues', function (hints) { const o = { brands: high.brands, mobile: false, platform: high.platform }; for (const h of [].concat(hints || [])) if (h in high) o[h] = high[h]; return Promise.resolve(o); }, 1); method(P, 'toJSON', function () { return { brands: high.brands, mobile: false, platform: high.platform }; }, 0); } } catch {}
  try { for (const C of [self.WebGLRenderingContext, self.WebGL2RenderingContext]) { if (!C) continue; const orig = C.prototype.getParameter; method(C.prototype, 'getParameter', function (p) { if (p === 37445) return ${JSON.stringify(id.os.gl[0])}; if (p === 37446) return ${JSON.stringify(id.os.gl[1])}; return orig.call(this, p); }, 1); } } catch {}
})();\n`;
}

// tag: random per scan. Hooks report through the original console.debug with this prefix; the
// page's own console is silenced, so it can neither read nor probe that channel.
export function initScript(id, tag) {
  const F = `function (SELF) {
  const TAG = ${JSON.stringify(tag)};
  const dbg = console.debug.bind(console);
  const L = (k, v) => { try { dbg(TAG + JSON.stringify([k, String(v ?? '').slice(0, 600)])); } catch {} };

  // Replacements look native: no prototype, not constructible, right name and length,
  // and Function.prototype.toString reports them as native code.
  const nativeToString = Function.prototype.toString;
  const masked = new WeakMap();
  const make = (name, impl, len) => {
    const w = { [name](...a) { return impl.apply(this, a); } }[name];
    try { Object.defineProperty(w, 'length', { value: len ?? impl.length }); Object.defineProperty(w, 'name', { value: name }); } catch {}
    masked.set(w, 'function ' + name + '() { [native code] }');
    return w;
  };
  const toString = make('toString', function () { return masked.has(this) ? masked.get(this) : nativeToString.call(this); }, 0);
  Object.defineProperty(Function.prototype, 'toString', { value: toString, writable: true, configurable: true, enumerable: false });
  const getter = (obj, prop, value) => {
    try {
      const C = obj && obj.constructor, onProto = C && C.prototype === obj;
      let g;
      g = make('get ' + prop, function () {
        if (onProto && !(this instanceof C)) { const e = new TypeError('Illegal invocation'); if (Error.captureStackTrace) Error.captureStackTrace(e, g); throw e; }
        return value;
      }, 0);
      Object.defineProperty(obj, prop, { get: g, configurable: true, enumerable: true });
    } catch {}
  };
  const method = (obj, prop, impl, len) => { try { Object.defineProperty(obj, prop, { value: make(prop, impl, len), writable: true, configurable: true, enumerable: false }); } catch {} };

  // The page's console goes nowhere (nobody sees it anyway), which also closes the
  // automation leak where logging a crafted object reveals a debugger listening.
  try { for (const k of ['log', 'debug', 'info', 'warn', 'error', 'dir', 'dirxml', 'table', 'trace', 'group', 'groupCollapsed', 'groupEnd', 'count', 'countReset', 'assert', 'time', 'timeLog', 'timeEnd', 'profile', 'profileEnd', 'timeStamp', 'clear']) if (typeof console[k] === 'function') method(console, k, function () {}, 0); } catch {}

  // Identity details the headless build leaves blank or different.
  getter(Navigator.prototype, 'webdriver', false);
  getter(Navigator.prototype, 'pdfViewerEnabled', true);
  try {
    const brands = ${JSON.stringify(id.brands)}, fullList = ${JSON.stringify(id.fullList)};
    const high = { architecture: ${JSON.stringify(id.os.arch)}, bitness: '64', brands, fullVersionList: fullList, mobile: false, model: '', platform: ${JSON.stringify(id.os.uaPlatform)}, platformVersion: ${JSON.stringify(id.os.platformVersion)}, uaFullVersion: ${JSON.stringify(id.full)}, wow64: false, formFactors: ['Desktop'] };
    const existing = navigator.userAgentData;
    const proto = window.NavigatorUAData ? NavigatorUAData.prototype : Object.prototype;
    if (window.NavigatorUAData && existing) {
      getter(proto, 'brands', brands.map(b => Object.freeze({ ...b })));
      getter(proto, 'platform', high.platform);
      getter(proto, 'mobile', false);
      method(proto, 'getHighEntropyValues', function (hints) { const o = { brands: high.brands, mobile: false, platform: high.platform }; for (const h of [].concat(hints || [])) if (h in high) o[h] = high[h]; return Promise.resolve(o); }, 1);
      method(proto, 'toJSON', function () { return { brands: high.brands, mobile: false, platform: high.platform }; }, 0);
    } else {
      const data = Object.create(proto);
      Object.defineProperties(data, { brands: { get: make('get brands', function () { return brands; }, 0) }, mobile: { get: make('get mobile', function () { return false; }, 0) }, platform: { get: make('get platform', function () { return high.platform; }, 0) } });
      method(data, 'getHighEntropyValues', function (hints) { const o = { brands, mobile: false, platform: high.platform }; for (const h of [].concat(hints || [])) if (h in high) o[h] = high[h]; return Promise.resolve(o); }, 1);
      method(data, 'toJSON', function () { return { brands, mobile: false, platform: high.platform }; }, 0);
      getter(Navigator.prototype, 'userAgentData', data);
    }
  } catch {}

  // Plugins and mime types as in a normal desktop Chrome.
  try {
    if (!navigator.plugins.length) {
      const names = ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'];
      const mimes = Object.create(MimeTypeArray.prototype), plugins = Object.create(PluginArray.prototype);
      const mt = [['application/pdf', 'pdf'], ['text/pdf', 'pdf']].map(([type, suffixes]) => { const m = Object.create(MimeType.prototype); Object.defineProperties(m, { type: { get: () => type }, suffixes: { get: () => suffixes }, description: { get: () => 'Portable Document Format' } }); return m; });
      const pl = names.map(name => { const p = Object.create(Plugin.prototype); Object.defineProperties(p, { name: { get: () => name }, filename: { get: () => 'internal-pdf-viewer' }, description: { get: () => 'Portable Document Format' }, length: { get: () => mt.length } }); mt.forEach((m, i) => Object.defineProperty(p, i, { get: () => m })); return p; });
      pl.forEach((p, i) => Object.defineProperty(plugins, i, { get: () => p, enumerable: true }));
      mt.forEach((m, i) => Object.defineProperty(mimes, i, { get: () => m, enumerable: true }));
      Object.defineProperty(plugins, 'length', { get: () => pl.length }); Object.defineProperty(mimes, 'length', { get: () => mt.length });
      method(plugins, 'item', function (i) { return pl[i] || null; }, 1); method(plugins, 'namedItem', function (n) { return pl.find(p => p.name === n) || null; }, 1); method(plugins, 'refresh', function () {}, 0);
      method(mimes, 'item', function (i) { return mt[i] || null; }, 1); method(mimes, 'namedItem', function (n) { return mt.find(m => m.type === n) || null; }, 1);
      mt.forEach(m => Object.defineProperty(m, 'enabledPlugin', { get: () => pl[0] }));
      getter(Navigator.prototype, 'plugins', plugins);
      getter(Navigator.prototype, 'mimeTypes', mimes);
    }
  } catch {}

  // The window.chrome object a real Chrome page sees.
  try {
    if (!window.chrome) {
      const chrome = { app: { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' } }, runtime: {} };
      method(chrome.app, 'getDetails', function () { return null; }, 0); method(chrome.app, 'getIsInstalled', function () { return false; }, 0); method(chrome.app, 'runningState', function () { return 'cannot_run'; }, 0);
      method(chrome, 'loadTimes', function () { const t = performance.timeOrigin / 1000; return { requestTime: t, startLoadTime: t, commitLoadTime: t + 0.1, finishDocumentLoadTime: t + 0.3, finishLoadTime: t + 0.5, firstPaintTime: t + 0.2, firstPaintAfterLoadTime: 0, navigationType: 'Other', wasFetchedViaSpdy: true, wasNpnNegotiated: true, npnNegotiatedProtocol: 'h2', wasAlternateProtocolAvailable: false, connectionInfo: 'h2' }; }, 0);
      method(chrome, 'csi', function () { return { onloadT: Date.now(), startE: Date.now() - 500, pageT: 500, tran: 15 }; }, 0);
      Object.defineProperty(window, 'chrome', { value: chrome, writable: true, configurable: true, enumerable: true });
    }
  } catch {}

  // A real graphics card instead of the software renderer.
  try {
    for (const C of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
      if (!C) continue;
      const orig = C.prototype.getParameter;
      method(C.prototype, 'getParameter', function (p) {
        if (p === 37445) return ${JSON.stringify(id.os.gl[0])};
        if (p === 37446) return ${JSON.stringify(id.os.gl[1])};
        return orig.call(this, p);
      }, 1);
    }
  } catch {}

  // Screen and window frame like a laptop with a browser window around the page.
  try {
    getter(Screen.prototype, 'width', 1920); getter(Screen.prototype, 'height', 1080);
    getter(Screen.prototype, 'availWidth', 1920); getter(Screen.prototype, 'availHeight', 1050);
    getter(Screen.prototype, 'colorDepth', 24); getter(Screen.prototype, 'pixelDepth', 24);
    const win = (prop, fn) => { try { Object.defineProperty(window, prop, { get: make('get ' + prop, fn, 0), set: make('set ' + prop, function () {}, 1), configurable: true, enumerable: true }); } catch {} };
    win('outerWidth', () => window.innerWidth + 16); win('outerHeight', () => window.innerHeight + 87);
    win('screenX', () => 120); win('screenY', () => 30); win('screenLeft', () => 120); win('screenTop', () => 30);
  } catch {}

  // Notification permission reads "ask" like a fresh profile, consistently in both APIs.
  try {
    if (window.Notification) getter(Notification, 'permission', 'default');
    if (navigator.permissions) {
      const q = Permissions.prototype.query;
      method(Permissions.prototype, 'query', function (d) { return d && d.name === 'notifications' ? Promise.resolve(Object.setPrototypeOf({ state: 'prompt', onchange: null, name: 'notifications' }, PermissionStatus.prototype)) : q.call(this, d); }, 1);
    }
  } catch {}

  // Workers made from in-page scripts start with the same disguise. The constructors are
  // transparent proxies, so they still read as native Worker / SharedWorker.
  try {
    const PRE = ${JSON.stringify(workerPrelude(id))};
    for (const name of ['Worker', 'SharedWorker']) {
      const W = window[name]; if (!W) continue;
      const P = new Proxy(W, { construct(target, args, nt) {
        try {
          const abs = new URL(String(args[0]), location.href).href;
          if (abs.startsWith('blob:') || abs.startsWith('data:')) {
            const mod = args[1] && typeof args[1] === 'object' && args[1].type === 'module';
            const src = PRE + (mod ? 'await import(' + JSON.stringify(abs) + ');' : 'importScripts(' + JSON.stringify(abs) + ');');
            args = [URL.createObjectURL(new Blob([src], { type: 'text/javascript' })), ...args.slice(1)];
          }
        } catch {}
        return Reflect.construct(target, args, nt);
      } });
      Object.defineProperty(window, name, { value: P, writable: true, configurable: true, enumerable: false });
    }
  } catch {}

  // Waterline's clock. Timers run normally; a private event (random name, no global) jumps time
  // forward and fires whatever was waiting, so delayed payloads show up without a trace.
  try {
    const nST = window.setTimeout.bind(window), nCT = window.clearTimeout.bind(window), nSI = window.setInterval.bind(window), nCI = window.clearInterval.bind(window);
    const RealDate = Date, realNow = RealDate.now.bind(RealDate), perfProto = Object.getPrototypeOf(performance), perfNow = perfProto.now;
    let skew = 0;
    const now = () => realNow() + skew;
    const timers = new Map();
    const run = (fn, args) => { try { typeof fn === 'function' ? fn(...args) : (0, eval)(String(fn)); } catch (e) { nST(() => { throw e; }, 0); } };
    method(window, 'setTimeout', function (fn, ms, ...args) { const d = Math.max(0, +ms || 0); const id = nST(() => { timers.delete(id); run(fn, args); }, d); timers.set(id, { fn, args, due: now() + d, every: 0 }); return id; }, 1);
    method(window, 'setInterval', function (fn, ms, ...args) { const d = Math.max(0, +ms || 0); const id = nSI(() => { const t = timers.get(id); if (t) t.due = now() + d; run(fn, args); }, d); timers.set(id, { fn, args, due: now() + d, every: Math.max(1, d) }); return id; }, 1);
    method(window, 'clearTimeout', function (id) { timers.delete(id); nCT(id); }, 0);
    method(window, 'clearInterval', function (id) { timers.delete(id); nCI(id); }, 0);
    const FakeDate = function Date(...a) { if (!new.target) return new RealDate(now()).toString(); return a.length ? new RealDate(...a) : new RealDate(now()); };
    FakeDate.prototype = RealDate.prototype;
    Object.defineProperty(FakeDate, 'length', { value: 7 });
    masked.set(FakeDate, 'function Date() { [native code] }');
    method(FakeDate, 'now', function () { return now(); }, 0); method(FakeDate, 'parse', function (s) { return RealDate.parse(s); }, 1); method(FakeDate, 'UTC', function (...a) { return RealDate.UTC(...a); }, 7);
    Object.defineProperty(window, 'Date', { value: FakeDate, writable: true, configurable: true, enumerable: false });
    method(perfProto, 'now', function () { return perfNow.call(performance) + skew; }, 0);
    window.addEventListener(TAG + 'ff', e => {
      const end = now() + (+e.detail || 0);
      for (let guard = 0; guard < 5000; guard++) {
        let next = null, nextId = null;
        for (const [id, t] of timers) if (t.due <= end && (!next || t.due < next.due)) { next = t; nextId = id; }
        if (!next) break;
        if (next.due > now()) skew += next.due - now();
        if (next.every) { next.due += next.every; run(next.fn, next.args); }
        else { timers.delete(nextId); nCT(nextId); run(next.fn, next.args); }
      }
      if (end > now()) skew += end - now();
    }, true);
  } catch {}

  // Waterline's own hooks: what the page tries to do to the visitor, recorded without a trace.
  try { if (navigator.clipboard) { const C = Object.getPrototypeOf(navigator.clipboard); method(C, 'writeText', function (t) { L('clipboard', t); return Promise.resolve(); }, 1); method(C, 'write', function () { L('clipboard', '[binary]'); return Promise.resolve(); }, 1); } } catch {}
  try { const ec = Document.prototype.execCommand; method(Document.prototype, 'execCommand', function (c, ...a) { if (String(c).toLowerCase() === 'copy') { try { L('clipboard', String(getSelection() || document.activeElement?.value || '')); } catch {} } return ec.call(this, c, ...a); }, 1); } catch {}
  try { method(window, 'open', function (u) { L('open', u); return null; }, 0); } catch {}
  try { if (navigator.mediaDevices) method(MediaDevices.prototype, 'getUserMedia', function (c) { L('media', JSON.stringify(c)); return Promise.reject(new DOMException('Permission denied', 'NotAllowedError')); }, 0); } catch {}
  try { if (window.Notification) method(Notification, 'requestPermission', function () { L('notify', ''); return Promise.resolve('denied'); }, 0); } catch {}
  try { method(Element.prototype, 'requestFullscreen', function () { L('fullscreen', ''); return Promise.resolve(); }, 0); } catch {}
  try { if (navigator.geolocation) method(Geolocation.prototype, 'getCurrentPosition', function () { L('geo', ''); }, 1); } catch {}
  try { if (navigator.serviceWorker) method(ServiceWorkerContainer.prototype, 'register', function () { L('sw', ''); return Promise.reject(new DOMException('Failed to register a ServiceWorker', 'SecurityError')); }, 1); } catch {}

  // Blank frames made by the page (about:blank, srcdoc) get a fresh copy of every browser
  // object before any init script runs there. Apply the same disguise on first access.
  try {
    const done = new WeakSet([window]);
    const cover = w => { try { if (w && !done.has(w)) { done.add(w); const href = w.location.href; if (href === 'about:blank' || href === 'about:srcdoc' || w.location.origin === location.origin) w.eval('(' + SELF + ')(' + JSON.stringify(SELF) + ')'); } } catch {} return w; };
    for (const [C, prop] of [[window.HTMLIFrameElement, 'contentWindow'], [window.HTMLFrameElement, 'contentWindow'], [window.HTMLObjectElement, 'contentWindow']]) {
      if (!C) continue;
      const d = Object.getOwnPropertyDescriptor(C.prototype, prop); if (!d || !d.get) continue;
      const orig = d.get;
      Object.defineProperty(C.prototype, prop, { get: make('get ' + prop, function () { return cover(orig.call(this)); }, 0), configurable: true, enumerable: true });
    }
    for (const [C, prop] of [[window.HTMLIFrameElement, 'contentDocument'], [window.HTMLFrameElement, 'contentDocument']]) {
      if (!C) continue;
      const d = Object.getOwnPropertyDescriptor(C.prototype, prop); if (!d || !d.get) continue;
      const orig = d.get, cwGet = Object.getOwnPropertyDescriptor(C.prototype, 'contentWindow').get;
      Object.defineProperty(C.prototype, prop, { get: make('get ' + prop, function () { try { cwGet.call(this); } catch {} return orig.call(this); }, 0), configurable: true, enumerable: true });
    }
  } catch {}
}`;
  return '(' + F + ')(' + JSON.stringify(F) + ');';
}

export const newTag = () => 'wl' + crypto.randomBytes(9).toString('hex') + ':';

// What a page can see about the browser, for checking the disguise holds.
export const FINGERPRINT = async () => {
  const gl = document.createElement('canvas').getContext('webgl'); const dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');
  const ua = navigator.userAgentData;
  const hi = ua ? await ua.getHighEntropyValues(['platform', 'platformVersion', 'fullVersionList']).catch(() => null) : null;
  const leaks = Object.getOwnPropertyNames(window).filter(k => /^(__wl|__pw|__playwright|playwright|cdc_|\$cdc|domAutomation|callPhantom|_phantom|__nightmare|_selenium|__driver|__webdriver)/i.test(k));
  const worker = await new Promise(res => {
    try {
      const w = new Worker(URL.createObjectURL(new Blob(['postMessage({ua:navigator.userAgent,platform:navigator.platform,lang:navigator.languages.join(","),hc:navigator.hardwareConcurrency})'], { type: 'text/javascript' })));
      w.onmessage = e => res(e.data); setTimeout(() => res(null), 2000);
    } catch { res(null); }
  });
  const nat = f => { try { return /\[native code\]/.test(Function.prototype.toString.call(f)) && !('prototype' in f); } catch { return false; } };
  return {
    webdriver: navigator.webdriver, userAgent: navigator.userAgent, platform: navigator.platform, uaPlatform: ua && ua.platform,
    brands: ua && ua.brands.map(b => b.brand + ' ' + b.version).join(' | '), highEntropyPlatform: hi && hi.platform,
    worker, workerMatches: !!worker && worker.ua === navigator.userAgent && worker.platform === navigator.platform,
    plugins: navigator.plugins.length, mimeTypes: navigator.mimeTypes.length, languages: navigator.languages.join(','),
    webglRenderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : 'none',
    screen: screen.width + 'x' + screen.height, outer: outerWidth + 'x' + outerHeight, chrome: typeof window.chrome,
    notification: window.Notification && Notification.permission, permNotification: navigator.permissions ? (await navigator.permissions.query({ name: 'notifications' })).state : null,
    nativeLooking: { setTimeout: nat(setTimeout), open: nat(window.open), toString: nat(Function.prototype.toString), webdriverGetter: nat(Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver').get), consoleLog: nat(console.log) },
    leaks, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  };
};

// Worker scripts loaded from a URL get the same disguise prepended at the network level, so the
// worker keeps its real address and relative paths. Returns true when it handled the request.
export async function patchWorkerScript(route, id) {
  const req = route.request();
  if (req.resourceType() !== 'script') return false;
  // Requests made by a worker have no owning frame; page scripts always do.
  let fromWorker = false;
  try { req.frame(); } catch { fromWorker = true; }
  if (!fromWorker) return false;
  try {
    const resp = await route.fetch();
    const ct = resp.headers()['content-type'] || '';
    if (resp.status() !== 200 || !/javascript|ecmascript|text\/plain/i.test(ct)) { await route.fulfill({ response: resp }); return true; }
    const body = await resp.text();
    await route.fulfill({ response: resp, body: workerPrelude(id) + body });
  } catch { try { await route.continue(); } catch {} }
  return true;
}
