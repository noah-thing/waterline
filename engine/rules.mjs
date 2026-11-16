// Static analysis rules for HTML and JavaScript.
// Severity: "block" = clear danger, "warn" = worth a look, "info" = context only.
// Rules are tuned to stay quiet on ordinary games and sites; ordinary analytics
// and ad trackers are deliberately NOT flagged.

export const ADULT_DOMAINS = [
  'pornhub', 'xvideos', 'xhamster', 'xnxx', 'redtube', 'youporn', 'spankbang', 'onlyfans', 'fansly',
  'chaturbate', 'stripchat', 'bongacams', 'livejasmin', 'cam4', 'myfreecams', 'brazzers', 'rule34',
  'e621', 'nhentai', 'hentaihaven', 'hanime', 'gelbooru', 'danbooru', 'sankakucomplex', 'motherless',
  'eporner', 'tnaflix', 'porntrex', 'erome', 'thisvid', 'heavy-r', 'efukt', 'theync', 'bestgore',
];
const adultHost = new RegExp(`(?:^|\\.)(?:${ADULT_DOMAINS.map(d => d.replace(/[-.]/g, '\\$&')).join('|')})\\.[a-z.]{2,8}$`, 'i');
export const isAdultHost = host => adultHost.test(host || '');
// Adult names are never printed in full, so the report itself is safe to show on stream.
export const maskHost = host => String(host || '').replace(/^www\./, '').replace(/^([a-z0-9])([a-z0-9-]+)([a-z0-9])(?=\.)/i, (m, a, mid, z) => a + '•'.repeat(Math.min(mid.length, 6)) + z);
const adultUrlInCode = new RegExp(`https?://(?:[a-z0-9-]+\\.)*(?:${ADULT_DOMAINS.join('|')})\\.[a-z.]{2,8}`, 'i');

export const IP_LOGGERS = /(?:grabify\.link|iplogger\.(?:org|com|ru|co|info)|2no\.co|yip\.su|iplis\.ru|ps3cfw\.com|blasze\.(?:com|tk)|ipgrabber\.ru|bmwforum\.co|leancoding\.co|spottyfly\.com|stopify\.co|minecraftcapes\.co|headshot\.monster|gamingfun\.me|crabrave\.pw|lovebird\.guru|trulove\.guru|dateing\.club|shrekis\.life|otherhalf\.life|joinmy\.site|fortnitechat\.site|fortnight\.space|freegiftcards\.co|stopify\.co|catsnthing\.com|curiouscat\.club|canadianlumberjacks\.online)/i;
const IP_LOOKUP = /(?:api\.ipify\.org|api64\.ipify\.org|ipapi\.co|ip-api\.com|ipinfo\.io|ipwho\.is|ipgeolocation\.io|geolocation-db\.com|icanhazip\.com|checkip\.amazonaws\.com|ifconfig\.me)/i;
const WEBHOOK = /(?:discord(?:app)?\.com\/api\/webhooks\/\d+|api\.telegram\.org\/bot\d+:|hooks\.slack\.com\/services\/|webhook\.site\/)/i;

const EXEC_EXT = /\.(?:exe|scr|msi|bat|cmd|ps1|vbs|vbe|jse|wsf|hta|jar|apk|dmg|pkg|lnk|iso|img|com|pif|reg|appx|msix|xll)(?:\?|#|$)/i;
export const ARCHIVE_EXT = /\.(?:zip|rar|7z|tar|gz)(?:\?|#|$)/i;
export const isExecutable = name => EXEC_EXT.test(name || '');

// Hard explicit terms only; words like "sexy" or "kill" are too common to flag.
const EXPLICIT_TEXT = /\b(?:porn(?:hub|o|ography)?|hentai|xxx+|nudes?|blowjob|cumshot|creampie|gangbang|onlyfans leak|dick ?pics?|pussy|titties|camgirl|nsfw content)\b/i;
const SLURS = /\b(?:n[i1]gg(?:er|a)s?|f[a@]gg?[o0]ts?|k[i1]kes?|tr[a@]nn(?:y|ies)|ch[i1]nks?|sp[i1]cs?)\b/i;

function lineOf(text, idx) { return text.slice(0, idx).split('\n').length; }
function snippet(text, idx, len = 160) {
  const s = Math.max(0, idx - 60);
  return text.slice(s, s + len).replace(/\s+/g, ' ').trim();
}

const CODE_RULES = [
  { id: 'clickfix', sev: 'block', cat: 'malware', title: 'Fake "verify you are human" command',
    detail: 'Copies a shell command to the clipboard and asks the visitor to run it. This is the ClickFix malware trick.',
    test: t => /(?:clipboard\.writeText|execCommand\(\s*['"]copy)[\s\S]{0,600}?(?:powershell|mshta|cmd(?:\.exe)?\s*\/c|iex\b|Invoke-(?:WebRequest|Expression)|curl\s+[^\n]{0,80}\|\s*(?:ba)?sh|bitsadmin|certutil)/i.exec(t)
      || /(?:powershell|mshta|iex\b|Invoke-Expression)[\s\S]{0,600}?(?:clipboard\.writeText|execCommand\(\s*['"]copy)/i.exec(t) },
  { id: 'miner', sev: 'block', cat: 'malware', title: 'Cryptocurrency miner',
    detail: 'Contains browser crypto-mining code that would run on your CPU while the page is open.',
    test: t => /(?:coinhive|coin-hive|cryptonight|cryptoloot|webminepool|minero\.cc|deepminer|stratum\+tcp:\/\/|xmrig|CoinImp|monerominer|crypto-loot)/i.exec(t) },
  { id: 'iplogger', sev: 'block', cat: 'privacy', title: 'IP logger',
    detail: 'Calls a known IP-grabbing service. Opening it on stream could leak your IP address.',
    test: t => IP_LOGGERS.exec(t) },
  { id: 'exfil', sev: 'block', cat: 'privacy', title: 'Sends your data to a private webhook',
    detail: 'Looks up visitor IP or reads stored tokens and posts them to a Discord/Telegram webhook.',
    test: t => { const w = WEBHOOK.exec(t); if (!w) return null;
      return (IP_LOOKUP.test(t) || /localStorage\.getItem\(\s*['"]token|document\.cookie|navigator\.userAgent/i.test(t)) ? w : null; } },
  { id: 'webhook', sev: 'warn', cat: 'privacy', title: 'Posts to a chat webhook',
    detail: 'Has a hard-coded Discord/Telegram webhook. Often harmless (score boards), sometimes used to collect visitor data.',
    test: t => WEBHOOK.exec(t) },
  { id: 'adult-url', sev: 'block', cat: 'nsfw', title: 'Links to an adult site in its code',
    detail: 'The code contains an address on a known adult site, which it could open or embed mid-game.',
    test: t => adultUrlInCode.exec(t) },
  { id: 'exe-link', sev: 'warn', cat: 'malware', title: 'Points to an executable download',
    detail: 'The code references a program file (.exe, .apk, .bat…). Games in a browser never need one.',
    test: t => /["'`](?:https?:)?\/\/[^"'`\s]{3,200}\.(?:exe|scr|msi|bat|cmd|ps1|vbs|hta|apk|jar|lnk)["'`?#]/i.exec(t) },
  { id: 'forced-dl', sev: 'warn', cat: 'malware', title: 'Can start a download by itself',
    detail: 'Builds a file in the page and clicks a hidden download link from code.',
    test: t => /createObjectURL\([\s\S]{0,300}?\.download\s*=[\s\S]{0,200}?\.click\(\)/.exec(t) || /msSaveOrOpenBlob|msSaveBlob/.exec(t) },
  { id: 'packed', sev: 'warn', cat: 'code', title: 'Packed code run through eval',
    detail: 'Uses a classic packer so the real code is hidden until it runs.',
    test: t => /eval\(function\(p,a,c,k,e,[rd]\)/.exec(t) },
  { id: 'eval-b64', sev: 'warn', cat: 'code', title: 'Decodes hidden code and runs it',
    detail: 'Runs code that only exists as an encoded string, so it can not be read by looking at the page.',
    test: t => /(?:eval|new\s+Function|setTimeout)\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/.exec(t) },
  { id: 'webcam', sev: 'warn', cat: 'privacy', title: 'Asks for camera or microphone',
    detail: 'Calls getUserMedia. A simple game has no reason to see or hear you.',
    test: t => /getUserMedia\s*\(/.exec(t) },
  { id: 'locker', sev: 'warn', cat: 'hostile', title: 'Tries to trap the browser',
    detail: 'Combines forced fullscreen with blocking you from leaving the page.',
    test: t => (/requestFullscreen|webkitRequestFullscreen/.test(t) && /onbeforeunload|addEventListener\(\s*['"]beforeunload/.test(t) && /(?:pushState[\s\S]{0,120}(?:setInterval|while\s*\(true|for\s*\(;;)|while\s*\(\s*true\s*\)\s*\{?\s*alert)/.test(t)) ? /requestFullscreen|webkitRequestFullscreen/.exec(t) : null },
  { id: 'scare', sev: 'warn', cat: 'stream', title: 'Jumpscare / screamer assets',
    detail: 'Asset names suggest a sudden loud scare, which can hurt viewers and get clipped.',
    test: t => /["'`/][^"'`\s]{0,60}(?:jump_?scare|screamer|scream\d*\.(?:mp3|wav|ogg)|earrape|ear_rape)[^"'`\s]{0,40}["'`]/i.exec(t) },
  { id: 'phish-form', sev: 'warn', cat: 'phishing', title: 'Password form that posts elsewhere',
    detail: 'Has a password field whose form sends data to a different site.',
    test: (t, ctx) => {
      const m = /<form[^>]*action=["'](https?:\/\/[^"']+)["'][^>]*>[\s\S]{0,3000}?type=["']password["']/i.exec(t);
      if (!m) return null; try { return new URL(m[1]).hostname.replace(/^www\./, '') !== ctx.host ? m : null; } catch { return null; } } },
  { id: 'nitro-scam', sev: 'warn', cat: 'phishing', title: 'Free Nitro / skins giveaway bait',
    detail: 'Classic bait text used by account-stealing pages.',
    test: t => /(?:free\s+discord\s+nitro|claim\s+your\s+nitro|steam\s+gift\s+card\s+generator|free\s+(?:robux|v-?bucks)\s+generator)/i.exec(t) },
];

// Heuristic: heavy obfuscation (javascript-obfuscator style). Info only on its
// own: plenty of legit games ship obfuscated builds.
function obfuscationScore(t) {
  const hexVars = (t.match(/_0x[a-f0-9]{4,6}/g) || []).length;
  const hexEsc = (t.match(/\\x[0-9a-f]{2}/gi) || []).length;
  return { hexVars, hexEsc, heavy: hexVars > 400 || hexEsc > 1500 };
}

export function scanCode(text, ctx) {
  const out = [];
  if (!text || text.length < 20) return out;
  const t = text.length > 6_000_000 ? text.slice(0, 6_000_000) : text;
  for (const r of CODE_RULES) {
    let m; try { m = r.test(t, ctx); } catch { m = null; }
    if (m) out.push({ rule: r.id, severity: r.sev, category: r.cat, title: r.title, detail: r.detail,
      where: ctx.source, line: lineOf(t, m.index ?? 0), excerpt: snippet(t, m.index ?? 0), source: 'code' });
  }
  const ob = obfuscationScore(t);
  if (ob.heavy) out.push({ rule: 'obfuscated', severity: 'info', category: 'code', title: 'Heavily obfuscated script',
    detail: 'Common in shipped games and ad scripts; on its own it only means the code is hard to read.', where: ctx.source, source: 'code' });
  return out;
}

export function scanText(text, where) {
  const out = [];
  if (!text) return out;
  const m = EXPLICIT_TEXT.exec(text);
  if (m) out.push({ rule: 'explicit-text', severity: 'warn', category: 'nsfw', title: 'Explicit words on screen',
    detail: 'The page shows sexual terms while running.', where, excerpt: '[hidden]', source: 'observed' });
  const s = SLURS.exec(text);
  if (s) out.push({ rule: 'slur', severity: 'block', category: 'stream', title: 'Slur shown on screen',
    detail: 'Hate speech appears on the page. That alone can get a stream banned.', where, excerpt: '[hidden]', source: 'observed' });
  if (/(?:press|hold)\s+(?:the\s+)?(?:windows|win|⊞)\s*(?:key\s*)?\+\s*r\b/i.test(text) && /ctrl\s*\+\s*v|paste/i.test(text))
    out.push({ rule: 'clickfix-text', severity: 'block', category: 'malware', title: 'Tells you to paste a command into Run',
      detail: 'Shows "Win + R, Ctrl + V" instructions: the ClickFix malware trick.', where, source: 'observed' });
  return out;
}

// Pull embedded images (data URIs) out of code and HTML: the classic way to
// hide an explicit picture inside an innocent-looking game file.
export function extractDataImages(text, limit = 40) {
  const out = [];
  const re = /data:image\/(?:png|jpe?g|gif|webp|bmp);base64,([A-Za-z0-9+/=]{2000,})/g;
  let m; while ((m = re.exec(text)) && out.length < limit) out.push(m[1]);
  return out;
}

// Image URLs referenced in code that the page may only load later.
export function extractImageUrls(text, base, limit = 60) {
  const out = new Set();
  const re = /["'`]((?:https?:)?\/\/[^"'`\s]{3,300}?\.(?:png|jpe?g|gif|webp)|[\w./-]{1,200}?\.(?:png|jpe?g|gif|webp))(?:\?[^"'`\s]*)?["'`]/gi;
  let m; while ((m = re.exec(text)) && out.size < limit) {
    try { out.add(new URL(m[1], base).href); } catch {}
  }
  return [...out];
}
