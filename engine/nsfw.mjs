// Local image moderation: NSFWJS (MobileNetV2) on the TF.js WASM backend.
// Every image is checked whole and as tiles, so a small explicit image in a
// corner of a big frame still gets caught.
import * as tf from '@tensorflow/tfjs';
import { setWasmPaths } from '@tensorflow/tfjs-backend-wasm';
import * as nsfw from 'nsfwjs';
import sharp from 'sharp';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let modelPromise;

async function model() {
  if (!modelPromise) {
    modelPromise = (async () => {
      setWasmPaths('file://' + path.join(root, 'node_modules/@tensorflow/tfjs-backend-wasm/dist/'));
      const ok = await tf.setBackend('wasm').catch(() => false);
      if (!ok) await tf.setBackend('cpu');
      await tf.ready();
      const origLog = console.log; console.log = () => {};
      try { return await nsfw.load('MobileNetV2'); } finally { console.log = origLog; }
    })();
  }
  return modelPromise;
}

async function classifyRaw(m, buf) {
  const { data, info } = await sharp(buf, { animated: false, limitInputPixels: 25e6 }).resize(224, 224, { fit: 'fill' }).removeAlpha().raw().toBuffer({ resolveWithObject: true });
  const t = tf.tensor3d(new Uint8Array(data), [info.height, info.width, 3]);
  try {
    const preds = await m.classify(t, 5);
    const s = Object.fromEntries(preds.map(p => [p.className, p.probability]));
    return { porn: s.Porn || 0, hentai: s.Hentai || 0, sexy: s.Sexy || 0, neutral: s.Neutral || 0, drawing: s.Drawing || 0 };
  } finally { t.dispose(); }
}

// Returns the worst score over the whole image and its tiles.
export async function classify(buf, { tiles = true } = {}) {
  const m = await model();
  let meta;
  try { meta = await sharp(buf, { animated: false, limitInputPixels: 25e6 }).metadata(); } catch { return null; }
  if (!meta.width || !meta.height || meta.width < 40 || meta.height < 40) return null;
  const png = await sharp(buf, { animated: false, limitInputPixels: 25e6 }).flatten({ background: '#808080' }).png().toBuffer();
  const regions = [null];
  if (tiles && meta.width >= 400 && meta.height >= 300) {
    const w = meta.width, h = meta.height;
    const hw = Math.floor(w / 2), hh = Math.floor(h / 2);
    regions.push(
      { left: 0, top: 0, width: hw, height: hh }, { left: hw, top: 0, width: w - hw, height: hh },
      { left: 0, top: hh, width: hw, height: h - hh }, { left: hw, top: hh, width: w - hw, height: h - hh },
      { left: Math.floor(w / 4), top: Math.floor(h / 4), width: hw, height: hh },
    );
  }
  let worst = null;
  for (const r of regions) {
    const b = r ? await sharp(png, { animated: false, limitInputPixels: 25e6 }).extract(r).toBuffer() : png;
    const s = await classifyRaw(m, b);
    s.explicit = Math.max(s.porn, s.hentai, s.porn + s.hentai * 0.9);
    if (!worst || s.explicit > worst.explicit || (s.explicit === worst.explicit && s.sexy > worst.sexy)) worst = s;
  }
  return worst;
}

// Tiny pixelated thumbnail: enough to see the shape of a frame on stream,
// never enough to show anything explicit.
export async function pixelThumb(buf, cells = 40) {
  try {
    const small = await sharp(buf, { animated: false, limitInputPixels: 25e6 }).resize(cells, Math.round(cells * 0.625), { fit: 'cover', kernel: 'nearest' }).png().toBuffer();
    return 'data:image/png;base64,' + small.toString('base64');
  } catch { return null; }
}

export const warm = () => model();
