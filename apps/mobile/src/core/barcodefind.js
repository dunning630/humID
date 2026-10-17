// Finding a barcode anywhere in the camera's view, the way a store's scan-and-go app
// does: no frame to line up with. Runs on a small grey copy of the whole view every
// look (a few milliseconds), so the reader can then be pointed at just that spot,
// at full resolution: faster, and it reads from further away.
//
// A barcode is a patch where the picture changes sharply in ONE direction (across the
// bars) and hardly at all in the other (along them). Text and edges change both ways.
// So: per pixel, how much more it changes across than along, in both orientations
// (bars upright, or lying down); averaged over a small neighbourhood; the strongest
// solid patch that's clearly one-directional is the barcode.
// Pure functions on { w, h, g } (one byte per pixel), tested in Node (tests/barcodefind.test.js).

/** Box sums over an integral image: mean of `src` in a (2rx+1)×(2ry+1) window. */
function boxMean(src, w, h, rx, ry) {
  const I = new Float64Array((w + 1) * (h + 1));
  for (let y = 0; y < h; y++) {
    let row = 0;
    for (let x = 0; x < w; x++) { row += src[y * w + x]; I[(y + 1) * (w + 1) + x + 1] = I[y * (w + 1) + x + 1] + row; }
  }
  const out = new Float32Array(w * h);
  for (let y = 0; y < h; y++) {
    const y0 = Math.max(0, y - ry), y1 = Math.min(h, y + ry + 1);
    for (let x = 0; x < w; x++) {
      const x0 = Math.max(0, x - rx), x1 = Math.min(w, x + rx + 1);
      const s = I[y1 * (w + 1) + x1] - I[y0 * (w + 1) + x1] - I[y1 * (w + 1) + x0] + I[y0 * (w + 1) + x0];
      out[y * w + x] = s / ((x1 - x0) * (y1 - y0));
    }
  }
  return out;
}

/** The largest 4-connected region of `mask` (1s), with its box and the sum of `weight` over it. */
function regions(mask, w, h, weight) {
  const seen = new Uint8Array(w * h), out = [];
  const stack = new Int32Array(w * h);
  for (let i = 0; i < w * h; i++) {
    if (!mask[i] || seen[i]) continue;
    let top = 0, n = 0, sum = 0, x0 = w, x1 = 0, y0 = h, y1 = 0;
    stack[top++] = i; seen[i] = 1;
    while (top) {
      const j = stack[--top], x = j % w, y = (j / w) | 0;
      n++; sum += weight[j];
      if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y;
      for (const k of [j - 1, j + 1, j - w, j + w]) {
        if (k < 0 || k >= w * h || seen[k] || !mask[k]) continue;
        if ((k === j - 1 && x === 0) || (k === j + 1 && x === w - 1)) continue;
        seen[k] = 1; stack[top++] = k;
      }
    }
    out.push({ n, sum, x0, y0, x1, y1 });
  }
  return out;
}

/**
 * Where's the barcode? im: a small grey copy of the view (about 400 px on its long side).
 * Returns null, or the strongest: { box: { x, y, w, h } in im's pixels, upright (bars
 * upright: true; lying down: false), strength, direction (how one-directional), score }.
 */
export const locateBarcode = (im, opts) => locateBarcodes(im, opts)[0] || null;

/** Every barcode-like patch in view, strongest first (a store card can lie beside the license). */
export function locateBarcodes(im, { minArea = 0.003, minStrength = 32 } = {}) {
  const { w, h, g } = im;
  const across = [new Float32Array(w * h), new Float32Array(w * h)]; // [bars upright, bars lying down]
  const along = [new Float32Array(w * h), new Float32Array(w * h)];
  for (let y = 1; y < h - 1; y++) for (let x = 1; x < w - 1; x++) {
    const i = y * w + x;
    const gx = Math.abs(g[i + 1] - g[i - 1]), gy = Math.abs(g[i + w] - g[i - w]);
    across[0][i] = gx; along[0][i] = gy;
    across[1][i] = gy; along[1][i] = gx;
  }
  const r = Math.max(3, Math.round(Math.max(w, h) / 80));
  const all = [];
  for (const o of [0, 1]) {
    // averaged over a patch a little longer along the bars than across them
    const A = boxMean(across[o], w, h, o ? r : r * 2, o ? r * 2 : r);
    const B = boxMean(along[o], w, h, o ? r : r * 2, o ? r * 2 : r);
    let max = 0;
    for (let i = 0; i < A.length; i++) if (A[i] > max) max = A[i];
    if (max < 18) continue;
    const thr = Math.max(12, max * 0.35);
    const raw = new Float32Array(w * h);
    for (let i = 0; i < A.length; i++) if (A[i] >= thr && A[i] > 1.3 * B[i] + 3) raw[i] = 1;
    // close the gaps (a stacked barcode's rows, a glare streak): blur the mask, keep what's mostly set
    const filled = boxMean(raw, w, h, r * 2, r * 2);
    const mask = new Uint8Array(w * h), weight = new Float32Array(w * h);
    for (let i = 0; i < A.length; i++) if (filled[i] > 0.35 && A[i] > thr * 0.5) { mask[i] = 1; weight[i] = Math.max(0, A[i] - B[i]); }
    const found = [];
    for (const c of regions(mask, w, h, weight)) {
      const bw = c.x1 - c.x0 + 1, bh = c.y1 - c.y0 + 1;
      if (bw < 4 || bh < 4 || c.n / (bw * bh) < 0.45) continue; // a scatter, not a patch
      // how one-directional the whole patch is
      let sa = 0, sb = 0;
      for (let y = c.y0; y <= c.y1; y++) for (let x = c.x0; x <= c.x1; x++) { const i = y * w + x; if (mask[i]) { sa += A[i]; sb += B[i]; } }
      found.push({ ...c, bw, bh, direction: sa / (sb + 1), strength: c.sum / c.n });
    }
    for (const c of found) {
      if (c.n < minArea * w * h || c.bw < 8 || c.bh < 8 || c.direction < 1.5 || c.strength < minStrength) continue;
      // a far-away barcode breaks into pieces: take in the barcode-like pieces right next to it
      let box = { x0: c.x0, y0: c.y0, x1: c.x1, y1: c.y1 };
      for (let grew = true; grew;) {
        grew = false;
        for (const d of found) {
          if (d === c || d.taken === c || d.direction < 1.3 || d.strength < minStrength * 0.6) continue;
          const gap = Math.max(d.x0 - box.x1, box.x0 - d.x1, d.y0 - box.y1, box.y0 - d.y1);
          if (gap > r * 2) continue;
          box = { x0: Math.min(box.x0, d.x0), y0: Math.min(box.y0, d.y0), x1: Math.max(box.x1, d.x1), y1: Math.max(box.y1, d.y1) };
          d.taken = c; grew = true;
        }
      }
      if (c.taken) continue; // already part of a stronger patch's barcode
      const score = c.sum * Math.min(3, c.direction);
      all.push({ box: { x: box.x0, y: box.y0, w: box.x1 - box.x0 + 1, h: box.y1 - box.y0 + 1 }, upright: o === 0, strength: c.strength, direction: c.direction, score });
    }
  }
  all.sort((a, b) => b.score - a.score);
  // the same barcode seen both ways round (a square-ish patch): keep the stronger
  return all.filter((a, i) => !all.slice(0, i).some((b) => overlap(a.box, b.box) > 0.5));
}

/** How much of the smaller box the two boxes share (0–1). */
export function overlap(a, b) {
  const w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x), h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
  return w <= 0 || h <= 0 ? 0 : (w * h) / Math.min(a.w * a.h, b.w * b.h);
}

/**
 * The part of the view to hand the reader, from a found barcode's box (in the same
 * pixels as W×H). A license's barcode is about three times as long across its bars as
 * along them; from far away only its bold start bars may stand out, so the crop is
 * stretched across the bars to that length both ways, then given a margin.
 */
export function readBox({ box, upright }, W, H, { pad = 0.15, shape = 3.4 } = {}) {
  let { x, y, w, h } = box;
  // short of that shape, it's not known which end was seen: reach out both ways
  if (upright) { const want = h * shape; if (w < want * 0.8) { x -= want - w; w = 2 * want - w; } }
  else { const want = w * shape; if (h < want * 0.8) { y -= want - h; h = 2 * want - h; } }
  const px = Math.max(w * pad, 8), py = Math.max(h * pad, 8);
  const x0 = Math.max(0, x - px), y0 = Math.max(0, y - py);
  return { x: x0, y: y0, w: Math.min(W, x + w + px) - x0, h: Math.min(H, y + h + py) - y0 };
}

/**
 * Where to look again, closer: from a small copy of the whole view, a far-away
 * barcode's fine pattern is a grey blur and only its bold start or stop bars stand
 * out. Around them, wide enough to hold a whole license barcode whichever end was
 * seen, looked at again in its own small copy (finer, since it's a smaller area), the
 * whole barcode shows.
 */
export function searchBox({ box, upright }, W, H, { shape = 3.4 } = {}) {
  const along = upright ? box.h : box.w;
  const reach = along * shape, extra = along * 0.5;
  const x0 = upright ? box.x - reach : box.x - extra, x1 = upright ? box.x + box.w + reach : box.x + box.w + extra;
  const y0 = upright ? box.y - extra : box.y - reach, y1 = upright ? box.y + box.h + extra : box.y + box.h + reach;
  const x = Math.max(0, x0), y = Math.max(0, y0);
  return { x, y, w: Math.min(W, x1) - x, h: Math.min(H, y1) - y };
}

/** A box found in a part of the view (`area`, shown at scale k) → the view's pixels. */
export const fromArea = (b, area, k) => ({ x: area.x + b.x * k, y: area.y + b.y * k, w: b.w * k, h: b.h * k });

/**
 * Which way the bars run, in degrees clockwise from upright (−90 to 90), from the
 * pixels inside `box` of im: the average direction the picture changes in (a
 * structure tensor), which for a barcode is straight across its bars. A slight tilt
 * is enough to stop the reader, so the crop is turned by exactly this much first.
 */
export function barAngle({ w, h, g }, box) {
  let xx = 0, yy = 0, xy = 0;
  const x0 = Math.max(1, Math.round(box.x)), y0 = Math.max(1, Math.round(box.y));
  const x1 = Math.min(w - 1, Math.round(box.x + box.w)), y1 = Math.min(h - 1, Math.round(box.y + box.h));
  for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) {
    // Sobel: steadier than a plain difference on a turned, pixelated pattern
    const i = y * w + x, a = g[i - w - 1], b = g[i - w], c = g[i - w + 1], d = g[i - 1], f = g[i + 1], p = g[i + w - 1], q = g[i + w], r = g[i + w + 1];
    const gx = c + 2 * f + r - a - 2 * d - p, gy = p + 2 * q + r - a - 2 * b - c;
    xx += gx * gx; yy += gy * gy; xy += gx * gy;
  }
  // the gradient's main direction (0 = changing left to right: upright bars)
  const theta = (0.5 * Math.atan2(2 * xy, xx - yy) * 180) / Math.PI;
  return theta;
}

/** A box → its four corners (for drawing). */
export const boxCorners = (b) => [{ x: b.x, y: b.y }, { x: b.x + b.w, y: b.y }, { x: b.x + b.w, y: b.y + b.h }, { x: b.x, y: b.y + b.h }];

/**
 * Keeps hold of a barcode from look to look so its highlight glides instead of
 * flickering, and lets go after a few looks without one.
 */
export function barTracker({ lose = 4 } = {}) {
  let box = null, missed = 0, since = 0;
  return {
    feed(found, now = Date.now()) {
      if (!found) { if (++missed >= lose) { box = null; since = 0; } return box; }
      missed = 0;
      const b = found.box;
      if (!box) { box = { ...b }; since = now; }
      else {
        const far = Math.abs(b.x - box.x) > box.w * 0.5 || Math.abs(b.y - box.y) > box.h * 0.5;
        box = far ? { ...b } : { x: box.x * 0.4 + b.x * 0.6, y: box.y * 0.4 + b.y * 0.6, w: box.w * 0.4 + b.w * 0.6, h: box.h * 0.4 + b.h * 0.6 };
        if (far) since = now;
      }
      return box;
    },
    get box() { return box; },
    /** How long the same barcode has been in view (ms). */
    held(now = Date.now()) { return box ? now - since : 0; },
  };
}
