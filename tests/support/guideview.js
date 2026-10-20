// Synthetic camera views for the guided-scan tests (tests/guide.test.js): a document laid on a
// table in the analysis window core/guide.js looks at (the outline and a 30% margin around it,
// 288 px across the outline), at any size, shift and turn, with blur, glare, darkness and noise.
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { windowFor } from "../../apps/mobile/src/core/guide.js";

export function pgm(name) {
  const b = gunzipSync(readFileSync(new URL(`../fixtures/docs/${name}.pgm.gz`, import.meta.url)));
  const head = b.toString("latin1", 0, 32).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  const w = +head[1], h = +head[2];
  return { w, h, g: new Uint8ClampedArray(b.subarray(head[0].length, head[0].length + w * h)) };
}

/** A small seeded generator (uniform 0..1). */
export function rng(seed = 1) {
  let r = seed >>> 0;
  return () => ((r = (r * 1664525 + 1013904223) >>> 0) / 4294967296);
}

/** The window for an outline of `ratio` (the analysis picture's size and where the outline is in it). */
export function windowOf(ratio = 85.6 / 54, width = 288) {
  const rect = { x: 290, y: 600, w: 500, h: 500 / ratio }; // anywhere in a bigger frame (the margin must fit): only the shape matters
  return windowFor(rect, 1080, 1920, { width });
}

/** Box blur, `r` pixels each way (r = 0 does nothing). */
export function blur(im, r) {
  if (r <= 0) return im;
  const { w, h } = im;
  const tmp = new Float32Array(w * h), out = new Uint8ClampedArray(w * h);
  const k = 2 * r + 1;
  for (let y = 0; y < h; y++) {
    let s = 0;
    for (let x = -r; x <= r; x++) s += im.g[y * w + Math.min(w - 1, Math.max(0, x))];
    for (let x = 0; x < w; x++) {
      tmp[y * w + x] = s / k;
      s += im.g[y * w + Math.min(w - 1, x + r + 1)] - im.g[y * w + Math.max(0, x - r)];
    }
  }
  for (let x = 0; x < w; x++) {
    let s = 0;
    for (let y = -r; y <= r; y++) s += tmp[Math.min(h - 1, Math.max(0, y)) * w + x];
    for (let y = 0; y < h; y++) {
      out[y * w + x] = s / k;
      s += tmp[Math.min(h - 1, y + r + 1) * w + x] - tmp[Math.max(0, y - r) * w + x];
    }
  }
  return { w, h, g: out };
}

/**
 * A view: `card` (a grey picture) on a table, as the analysis window sees it.
 *   size   the document's width as a share of the outline's (1 fills it)
 *   dx, dy its centre's offset from the outline's centre, in outline sizes
 *   deg    turned clockwise by this much
 *   keyV   top narrower by this share (a phone held at an angle)
 *   table  grey level of the table (or "grain": the wood-like desk)
 *   blurPx, glare (0..1 share of width: a white blob on the document), dark (multiplier), noise (sigma)
 */
export function scene({ card, size = 1, dx = 0, dy = 0, deg = 0, keyV = 0, table = 62, blurPx = 0, glare = 0, dark = 1, noise = 1.2, seed = 3, ratio = 85.6 / 54, empty = false } = {}) {
  const win = windowOf(ratio);
  const { w: W, h: H, guide } = win;
  const rnd = rng(seed);
  const cw = guide.w * size, ch = cw * (card.h / card.w);
  const cx = guide.x + guide.w / 2 + dx * guide.w, cy = guide.y + guide.h / 2 + dy * guide.h;
  const a = (deg * Math.PI) / 180, cos = Math.cos(a), sin = Math.sin(a);
  const g = new Uint8ClampedArray(W * H);
  const sc = card.w / cw;
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      let v = table === "grain" ? 78 + ((y * 7) % 5) * 3 - 6 + Math.sin(x * 0.07 + y * 0.9) * 5 : table;
      if (!empty) {
        const px = x - cx, py = y - cy;
        const rx = px * cos + py * sin, ry = -px * sin + py * cos;      // into the document's own axes
        const vn = ry / ch;                                             // −0.5 (top) .. 0.5
        const kx = 1 + keyV * (vn + 0.5) * 2 - keyV;                    // top narrower when keyV > 0
        const u = (rx / kx) * sc + card.w / 2, vv = ry * sc + card.h / 2;
        // coverage by the distance inside the edge (anti-aliased)
        const d = Math.min(u, card.w - u, vv, card.h - vv) / sc;
        const cover = Math.max(0, Math.min(1, d + 0.5));
        if (cover > 0) {
          const uu = Math.max(0, Math.min(card.w - 1.001, u)), v2 = Math.max(0, Math.min(card.h - 1.001, vv));
          const x0 = uu | 0, y0 = v2 | 0, fx = uu - x0, fy = v2 - y0;
          const c = card.g, p = y0 * card.w + x0;
          const s = c[p] * (1 - fx) * (1 - fy) + c[p + 1] * fx * (1 - fy) + c[p + card.w] * (1 - fx) * fy + c[p + card.w + 1] * fx * fy;
          v = v * (1 - cover) + s * cover;
        }
      }
      g[y * W + x] = v;
    }
  }
  let im = blur({ w: W, h: H, g }, blurPx);
  const out = im.g;
  const gl = { x: cx - cw * 0.12, y: cy - ch * 0.1, r: Math.max(2, glare * guide.w) };
  for (let i = 0; i < out.length; i++) {
    let v = out[i] * dark;
    if (glare) {
      const x = i % W, y = (i / W) | 0, d = Math.hypot(x - gl.x, (y - gl.y) * 1.3) / gl.r;
      if (d < 1.4) v = v + (255 - v) * Math.max(0, Math.min(1, (1.4 - d) * 3));
    }
    v += (rnd() + rnd() + rnd() - 1.5) * 2 * noise;
    out[i] = v;
  }
  return { im, guide, win };
}
