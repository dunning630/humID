// Camera-like views of real text pages for tests (the same helpers tests/docfind.test.js uses):
// a page (tests/fixtures/docs) laid into a grey view at given corners, tilted, in perspective,
// on a plain or grained table, with sensor noise.
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { homography, rotateGray } from "../../apps/mobile/src/core/docfind.js";

export const fixture = (n) => {
  const b = gunzipSync(readFileSync(new URL(`../fixtures/docs/${n}.pgm.gz`, import.meta.url)));
  const head = b.toString("latin1", 0, 32).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  const w = +head[1], h = +head[2];
  return { w, h, g: new Uint8ClampedArray(b.subarray(head[0].length, head[0].length + w * h)) };
};
export const PAGES = { letter: fixture("page-letter"), a4: fixture("page-a4"), card: fixture("page-card") };

/** Invert the rectangle → corners map, to draw a page into a view. */
export function inverse(H) {
  const [a, b, c, d, e, f, g, h] = H;
  const m = [[a, b, c], [d, e, f], [g, h, 1]];
  const det = m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);
  const inv = [
    [(m[1][1] * m[2][2] - m[1][2] * m[2][1]) / det, (m[0][2] * m[2][1] - m[0][1] * m[2][2]) / det, (m[0][1] * m[1][2] - m[0][2] * m[1][1]) / det],
    [(m[1][2] * m[2][0] - m[1][0] * m[2][2]) / det, (m[0][0] * m[2][2] - m[0][2] * m[2][0]) / det, (m[0][2] * m[1][0] - m[0][0] * m[1][2]) / det],
    [(m[1][0] * m[2][1] - m[1][1] * m[2][0]) / det, (m[0][1] * m[2][0] - m[0][0] * m[2][1]) / det, (m[0][0] * m[1][1] - m[0][1] * m[1][0]) / det],
  ];
  return (x, y) => { const z = inv[2][0] * x + inv[2][1] * y + inv[2][2]; return [(inv[0][0] * x + inv[0][1] * y + inv[0][2]) / z, (inv[1][0] * x + inv[1][1] * y + inv[1][2]) / z]; };
}

/**
 * A camera view W×H with `page` (turned `turn` degrees clockwise) whose corners land on
 * `quad` (tl, tr, br, bl of the turned page). table: grey level or "grain"; thumb: cover
 * part of one side.
 */
export function view({ page, turn = 0, quad, W = 960, H = 720, table = 60, thumb = false, seed = 1 }) {
  let r = seed;
  const rnd = () => ((r = (r * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const p = rotateGray(page, turn);
  const back = inverse(homography(p.w, p.h, quad));
  const g = new Uint8ClampedArray(W * H);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const [u, v] = back(x + 0.5, y + 0.5);
    let val;
    if (u >= 0 && v >= 0 && u < p.w - 1 && v < p.h - 1) val = p.g[(v | 0) * p.w + (u | 0)];
    else val = table === "grain" ? 105 + 18 * Math.sin(x / 9 + 3 * Math.sin(y / 50)) : table;
    if (thumb) { const dx = x - thumb.x, dy = (y - thumb.y) / 1.4; if (dx * dx + dy * dy < thumb.r * thumb.r) val = 150 + (x % 7); }
    g[y * W + x] = Math.max(0, Math.min(255, val * (0.88 + 0.12 * (x / W)) + (rnd() - 0.5) * 10));
  }
  return { w: W, h: H, g };
}

/** Corners for a page centred at (cx, cy), long-side `size`, tilted `deg`, `k` perspective. */
export function place(page, turn, { cx, cy, size, deg = 0, k = 0 }) {
  const sideways = turn % 180 !== 0;
  const pw = sideways ? page.h : page.w, ph = sideways ? page.w : page.h;
  const s = size / Math.max(pw, ph), w = pw * s, h = ph * s, a = (deg * Math.PI) / 180;
  return [[-w / 2 * (1 - k), -h / 2], [w / 2 * (1 - k), -h / 2], [w / 2 * (1 + k), h / 2], [-w / 2 * (1 + k), h / 2]]
    .map(([x, y]) => ({ x: cx + x * Math.cos(a) - y * Math.sin(a), y: cy + x * Math.sin(a) + y * Math.cos(a) }));
}

/** Worst corner distance between two outlines (as fractions of the view's diagonal). */
export function cornerError(found, truth, W, H) {
  let best = Infinity;
  for (let s = 0; s < 4; s++) best = Math.min(best, Math.max(...truth.map((t, i) => Math.hypot(found[(i + s) % 4].x - t.x, found[(i + s) % 4].y - t.y))));
  return best / Math.hypot(W, H);
}

