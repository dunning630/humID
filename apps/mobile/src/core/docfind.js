// Finding a document anywhere in the camera's view, straightening it, and turning
// it the right way up. Plain arithmetic on small grey images, on this device: no
// models, nothing sent anywhere. Pure functions on { w, h, g } (one byte per pixel)
// and on RGBA { width, height, data }, so they're tested in Node with drawn and
// rendered pages (tests/docfind.test.js).
//
//   findDocument   the document's four corners, wherever it is in the picture and
//                  however it's tilted: edges → straight lines (a Hough transform
//                  that votes along each edge's own direction) → the four lines
//                  that best make a document: a convex four-sided shape whose sides
//                  are backed by edge along most of their length, with the inside
//                  consistently lighter (or darker) than the outside, as large as
//                  the picture allows. Then each side is refitted to its own edge
//                  points, so the corners hold at full resolution.
//   lookAt         one live look: the corners plus light, focus and steadiness,
//                  and what to tell the person
//   tracker        smooths the corners between looks and decides when they've held
//                  still long enough to take the photo
//   homography /   the perspective map from a straight rectangle onto the four
//   warp           corners, and the straightened picture (bilinear)
//   orientation    which way up the page reads: the direction text lines run
//                  (projection profiles), then which way is up (ascenders outnumber
//                  descenders; lines start together on the left and end ragged)

const D2R = Math.PI / 180;

/** Proportions (long side / short side) documents commonly have. */
export const PAPER = { id1: 1.586, td3: 1.42, a4: 1.414, letter: 1.294, legal: 1.647 };

/* ---------------- basics ---------------- */

/** RGBA ImageData-like → grey { w, h, g }. */
export function toGray({ data, width, height }) {
  const g = new Uint8ClampedArray(width * height);
  for (let i = 0, j = 0; j < g.length; i += 4, j++) g[j] = (data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) >> 8;
  return { w: width, h: height, g };
}

/** Grey image scaled down (area average) so its long side is at most `max`. */
export function shrink(im, max) {
  const s = Math.min(1, max / Math.max(im.w, im.h));
  if (s === 1) return im;
  const w = Math.max(1, Math.round(im.w * s)), h = Math.max(1, Math.round(im.h * s));
  const g = new Uint8ClampedArray(w * h);
  const fx = im.w / w, fy = im.h / h;
  for (let y = 0; y < h; y++) {
    const y0 = Math.floor(y * fy), y1 = Math.max(y0 + 1, Math.floor((y + 1) * fy));
    for (let x = 0; x < w; x++) {
      const x0 = Math.floor(x * fx), x1 = Math.max(x0 + 1, Math.floor((x + 1) * fx));
      let t = 0;
      for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) t += im.g[yy * im.w + xx];
      g[y * w + x] = t / ((y1 - y0) * (x1 - x0));
    }
  }
  return { w, h, g };
}

/** A grey image turned clockwise by 90, 180 or 270 degrees. */
export function rotateGray(im, deg) {
  const d = ((deg % 360) + 360) % 360;
  if (!d) return im;
  const { w, h } = im;
  const W = d === 180 ? w : h, H = d === 180 ? h : w;
  const g = new Uint8ClampedArray(w * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const v = im.g[y * w + x];
    if (d === 90) g[x * W + (h - 1 - y)] = v;
    else if (d === 180) g[(h - 1 - y) * W + (w - 1 - x)] = v;
    else g[(w - 1 - x) * W + y] = v;
  }
  return { w: W, h: H, g };
}

/** Two passes of a 3×3 box blur: close to a small Gaussian, and cheap. */
function smooth(im) {
  const { w, h } = im;
  let src = im.g, out = null;
  for (let pass = 0; pass < 2; pass++) {
    out = new Float32Array(w * h);
    for (let y = 0; y < h; y++) {
      const ya = y > 0 ? y - 1 : 0, yb = y < h - 1 ? y + 1 : h - 1;
      for (let x = 0; x < w; x++) {
        const xa = x > 0 ? x - 1 : 0, xb = x < w - 1 ? x + 1 : w - 1;
        out[y * w + x] = (src[ya * w + xa] + src[ya * w + x] + src[ya * w + xb] + src[y * w + xa] + src[y * w + x] + src[y * w + xb]
          + src[yb * w + xa] + src[yb * w + x] + src[yb * w + xb]) / 9;
      }
    }
    src = out;
  }
  return out;
}

/** Sobel gradients of a smoothed image: gx, gy and magnitude. */
function gradients(s, w, h) {
  const gx = new Float32Array(w * h), gy = new Float32Array(w * h), mag = new Float32Array(w * h);
  for (let y = 1; y < h - 1; y++) for (let x = 1; x < w - 1; x++) {
    const i = y * w + x;
    const a = s[i - w - 1], b = s[i - w], c = s[i - w + 1], d = s[i - 1], f = s[i + 1], g = s[i + w - 1], k = s[i + w], l = s[i + w + 1];
    const X = c + 2 * f + l - a - 2 * d - g, Y = g + 2 * k + l - a - 2 * b - c;
    gx[i] = X; gy[i] = Y; mag[i] = Math.hypot(X, Y);
  }
  return { gx, gy, mag };
}

/**
 * The edge strength that counts: well above the picture's own grain (its median
 * gradient, which a page of text barely moves), and never below about an 8-grey-level step.
 */
function edgeThreshold(mag) {
  const hist = new Uint32Array(1024);
  for (let i = 0; i < mag.length; i++) hist[Math.min(1023, mag[i] | 0)]++;
  let acc = 0, med = 0;
  for (let b = 0; b < 1024; b++) { acc += hist[b]; if (acc >= mag.length * 0.5) { med = b; break; } }
  return Math.max(28, Math.min(110, med * 4));
}

/* ---------------- lines ---------------- */

const NT = 180;
const COS = new Float32Array(NT), SIN = new Float32Array(NT);
for (let t = 0; t < NT; t++) { COS[t] = Math.cos(t * D2R); SIN[t] = Math.sin(t * D2R); }

/**
 * Straight lines in the picture, as { t (degrees, the line's normal), r (px), v (votes) }:
 * x·cos t + y·sin t = r. Each thin edge pixel votes only for lines near its own
 * direction, so a page of text doesn't drown out the document's border.
 */
function lines(w, h, gx, gy, mag, thr) {
  const diag = Math.ceil(Math.hypot(w, h)), NR = 2 * diag + 1;
  const acc = new Float32Array(NT * NR);
  for (let y = 2; y < h - 2; y++) for (let x = 2; x < w - 2; x++) {
    const i = y * w + x, m = mag[i];
    if (m < thr) continue;
    // keep only the crest of each edge (non-maximum suppression across it)
    const ux = gx[i] / m, uy = gy[i] / m;
    const sx = Math.round(ux), sy = Math.round(uy);
    if (m < mag[i + sy * w + sx] || m < mag[i - sy * w - sx]) continue;
    let t0 = Math.round(Math.atan2(uy, ux) / D2R);
    const wgt = Math.min(2, m / thr);
    for (let dt = -5; dt <= 5; dt++) {
      let t = t0 + dt;
      t = ((t % 360) + 360) % 360;
      const flip = t >= 180;
      if (flip) t -= 180;
      const r = Math.round(x * COS[t] + y * SIN[t]);
      acc[t * NR + r + diag] += wgt;
    }
  }
  // peaks: local maxima in a window (wrapping round at 180° with the distance flipped)
  const min = Math.max(10, Math.min(w, h) * 0.12);
  const peaks = [];
  const get = (t, r) => {
    if (t < 0) { t += NT; r = -r; } else if (t >= NT) { t -= NT; r = -r; }
    const ri = r + diag;
    return ri < 0 || ri >= NR ? 0 : acc[t * NR + ri];
  };
  for (let t = 0; t < NT; t++) for (let ri = 0; ri < NR; ri++) {
    const v = acc[t * NR + ri];
    if (v < min) continue;
    const r = ri - diag;
    let top = true;
    for (let dt = -3; dt <= 3 && top; dt++) for (let dr = -4; dr <= 4; dr++) {
      if (!dt && !dr) continue;
      const u = get(t + dt, r + dr);
      if (u > v || (u === v && (dt < 0 || (dt === 0 && dr < 0)))) { top = false; break; }
    }
    if (top) peaks.push({ t, r, v });
  }
  peaks.sort((a, b) => b.v - a.v);
  return peaks.slice(0, 28);
}

/** Where two lines { t, r } (or { a, b, c }: a·x + b·y = c) cross, or null if nearly parallel. */
function cross(p, q) {
  const [a1, b1, c1] = p.a !== undefined ? [p.a, p.b, p.c] : [Math.cos(p.t * D2R), Math.sin(p.t * D2R), p.r];
  const [a2, b2, c2] = q.a !== undefined ? [q.a, q.b, q.c] : [Math.cos(q.t * D2R), Math.sin(q.t * D2R), q.r];
  const det = a1 * b2 - a2 * b1;
  if (Math.abs(det) < 0.2) return null;
  return { x: (c1 * b2 - c2 * b1) / det, y: (a1 * c2 - a2 * c1) / det };
}

/* ---------------- the document ---------------- */

const area = (q) => Math.abs(q.reduce((s, p, i) => { const n = q[(i + 1) % 4]; return s + p.x * n.y - n.x * p.y; }, 0)) / 2;
const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

function convex(q) {
  let sign = 0;
  for (let i = 0; i < 4; i++) {
    const a = q[i], b = q[(i + 1) % 4], c = q[(i + 2) % 4];
    const z = (b.x - a.x) * (c.y - b.y) - (b.y - a.y) * (c.x - b.x);
    if (Math.abs(z) < 1e-6) return false;
    if (!sign) sign = Math.sign(z); else if (Math.sign(z) !== sign) return false;
  }
  return true;
}

function cornerAngles(q) {
  return q.map((p, i) => {
    const a = q[(i + 3) % 4], b = q[(i + 1) % 4];
    const v1x = a.x - p.x, v1y = a.y - p.y, v2x = b.x - p.x, v2y = b.y - p.y;
    return Math.acos(Math.max(-1, Math.min(1, (v1x * v2x + v1y * v2y) / (Math.hypot(v1x, v1y) * Math.hypot(v2x, v2y))))) / D2R;
  });
}

/**
 * How much of one side (a → b) is backed by an edge running its way. Samples the middle
 * 88% (corners are often rounded), looks a few pixels either side of the line for an
 * edge crest pointing across it. Returns { cover, pts (edge points found), lighter
 * (samples where the inside is the lighter side), crisp (how sharp the step is) }.
 */
function support(ctx, a, b, centre) {
  const { w, h, s, gx, gy, mag, thr, raw } = ctx;
  const len = dist(a, b);
  let nx = -(b.y - a.y) / len, ny = (b.x - a.x) / len;
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
  if (nx * (centre.x - mx) + ny * (centre.y - my) > 0) { nx = -nx; ny = -ny; } // n points outward
  const K = Math.max(16, Math.min(64, Math.round(len / 4)));
  const pts = [];
  let hits = 0, lighter = 0, crisp = 0, crispN = 0;
  const cosMax = Math.cos(25 * D2R);
  for (let k = 0; k < K; k++) {
    const f = 0.06 + (0.88 * (k + 0.5)) / K;
    const px = a.x + (b.x - a.x) * f, py = a.y + (b.y - a.y) * f;
    let best = 0, bx = 0, by = 0;
    for (let d = -3; d <= 3; d++) {
      const x = Math.round(px + nx * d), y = Math.round(py + ny * d);
      if (x < 1 || y < 1 || x >= w - 1 || y >= h - 1) continue;
      const i = y * w + x, m = mag[i];
      if (m <= best || Math.abs((gx[i] * nx + gy[i] * ny) / m) < cosMax) continue;
      best = m; bx = x; by = y;
    }
    if (best < thr * 0.8) continue;
    hits++;
    pts.push({ x: bx, y: by });
    const at = (o) => {
      const x = Math.min(w - 1, Math.max(0, Math.round(bx + nx * o))), y = Math.min(h - 1, Math.max(0, Math.round(by + ny * o)));
      return s[y * w + x];
    };
    if (at(-4) > at(4)) lighter++;
    // crispness on the unsmoothed picture: the steepest single step as a share of the whole step
    const rv = (o) => {
      const x = Math.min(w - 1, Math.max(0, Math.round(bx + nx * o))), y = Math.min(h - 1, Math.max(0, Math.round(by + ny * o)));
      return raw[y * w + x];
    };
    const total = Math.abs(rv(-6) - rv(6));
    if (total >= 16) {
      let step = 0;
      for (let j = -6; j < 6; j++) step = Math.max(step, Math.abs(rv(j + 1) - rv(j)));
      crisp += Math.min(1, step / total); crispN++;
    }
  }
  return { cover: hits / K, pts, lighter, hits, crisp: crispN ? crisp / crispN : 0 };
}

/** A line through edge points, by total least squares: { a, b, c } with a·x + b·y = c. */
function fit(pts) {
  const n = pts.length;
  let mx = 0, my = 0;
  for (const p of pts) { mx += p.x; my += p.y; }
  mx /= n; my /= n;
  let sxx = 0, sxy = 0, syy = 0;
  for (const p of pts) { const dx = p.x - mx, dy = p.y - my; sxx += dx * dx; sxy += dx * dy; syy += dy * dy; }
  const th = 0.5 * Math.atan2(2 * sxy, sxx - syy); // direction of the points
  const a = -Math.sin(th), b = Math.cos(th);
  return { a, b, c: a * mx + b * my };
}

/** Points of `pts` close to the line, to refit without a stray edge pulling it. */
const near = (pts, L, tol) => pts.filter((p) => Math.abs(L.a * p.x + L.b * p.y - L.c) <= tol);

/**
 * Find the document. im is a small grey picture (around 320–640 px on its long side).
 *   minArea   the smallest share of the picture a document may take (default 0.08)
 *   prior     the last look's corners, to prefer the same document while tracking
 *   ratio     the shape expected (long side / short side), for a card or passport page:
 *             outlines of that shape are preferred over, say, the photo printed on it
 * Returns null, or { quad: [tl, tr, br, bl] as { x, y } in im's pixels, score,
 * cover (per side: top, right, bottom, left), area (share of the picture), crisp,
 * ratio (long side / short side, rough) }.
 */
export function findDocument(im, { minArea = 0.08, prior = null, ratio = null } = {}) {
  const { w, h } = im;
  if (w < 32 || h < 32) return null;
  const s = smooth(im);
  const { gx, gy, mag } = gradients(s, w, h);
  const thr = edgeThreshold(mag);
  const L = lines(w, h, gx, gy, mag, thr);
  const ctx = { w, h, s, gx, gy, mag, thr, raw: im.g };
  // sort into the two families a document's sides fall in
  const horiz = [], vert = [];
  for (const l of L) (l.t >= 45 && l.t < 135 ? horiz : vert).push(l);
  const H = horiz.slice(0, 10), V = vert.slice(0, 10);
  const cx = w / 2, cy = h / 2;
  const yAt = (l) => (l.r - cx * Math.cos(l.t * D2R)) / Math.sin(l.t * D2R);
  const xAt = (l) => (l.r - cy * Math.sin(l.t * D2R)) / Math.cos(l.t * D2R);
  const angleBetween = (p, q) => { let d = Math.abs(p.t - q.t) % 180; return Math.min(d, 180 - d); };
  const margin = 0.03;
  const inside = (p) => p.x >= -w * margin && p.x <= w * (1 + margin) && p.y >= -h * margin && p.y <= h * (1 + margin);

  let best = null;
  const consider = (q, sides) => {
    if (!q.every(inside) || !convex(q)) return null;
    const A = area(q) / (w * h);
    if (A < minArea) return null;
    if (cornerAngles(q).some((a) => a < 55 || a > 125)) return null;
    const lens = [dist(q[0], q[1]), dist(q[1], q[2]), dist(q[2], q[3]), dist(q[3], q[0])];
    if (Math.min(lens[0], lens[2]) / Math.max(lens[0], lens[2]) < 0.55 || Math.min(lens[1], lens[3]) / Math.max(lens[1], lens[3]) < 0.55) return null;
    const centre = { x: (q[0].x + q[1].x + q[2].x + q[3].x) / 4, y: (q[0].y + q[1].y + q[2].y + q[3].y) / 4 };
    const sup = sides || [0, 1, 2, 3].map((i) => support(ctx, q[i], q[(i + 1) % 4], centre));
    const cov = sup.map((x) => x.cover);
    const sorted = [...cov].sort((a, b) => a - b);
    if (sorted[0] < 0.25 || sorted[1] < 0.45) return null;
    // the inside is lighter (or darker) than the outside all the way round: a document's
    // border does that; a line of text or the edge of a photo on the document doesn't
    const lean = sup.map((x) => (x.hits ? 2 * (x.lighter / x.hits) - 1 : 0));
    const agree = lean.every((v) => v > 0) || lean.every((v) => v < 0);
    const polarity = agree ? Math.min(...lean.map(Math.abs)) : 0;
    const mean = (cov[0] + cov[1] + cov[2] + cov[3]) / 4;
    let score = mean * (0.6 + 0.4 * sorted[0]) * (0.3 + 0.7 * polarity) * Math.pow(A, 0.75);
    if (prior) {
      const moved = q.reduce((t, p, i) => t + dist(p, prior[i]), 0) / 4 / Math.hypot(w, h);
      if (moved < 0.04) score *= 1.15;
    }
    const long = (Math.max(lens[0], lens[2]) + Math.max(lens[1], lens[3])) / 2;
    const r = (lens[0] + lens[2]) / (lens[1] + lens[3]);
    if (ratio) score *= 0.4 + 0.6 * Math.exp(-(((Math.max(r, 1 / r) / ratio - 1) / 0.12) ** 2));
    return { quad: q, score, cover: cov, area: A, polarity, sup, crisp: sup.reduce((t, x) => t + x.crisp, 0) / 4, ratio: Math.max(r, 1 / r), long };
  };

  for (let i = 0; i < H.length; i++) for (let j = i + 1; j < H.length; j++) {
    const a = H[i], b = H[j];
    if (angleBetween(a, b) > 30 || Math.abs(yAt(a) - yAt(b)) < h * 0.12) continue;
    const [top, bottom] = yAt(a) < yAt(b) ? [a, b] : [b, a];
    for (let k = 0; k < V.length; k++) for (let m = k + 1; m < V.length; m++) {
      const c = V[k], d = V[m];
      if (angleBetween(c, d) > 30 || Math.abs(xAt(c) - xAt(d)) < w * 0.12) continue;
      const [left, right] = xAt(c) < xAt(d) ? [c, d] : [d, c];
      const tl = cross(top, left), tr = cross(top, right), br = cross(bottom, right), bl = cross(bottom, left);
      if (!tl || !tr || !br || !bl) continue;
      const got = consider([tl, tr, br, bl]);
      if (got && (!best || got.score > best.score)) best = got;
    }
  }
  if (!best) return null;

  // refit each side to its own edge points (twice, dropping strays), then the corners again
  const sides = [0, 1, 2, 3].map((i) => {
    let pts = best.sup[i].pts;
    if (pts.length < 8) return null;
    let Lf = fit(pts);
    pts = near(pts, Lf, 1.5);
    if (pts.length >= 8) Lf = fit(pts);
    return Lf;
  });
  if (sides.every(Boolean)) {
    const q = [cross(sides[0], sides[3]), cross(sides[0], sides[1]), cross(sides[2], sides[1]), cross(sides[2], sides[3])];
    if (q.every(Boolean)) {
      const again = consider(q);
      if (again && again.score >= best.score * 0.85) best = again;
    }
  }
  const { sup, ...out } = best;
  out.quad = out.quad.map((p) => ({ x: Math.min(w, Math.max(0, p.x)), y: Math.min(h, Math.max(0, p.y)) }));
  return out;
}

/* ---------------- a live look ---------------- */

/** Mean brightness and share of blown-out pixels inside the corners (sampled). */
function lightInside(im, q) {
  const c = { x: (q[0].x + q[1].x + q[2].x + q[3].x) / 4, y: (q[0].y + q[1].y + q[2].y + q[3].y) / 4 };
  let sum = 0, bright = 0, n = 0;
  for (let i = 0; i < 4; i++) {
    const p = q[i];
    for (let k = 1; k <= 6; k++) for (let j = 1; j <= 6; j++) {
      // points spread over the quarter of the document nearest this corner, kept off the border
      const fx = 0.15 + 0.7 * (k / 7), fy = 0.15 + 0.7 * (j / 7);
      const x = Math.round(c.x + (p.x - c.x) * fx * (j % 2 ? 1 : 0.5)), y = Math.round(c.y + (p.y - c.y) * fy * (k % 2 ? 1 : 0.5));
      if (x < 0 || y < 0 || x >= im.w || y >= im.h) continue;
      const v = im.g[y * im.w + x];
      sum += v; if (v >= 253) bright++; n++;
    }
  }
  return { mean: n ? sum / n : 0, glare: n ? bright / n > 0.35 : false };
}

/**
 * One look through the camera. im: a small grey copy of the whole view.
 *   shape   "id1" | "td3" — a card or passport page of that shape; "full" — any document
 *   prev    the previous look's picture (same size), for steadiness
 *   prior   the previous look's corners, to keep hold of the same document
 * Returns { found, quad, ratio, area, fits, light, glare, sharp, steady, ok, hint }.
 */
export function lookAt(im, { shape = "full", prev = null, prior = null } = {}) {
  const doc = findDocument(im, { minArea: 0.03, prior, ratio: PAPER[shape] || null });
  let motion = 0;
  if (prev && prev.w === im.w && prev.h === im.h) {
    let d = 0, k = 0;
    for (let i = 0; i < im.g.length; i += 7) { d += Math.abs(im.g[i] - prev.g[i]); k++; }
    motion = d / k;
  }
  const steady = !prev || motion < 10;
  if (!doc) {
    // Nothing found: is it because there's no light? (a dark view has no edges to find)
    // Only a really dark view counts (a dark table in good light is not "too dark"): dark on average AND no bright part.
    const hist = new Uint32Array(256);
    let sum = 0, n = 0;
    for (let i = 0; i < im.g.length; i += 11) { sum += im.g[i]; hist[im.g[i]]++; n++; }
    const mean = n ? sum / n : 0;
    let acc = 0, p95 = 0;
    for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc >= n * 0.95) { p95 = v; break; } }
    const dim = mean < 28 && p95 < 50;
    return { found: false, quad: null, steady, motion, ok: false, mean, dim, hint: dim ? "Find a little more light" : shape === "full" ? "Point the camera at the document" : "Point the camera at the card" };
  }
  const want = PAPER[shape];
  const fits = !want || Math.abs(doc.ratio / want - 1) < 0.14;
  const big = doc.area >= (shape === "full" ? 0.12 : 0.08);
  const { mean, glare } = lightInside(im, doc.quad);
  const light = mean >= 45 && mean <= 245;
  const sharp = doc.crisp >= 0.3;
  const ok = fits && big && light && sharp && steady;
  const hint = !fits ? (shape === "td3" ? "Show the passport's photo page" : "That doesn't look like a card. Show just the card")
    : !big ? "Move a little closer"
    : glare ? "Glare: tilt the document a little"
    : !light ? (mean < 45 ? "Find a little more light" : "Too bright: move out of direct light")
    : !steady ? "Hold still…"
    : !sharp ? "Hold still while it focuses…"
    : "Hold still…";
  return { found: true, quad: doc.quad, ratio: doc.ratio, area: doc.area, cover: doc.cover, crisp: doc.crisp, fits, big, light, glare, sharp, steady, motion, mean, ok, hint };
}

/**
 * Smooths the corners from look to look (so the outline glides rather than jitters)
 * and decides when to take the photo, calmly: `need` good looks in a row with the
 * corners barely moving, held for at least `hold` ms, and the picture as sharp as it
 * has been during the hold (the camera's focus has settled, not still hunting). A
 * lost document is let go after a few empty looks.
 */
export function tracker({ need = 5, still = 0.02, lose = 3, hold = 0 } = {}) {
  let quad = null, raw = null, run = 0, missed = 0, diag = 1, since = 0, sharpest = 0, held = 0;
  return {
    /** Feed one look and the picture's size; returns { quad (smoothed), fire }. */
    feed(look, w, h, now = Date.now()) {
      diag = Math.hypot(w, h);
      if (!look.found) {
        run = 0; since = 0; sharpest = 0; held = 0;
        if (++missed >= lose) { quad = null; raw = null; }
        return { quad, fire: false };
      }
      missed = 0;
      const moved = raw ? Math.max(...look.quad.map((p, i) => dist(p, raw[i]))) / diag : 1;
      raw = look.quad;
      quad = !quad || moved > 0.08 ? look.quad : quad.map((p, i) => ({ x: p.x * 0.45 + look.quad[i].x * 0.55, y: p.y * 0.45 + look.quad[i].y * 0.55 }));
      run = look.ok && moved < still ? run + 1 : look.ok ? 1 : 0;
      if (run <= 1) { since = now; sharpest = 0; }
      const crisp = look.crisp ?? 1;
      sharpest = Math.max(sharpest, crisp);
      held = now - since;
      const settled = crisp >= sharpest * 0.9;
      return { quad, fire: run >= need && held >= hold && settled };
    },
    get quad() { return quad; },
    get progress() { return Math.min(1, run / need, hold ? held / hold : 1); },
    reset() { quad = null; raw = null; run = 0; missed = 0; since = 0; sharpest = 0; held = 0; },
  };
}

/* ---------------- straightening ---------------- */

/**
 * The perspective map that sends the rectangle (0,0)–(W,H) onto the corners
 * [tl, tr, br, bl]: returns [a..h] for x' = (a·x + b·y + c) / (g·x + h·y + 1),
 * y' = (d·x + e·y + f) / (g·x + h·y + 1).
 */
export function homography(W, H, quad) {
  const src = [[0, 0], [W, 0], [W, H], [0, H]];
  const A = [], B = [];
  for (let i = 0; i < 4; i++) {
    const [x, y] = src[i], { x: u, y: v } = quad[i];
    A.push([x, y, 1, 0, 0, 0, -u * x, -u * y]); B.push(u);
    A.push([0, 0, 0, x, y, 1, -v * x, -v * y]); B.push(v);
  }
  // Gaussian elimination with partial pivoting
  for (let c = 0; c < 8; c++) {
    let p = c;
    for (let r = c + 1; r < 8; r++) if (Math.abs(A[r][c]) > Math.abs(A[p][c])) p = r;
    [A[c], A[p]] = [A[p], A[c]]; [B[c], B[p]] = [B[p], B[c]];
    if (Math.abs(A[c][c]) < 1e-12) throw new Error("The corners don't make a document shape.");
    for (let r = 0; r < 8; r++) {
      if (r === c) continue;
      const f = A[r][c] / A[c][c];
      if (!f) continue;
      for (let k = c; k < 8; k++) A[r][k] -= f * A[c][k];
      B[r] -= f * B[c];
    }
  }
  return B.map((b, i) => b / A[i][i]);
}

/**
 * Width and height of the straightened document, in the source's pixels. The proportion
 * comes from the average of each pair of opposite sides (perspective makes the near side
 * longer and the far side shorter by about the same), snapped to a common document
 * proportion when within 6% (`prefer` first: a card's known shape); the size from the
 * longest side, so no detail is lost, at most `max` on the long side.
 */
export function outputSize(quad, { prefer = null, max = 3000 } = {}) {
  const across = (dist(quad[0], quad[1]) + dist(quad[3], quad[2])) / 2;
  const down = (dist(quad[0], quad[3]) + dist(quad[1], quad[2])) / 2;
  const longest = Math.max(dist(quad[0], quad[1]), dist(quad[3], quad[2]), dist(quad[0], quad[3]), dist(quad[1], quad[2]));
  let r = Math.max(across, down) / Math.min(across, down);
  const options = prefer ? [PAPER[prefer]] : [PAPER.id1, PAPER.a4, PAPER.letter, PAPER.legal];
  r = options.find((p) => p && Math.abs(r / p - 1) < 0.06) || r;
  const long = Math.min(longest, max);
  const W = across >= down ? long : long / r, H = across >= down ? long / r : long;
  return { width: Math.max(1, Math.round(W)), height: Math.max(1, Math.round(H)) };
}

/**
 * The straightened document: RGBA { width, height, data } sampled bilinearly from src.
 * crop { x, y, w, h } (in the straightened picture's own pixels) makes only that part of it,
 * so a strip such as the MRZ costs a third of the whole page.
 */
export function warp(src, quad, width, height, crop = null) {
  const [a, b, c, d, e, f, g, h] = homography(width, height, quad);
  const cx = crop ? Math.round(crop.x) : 0, cy = crop ? Math.round(crop.y) : 0;
  const ow = crop ? Math.round(crop.w) : width, oh = crop ? Math.round(crop.h) : height;
  const out = new Uint8ClampedArray(ow * oh * 4);
  const sw = src.width, sh = src.height, sd = src.data;
  for (let y = 0; y < oh; y++) {
    const yy = y + cy + 0.5;
    let nx = b * yy + c + a * (cx + 0.5), ny = e * yy + f + d * (cx + 0.5), dn = h * yy + 1 + g * (cx + 0.5);
    for (let x = 0, o = y * ow * 4; x < ow; x++, o += 4) {
      const u = nx / dn - 0.5, v = ny / dn - 0.5;
      nx += a; ny += d; dn += g;
      const x0 = Math.floor(u), y0 = Math.floor(v);
      const fx = u - x0, fy = v - y0;
      const xa = x0 < 0 ? 0 : x0 >= sw ? sw - 1 : x0, xb = x0 + 1 < 0 ? 0 : x0 + 1 >= sw ? sw - 1 : x0 + 1;
      const ya = y0 < 0 ? 0 : y0 >= sh ? sh - 1 : y0, yb = y0 + 1 < 0 ? 0 : y0 + 1 >= sh ? sh - 1 : y0 + 1;
      const i00 = (ya * sw + xa) * 4, i10 = (ya * sw + xb) * 4, i01 = (yb * sw + xa) * 4, i11 = (yb * sw + xb) * 4;
      const w00 = (1 - fx) * (1 - fy), w10 = fx * (1 - fy), w01 = (1 - fx) * fy, w11 = fx * fy;
      out[o] = sd[i00] * w00 + sd[i10] * w10 + sd[i01] * w01 + sd[i11] * w11;
      out[o + 1] = sd[i00 + 1] * w00 + sd[i10 + 1] * w10 + sd[i01 + 1] * w01 + sd[i11 + 1] * w11;
      out[o + 2] = sd[i00 + 2] * w00 + sd[i10 + 2] * w10 + sd[i01 + 2] * w01 + sd[i11 + 2] * w11;
      out[o + 3] = 255;
    }
  }
  return { width: ow, height: oh, data: out };
}

/** Where the straightened rectangle's point (x, y) falls in the picture, for the map `homography(W, H, quad)` gave. */
export function applyHomography(m, x, y) {
  const [a, b, c, d, e, f, g, h] = m;
  const z = g * x + h * y + 1;
  return { x: (a * x + b * y + c) / z, y: (d * x + e * y + f) / z };
}

/**
 * The same four corners, labelled for a card read lying flat and the right way round:
 * a card held on end (its short sides across) is turned a quarter, then `turn` (0 or 180)
 * more. Matches straightening the card, rotating it a quarter if it stands, then turning
 * it, without ever making the whole card.
 */
export function relabel(quad, turn = 0) {
  const across = (dist(quad[0], quad[1]) + dist(quad[3], quad[2])) / 2;
  const down = (dist(quad[0], quad[3]) + dist(quad[1], quad[2])) / 2;
  let q = down > across ? [quad[3], quad[0], quad[1], quad[2]] : quad;
  for (let t = ((turn % 360) + 360) % 360; t >= 90; t -= 90) q = [q[3], q[0], q[1], q[2]];
  return q;
}

/**
 * What the MRZ reader needs from a live card, without straightening the whole card:
 * the strip of the card the lines sit in, at the size the reader likes (a character about
 * 30 px wide). Returns { width, height (the strip), flatW, flatH (the whole card at that
 * scale), crop, quad (the relabelled corners), box (where the strip lies in the
 * picture: x, y, w, h) }.
 *   shape  "td3" | "id1"     turn  0 or 180     scale  1 normally
 */
export function bandPlan(quad, shape = "td3", { turn = 0, scale = 1, chars } = {}) {
  const q = relabel(quad, turn);
  const share = shape === "td3" ? 0.34 : 0.48;
  const n = chars || (shape === "td3" ? 44 : 30);
  const flatW = Math.round(n * 30 * scale), flatH = Math.round(flatW / (PAPER[shape] || PAPER.id1));
  const y0 = Math.round(flatH * (1 - share));
  const crop = { x: 0, y: y0, w: flatW, h: flatH - y0 };
  const m = homography(flatW, flatH, q);
  const pts = [[0, y0], [flatW, y0], [flatW, flatH], [0, flatH]].map(([x, y]) => applyHomography(m, x, y));
  const xs = pts.map((p) => p.x), ys = pts.map((p) => p.y);
  const x = Math.min(...xs), y = Math.min(...ys);
  return { width: crop.w, height: crop.h, flatW, flatH, crop, quad: q, box: { x, y, w: Math.max(...xs) - x, h: Math.max(...ys) - y } };
}

/** Corners from one picture's pixels to another's (a small analysis copy → the full photo). */
export const scaleQuad = (quad, sx, sy = sx, ox = 0, oy = 0) => quad.map((p) => ({ x: p.x * sx + ox, y: p.y * sy + oy }));

/* ---------------- which way up ---------------- */

/** Ink: pixels clearly darker than their neighbourhood (adaptive, so shading doesn't count). */
function ink(im) {
  const { w, h, g } = im;
  const I = new Float64Array((w + 1) * (h + 1));
  for (let y = 0; y < h; y++) {
    let row = 0;
    for (let x = 0; x < w; x++) { row += g[y * w + x]; I[(y + 1) * (w + 1) + x + 1] = I[y * (w + 1) + x + 1] + row; }
  }
  const R = Math.max(6, Math.round(Math.min(w, h) / 40));
  const out = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) {
    const y0 = Math.max(0, y - R), y1 = Math.min(h, y + R + 1);
    for (let x = 0; x < w; x++) {
      const x0 = Math.max(0, x - R), x1 = Math.min(w, x + R + 1);
      const mean = (I[y1 * (w + 1) + x1] - I[y0 * (w + 1) + x1] - I[y1 * (w + 1) + x0] + I[y0 * (w + 1) + x0]) / ((y1 - y0) * (x1 - x0));
      if (g[y * w + x] < mean - 14 && g[y * w + x] < 200) out[y * w + x] = 1;
    }
  }
  return out;
}

/**
 * Keep only marks the size of letters and words: drops photos' borders, ruled lines,
 * boxes and specks, which would otherwise blur the text's own pattern.
 */
function letters(mask, w, h) {
  const out = new Uint8Array(w * h), seen = new Uint8Array(w * h);
  const stack = new Int32Array(w * h);
  const maxH = Math.max(6, h / 10), maxW = Math.max(12, w / 3);
  for (let start = 0; start < mask.length; start++) {
    if (!mask[start] || seen[start]) continue;
    let top = 0, n = 0, x0 = w, x1 = 0, y0 = h, y1 = 0;
    stack[top++] = start; seen[start] = 1;
    const members = [];
    while (top) {
      const i = stack[--top];
      members.push(i); n++;
      const x = i % w, y = (i / w) | 0;
      if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y;
      for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
        const xx = x + dx, yy = y + dy;
        if (xx < 0 || yy < 0 || xx >= w || yy >= h) continue;
        const j = yy * w + xx;
        if (mask[j] && !seen[j]) { seen[j] = 1; stack[top++] = j; }
      }
    }
    const bh = y1 - y0 + 1, bw = x1 - x0 + 1;
    if (n >= 3 && bh >= 2 && bh <= maxH && bw <= maxW) for (const i of members) out[i] = 1;
  }
  return out;
}

/** How strongly a profile swings from line to gap: high-passed energy over total. */
function swing(P, win) {
  const n = P.length;
  let e = 0, t = 0, run = 0;
  const C = new Float64Array(n + 1);
  for (let i = 0; i < n; i++) C[i + 1] = C[i] + P[i];
  for (let i = 0; i < n; i++) {
    const a = Math.max(0, i - win), b = Math.min(n, i + win + 1);
    const local = (C[b] - C[a]) / (b - a);
    e += (P[i] - local) ** 2; t += P[i] * P[i]; run += P[i];
  }
  return run ? e / t : 0;
}

/** Lines of text in an image whose lines run across: [{ y0, y1, P (ink per row) }]. */
function textLines(mask, w, h) {
  const P = new Float64Array(h);
  for (let y = 0; y < h; y++) { let n = 0; for (let x = 0; x < w; x++) n += mask[y * w + x]; P[y] = n; }
  const sorted = [...P].filter((v) => v > 0).sort((a, b) => a - b);
  if (sorted.length < 8) return [];
  const thr = Math.max(2, sorted[Math.floor(sorted.length * 0.5)] * 0.25);
  const out = [];
  for (let y = 0; y < h;) {
    if (P[y] < thr) { y++; continue; }
    let y1 = y;
    while (y1 < h && P[y1] >= thr) y1++;
    if (y1 - y >= 4 && y1 - y <= h / 6) out.push({ y0: y, y1 });
    y = y1;
  }
  return out.map((l) => ({ ...l, P: P.subarray(l.y0, l.y1) }));
}

/**
 * Is a picture with horizontal text lines the right way up? Two cues, each a vote:
 *  - ascenders and capitals (b d f h k l t, A–Z) rise above the line's core far more
 *    often than descenders (g j p q y) drop below it;
 *  - lines start together at the left margin and end ragged on the right.
 * Returns a score: > 0 upright, < 0 upside down, near 0 can't tell.
 */
function upright(mask, w, h) {
  const L = textLines(mask, w, h);
  if (L.length < 2) return 0;
  let up = 0, down = 0;
  const starts = [], ends = [];
  for (const l of L) {
    const P = l.P, n = P.length;
    let peak = 0;
    for (let i = 0; i < n; i++) peak = Math.max(peak, P[i]);
    // the core: rows carrying at least half the line's heaviest row
    let c0 = 0, c1 = n - 1;
    while (c0 < n && P[c0] < peak * 0.5) c0++;
    while (c1 > 0 && P[c1] < peak * 0.5) c1--;
    for (let i = 0; i < c0; i++) up += P[i];
    for (let i = c1 + 1; i < n; i++) down += P[i];
    // where the line's ink starts and ends
    let s = -1, e = -1;
    for (let x = 0; x < w && s < 0; x++) for (let y = l.y0; y < l.y1; y++) if (mask[y * w + x]) { s = x; break; }
    for (let x = w - 1; x >= 0 && e < 0; x--) for (let y = l.y0; y < l.y1; y++) if (mask[y * w + x]) { e = x; break; }
    if (s >= 0 && e > s + w * 0.2) { starts.push(s); ends.push(e); }
  }
  const asc = Math.log((up + 1) / (down + 1));
  let ragged = 0;
  if (starts.length >= 4) {
    // how many line starts sit at the most common start (the margin), against the same for ends
    const share = (v) => {
      const tol = w * 0.015;
      let best = 0;
      for (const a of v) { let k = 0; for (const b of v) if (Math.abs(a - b) <= tol) k++; best = Math.max(best, k); }
      return best / v.length;
    };
    ragged = share(starts) - share(ends);
  }
  return Math.max(-1.5, Math.min(1.5, asc)) + ragged;
}

/**
 * Which way to turn a straightened page so it reads upright: { rotate (0, 90, 180 or
 * 270, clockwise), confidence (0–1, overall), sideways (how sure which way the lines
 * run), upright (how sure which way is up), lines ("across" | "down" | null) }.
 *   landscape   true for cards and passport pages: only turns that leave it wider
 *               than tall are considered
 */
export function orientation(im, { landscape = false } = {}) {
  const small = shrink(im, 900);
  const { w, h } = small;
  // leave the outer 5% out: a border or a shadow at the edge isn't text
  const mx = Math.round(w * 0.05), my = Math.round(h * 0.05);
  const cw = w - 2 * mx, ch = h - 2 * my;
  const crop = { w: cw, h: ch, g: new Uint8ClampedArray(cw * ch) };
  for (let y = 0; y < ch; y++) crop.g.set(small.g.subarray((y + my) * w + mx, (y + my) * w + mx + cw), y * cw);
  const mask = letters(ink(crop), cw, ch);
  let total = 0;
  for (let i = 0; i < mask.length; i++) total += mask[i];
  if (total < crop.w * crop.h * 0.004) return { rotate: landscape && h > w ? 90 : 0, confidence: 0, sideways: 0, upright: 0, lines: null };
  const rows = new Float64Array(ch), cols = new Float64Array(cw);
  for (let y = 0; y < ch; y++) for (let x = 0; x < cw; x++) if (mask[y * cw + x]) { rows[y]++; cols[x]++; }
  const win = Math.max(4, Math.round(Math.min(cw, ch) / 60));
  const across = swing(rows, win), down = swing(cols, win);
  let linesRun = across >= down ? "across" : "down";
  let axisConf = Math.min(1, Math.abs(Math.log((across + 1e-6) / (down + 1e-6))) / 0.7);
  if (landscape) {
    // a card's text runs along its long side
    const wantDown = h > w;
    if ((linesRun === "down") !== wantDown && axisConf < 0.6) { linesRun = wantDown ? "down" : "across"; axisConf = 0.3; }
  }
  // bring the lines across, then ask which way up
  const turned = linesRun === "across" ? { w: cw, h: ch, g: mask } : (() => { const r = rotateGray({ w: cw, h: ch, g: mask }, 90); return r; })();
  const score = upright(turned.g, turned.w, turned.h);
  const flip = score < 0;
  let rotate = linesRun === "across" ? (flip ? 180 : 0) : (flip ? 270 : 90);
  if (landscape && (rotate === 90 || rotate === 270) !== h > w) rotate = (rotate + 90) % 360; // never leave a card standing up
  const upConf = Math.min(1, Math.abs(score) / 0.8);
  const r2 = (v) => Math.round(v * 100) / 100;
  return { rotate, confidence: r2(Math.min(axisConf, upConf)), sideways: r2(axisConf), upright: r2(upConf), lines: linesRun };
}
