// The guided scan (apps 2.2.0): the way a bank's check-deposit or ID-verification scan works.
// A fixed outline is drawn on the screen at the document's real proportions; the person
// lines the document up inside it; the app measures a small grey copy of the frame in and
// around the outline and says, in plain words, what to change (Move closer, Hold steady,
// Too much glare…); when it is lined up, steady and sharp for a moment the photo is taken
// and cropped to the outline's rectangle. Nothing here tracks a free-form quad: the outline
// is where the crop is, so a wobbling detector can't move the photo.
//
// Pure functions on grey pictures { w, h, g } and plain objects, so the whole thing is
// tested in Node (tests/guide.test.js). The screen (screens/add/camera.jsx) only grabs the pictures,
// feeds the numbers in and draws what comes out; core/guidecap.js takes the still.
//
//   TEMPLATES / templateFor   the outline for each kind of document: proportions, what to expect on it
//   windowFor                 which part of a video frame to look at (the outline and a margin around it)
//   measure                   the numbers: brightness, glare, sharpness, motion, where the document's
//                             four edges are relative to the outline (and so its size, tilt and shift)
//   judge                     the numbers → one verdict: the message to show (or none) and whether it is ready
//   holdTracker               "ready for about 0.6 s" → fire
//
// Nothing here sees a word read from a document, and nothing is logged or kept.

const D2R = Math.PI / 180;

/* ---------------- the outlines ---------------- */

/** Real proportions (long side / short side): ID-1 is 85.6 × 54 mm, ID-3 (a passport's data page) 125 × 88 mm. */
export const RATIO = { id1: 85.6 / 54, td3: 125 / 88 };

/**
 * What each outline shows inside it, as faint dashed zones ([x, y, w, h] in percent of the outline)
 * so the person knows which way up and which side. Decoration only.
 */
const ZONES = {
  "id-front": [["photo", 5, 22, 28, 60], ["line", 40, 28, 50, 8], ["line", 40, 46, 42, 8], ["line", 40, 64, 46, 8]],
  "id-back": [["bar", 6, 38, 88, 36], ["line", 6, 12, 60, 8]],
  "id-back-mrz": [["line", 6, 12, 60, 8], ["mrz", 4, 62, 92, 30]],
  "passport": [["photo", 4, 18, 24, 52], ["line", 34, 20, 56, 8], ["line", 34, 36, 48, 8], ["mrz", 3, 72, 94, 22]],
  "pay-front": [["chip", 7, 30, 15, 20], ["num", 7, 56, 86, 12], ["line", 7, 78, 50, 8]],
  "pay-back": [["stripe", 0, 12, 100, 18], ["sign", 7, 44, 58, 16]],
  "plain": [],
};

/**
 * The template for a document: { id, shape ("id1" | "td3"), noun, side, expect ({ barcode, mrz }), zones }.
 *   kind  the ID kind picked on "What are you adding?" (driver_license, passport, id_card, residence_permit, other, card)
 *   side  "front" | "back"
 *   read  what the camera is to read ({ barcode, mrz }); what the template expects to see
 */
export function templateFor({ kind = "other", side = "front", shape = "id1", read = {} } = {}) {
  const td3 = shape === "td3" || kind === "passport";
  const back = side === "back";
  const noun = td3 ? "passport page" : kind === "driver_license" ? "license" : kind === "card" ? "card" : "card";
  let zones = "plain";
  if (td3) zones = "passport";
  else if (kind === "card") zones = back ? "pay-back" : "pay-front";
  else if (!back) zones = "id-front";
  else zones = read.mrz && !read.barcode ? "id-back-mrz" : read.barcode ? "id-back" : "plain";
  return {
    id: `${kind}-${side}`, kind, side, shape: td3 ? "td3" : "id1", ratio: td3 ? RATIO.td3 : RATIO.id1, noun,
    expect: { barcode: !!read.barcode, mrz: !!read.mrz },
    // the license's front shouldn't show a PDF417: if one does, it's the back
    forbid: { barcode: kind === "driver_license" && !back },
    zones: ZONES[zones].map(([k, x, y, w, h]) => ({ k, x, y, w, h })),
  };
}

/* ---------------- what the camera asks for ---------------- */

/**
 * The live preview's size. Not 4K: a 4K preview inside an Android WebView made the picture
 * unsteady in 2.1.1, and the analysis only needs a few hundred pixels. 1080p is plenty to
 * line a card up; the photo itself is taken as a still (ImageCapture.takePhoto, full sensor
 * resolution) where the WebView offers it, and from a 1080p frame where it doesn't. A passport's
 * machine-readable lines are small print, so its preview asks for 1440p.
 *
 * `portrait`: the screen is taller than wide, so the preview is asked for taller than wide too
 * (a portrait screen showing a landscape preview would crop the sides away and leave the outline
 * a third of the pixels; the browser may also crop a mismatched preview to the sizes asked for).
 * The caller checks what came back (previewTurned) and asks again the other way round if it is wrong.
 */
export function liveConstraints(template, { portrait = true, exact = false } = {}) {
  const td3 = template?.shape === "td3";
  const long = td3 ? 2560 : 1920, short = td3 ? 1440 : 1080;
  // 3.0: only the long side is asked for, with resizeMode "none": a width AND a height make a browser cut the
  // frame to that shape (a portrait phone lost the top and bottom of the page), and the outline needs the whole view.
  if (!exact) return { facingMode: { ideal: "environment" }, width: { ideal: long }, frameRate: { ideal: 30, max: 30 }, resizeMode: "none" };
  // the second ask, when the first came back turned the wrong way for the screen: both sizes, in the screen's orientation
  return { facingMode: { ideal: "environment" }, width: { ideal: portrait ? short : long }, height: { ideal: portrait ? long : short }, frameRate: { ideal: 30, max: 30 } };
}

/** The preview came back turned the other way round from the screen (landscape on a portrait screen, or the reverse). */
export const previewTurned = (vw, vh, portraitScreen) => vw > 0 && vh > 0 && vw !== vh ? (vh > vw) !== portraitScreen : vw === vh && portraitScreen;

/* ---------------- thresholds ---------------- */

/** Every threshold in one place, so they are tuned (and tested) together. */
export const TH = {
  windowMargin: 0.3,       // how far around the outline the analysis looks (share of its size)
  windowWidth: 288,        // the outline is analysed at this many pixels across
  minStep: 12,             // a document edge: at least this much of a step in grey (2 px apart)
  edgeFrac: 0.25,          // the outermost peak at least this share of the strongest on a side
  searchIn: 0.45,          // look for an edge this far inside the outline… (share of its size)
  searchOut: 0.3,          // …and this far outside it
  small: 0.78,             // document narrower than this share of the outline: Move closer
  snug: 0.88,              // …narrower than this: Fill the outline
  big: 1.06,               // wider than this: Move back a little
  edgeIn: 0.085,           // each edge may be this far inside the outline (share of its size) and still count as lined up
  edgeOut: 0.03,           // …and this far outside (the crop keeps a 4% margin)
  shift: 0.045,            // the document's centre this far off the outline's centre: Line it up
  tilt: 6,                 // degrees turned in the plane: Straighten the card
  flat: 5.5,               // degrees of one side narrowing (a phone held at an angle): Hold the phone flat
  deskew: [1, 10],         // turn the crop straight when the card is turned by an amount in this range (degrees)
  dark: { p95: 85, mean: 30, empty: { p95: 50, mean: 28 } }, // Too dark: nothing bright on the document, or (with no document in view) a view that is dark all over
  glare: { sat: 253, share: 0.025, cell: 0.5, cells: 1, paper: 228, paperShare: 0.1, paperCells: 2 }, // saturated pixels: this share of the outline, in patches that are at least half white (a white card needs more of both)
  sharp: 0.55,             // focus measure (Laplacian variance relative to gradient energy) below this: blurry
  sharpRel: 0.6,           // …or below this share of the best focus seen on this document (the camera is still hunting)
  steady: 0.004,           // frame-to-frame movement, in outline widths: above this it is moving
  holdMs: 600,             // lined up, steady and sharp for this long takes the photo
  graceMs: 220,            // one bad look this short doesn't restart the hold
  aspect: 0.07,            // the document's width and height (as shares of the outline's) differ by more than this even after looking again: the edges can't be told
  barAcross: 0.5,          // a license barcode's width as a share of the outline's, when the card fills it
};

/* ---------------- the window ---------------- */

/**
 * Which part of a video frame is analysed: the outline and a margin around it (so an edge a
 * little outside the outline is seen), at TH.windowWidth pixels across the outline.
 *   rect   the outline in the video's pixels { x, y, w, h }
 * Returns { src (the part of the frame to copy), w, h (the picture's size), guide (the outline in it), scale }.
 */
export function windowFor(rect, vw, vh, { margin = TH.windowMargin, width = TH.windowWidth } = {}) {
  const x0 = Math.max(0, rect.x - rect.w * margin), y0 = Math.max(0, rect.y - rect.h * margin);
  const x1 = Math.min(vw, rect.x + rect.w * (1 + margin)), y1 = Math.min(vh, rect.y + rect.h * (1 + margin));
  const scale = width / rect.w;
  return {
    src: { x: x0, y: y0, w: x1 - x0, h: y1 - y0 },
    w: Math.max(1, Math.round((x1 - x0) * scale)), h: Math.max(1, Math.round((y1 - y0) * scale)),
    guide: { x: (rect.x - x0) * scale, y: (rect.y - y0) * scale, w: rect.w * scale, h: rect.h * scale },
    scale,
  };
}

/* ---------------- measurements ---------------- */

const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

/** Mean of |g(p+1) − g(p−1)| over a run of cross positions, for each position along the edge's normal. */
function profile(im, horizontal, lo, hi, a, b) {
  // horizontal: the edge is a horizontal line (the top or bottom of the document), so p is y and the cross runs over x
  const { w, g } = im;
  const n = hi - lo + 1;
  const out = new Float32Array(Math.max(0, n));
  const cnt = Math.max(1, b - a);
  for (let i = 0; i < n; i++) {
    const p = lo + i;
    let t = 0;
    if (horizontal) { const r0 = (p - 1) * w, r1 = (p + 1) * w; for (let c = a; c < b; c++) t += Math.abs(g[r1 + c] - g[r0 + c]); }
    else { for (let c = a; c < b; c++) { const o = c * w + p; t += Math.abs(g[o + 1] - g[o - 1]); } }
    out[i] = t / cnt;
  }
  return out;
}

/**
 * The document's edge in a profile: the outermost peak at least TH.edgeFrac of the strongest
 * (the edge is the outermost thing of any weight; what's inside is print). `outer` is -1 when
 * the outside is at low positions (top, left) and +1 otherwise. Returns { p (sub-sample
 * position), v (its strength), max } or null.
 */
function edgeIn(P, lo, outer, { minStep = TH.minStep, frac = TH.edgeFrac } = {}) {
  const n = P.length;
  if (n < 5) return null;
  const S = new Float32Array(n);
  for (let i = 0; i < n; i++) S[i] = (P[Math.max(0, i - 1)] + 2 * P[i] + P[Math.min(n - 1, i + 1)]) / 4;
  let max = 0, sum = 0;
  for (let i = 0; i < n; i++) { if (S[i] > max) max = S[i]; sum += S[i]; }
  if (max < minStep || max < 1.8 * (sum / n)) return null;
  const th = Math.max(minStep, frac * max);
  const peaks = [];
  for (let i = 1; i < n - 1; i++) if (S[i] >= th && S[i] >= S[i - 1] && S[i] > S[i + 1]) peaks.push(i);
  if (!peaks.length) return null;
  const i = outer < 0 ? peaks[0] : peaks[peaks.length - 1];
  // sub-sample position (parabola through the peak)
  const a = S[i - 1], b = S[i], c = S[i + 1], d = a - 2 * b + c;
  const off = d < -1e-6 ? clamp(0.5 * (a - c) / d, -0.5, 0.5) : 0;
  return { p: lo + i + off, v: S[i], max };
}

/** Least-median-ish robust line y = a + b·x through points (Theil–Sen), with the share that sits on it. */
function robustLine(pts, tol) {
  const n = pts.length;
  if (n < 2) return null;
  const slopes = [];
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) { const dx = pts[j][0] - pts[i][0]; if (Math.abs(dx) >= 1) slopes.push((pts[j][1] - pts[i][1]) / dx); }
  if (!slopes.length) return null;
  slopes.sort((p, q) => p - q);
  let b = slopes[slopes.length >> 1];
  const med = (arr) => { const s = arr.slice().sort((p, q) => p - q); return s[s.length >> 1]; };
  let a = med(pts.map(([x, y]) => y - b * x));
  // one refinement on the inliers
  let inl = pts.filter(([x, y]) => Math.abs(y - (a + b * x)) <= tol);
  if (inl.length >= 3) {
    const mx = inl.reduce((t, p) => t + p[0], 0) / inl.length, my = inl.reduce((t, p) => t + p[1], 0) / inl.length;
    let sxx = 0, sxy = 0;
    for (const [x, y] of inl) { sxx += (x - mx) ** 2; sxy += (x - mx) * (y - my); }
    if (sxx > 1e-6) { b = sxy / sxx; a = my - b * mx; inl = pts.filter(([x, y]) => Math.abs(y - (a + b * x)) <= tol); }
  }
  return { a, b, inliers: inl.length, share: inl.length / n };
}

/**
 * Where one side of the document is, relative to the same side of the outline.
 *   side   "top" | "bottom" | "left" | "right"
 * Looks, along the side (the middle 80%), for the document's outermost edge within TH.searchIn
 * inside and TH.searchOut outside the outline: first in a few runs (so a turned document still
 * gives a position), then column by column near that to fit a straight line, which also gives
 * the angle. Returns { found, off (share of the outline's size; + is outside the outline), slope
 * (radians; of the edge's line), strength, line (share of points on the line) }.
 */
export function sideEdge(im, guide, side, opt = {}) {
  const minStep = opt.minStep ?? TH.minStep, frac = opt.frac ?? TH.edgeFrac, minRuns = opt.minRuns ?? 2;
  const horizontal = side === "top" || side === "bottom";
  const gx = guide.x, gy = guide.y, gw = guide.w, gh = guide.h;
  const along0 = horizontal ? gx : gy, alongLen = horizontal ? gw : gh;
  const edge0 = horizontal ? gy : gx, edgeLen = horizontal ? gh : gw;
  const nearLow = side === "top" || side === "left"; // the outline's side is at the low coordinate
  const base = nearLow ? edge0 : edge0 + edgeLen;
  const limit = horizontal ? im.h : im.w;
  // the search range along the normal (in picture pixels), kept 2 px inside the picture
  const inward = edgeLen * (opt.inShare ?? TH.searchIn), outward = edgeLen * (opt.outShare ?? TH.searchOut);
  let lo = Math.round(nearLow ? base - outward : base - inward), hi = Math.round(nearLow ? base + inward : base + outward);
  lo = Math.max(2, lo); hi = Math.min(limit - 3, hi);
  if (hi - lo < 8) return { found: false };
  const a0 = Math.round(along0 + alongLen * 0.1), a1 = Math.round(along0 + alongLen * 0.9);
  const lim2 = horizontal ? im.w : im.h;
  const A0 = Math.max(0, a0), A1 = Math.min(lim2, a1);
  if (A1 - A0 < 12) return { found: false };
  const outer = nearLow ? -1 : 1;
  // stage 1: five runs along the side
  const runs = 5, step = (A1 - A0) / runs;
  const pts = [];
  let strength = 0, got = 0;
  for (let r = 0; r < runs; r++) {
    const ra = Math.round(A0 + r * step), rb = Math.round(A0 + (r + 1) * step);
    const e = edgeIn(profile(im, horizontal, lo, hi, ra, rb), lo, outer, { minStep, frac });
    if (e) { pts.push([(ra + rb) / 2, e.p]); strength = Math.max(strength, e.v); got++; }
  }
  if (got < minRuns) return { found: false };
  let line = robustLine(pts, Math.max(1.5, edgeLen * 0.03));
  if (!line || line.inliers < 2) return { found: false };
  // stage 2: column groups close to that line, then a robust line through the strongest of them
  const grp = 4, fine = [];
  const win = Math.max(5, Math.round(edgeLen * 0.045));
  for (let c = A0; c + grp <= A1; c += grp) {
    const mid = c + grp / 2, p0 = Math.round(line.a + line.b * mid);
    const l2 = Math.max(lo, p0 - win), h2 = Math.min(hi, p0 + win);
    if (h2 - l2 < 4) continue;
    const P = profile(im, horizontal, l2, h2, c, c + grp);
    // the outermost peak of weight (as in stage 1), so print near the edge can't pull the line inward
    let mx = 0;
    for (let i = 0; i < P.length; i++) if (P[i] > mx) mx = P[i];
    const th = Math.max(minStep, 0.5 * mx, 0.35 * strength);
    let bi = -1;
    for (let k = 0; k < P.length; k++) {
      const i = outer < 0 ? k : P.length - 1 - k;
      if (P[i] >= th && P[i] >= P[Math.max(0, i - 1)] && P[i] >= P[Math.min(P.length - 1, i + 1)]) { bi = i; break; }
    }
    if (bi >= 0) fine.push([mid, l2 + bi]);
  }
  const fl = fine.length >= 6 ? robustLine(fine, 1.2) : null;
  const use = fl && fl.share >= 0.5 ? fl : line;
  const centre = along0 + alongLen / 2;
  const pos = use.a + use.b * centre;
  const off = nearLow ? (base - pos) / edgeLen : (pos - base) / edgeLen;
  return { found: true, off, slope: Math.atan(use.b), strength, line: fl ? fl.share : line.share, ref: use === fl ? "fine" : "runs" };
}

/**
 * Grey-picture statistics inside the outline: brightness, glare, focus.
 *   mean, p5, p95   brightness (0–255)
 *   sat             share of the outline's pixels that are saturated, and `patch`: the share of 6×4 cells that are mostly saturated
 *   focus           Laplacian variance relative to the gradient energy (contrast cancels out: only sharpness is left)
 *   energy          mean gradient size: nearly nothing inside means nothing (or a blank card) is there
 */
export function inside(im, guide) {
  const x0 = Math.max(2, Math.round(guide.x + guide.w * 0.04)), x1 = Math.min(im.w - 2, Math.round(guide.x + guide.w * 0.96));
  const y0 = Math.max(2, Math.round(guide.y + guide.h * 0.04)), y1 = Math.min(im.h - 2, Math.round(guide.y + guide.h * 0.96));
  const w = x1 - x0, h = y1 - y0;
  if (w < 8 || h < 8) return { mean: 0, p5: 0, p95: 0, sat: 0, patch: 0, focus: 0, energy: 0, n: 0 };
  const g = im.g, W = im.w;
  const hist = new Uint32Array(256);
  const CX = 6, CY = 4, cellSat = new Uint32Array(CX * CY), cellN = new Uint32Array(CX * CY);
  let sum = 0, sat = 0, lap = 0, lap2 = 0, grad2 = 0, grad1 = 0, n = 0;
  const satV = TH.glare.sat;
  for (let y = y0; y < y1; y++) {
    const cy = Math.min(CY - 1, (((y - y0) * CY) / h) | 0);
    for (let x = x0; x < x1; x++) {
      const o = y * W + x, v = g[o];
      hist[v]++; sum += v;
      const cell = cy * CX + Math.min(CX - 1, (((x - x0) * CX) / w) | 0);
      cellN[cell]++;
      if (v >= satV) { sat++; cellSat[cell]++; }
      const gx = g[o + 1] - g[o - 1], gy = g[o + W] - g[o - W];
      grad2 += gx * gx + gy * gy; grad1 += Math.abs(gx) + Math.abs(gy);
      const l = 4 * v - g[o - 1] - g[o + 1] - g[o - W] - g[o + W];
      lap += l; lap2 += l * l;
      n++;
    }
  }
  const pct = (q) => { let acc = 0; for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc >= n * q) return v; } return 255; };
  let patch = 0;
  for (let i = 0; i < CX * CY; i++) if (cellN[i] && cellSat[i] / cellN[i] >= TH.glare.cell) patch++;
  const lapVar = lap2 / n - (lap / n) ** 2;
  const g2 = grad2 / n;
  return {
    mean: sum / n, p5: pct(0.05), p50: pct(0.5), p95: pct(0.95), sat: sat / n, patch,
    lapVar, focus: g2 > 1 ? lapVar / (g2 + 1) : null, energy: grad1 / n / 2, n,
  };
}

/**
 * How far the picture moved since the last one, in outline widths: Σ|ΔI| / Σ|∇I| is the shift
 * in pixels (for a small shift, ΔI ≈ ∇I·d), measured only over the outline's area.
 */
export function motionOf(im, prev, guide) {
  if (!prev || prev.w !== im.w || prev.h !== im.h) return null;
  // on 2×2 averages: a print of fine bars (a barcode) would otherwise hide a shift of more than a bar's width
  const x0 = Math.max(2, Math.round(guide.x)) & ~1, x1 = Math.min(im.w - 4, Math.round(guide.x + guide.w));
  const y0 = Math.max(2, Math.round(guide.y)) & ~1, y1 = Math.min(im.h - 4, Math.round(guide.y + guide.h));
  const cw = (x1 - x0) >> 1, ch = (y1 - y0) >> 1;
  if (cw < 8 || ch < 8) return null;
  const W = im.w, g = im.g, p = prev.g;
  const a = new Float32Array(cw * ch), b = new Float32Array(cw * ch);
  for (let y = 0; y < ch; y++) {
    for (let x = 0; x < cw; x++) {
      const o = (y0 + 2 * y) * W + x0 + 2 * x;
      a[y * cw + x] = (g[o] + g[o + 1] + g[o + W] + g[o + W + 1]) / 4;
      b[y * cw + x] = (p[o] + p[o + 1] + p[o + W] + p[o + W + 1]) / 4;
    }
  }
  let d = 0, e = 0;
  for (let y = 1; y < ch - 1; y++) {
    for (let x = 1; x < cw - 1; x++) {
      const o = y * cw + x;
      d += Math.abs(a[o] - b[o]);
      e += (Math.abs(a[o + 1] - a[o - 1]) + Math.abs(a[o + cw] - a[o - cw])) / 2;
    }
  }
  if (e < 150) return d > 150 ? 1 : 0; // no edges to move: a wholesale change of brightness is a change, nothing else is
  return ((d / e) * 2) / guide.w;
}

/**
 * The document has the outline's proportions, so its width and height (as shares of the outline's)
 * must agree. When they don't, an edge was taken for something inside the document (a dark band that
 * matches the table hides the real edge): the true edge is always further out, by about the shortfall.
 * Look for it there, more sensitively, in a narrow band; take it only when it is clearly an edge.
 */
export function refineByAspect(im, guide, edges) {
  const f = (s) => (edges[s]?.found ? edges[s] : null);
  const L = f("left"), R = f("right"), T = f("top"), B = f("bottom");
  if (!(L && R && T && B)) return edges;
  const gap = (1 + L.off + R.off) - (1 + T.off + B.off); // + : the height is short
  if (Math.abs(gap) <= 0.05) return edges;
  const pair = gap > 0 ? ["top", "bottom"] : ["left", "right"];
  const miss = Math.abs(gap);
  const look = (s, target) => {
    const r = sideEdge(im, guide, s, { inShare: -(target - 0.04), outShare: target + 0.04, minStep: 5, frac: 0.4, minRuns: 3 });
    return r.found && Math.abs(r.off - target) < 0.05 && r.off > edges[s].off + 0.02 ? r : null;
  };
  // one of the pair holds the whole shortfall…
  const one = pair.map((s) => [s, look(s, edges[s].off + miss)]).filter(([, r]) => r);
  if (one.length === 1) return { ...edges, [one[0][0]]: one[0][1] };
  // …or each holds half
  if (!one.length) {
    const both = pair.map((s) => [s, look(s, edges[s].off + miss / 2)]);
    if (both.every(([, r]) => r)) return { ...edges, [both[0][0]]: both[0][1], [both[1][0]]: both[1][1] };
  }
  return edges;
}

/** All the numbers for one picture. `prev` is the previous picture (for movement). */
export function measure(im, guide, { prev = null } = {}) {
  const st = inside(im, guide);
  let edges = {};
  for (const s of ["top", "bottom", "left", "right"]) edges[s] = sideEdge(im, guide, s);
  edges = refineByAspect(im, guide, edges);
  return { ...st, motion: motionOf(im, prev, guide), edges, ...fitOf(edges) };
}

/**
 * The document's size, shift and turn from where its edges are.
 *   scale   its width as a share of the outline's (1 = fills it exactly), from the edges found
 *   dx, dy  its centre's offset from the outline's centre, in outline sizes (+ is right / down)
 *   rot     turned in the plane, degrees (+ clockwise)
 *   flatH, flatV   one side narrowing, degrees (a phone held at an angle)
 *   sides   how many of the four edges were found
 */
export function fitOf(edges) {
  const f = (s) => (edges[s]?.found ? edges[s] : null);
  const T = f("top"), B = f("bottom"), L = f("left"), R = f("right");
  const found = [T, B, L, R].filter(Boolean);
  const sides = found.length;
  if (sides < 2) return { sides, scale: null, dx: 0, dy: 0, rot: 0, flatH: 0, flatV: 0, rotSpread: 0, aspect: 0 };
  const scale = 1 + 2 * (found.reduce((t, e) => t + e.off, 0) / sides);
  const dx = L && R ? (R.off - L.off) / 2 : 0, dy = T && B ? (B.off - T.off) / 2 : 0;
  const angs = [];
  if (T) angs.push(T.slope); if (B) angs.push(B.slope); if (L) angs.push(-L.slope); if (R) angs.push(-R.slope);
  const rot = angs.length ? (angs.reduce((t, a) => t + a, 0) / angs.length) / D2R : 0;
  const spread = angs.length > 1 ? (Math.max(...angs) - Math.min(...angs)) / D2R : 0;
  const flatH = T && B ? (B.slope - T.slope) / 2 / D2R : 0;
  const flatV = L && R ? (R.slope - L.slope) / 2 / D2R : 0;
  // a width and a height that still disagree: the proportions aren't the outline's, or an edge was missed
  const aspect = L && R && T && B ? (1 + L.off + R.off) - (1 + T.off + B.off) : 0;
  return { sides, scale, dx, dy, rot, flatH, flatV, rotSpread: spread, aspect };
}

/* ---------------- the verdict ---------------- */

/** What can be said, and the words. `detail` may be replaced by a direction by judge(). */
export const MESSAGES = {
  dark: { title: "Too dark", detail: "Turn on the light, or move somewhere brighter.", help: "light" },
  glare: { title: "Too much glare", detail: "Tilt the document a little so the shine moves off it.", help: null },
  closer: { title: "Move closer", detail: "Fill the outline with the document.", help: null },
  fill: { title: "Fill the outline", detail: "Bring it a little closer, edge to edge.", help: null },
  back: { title: "Move back a little", detail: "The whole document has to fit inside the outline.", help: null },
  shift: { title: "Line it up", detail: "Move it so its edges meet the outline.", help: null },
  tilt: { title: "Straighten the card", detail: "Turn it until its edges run along the outline.", help: null },
  flat: { title: "Hold the phone flat", detail: "Hold it straight above the document, not at an angle.", help: null },
  blur: { title: "Not sharp yet", detail: "Hold still and let the camera focus. Wipe the lens if it stays blurry.", help: null },
  showback: { title: "Show the back", detail: "Turn it to the side with the barcode, or press the round button.", help: null },
  showfront: { title: "Show the front", detail: "The side with your photo.", help: null },
  showpage: { title: "Show the photo page", detail: "The page with your photo and the two lines of <<<.", help: null },
};

/** How long a problem must last before it is said (ms), where it is not the usual 700: a blur is often just the focus settling; the wrong side takes a moment to turn. */
export const SAY_AFTER = { blur: 1800, showback: 1800, showfront: 1800, showpage: 2200, dark: 900 };

/**
 * One verdict from the numbers.
 *   m         measure()'s result
 *   template  templateFor()'s result
 *   extra     optional strong signals: { barcode: { across (share of the outline's width), upright } | null, mrz: boolean }
 *             (omitted keys mean "not looked for")
 * Returns {
 *   key       the message (a key of MESSAGES) or null when there is nothing to fix
 *   detail    the words under it
 *   present   something that looks like the document is in the outline
 *   aligned   size and position are right (the crop will hold the whole document)
 *   steady, sharp, ready   ready = nothing to fix, steady and sharp
 *   scale, rot, deskew (degrees to turn the crop by, or 0)
 * }
 * The order matters: light first (nothing else can be measured in the dark), then size, then
 * position, then turn, then the picture's own quality, then the wrong side.
 */
export function judge(m, template, extra = {}) {
  const out = { key: null, detail: null, present: false, aligned: false, steady: true, sharp: true, ready: false, scale: m.scale, rot: m.rot, deskew: 0 };
  const say = (key, detail) => { out.key = key; out.detail = detail || MESSAGES[key].detail; return out; };
  const noun = template?.noun || "card";
  if (!m.n) return out;
  // light: nothing can be measured in the dark. With the document in view its own brightness
  // counts; with nothing in view only a view that is dark all over does (a dark table in good light isn't "too dark")
  const D = TH.dark;
  if (m.sides >= 2 ? m.p95 < D.p95 || m.mean < D.mean : m.mean < D.empty.mean && m.p95 < D.empty.p95) return say("dark");
  const G = TH.glare, whitePaper = m.p50 >= G.paper;
  if (m.patch >= (whitePaper ? G.paperCells : G.cells) && m.sat >= (whitePaper ? G.paperShare : G.share)) return say("glare");
  // is anything there
  const textured = m.energy > 6;
  out.present = m.sides >= 2 || textured;
  if (!out.present) return out;
  // the barcode / MRZ as a second opinion on size when the edges can't give one
  let scale = m.scale;
  const bar = extra.barcode;
  if (scale == null && bar && template?.expect?.barcode) scale = bar.across / TH.barAcross * 0.9;
  out.scale = scale;
  // the edges can't be told apart from print: nothing is said about size, and nothing is taken by itself
  // (a document well past the outline is cut off by the picture's edge, which skews the shape: that is still "move back")
  // (a turned or tilted document has a skewed shape too, and says so below)
  const skewed = (Math.abs(m.rot) > TH.tilt && m.rotSpread < 6) || Math.abs(m.flatH) > TH.flat || Math.abs(m.flatV) > TH.flat;
  if (Math.abs(m.aspect || 0) > TH.aspect && !skewed) { if (scale != null && m.sides >= 3 && scale > TH.big) return say("back"); out.unsure = true; out.present = false; return out; }
  const edgeOk = m.sides >= 3;
  if (scale != null && (edgeOk || bar)) {
    if (scale < TH.small) return say("closer");
    if (scale < TH.snug) return say("fill");
    if (scale > TH.big) return say("back");
  } else if (!edgeOk) {
    return out; // present, but the edges can't be told: the outline's generic prompt stays up and nothing is captured by itself
  }
  // position: every edge found must sit within what the crop (the outline plus a margin) holds
  const out_ = (e) => e.found && (e.off < -TH.edgeIn || e.off > TH.edgeOut);
  if (Object.values(m.edges).some(out_) || Math.abs(m.dx) > TH.shift || Math.abs(m.dy) > TH.shift) {
    // which way: the document sits to the right if its right edge is further out than its left
    const side = (v, neg, pos) => (v > TH.shift / 2 ? pos : v < -TH.shift / 2 ? neg : "");
    const x = side(m.dx, "left", "right"), y = side(m.dy, "higher", "lower");
    const move = [side(m.dx, "right", "left"), side(m.dy, "down", "up")].filter(Boolean).join(" and ");
    const at = [y, x && `to the ${x}`].filter(Boolean).join(" and ");
    return say("shift", at ? `The ${noun} sits ${at} of the outline. Move it ${move}.` : null);
  }
  // turn
  if (Math.abs(m.rot) > TH.tilt && m.rotSpread < 6) return say("tilt", template?.shape === "td3" ? "Turn the page until its edges run along the outline." : null);
  if (Math.abs(m.flatH) > TH.flat || Math.abs(m.flatV) > TH.flat) return say("flat");
  if (Math.abs(m.rot) >= TH.deskew[0] && Math.abs(m.rot) <= TH.deskew[1] && m.rotSpread < 4 && m.sides >= 3) out.deskew = m.rot;
  // the picture's own quality
  out.aligned = true;
  out.steady = m.motion == null ? true : m.motion <= TH.steady;
  out.sharp = m.focus == null ? true : m.focus >= TH.sharp && !(extra.bestFocus > 1.2 && m.focus < TH.sharpRel * extra.bestFocus);
  // the wrong side, said once it has held (SAY_AFTER); and ready is withheld while it is wrong
  const wrong = wrongSide(template, extra, out);
  if (wrong && out.steady && out.sharp) { out.key = wrong; out.detail = MESSAGES[wrong].detail; out.aligned = true; return out; }
  if (!out.sharp && out.steady) { out.key = "blur"; out.detail = MESSAGES.blur.detail; return out; }
  out.ready = out.steady && out.sharp;
  return out;
}

/** "showback" / "showfront" / "showpage" when a strong signal says this isn't the side asked for, else null. */
function wrongSide(template, extra, v) {
  if (!template) return null;
  if (template.expect.barcode && !template.expect.mrz && extra.barcode === null) return "showback";
  if (template.expect.mrz && !template.expect.barcode && template.shape === "td3" && extra.mrz === false) return "showpage";
  if (template.expect.barcode && template.expect.mrz && extra.barcode === null && extra.mrz === false) return "showback";
  if (template.forbid?.barcode && extra.barcode) return "showfront";
  return null;
}

/* ---------------- the hold ---------------- */

/**
 * "Lined up, steady and sharp for about 0.6 s" → fire. Feed it each verdict's `ready`; one bad
 * look in a row (shorter than graceMs) doesn't restart the count. progress runs 0..1 for the bar.
 */
export function holdTracker({ holdMs = TH.holdMs, graceMs = TH.graceMs } = {}) {
  let since = 0, lastGood = 0, fired = false;
  return {
    feed(ready, now) {
      if (fired) return { progress: 1, fire: false };
      if (ready) {
        if (!since) since = now;
        lastGood = now;
      } else if (since && now - lastGood > graceMs) since = 0;
      const progress = since ? clamp((now - since) / holdMs, 0, 1) : 0;
      if (since && now - since >= holdMs && ready) { fired = true; return { progress: 1, fire: true }; }
      return { progress, fire: false };
    },
    reset() { since = 0; lastGood = 0; fired = false; },
  };
}

/* ---------------- barcodes and MRZ as extra signals ---------------- */

/**
 * A barcode found by core/barcodefind.js in the analysis picture → { across } as a share of the
 * outline's width (its long side), or null for none. `spots` are locateBarcodes() results in the picture's pixels.
 */
export function barcodeSignal(spots, guide) {
  const inGuide = (spots || []).filter((s) => {
    const cx = s.box.x + s.box.w / 2, cy = s.box.y + s.box.h / 2;
    return cx > guide.x && cx < guide.x + guide.w && cy > guide.y && cy < guide.y + guide.h;
  });
  if (!inGuide.length) return null;
  const s = inGuide.sort((a, b) => b.box.w * b.box.h - a.box.w * a.box.h)[0];
  return { across: (s.upright ? s.box.w : s.box.h) / guide.w, upright: s.upright, box: s.box };
}

/** The outline's bottom third as a small picture for core/addroute.js mrzBandLikely: { w, h, g }. */
export function bottomBand(im, guide, share = 0.34) {
  const x0 = Math.max(0, Math.round(guide.x)), x1 = Math.min(im.w, Math.round(guide.x + guide.w));
  const y1 = Math.min(im.h, Math.round(guide.y + guide.h)), y0 = Math.max(0, Math.round(y1 - guide.h * share));
  const w = x1 - x0, h = y1 - y0;
  const g = new Uint8ClampedArray(w * h);
  for (let y = 0; y < h; y++) g.set(im.g.subarray((y0 + y) * im.w + x0, (y0 + y) * im.w + x0 + w), y * w);
  return { w, h, g };
}

/* ---------------- still ↔ preview ---------------- */

/**
 * Where the preview's frame sits in a still photo, when both come from the same sensor: the
 * preview is the part of the sensor's field the still also covers (they share the dimension that
 * is the same), centred. Returns the photo's pixels per video pixel and the offset of the video's
 * origin in the photo.
 */
export function stillMapping(vw, vh, pw, ph) {
  const scale = Math.min(pw / vw, ph / vh);
  return { scale, ox: (pw - vw * scale) / 2, oy: (ph - vh * scale) / 2 };
}

/** The outline's rectangle (video pixels) in a still, through stillMapping, shifted by (dx, dy) video pixels. */
export function rectInStill(rect, map, dx = 0, dy = 0) {
  return { x: map.ox + (rect.x + dx) * map.scale, y: map.oy + (rect.y + dy) * map.scale, w: rect.w * map.scale, h: rect.h * map.scale };
}

/**
 * How well two small grey pictures of the same size agree (normalised cross-correlation, −1..1),
 * searched over shifts of up to `reach` pixels: { score, dx, dy }. Used to confirm that a still
 * photo really shows the outline's part of the scene before it replaces the preview frame, and to
 * correct a small mismatch of framing between the two.
 */
export function agree(a, b, reach = 3) {
  if (a.w !== b.w || a.h !== b.h) return { score: -1, dx: 0, dy: 0 };
  let best = { score: -1, dx: 0, dy: 0 };
  const m = reach, w = a.w, h = a.h;
  for (let dy = -m; dy <= m; dy++) {
    for (let dx = -m; dx <= m; dx++) {
      let sa = 0, sb = 0, saa = 0, sbb = 0, sab = 0, n = 0;
      for (let y = m; y < h - m; y++) {
        for (let x = m; x < w - m; x++) {
          const p = a.g[y * w + x], q = b.g[(y + dy) * w + x + dx];
          sa += p; sb += q; saa += p * p; sbb += q * q; sab += p * q; n++;
        }
      }
      const va = saa - (sa * sa) / n, vb = sbb - (sb * sb) / n;
      const score = va > 1 && vb > 1 ? (sab - (sa * sb) / n) / Math.sqrt(va * vb) : -1;
      if (score > best.score) best = { score, dx, dy };
    }
  }
  return best;
}

/** The share of the picture a preview thumbnail has to agree with the still for the still to be used. */
export const STILL_AGREES = 0.6;
