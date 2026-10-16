// Is a document lined up in the camera's frame, sharp and steady enough to take?
// Runs on a small grey copy of the area around the on-screen frame (about 320 px
// wide) several times a second, so it's plain arithmetic: no models, nothing sent
// anywhere. Pure functions on { w, h, g } (one byte per pixel), so it's tested in
// Node with drawn images (tests/detect.test.js).
//
// What it checks, in order:
//   edges     each side of the frame has a straight, high-contrast edge near it
//             (the document's border), along most of its length, and together
//             they make a document of the expected shape (cards 1.586:1, a
//             passport photo page 1.42:1) filling most of the frame
//   light     not too dark, and not washed out (glare only earns a hint)
//   sharp     the border is a crisp step, not a blurred ramp (focus, motion)
//   steady    the picture barely changed since the last look
// Several good looks in a row and the camera takes the photo by itself.

/** Proportions of each document shape (width / height). */
export const ASPECT = { id1: 1.586, td3: 1.42 };

/** RGBA ImageData-like → grey { w, h, g }. */
export function toGray({ data, width, height }) {
  const g = new Uint8ClampedArray(width * height);
  for (let i = 0, j = 0; j < g.length; i += 4, j++) g[j] = (data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) >> 8;
  return { w: width, h: height, g };
}

const at = (im, x, y) => im.g[Math.min(im.h - 1, Math.max(0, y)) * im.w + Math.min(im.w - 1, Math.max(0, x))];
/** Mean of a small vertical / horizontal run, to steady single noisy pixels. */
const avgV = (im, x, y) => (at(im, x - 1, y) + at(im, x, y) + at(im, x + 1, y)) / 3;
const avgH = (im, x, y) => (at(im, x, y - 1) + at(im, x, y) + at(im, x, y + 1)) / 3;

const CONTRAST = 22;    // grey levels across a border that count as an edge
const COVERAGE = 0.6;   // share of a side's length that must show that edge
const SPAN = 0.76;      // the middle of each side is checked (corners are rounded)

/**
 * Find the strongest straight edge near where one side of the frame is.
 * side: "top" | "bottom" | "left" | "right"; at: expected position (px);
 * from, to: the other axis' extent (px). Returns { pos, coverage, sharp }.
 */
function findEdge(im, side, expected, from, to, band) {
  const horizontal = side === "top" || side === "bottom";
  const len = to - from;
  const a = Math.round(from + len * (1 - SPAN) / 2), b = Math.round(to - len * (1 - SPAN) / 2);
  const step = Math.max(1, Math.round((b - a) / 48));
  const line = (q) => (horizontal ? (k) => avgV(im, q, best.pos + k) : (k) => avgH(im, best.pos + k, q));
  let best = { pos: Math.round(expected), coverage: 0, strength: 0 };
  // the position along the band where the edge runs furthest and strongest
  for (let p = Math.max(7, Math.round(expected - band)); p <= Math.min((horizontal ? im.h : im.w) - 8, Math.round(expected + band)); p++) {
    let hits = 0, n = 0, strength = 0;
    for (let q = a; q <= b; q += step) {
      n++;
      const across = horizontal ? Math.abs(avgV(im, q, p + 3) - avgV(im, q, p - 3)) : Math.abs(avgH(im, p + 3, q) - avgH(im, p - 3, q));
      strength += across;
      if (across >= CONTRAST) hits++;
    }
    const coverage = hits / n;
    if (coverage > best.coverage || (coverage === best.coverage && strength > best.strength)) best = { pos: p, coverage, strength };
  }
  // how crisp it is there: the steepest single-pixel step, as a share of the whole
  // step across 12 px. A focused border is nearly all one step; a blurred one a ramp.
  let steep = 0, k = 0;
  for (let q = a; q <= b; q += step) {
    const v = line(q);
    const total = Math.abs(v(6) - v(-6));
    if (total < CONTRAST) continue;
    let s1 = 0;
    for (let j = -6; j < 6; j++) s1 = Math.max(s1, Math.abs(v(j + 1) - v(j)));
    steep += Math.min(1, s1 / total); k++;
  }
  return { pos: best.pos, coverage: best.coverage, sharp: k ? steep / k : 0 };
}

/**
 * Look at one frame.
 *   im      grey crop around the on-screen frame
 *   guide   where the frame sits in that crop, as fractions { x0, y0, x1, y1 }
 *   shape   "id1" | "td3"
 *   prev    the previous look's crop (same size), for steadiness
 * Returns { found, aligned, sharp, light, glare, steady, ok, hint, edges }.
 */
export function analyzeFrame(im, { guide, shape = "id1", prev = null } = {}) {
  const gx0 = guide.x0 * im.w, gx1 = guide.x1 * im.w, gy0 = guide.y0 * im.h, gy1 = guide.y1 * im.h;
  const bandX = (gx1 - gx0) * 0.1, bandY = (gy1 - gy0) * 0.12;
  const top = findEdge(im, "top", gy0, gx0, gx1, bandY);
  const bottom = findEdge(im, "bottom", gy1, gx0, gx1, bandY);
  const left = findEdge(im, "left", gx0, gy0, gy1, bandX);
  const right = findEdge(im, "right", gx1, gy0, gy1, bandX);
  const sides = [top, right, bottom, left];
  const seen = sides.filter((s) => s.coverage >= COVERAGE).length;
  const found = seen === 4;

  // the four edges must make the document's shape, and fill most of the frame
  const w = right.pos - left.pos, h = bottom.pos - top.pos;
  const aspect = h > 0 ? w / h : 0;
  const want = ASPECT[shape] || ASPECT.id1;
  const fill = (w * h) / ((gx1 - gx0) * (gy1 - gy0));
  const aligned = found && Math.abs(aspect / want - 1) < 0.08 && fill > 0.72;

  // light and glare, inside the document
  let sum = 0, bright = 0, n = 0;
  const ix0 = Math.round(left.pos + w * 0.08), ix1 = Math.round(right.pos - w * 0.08);
  const iy0 = Math.round(top.pos + h * 0.08), iy1 = Math.round(bottom.pos - h * 0.08);
  for (let y = iy0; y < iy1; y += 2) for (let x = ix0; x < ix1; x += 2) { const v = at(im, x, y); sum += v; if (v >= 253) bright++; n++; }
  const mean = n ? sum / n : 0;
  const light = mean >= 45 && mean <= 240;
  // white card stock and barcode areas are legitimately near-white: only a large blown-out area is glare
  const glare = n ? bright / n > 0.4 : false;

  // focus: a crisp border has most of its contrast in one or two pixels
  const sharpness = found ? sides.reduce((t, s) => t + s.sharp, 0) / 4 : 0;
  const sharp = sharpness >= 0.38;

  // steadiness: hardly anything moved since the last look
  let motion = 0;
  if (prev && prev.w === im.w && prev.h === im.h) {
    let d = 0, k = 0;
    for (let i = 0; i < im.g.length; i += 7) { d += Math.abs(im.g[i] - prev.g[i]); k++; }
    motion = d / k;
  }
  const steady = !prev || motion < 7;

  // Glare is advice, not a veto: near-white card stock and barcode areas look the same
  // to a brightness count, and a photo with a little glare is still worth keeping.
  const ok = aligned && light && sharp && steady;
  const hint = ok ? "Hold still…"
    : !found ? (seen >= 2 ? "Line the edges up with the frame" : "Fit the document in the frame")
    : !aligned ? (fill <= 0.72 ? "Move a little closer" : "Line the edges up with the frame")
    : glare ? "Glare: tilt the document a little"
    : !light ? (mean < 45 ? "Find a little more light" : "Too bright: move out of direct light")
    : !steady ? "Hold still…"
    : "Hold still while it focuses…";
  return { found, aligned, sharp, sharpness, light, glare, steady, motion, ok, hint, edges: { top: top.pos, right: right.pos, bottom: bottom.pos, left: left.pos }, coverage: sides.map((s) => s.coverage) };
}

/**
 * Decides when to take the photo: after `need` good looks in a row. A bad look
 * starts the count again, so a passing blur or a hand moving resets it.
 */
export function autoShutter({ need = 4 } = {}) {
  let run = 0;
  return {
    /** Feed one look; true when it's time to take the photo. */
    feed(look) { run = look.ok ? run + 1 : 0; return run >= need; },
    get progress() { return Math.min(1, run / need); },
    reset() { run = 0; },
  };
}
