// Finding the document in a still when the live view already knows roughly where it is.
// The still is searched again at a finer scale (core/scan.js cornersIn), and most of what
// that costs is edges and candidate outlines in the rest of the picture: the table, the
// background. So the search is made first in just the part of the picture around the live
// outline (a margin each side), which is where the document is; only if that finds nothing
// is the whole picture searched. Same search (findDocument), same scale, a smaller picture.
// Pure functions on small grey pictures { w, h, g }, tested in Node (tests/capture.test.js).
import { findDocument } from "./docfind.js";

/** The grey picture's part inside `box` ({ x, y, w, h }, whole pixels). */
export function cropGray(im, box) {
  const g = new Uint8ClampedArray(box.w * box.h);
  for (let y = 0; y < box.h; y++) g.set(im.g.subarray((box.y + y) * im.w + box.x, (box.y + y) * im.w + box.x + box.w), y * box.w);
  return { w: box.w, h: box.h, g };
}

/** The box around `quad` grown by `margin` of its own size each side, kept inside im; null if it would be most of the picture anyway. */
export function boxAround(quad, im, margin = 0.12) {
  const xs = quad.map((p) => p.x), ys = quad.map((p) => p.y);
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const mx = (x1 - x0) * margin + 4, my = (y1 - y0) * margin + 4;
  const bx = Math.max(0, Math.floor(x0 - mx)), by = Math.max(0, Math.floor(y0 - my));
  const bw = Math.min(im.w, Math.ceil(x1 + mx)) - bx, bh = Math.min(im.h, Math.ceil(y1 + my)) - by;
  if (bw < 48 || bh < 48 || (bw * bh) / (im.w * im.h) > 0.55) return null;
  return { x: bx, y: by, w: bw, h: bh };
}

/**
 * The document near `prior` (its corners in im's pixels): the same answer findDocument()
 * gives for the whole picture, looked for in the part around `prior` first.
 *   returns { quad (in im's pixels), … } or null
 */
export function findNear(im, prior, { ratio = null, minArea = 0.03 } = {}) {
  const box = prior ? boxAround(prior, im) : null;
  if (box) {
    const part = cropGray(im, box);
    const shifted = prior.map((p) => ({ x: p.x - box.x, y: p.y - box.y }));
    // inside the box the document is most of what there is (its own area plus a margin)
    const d = findDocument(part, { minArea: Math.max(minArea, 0.2), prior: shifted, ratio });
    if (d) return { ...d, quad: d.quad.map((p) => ({ x: p.x + box.x, y: p.y + box.y })), near: true };
  }
  return findDocument(im, { minArea, prior, ratio });
}
