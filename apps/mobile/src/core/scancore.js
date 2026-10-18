// The per-frame analysis, free of any browser object so the same code runs in the scan
// worker (core/scanworker.js), on the main thread when workers aren't available
// (core/analyzer.js), and in Node (tests/scanflow.test.js, the benchmark). Works on small
// grey pictures { w, h, g } only.
import { lookAt, shrink } from "./docfind.js";
import { locateBarcodes } from "./barcodefind.js";

/** The long side of the picture the document is looked for in: 224 px finds the outline as exactly as 320 does at half the work. */
export const LOOK_PX = 224;
/** The long side of the picture a barcode is first looked for in (a barcode's bars need more). */
export const BAR_PX = 400;

/**
 * One analyser: remembers the previous look's picture (for steadiness) and answers
 * `look` (the document) and `locate` (barcode-like patches). `gray` is the camera's
 * picture at LOOK_PX (or BAR_PX when barcodes are wanted; the document is then looked
 * for in a smaller copy of it).
 */
export function createCore() {
  let prev = null;
  return {
    look(gray, { shape = "full", prior = null, bar = false } = {}) {
      const t0 = now();
      const small = Math.max(gray.w, gray.h) > LOOK_PX * 1.15 ? shrink(gray, LOOK_PX) : gray;
      const look = lookAt(small, { shape, prev, prior });
      prev = small;
      const t1 = now();
      const spots = bar ? locateBarcodes(gray) : null;
      return { look, w: small.w, h: small.h, spots, bw: gray.w, bh: gray.h, ms: Math.round(t1 - t0), barMs: Math.round(now() - t1) };
    },
    locate(gray) { return locateBarcodes(gray); },
    reset() { prev = null; },
  };
}

const now = () => (typeof performance !== "undefined" ? performance.now() : Date.now());
