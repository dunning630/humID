// Reading documents with the camera, on this device: the barcode reader
// (PDF417 on North American licenses), the MRZ reader (OCR of the
// machine-readable lines on passports and ID cards) and the image handling
// around them. The engines and the MRZ model ship inside the app
// (assets/scan, assets/ocr) and load the first time a document is scanned;
// nothing is sent anywhere to be read.
//
//   barcode   zxing-cpp (WebAssembly), PDF417
//   MRZ       Tesseract (WebAssembly, in a worker) with an OCR-B model trained
//             for MRZs (DoubangoTelecom/tesseractMRZ, BSD-3-Clause)

import { warp, outputSize, findDocument, orientation, toGray, shrink, scaleQuad, bandPlan } from "./docfind.js";
import { cleanScan, lightField, paperShare } from "./scanclean.js";
import { cleanPixels } from "./scanjobs.js";
import { findNear } from "./docnear.js";
import { b64Bytes, bytesB64 } from "./bytes.js";
import { span } from "./perf.js";

export { createAnalyzer } from "./analyzer.js";

/* global __HUMID_OCR_DIR__, __HUMID_SCAN_DIR__ */
// The engines live in content-hashed directories next to the app bundle (build.mjs), so
// the edge serves them immutable and a new engine is never confused with an old one.
const OCR_DIR = typeof __HUMID_OCR_DIR__ !== "undefined" ? __HUMID_OCR_DIR__ : "ocr";
const SCAN_DIR = typeof __HUMID_SCAN_DIR__ !== "undefined" ? __HUMID_SCAN_DIR__ : "scan";
// Absolute: this module may land in any chunk, and the engines sit beside the app bundle.
const asset = (p) => `/assets/${p}`;
// WebAssembly SIMD makes Tesseract's LSTM pass about twice as fast (less time, less
// battery per read). A 10-byte module with one SIMD instruction tells us if it's there.
const SIMD = (() => { try { return WebAssembly.validate(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11])); } catch { return false; } })();
const CORE = "tesseract-core-simd-lstm.js";
const NO_SIMD = "This phone's browser can't run the document reader. Type the details instead; a newer system version fixes this.";
const MRZ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<";

/* ---------------- engines ---------------- */

let barcodeP = null;
/** { read(ImageData) → Promise<string[]> } — PDF417 texts found, control characters kept. */
export function barcodeReader() {
  barcodeP ||= (async () => {
    const zx = await import("zxing-wasm/reader");
    await zx.prepareZXingModule({
      overrides: { locateFile: (path, prefix) => (path.endsWith(".wasm") ? asset(`${SCAN_DIR}/${path}`) : prefix + path) },
      fireImmediately: true,
    });
    return {
      async read(img, { harder = true } = {}) {
        const r = await zx.readBarcodes(img, { formats: ["PDF417"], tryHarder: harder, tryRotate: harder, tryInvert: false, textMode: "Plain", maxNumberOfSymbols: 1 });
        return r.filter((x) => x.isValid && x.text).map((x) => x.text);
      },
    };
  })();
  barcodeP.catch(() => { barcodeP = null; });
  return barcodeP;
}

let qrP = null;
/** { read(ImageData) → Promise<string[]> } — QR codes, for devices without a native BarcodeDetector. */
export function qrReader() {
  qrP ||= (async () => {
    const zx = await import("zxing-wasm/reader");
    await zx.prepareZXingModule({
      overrides: { locateFile: (path, prefix) => (path.endsWith(".wasm") ? asset(`${SCAN_DIR}/${path}`) : prefix + path) },
      fireImmediately: true,
    });
    return {
      async read(img) {
        const r = await zx.readBarcodes(img, { formats: ["QRCode"], tryHarder: false, tryRotate: false, tryInvert: false, textMode: "Plain", maxNumberOfSymbols: 1 });
        return r.filter((x) => x.isValid && x.text).map((x) => x.text);
      },
    };
  })();
  qrP.catch(() => { qrP = null; });
  return qrP;
}

let ocrP = null;
/** { read(canvas) → Promise<string> } — the MRZ reader. One worker, reused until released. */
export function mrzReader() {
  ocrP ||= (async () => {
    if (!SIMD) throw Object.assign(new Error(NO_SIMD), { code: "no_simd" });
    const { default: Tesseract } = await import("tesseract.js/dist/tesseract.esm.min.js");
    const base = asset(`${OCR_DIR}/`);
    const worker = await Tesseract.createWorker("mrz", 1 /* LSTM only */, {
      workerPath: `${base}worker.min.js`, corePath: `${base}${CORE}`, langPath: base.replace(/\/$/, ""),
      gzip: false, cacheMethod: "none", workerBlobURL: false, logger: () => {}, errorHandler: () => {},
    });
    await worker.setParameters({ tessedit_char_whitelist: MRZ_CHARS, tessedit_pageseg_mode: "6", preserve_interword_spaces: "0" });
    return { read: async (canvas) => (await worker.recognize(canvas)).data.text || "", stop: () => worker.terminate() };
  })();
  ocrP.catch(() => { ocrP = null; });
  return ocrP;
}

let textP = null;
/**
 * { read(canvas, { front }) → Promise<string> } — general printed text, for payment cards.
 * front: digits, capitals and the separators a card front uses; the back is read unrestricted
 * (the security code, the bank's phone number). One worker, reused until released.
 */
export function textReader() {
  textP ||= (async () => {
    if (!SIMD) throw Object.assign(new Error(NO_SIMD), { code: "no_simd" });
    const { default: Tesseract } = await import("tesseract.js/dist/tesseract.esm.min.js");
    const base = asset(`${OCR_DIR}/`);
    const worker = await Tesseract.createWorker("eng", 1 /* LSTM only */, {
      workerPath: `${base}worker.min.js`, corePath: `${base}${CORE}`, langPath: base.replace(/\/$/, ""),
      gzip: false, cacheMethod: "none", workerBlobURL: false, logger: () => {}, errorHandler: () => {},
    });
    let mode = null;
    const set = async (front) => {
      if (mode === front) return;
      await worker.setParameters({ tessedit_char_whitelist: front ? "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ/-.' " : "", tessedit_pageseg_mode: "11", preserve_interword_spaces: "1" });
      mode = front;
    };
    // A card photo goes to the reader as a JPEG (q 0.95): the reader's own conversion of a canvas is a PNG, which takes
    // two to three times as long to make (0.5 s against 0.2 s for a 2600 px card at 4x slower than this machine) and leaves the print as sharp.
    const asImage = async (canvas) => { try { return await toBlob(canvas, "image/jpeg", 0.95); } catch { return canvas; } };
    return { read: async (canvas, { front = true } = {}) => { await set(front); return (await worker.recognize(await asImage(canvas))).data.text || ""; }, stop: () => worker.terminate() };
  })();
  textP.catch(() => { textP = null; });
  return textP;
}

/** Free the readers' memory (tens of MB) when no document is being scanned. */
export async function releaseReaders() {
  const running = [ocrP, textP];
  ocrP = null; textP = null;
  for (const p of running) { try { (await p)?.stop(); } catch { /* already gone */ } }
}

/* ---------------- images ---------------- */

export function canvas(w, h) {
  const c = document.createElement("canvas");
  c.width = Math.max(1, Math.round(w)); c.height = Math.max(1, Math.round(h));
  return c;
}
const ctx2d = (c) => c.getContext("2d", { willReadFrequently: true });

/**
 * Where an on-screen element (the document frame) falls in the video's own
 * pixels, for a <video> shown with object-fit: cover. pad grows it by a
 * fraction on every side, for documents held a little off-frame.
 */
export function frameInVideo(video, el, pad = 0) {
  const vr = video.getBoundingClientRect(), er = el.getBoundingClientRect();
  const vw = video.videoWidth, vh = video.videoHeight;
  if (!vw || !vh) return null;
  const scale = Math.max(vr.width / vw, vr.height / vh);
  const offX = (vr.width - vw * scale) / 2, offY = (vr.height - vh * scale) / 2;
  let x = (er.left - vr.left - offX) / scale, y = (er.top - vr.top - offY) / scale;
  let w = er.width / scale, h = er.height / scale;
  x -= w * pad; y -= h * pad; w *= 1 + 2 * pad; h *= 1 + 2 * pad;
  const x0 = Math.max(0, x), y0 = Math.max(0, y);
  return { x: x0, y: y0, w: Math.min(vw, x + w) - x0, h: Math.min(vh, y + h) - y0 };
}

/** Copy part of a video frame or image into a canvas, at most maxW wide. */
export function grab(src, rect, maxW = Infinity) {
  const r = rect || { x: 0, y: 0, w: src.videoWidth || src.width, h: src.videoHeight || src.height };
  const s = Math.min(1, maxW / r.w);
  const c = canvas(r.w * s, r.h * s);
  const g = ctx2d(c);
  g.imageSmoothingQuality = "high";
  g.drawImage(src, r.x, r.y, r.w, r.h, 0, 0, c.width, c.height);
  return c;
}
export const imageData = (c) => ctx2d(c).getImageData(0, 0, c.width, c.height);
/** A small grey copy of part of a video frame or picture, at most `max` wide. */
export const grayRegion = (src, rect, max = 560) => toGray(imageData(grab(src, rect, max)));

const b64 = bytesB64;
const toBlob = (c, type, q) => new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error("Couldn't encode the photo."))), type, q));

/** A canvas as a JPEG for the record: { type, data (base64), width, height, size }. */
export async function jpeg(c, { maxW = 1600, quality = 0.86 } = {}) {
  const end = span("jpeg");
  const src = c.width > maxW ? grab(c, null, maxW) : c;
  let blob;
  try { blob = await toBlob(src, "image/jpeg", quality); }
  catch { blob = await toBlob(src.width > 1000 ? grab(src, null, 1000) : src, "image/jpeg", 0.8); } // low memory: smaller
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const out = { type: "image/jpeg", data: b64(bytes), width: src.width, height: src.height, size: bytes.length };
  end();
  return out;
}

/**
 * Did the camera hand back a real picture? Some Android WebViews give a black (or
 * one-colour) frame for the first moments after the camera starts, or after the app
 * comes back to the screen. Checks a small copy for any variation at all.
 */
export function looksBlank(c) {
  const w = 48, h = Math.max(1, Math.round((48 * c.height) / Math.max(1, c.width)));
  const small = canvas(w, h);
  ctx2d(small).drawImage(c, 0, 0, w, h);
  const d = ctx2d(small).getImageData(0, 0, w, h).data;
  let min = 255, max = 0;
  for (let i = 0; i < d.length; i += 4) { const y = (d[i] * 77 + d[i + 1] * 150 + d[i + 2] * 29) >> 8; if (y < min) min = y; if (y > max) max = y; }
  return max - min < 12;
}
export const imageUrl = (img) => (img ? `data:${img.type};base64,${img.data}` : null);
export const imageBytes = (img) => b64Bytes(img.data);

/* ---------------- straightening ---------------- */

/**
 * The longest side, in pixels, a straightened picture is made at: the proportion sealed is
 * what a person reads, and a bigger picture only costs time (the warp, the clean scan, the
 * JPEG, and on a phone every megapixel is a second or so). A card is kept at the width
 * its record stores (jpeg() saves 1600; the card flow 1200); a page at about 235 dpi on a
 * letter or A4 sheet, which is where small print is still crisp.
 */
export const CARD_PX = 1600;
export const PAGE_PX = 2600;

/**
 * The part of c the document lies in, as pixels to warp from: not the whole 8 megapixel
 * frame (reading all of it back from the canvas cost more than the warp), just the
 * quad's bounding box plus a margin, and when the output is much smaller than the
 * source, that part scaled down by the browser first (so the warp isn't sampling a
 * picture twice its size: faster, and smoother than skipping pixels). Returns
 * { src (RGBA { width, height, data }), quad (the same corners, in src's pixels) }.
 */
function sourceFor(c, quad, size) {
  const xs = quad.map((p) => p.x), ys = quad.map((p) => p.y);
  const x0 = Math.max(0, Math.floor(Math.min(...xs)) - 2), y0 = Math.max(0, Math.floor(Math.min(...ys)) - 2);
  const x1 = Math.min(c.width, Math.ceil(Math.max(...xs)) + 2), y1 = Math.min(c.height, Math.ceil(Math.max(...ys)) + 2);
  const w = Math.max(1, x1 - x0), h = Math.max(1, y1 - y0);
  const side = Math.max(Math.hypot(quad[1].x - quad[0].x, quad[1].y - quad[0].y), Math.hypot(quad[3].x - quad[2].x, quad[3].y - quad[2].y),
    Math.hypot(quad[3].x - quad[0].x, quad[3].y - quad[0].y), Math.hypot(quad[2].x - quad[1].x, quad[2].y - quad[1].y));
  const k = Math.max(size.width, size.height) / Math.max(1, side); // output pixels per source pixel
  if (k >= 0.75) return { src: ctx2d(c).getImageData(x0, y0, w, h), quad: quad.map((p) => ({ x: p.x - x0, y: p.y - y0 })) };
  const sc = canvas(w * k, h * k);
  const g = ctx2d(sc);
  g.imageSmoothingQuality = "medium";
  g.drawImage(c, x0, y0, w, h, 0, 0, sc.width, sc.height);
  const fx = sc.width / w, fy = sc.height / h;
  return { src: g.getImageData(0, 0, sc.width, sc.height), quad: quad.map((p) => ({ x: (p.x - x0) * fx, y: (p.y - y0) * fy })) };
}

/**
 * Straighten, and keep the grey 900 px copy the page's orientation is judged from, made from
 * the pixels just warped (an area average: cheap) rather than by drawing the new canvas
 * smaller (which made the browser build a mip chain of every megapixel of it).
 */
function straightenWith(c, quad, { prefer = null, max = 3000 } = {}) {
  const end = span("straighten");
  const size = outputSize(quad, { prefer, max: Math.min(max, prefer ? CARD_PX : PAGE_PX) });
  const { src, quad: q } = sourceFor(c, quad, size);
  const out = warp(src, q, size.width, size.height);
  const oc = canvas(size.width, size.height);
  ctx2d(oc).putImageData(new ImageData(out.data, out.width, out.height), 0, 0);
  const gray = shrink(toGray(out), 900);
  end();
  return { canvas: oc, gray };
}

/** The document inside `quad` (in c's pixels), straightened into its own canvas. */
export function straighten(c, quad, { prefer = null, max = 3000 } = {}) {
  return straightenWith(c, quad, { prefer, max }).canvas;
}

/**
 * The "clean scan" of a straightened page (core/scanclean.js): even light, white
 * paper, crisp ink. Returns { canvas, paper } — paper says how much of it looked like
 * paper, so a photo or a dark card isn't offered as a scan by default.
 */
export function cleanCanvas(c) {
  const end = span("clean-main");
  const out = cleanScan(imageData(c));
  const oc = canvas(out.width, out.height);
  ctx2d(oc).putImageData(new ImageData(out.data, out.width, out.height), 0, 0);
  end();
  return { canvas: oc, paper: out.paper };
}

/**
 * Does this page look like paper? The same measure cleanCanvas() reports as `paper`, from a
 * small copy (the light is judged in blocks, so 600 px says what 2600 does): a few
 * milliseconds, so the review can say whether to suggest the clean scan before it exists.
 */
export function paperOf(c) {
  const small = c.width > 600 ? grab(c, null, 600) : c;
  return paperShare(lightField(imageData(small)));
}

/**
 * cleanCanvas(), made off the main thread (core/scanjobs.js): the page is read out of the
 * canvas, handed to the scan worker, and the result drawn back into a new canvas. Resolves
 * { canvas, paper }; the screen waiting for it carries on meanwhile.
 */
export async function cleanCanvasAsync(c) {
  const out = await cleanPixels(imageData(c));
  const oc = canvas(out.width, out.height);
  ctx2d(oc).putImageData(new ImageData(out.data, out.width, out.height), 0, 0);
  return { canvas: oc, paper: out.paper };
}

/** A canvas turned clockwise by 90, 180 or 270 degrees (or itself, for 0). */
export function rotateCanvas(c, deg) {
  const d = ((deg % 360) + 360) % 360;
  if (!d) return c;
  const side = d % 180 !== 0;
  const out = canvas(side ? c.height : c.width, side ? c.width : c.height);
  const g = ctx2d(out);
  g.translate(out.width / 2, out.height / 2);
  g.rotate((d * Math.PI) / 180);
  g.drawImage(c, -c.width / 2, -c.height / 2);
  return out;
}

/** A small grey copy of a canvas or video frame, at most `max` on its long side. */
export function grayOf(src, max = 320) {
  const w = src.videoWidth || src.width, h = src.videoHeight || src.height;
  const s = Math.min(1, max / Math.max(w, h));
  const c = canvas(w * s, h * s);
  const g = ctx2d(c);
  g.imageSmoothingQuality = "medium";
  g.drawImage(src, 0, 0, c.width, c.height);
  return toGray(imageData(c));
}

/**
 * The document's corners in a still photo, in the photo's pixels: looked for afresh at
 * 640 px (finer than the live view); if the live view had it (`hint`, same pixels) and
 * the still agrees, the still's (finer) corners, else the live view's. null if neither.
 */
export function cornersIn(c, { hint = null, shape = "full" } = {}) {
  const end = span("corners");
  try { return cornersInside(c, { hint, shape }); } finally { end(); }
}
function cornersInside(c, { hint, shape }) {
  const im = grayOf(c, 640), k = c.width / im.w;
  const prior = hint ? scaleQuad(hint, 1 / k) : null;
  const ratio = { id1: 1.586, td3: 1.42 }[shape] || null;
  const d = hint ? findNear(im, prior, { ratio, minArea: 0.03 }) : findDocument(im, { minArea: 0.12, prior, ratio });
  if (d) {
    const q = scaleQuad(d.quad, k);
    if (!hint) return q;
    const diag = Math.hypot(c.width, c.height);
    const off = q.reduce((t, p, i) => t + Math.hypot(p.x - hint[i].x, p.y - hint[i].y), 0) / 4 / diag;
    if (off < 0.04) return q;
  }
  return hint;
}

/**
 * A photo, developed: the document straightened (when its corners are known) and turned
 * the way it reads. Returns { canvas (the proposal), original, straightened, rotate,
 * confidence }; canvas is the original itself when there's nothing to change.
 *   card   true for cards and passport pages (kept wider than tall)
 */
export function develop(original, quad, { shape = "full" } = {}) {
  const card = shape !== "full";
  const st = quad ? straightenWith(original, quad, { prefer: card ? shape : null, max: card ? CARD_PX : PAGE_PX }) : null;
  const flat = st?.canvas || null;
  const base = flat || original;
  const endO = span("orientation");
  const o = orientation(st?.gray || grayOf(base, 900), { landscape: card }); // orientation() works at 900
  endO();
  // Turn it when it's clear which way up it reads. Text clearly running down the page is
  // turned across even when which way is up is a closer call (a sideways page is wrong
  // either way; the guess is right far more often than not, and a tap turns it). A
  // straightened card is always kept wide.
  const sideways = o.lines === "down" && o.sideways >= 0.4;
  const rotate = o.confidence >= 0.25 || sideways || (card && flat && base.height > base.width) ? o.rotate : 0;
  const out = rotate ? rotateCanvas(base, rotate) : base;
  return { canvas: out, original, straightened: !!flat, rotate, confidence: o.confidence, changed: out !== original };
}

/** A photo file (camera roll, Files) → canvas, upright, at most maxSide on its long side. */
export async function fileToCanvas(file, maxSide = PAGE_PX) {
  // Older WebKit rejects the options bag; it already applies the photo's orientation.
  const bmp = await createImageBitmap(file, { imageOrientation: "from-image" }).catch(() => createImageBitmap(file));
  const s = Math.min(1, maxSide / Math.max(bmp.width, bmp.height));
  const c = canvas(bmp.width * s, bmp.height * s);
  ctx2d(c).drawImage(bmp, 0, 0, c.width, c.height);
  bmp.close?.();
  return c;
}

/** Grayscale and stretch the contrast (2nd to 98th percentile): faint print and glare both help OCR less. */
export function enhance(c, { threshold = false } = {}) {
  const out = canvas(c.width, c.height);
  ctx2d(out).putImageData(enhanceData(imageData(c), { threshold }), 0, 0);
  return out;
}

/** enhance() on pixels (ImageData or { width, height, data }): changed in place, returned as ImageData. */
export function enhanceData(img, { threshold = false } = {}) {
  const d = img.data;
  const hist = new Uint32Array(256);
  for (let i = 0; i < d.length; i += 4) { const y = (d[i] * 77 + d[i + 1] * 150 + d[i + 2] * 29) >> 8; d[i] = y; hist[y]++; }
  const n = d.length / 4;
  let lo = 0, hi = 255, acc = 0;
  for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc > n * 0.02) { lo = v; break; } }
  acc = 0;
  for (let v = 255; v >= 0; v--) { acc += hist[v]; if (acc > n * 0.02) { hi = v; break; } }
  const span = Math.max(16, hi - lo);
  const cut = lo + span * 0.55;
  for (let i = 0; i < d.length; i += 4) {
    let y = d[i];
    y = threshold ? (y < cut ? 0 : 255) : Math.max(0, Math.min(255, ((y - lo) * 255) / span));
    d[i] = d[i + 1] = d[i + 2] = y;
  }
  return img instanceof ImageData ? img : new ImageData(d, img.width, img.height);
}

/**
 * The machine-readable lines of a document image: the bottom of a passport's
 * photo page (td3) or of an ID card's back (id1), scaled so a character is
 * about 30 px wide, which is where the OCR model reads best.
 */
export function mrzBand(c, shape = "td3", { threshold = false, scale = 1 } = {}) {
  const share = shape === "td3" ? 0.34 : 0.48;
  const y = Math.round(c.height * (1 - share));
  const chars = shape === "td3" ? 44 : 30;
  const targetW = chars * 30 * scale;
  const s = Math.max(0.5, Math.min(3, targetW / c.width));
  const out = canvas(c.width * s, (c.height - y) * s);
  const g = ctx2d(out);
  g.imageSmoothingQuality = "high";
  g.drawImage(c, 0, y, c.width, c.height - y, 0, 0, out.width, out.height);
  return enhance(out, { threshold });
}

/**
 * The MRZ strip of a card seen live, ready for the reader: only the strip is
 * straightened (a third of the card, at the size the reader likes), straight from the
 * pixels of the video that hold it. Same picture as mrzBand(straighten(card)) at a
 * fraction of the work (no whole-card copy, warp or readback).
 *   quad   the card's corners in the video's pixels, [tl, tr, br, bl]
 *   turn   0, or 180 for a card seen upside down
 */
export function liveMrzBand(video, quad, shape = "td3", { turn = 0, scale = 1, threshold = false } = {}) {
  const plan = bandPlan(quad, shape, { turn, scale });
  const vw = video.videoWidth || video.width, vh = video.videoHeight || video.height;
  const pad = 3;
  const x0 = Math.max(0, Math.floor(plan.box.x - pad)), y0 = Math.max(0, Math.floor(plan.box.y - pad));
  const x1 = Math.min(vw, Math.ceil(plan.box.x + plan.box.w + pad)), y1 = Math.min(vh, Math.ceil(plan.box.y + plan.box.h + pad));
  const rect = { x: x0, y: y0, w: Math.max(1, x1 - x0), h: Math.max(1, y1 - y0) };
  // the strip is read at `flatW` across; no need for more pixels than that going in
  const across = Math.hypot(plan.quad[1].x - plan.quad[0].x, plan.quad[1].y - plan.quad[0].y);
  const s = Math.min(1, plan.flatW / Math.max(1, across));
  const c = grab(video, rect, rect.w * s);
  const k = c.width / rect.w;
  const q = plan.quad.map((p) => ({ x: (p.x - rect.x) * k, y: (p.y - rect.y) * (c.height / rect.h) }));
  const out = warp(imageData(c), q, plan.flatW, plan.flatH, plan.crop);
  const strip = canvas(out.width, out.height);
  ctx2d(strip).putImageData(enhanceData(new ImageData(out.data, out.width, out.height), { threshold }), 0, 0);
  return strip;
}

/* ---------------- scan modes: what the camera is asked to do ---------------- */

/**
 * The three things the camera scans, by the kind of document the person chose. This is the
 * one place that says what each asks of the camera and the readers:
 *
 *   license   side "front" (photo, taken by itself) or "back" (the PDF417 barcode, read by itself)
 *   passport  the photo page and its machine-readable lines (MRZ)
 *   card      a payment card, front or back (photographed; the card screen reads the text)
 *
 * scanOptions(mode, { side }) are props for <DocCamera/> (screens/add/camera.jsx):
 *   <DocCamera {...scanOptions("passport")} onDone={…} onCancel={…} />
 * warmScan(mode) starts loading what that mode will need (WebAssembly, the MRZ model, the
 * worker). Call it the moment the document type is chosen, before the camera opens, so
 * the engines are ready when the first frame is.
 */
export const SCAN_MODES = {
  license: {
    front: { shape: "id1", read: {}, title: "Front of the license", hint: "Point the camera at the card, anywhere in view. It takes the photo by itself." },
    back: { shape: "id1", read: { barcode: true }, title: "Back of the license", hint: "Show the back, anywhere in view. It finds the barcode and reads it by itself." },
    warm: ["barcode"],
  },
  passport: {
    front: { shape: "td3", read: { mrz: true }, title: "The photo page", hint: "Show the photo page, with the two lines of <<<. It finds the page by itself." },
    warm: ["mrz"],
  },
  card: {
    front: { shape: "id1", read: {}, title: "The front of the card", hint: "Fit the card in the frame, number side up." },
    back: { shape: "id1", read: {}, title: "The back of the card", hint: "The side with the signature strip. The photo isn't kept." },
    warm: ["text"],
  },
};

export const scanModes = () => Object.keys(SCAN_MODES);

/** The scan modes an ID record kind will use (for warming the engines as soon as the kind is known). */
export const modesForKind = (kind) => ({ driver_license: ["license"], passport: ["passport"], id_card: ["license", "passport"], residence_permit: ["passport"], card: ["card"] }[kind] || []);

/** DocCamera props for a scan mode (and side: "front" by default). Throws for a mode that doesn't exist. */
export function scanOptions(mode, { side = "front" } = {}) {
  const m = SCAN_MODES[mode];
  if (!m) throw new Error(`Unknown scan mode: ${mode}`);
  const o = m[side] || m.front;
  return { mode, side: m[side] ? side : "front", shape: o.shape, read: { ...o.read }, title: o.title, hint: o.hint };
}

/**
 * Start getting a mode's engines ready. Safe to call any number of times, from anywhere, and
 * never throws or waits: engines that can't start are reported when the camera needs them.
 */
export function warmScan(mode) {
  const m = SCAN_MODES[mode];
  if (!m) return Promise.resolve([]);
  const loaders = { barcode: barcodeReader, mrz: mrzReader, text: textReader };
  return Promise.allSettled(m.warm.map((w) => loaders[w]()));
}

/** The most pixels a chip photo may declare: an ID portrait is a few hundred thousand; a huge header is a hostile chip or file, not a photo. */
export const MAX_PORTRAIT_PIXELS = 4_000_000;
export const MAX_PORTRAIT_BYTES = 2 * 1024 * 1024;
export const portraitTooBig = ({ width, height }) => !(width > 0 && height > 0) || width * height > MAX_PORTRAIT_PIXELS;

/** A chip's JPEG 2000 photo → a JPEG the app can show (decoder loaded only for these). */
export async function jp2ToJpeg(bytes) {
  if (!bytes || bytes.length > MAX_PORTRAIT_BYTES) throw new Error("The chip's photo is too large.");
  const { JpxImage } = await import("jpeg2000");
  const j = new JpxImage();
  j.parse(bytes);
  // what the header declares decides the canvas size: refuse before allocating anything
  if (portraitTooBig(j)) throw new Error("The chip's photo declares an unreasonable size.");
  const c = canvas(j.width, j.height);
  const img = ctx2d(c).createImageData(j.width, j.height);
  const n = j.componentsCount;
  for (const t of j.tiles) {
    for (let y = 0; y < t.height; y++) {
      for (let x = 0; x < t.width; x++) {
        const s = (y * t.width + x) * n, o = ((t.top + y) * j.width + t.left + x) * 4;
        const r = t.items[s], g = n >= 3 ? t.items[s + 1] : r, b = n >= 3 ? t.items[s + 2] : r;
        img.data[o] = r; img.data[o + 1] = g; img.data[o + 2] = b; img.data[o + 3] = 255;
      }
    }
  }
  ctx2d(c).putImageData(img, 0, 0);
  return jpeg(c, { maxW: 1200, quality: 0.9 });
}

/** Chip photo bytes (JPEG or JPEG 2000) → an image for the record. */
export async function portraitImage({ type, bytes }) {
  if (!bytes || bytes.length > MAX_PORTRAIT_BYTES) throw new Error("The chip's photo is too large.");
  if (type === "image/jpeg") return { type, data: b64(bytes), size: bytes.length };
  return jp2ToJpeg(bytes);
}
