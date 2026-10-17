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

import { warp, outputSize, findDocument, orientation, toGray, shrink, scaleQuad } from "./docfind.js";

const asset = (p) => new URL(`./${p}`, import.meta.url).href;
const MRZ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<";

/* ---------------- engines ---------------- */

let barcodeP = null;
/** { read(ImageData) → Promise<string[]> } — PDF417 texts found, control characters kept. */
export function barcodeReader() {
  barcodeP ||= (async () => {
    const zx = await import("zxing-wasm/reader");
    await zx.prepareZXingModule({
      overrides: { locateFile: (path, prefix) => (path.endsWith(".wasm") ? asset(`scan/${path}`) : prefix + path) },
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

let ocrP = null;
/** { read(canvas) → Promise<string> } — the MRZ reader. One worker, reused until released. */
export function mrzReader() {
  ocrP ||= (async () => {
    const { default: Tesseract } = await import("tesseract.js/dist/tesseract.esm.min.js");
    const base = asset("ocr/");
    const worker = await Tesseract.createWorker("mrz", 1 /* LSTM only */, {
      workerPath: `${base}worker.min.js`, corePath: `${base}tesseract-core-lstm.js`, langPath: base.replace(/\/$/, ""),
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
    const { default: Tesseract } = await import("tesseract.js/dist/tesseract.esm.min.js");
    const base = asset("ocr/");
    const worker = await Tesseract.createWorker("eng", 1 /* LSTM only */, {
      workerPath: `${base}worker.min.js`, corePath: `${base}tesseract-core-lstm.js`, langPath: base.replace(/\/$/, ""),
      gzip: false, cacheMethod: "none", workerBlobURL: false, logger: () => {}, errorHandler: () => {},
    });
    let mode = null;
    const set = async (front) => {
      if (mode === front) return;
      await worker.setParameters({ tessedit_char_whitelist: front ? "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ/-.' " : "", tessedit_pageseg_mode: "11", preserve_interword_spaces: "1" });
      mode = front;
    };
    return { read: async (canvas, { front = true } = {}) => { await set(front); return (await worker.recognize(canvas)).data.text || ""; }, stop: () => worker.terminate() };
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

// Small chunks: spreading tens of thousands of arguments can overflow the stack on phones.
const b64 = (bytes) => { let s = ""; for (let i = 0; i < bytes.length; i += 0x1000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x1000)); return btoa(s); };
const toBlob = (c, type, q) => new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error("Couldn't encode the photo."))), type, q));

/** A canvas as a JPEG for the record: { type, data (base64), width, height, size }. */
export async function jpeg(c, { maxW = 1600, quality = 0.86 } = {}) {
  const src = c.width > maxW ? grab(c, null, maxW) : c;
  let blob;
  try { blob = await toBlob(src, "image/jpeg", quality); }
  catch { blob = await toBlob(src.width > 1000 ? grab(src, null, 1000) : src, "image/jpeg", 0.8); } // low memory: smaller
  const bytes = new Uint8Array(await blob.arrayBuffer());
  return { type: "image/jpeg", data: b64(bytes), width: src.width, height: src.height, size: bytes.length };
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
export const imageBytes = (img) => Uint8Array.from(atob(img.data), (ch) => ch.charCodeAt(0));

/* ---------------- straightening ---------------- */

/** The document inside `quad` (in c's pixels), straightened into its own canvas. */
export function straighten(c, quad, { prefer = null, max = 3000 } = {}) {
  const size = outputSize(quad, { prefer, max });
  const out = warp(imageData(c), quad, size.width, size.height);
  const oc = canvas(size.width, size.height);
  ctx2d(oc).putImageData(new ImageData(out.data, out.width, out.height), 0, 0);
  return oc;
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
  const im = grayOf(c, 640), k = c.width / im.w;
  const prior = hint ? scaleQuad(hint, 1 / k) : null;
  const ratio = { id1: 1.586, td3: 1.42 }[shape] || null;
  const d = findDocument(im, { minArea: hint ? 0.03 : 0.12, prior, ratio });
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
  const flat = quad ? straighten(original, quad, { prefer: card ? shape : null, max: card ? 2000 : 3000 }) : null;
  const base = flat || original;
  const o = orientation(grayOf(base, 1100), { landscape: card });
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
export async function fileToCanvas(file, maxSide = 3200) {
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
  const img = imageData(c);
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
  const out = canvas(c.width, c.height);
  ctx2d(out).putImageData(img, 0, 0);
  return out;
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

/** A chip's JPEG 2000 photo → a JPEG the app can show (decoder loaded only for these). */
export async function jp2ToJpeg(bytes) {
  const { JpxImage } = await import("jpeg2000");
  const j = new JpxImage();
  j.parse(bytes);
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
  if (type === "image/jpeg") return { type, data: b64(bytes), size: bytes.length };
  return jp2ToJpeg(bytes);
}
