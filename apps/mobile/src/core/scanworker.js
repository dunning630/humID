// The scan worker: looks for the document and for barcodes in small grey pictures, and
// reads PDF417 barcodes (zxing-cpp, WebAssembly), all off the main thread, so the
// camera view and the buttons stay smooth while the analysis runs. Everything stays
// on this device: the worker gets small pictures in memory and answers with corners.
// It never logs, stores or sends a picture. Started by core/analyzer.js (the live looks and
// barcode reads) and core/scanjobs.js (the clean scan of a page).
import { createCore } from "./scancore.js";
import { toGray } from "./docfind.js";
import { cleanScan } from "./scanclean.js";

const core = createCore();
/* global __HUMID_SCAN_DIR__ */
// The barcode engine sits in a content-hashed directory beside the app bundle (build.mjs).
const SCAN_DIR = typeof __HUMID_SCAN_DIR__ !== "undefined" ? __HUMID_SCAN_DIR__ : "scan";
const asset = (p) => `/assets/${p}`;
let zx = null;
let canvas = null;

async function barcodes() {
  zx ||= (async () => {
    const m = await import("zxing-wasm/reader");
    await m.prepareZXingModule({
      overrides: { locateFile: (path, prefix) => (path.endsWith(".wasm") ? asset(`${SCAN_DIR}/${path}`) : prefix + path) },
      fireImmediately: true,
    });
    return m;
  })();
  zx.catch(() => { zx = null; });
  return zx;
}

/** A picture in whichever form it came: a bitmap (drawn here, off the main thread) or grey bytes. */
function grayOf(m) {
  if (m.gray) return { w: m.gray.w, h: m.gray.h, g: new Uint8ClampedArray(m.gray.buf) };
  const b = m.bitmap;
  if (!canvas || canvas.width !== b.width || canvas.height !== b.height) canvas = new OffscreenCanvas(b.width, b.height);
  const g = canvas.getContext("2d", { willReadFrequently: true });
  g.drawImage(b, 0, 0);
  b.close?.();
  return toGray(g.getImageData(0, 0, canvas.width, canvas.height));
}

self.onmessage = async (e) => {
  const m = e.data;
  try {
    if (m.op === "look") {
      self.postMessage({ id: m.id, ok: true, ...core.look(grayOf(m), { shape: m.shape, prior: m.prior, bar: m.bar }) });
    } else if (m.op === "locate") {
      self.postMessage({ id: m.id, ok: true, spots: core.locate(grayOf(m)) });
    } else if (m.op === "read") {
      const zxr = await barcodes();
      const img = new ImageData(new Uint8ClampedArray(m.buf), m.w, m.h);
      const r = await zxr.readBarcodes(img, { formats: ["PDF417"], tryHarder: m.harder !== false, tryRotate: m.harder !== false, tryInvert: false, textMode: "Plain", maxNumberOfSymbols: 1 });
      self.postMessage({ id: m.id, ok: true, texts: r.filter((x) => x.isValid && x.text).map((x) => x.text) });
    } else if (m.op === "clean") {
      // the clean scan of a page (core/scanclean.js): RGBA in, RGBA out, the buffers moved, not copied
      const out = cleanScan({ width: m.w, height: m.h, data: new Uint8ClampedArray(m.buf) });
      self.postMessage({ id: m.id, ok: true, w: out.width, h: out.height, buf: out.data.buffer, paper: out.paper }, [out.data.buffer]);
    } else if (m.op === "warm") {
      await barcodes();
      self.postMessage({ id: m.id, ok: true });
    } else if (m.op === "reset") {
      core.reset();
      self.postMessage({ id: m.id, ok: true });
    }
  } catch (err) {
    self.postMessage({ id: m.id, ok: false, error: String(err?.message || err).slice(0, 120) });
  }
};
