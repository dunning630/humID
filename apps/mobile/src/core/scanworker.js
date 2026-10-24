// The scan worker: the clean scan of a page (core/scanclean.js) and PDF417 reads (zxing-cpp,
// WebAssembly), off the main thread, so the screen stays smooth. Everything stays on this
// device: the worker gets pictures in memory and answers with pixels or text. It never logs,
// stores or sends a picture. Started by core/scanjobs.js. (5.0: the live camera analysis that
// ran here is native now, plugins/humid-docscan.)
import { cleanScan } from "./scanclean.js";

/* global __HUMID_SCAN_DIR__ */
// The barcode engine sits in a content-hashed directory beside the app bundle (build.mjs).
const SCAN_DIR = typeof __HUMID_SCAN_DIR__ !== "undefined" ? __HUMID_SCAN_DIR__ : "scan";
const asset = (p) => `/assets/${p}`;
let zx = null;

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

self.onmessage = async (e) => {
  const m = e.data;
  try {
    if (m.op === "read") {
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
    }
  } catch (err) {
    self.postMessage({ id: m.id, ok: false, error: String(err?.message || err).slice(0, 120) });
  }
};
