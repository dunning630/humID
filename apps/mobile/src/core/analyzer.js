/* global __HUMID_WORKER__ */
// The camera's analysis, away from the main thread where the phone allows it.
//
// Each look: a small copy of the camera's frame (made by the browser, off the main
// thread: createImageBitmap with a size) goes to a worker (core/scanworker.js), which
// draws it into an OffscreenCanvas, makes the grey picture and finds the document (and
// barcodes). Where workers, OffscreenCanvas or bitmaps aren't there (older WebViews), or
// the worker stops answering, the same code (core/scancore.js) runs on the main thread
// instead, on a smaller picture than before, one look at a time. Either way a look is
// never started while the last is still running, so work can't pile up.
//
// Nothing leaves the device and nothing is logged: frames live in memory until the look
// is answered.
import { createCore, LOOK_PX, BAR_PX } from "./scancore.js";
import { toGray } from "./docfind.js";

const CALL_TIMEOUT = 4000;

export const supports = () => ({
  worker: typeof Worker === "function" && typeof OffscreenCanvas === "function",
  bitmap: typeof createImageBitmap === "function",
});

let sharedCanvas = null;
/** A small grey copy of a video frame, made on the main thread (the fallback). */
function grayOfVideo(v, px) {
  const w = v.videoWidth, h = v.videoHeight, s = Math.min(1, px / Math.max(w, h));
  const cw = Math.max(1, Math.round(w * s)), ch = Math.max(1, Math.round(h * s));
  const c = (sharedCanvas ||= document.createElement("canvas"));
  if (c.width !== cw || c.height !== ch) { c.width = cw; c.height = ch; }
  const g = c.getContext("2d", { willReadFrequently: true });
  g.imageSmoothingQuality = "low";
  g.drawImage(v, 0, 0, cw, ch);
  return toGray(g.getImageData(0, 0, cw, ch));
}

/**
 * createAnalyzer({ shape, bar, workerUrl })
 *   look(video, { prior })   → { look, w, h (the picture the look was made in), spots (barcode-like patches in a bw×bh
 *                              picture, when bar), bw, bh, ms }
 *   locate(gray)             → barcode-like patches in a small grey picture
 *   read(imageData, {harder})→ PDF417 texts found (control characters kept)
 *   warm()                   → get the barcode engine ready
 *   where                    → "worker" or "main"
 *   close()
 */
export function createAnalyzer({ shape = "full", bar = false, workerUrl = null, forceMain = false } = {}) {
  const can = supports();
  // Two workers from the one file: one for looks (the outline must never wait), one for the
  // barcode reader (a hard read can take a second).
  const workers = {};
  let dead = forceMain || !can.worker;
  let seq = 0, failures = 0;
  const pending = new Map();
  let core = null;
  const mainCore = () => (core ||= createCore());

  function fail(err) {
    dead = true;
    for (const k of Object.keys(workers)) { try { workers[k].terminate(); } catch { /* gone */ } delete workers[k]; }
    for (const [, p] of pending) { clearTimeout(p.timer); p.reject(err); }
    pending.clear();
  }

  function spawn(role) {
    if (workers[role] || dead) return workers[role] || null;
    try {
      const w = new Worker(workerUrl || (typeof __HUMID_WORKER__ !== "undefined" ? __HUMID_WORKER__ : new URL("./scanworker.js", import.meta.url)), { type: "module" });
      w.onmessage = (e) => {
        const p = pending.get(e.data.id);
        if (!p) return;
        pending.delete(e.data.id); clearTimeout(p.timer);
        e.data.ok ? p.resolve(e.data) : p.reject(new Error(e.data.error || "worker"));
      };
      w.onerror = () => fail(new Error("worker"));
      workers[role] = w;
    } catch { dead = true; }
    return workers[role] || null;
  }

  /** A call to a worker. A look that isn't answered in time means the worker is stuck: both are dropped for good and the main thread takes over. */
  function call(msg, transfer = [], { role = "look", ms = CALL_TIMEOUT, kill = true } = {}) {
    const w = spawn(role);
    if (!w) return Promise.reject(new Error("no worker"));
    return new Promise((resolve, reject) => {
      const id = ++seq;
      const timer = setTimeout(() => { pending.delete(id); if (kill) fail(new Error("worker timed out")); reject(new Error("worker timed out")); }, ms);
      pending.set(id, { resolve, reject, timer });
      try { w.postMessage({ id, ...msg }, transfer); } catch (e) { pending.delete(id); clearTimeout(timer); reject(e); }
    });
  }

  const px = bar ? BAR_PX : LOOK_PX;

  async function look(video, { prior = null } = {}) {
    const vw = video.videoWidth, vh = video.videoHeight;
    if (!vw || !vh) throw new Error("no frame");
    if (!dead) {
      try {
        const s = Math.min(1, px / Math.max(vw, vh));
        let bitmap = null;
        if (can.bitmap) {
          try {
            bitmap = await createImageBitmap(video, { resizeWidth: Math.max(1, Math.round(vw * s)), resizeHeight: Math.max(1, Math.round(vh * s)), resizeQuality: "low" });
            // a WebView that ignores the size options hands back the whole frame: never send that on
            if (bitmap.width > px * 1.5) { bitmap.close?.(); bitmap = null; can.bitmap = false; }
          } catch { bitmap = null; can.bitmap = false; /* bitmaps from video aren't offered here: draw it ourselves */ }
        }
        if (bitmap) {
          const r = finish(await call({ op: "look", bitmap, shape, prior, bar }, [bitmap]), vw);
          failures = 0;
          return r;
        }
        const g = grayOfVideo(video, px);
        const r = finish(await call({ op: "look", gray: { w: g.w, h: g.h, buf: g.g.buffer }, shape, prior, bar }, [g.g.buffer]), vw);
        failures = 0;
        return r;
      } catch {
        // the worker failed (a WebView without OffscreenCanvas 2D, say): after twice running, stop using it
        if (!dead && ++failures >= 2) fail(new Error("worker unusable"));
      }
    }
    const g = grayOfVideo(video, px);
    return finish({ ...mainCore().look(g, { shape, prior, bar }) }, vw);
  }

  /** Corners come back in the look picture's pixels; `k` takes them to the video's. */
  const finish = (r, vw) => ({ ...r, k: vw / r.w });

  async function locate(gray) {
    if (!dead) {
      try { return (await call({ op: "locate", gray: { w: gray.w, h: gray.h, buf: gray.g.buffer.slice(0) } })).spots; } catch { /* here, then */ }
    }
    return mainCore().locate(gray);
  }

  /** Read PDF417 from RGBA pixels. Returns null when the worker can't (the caller reads on the main thread). */
  async function read(img, { harder = true } = {}) {
    if (dead) return null;
    try {
      const buf = img.data.buffer.slice(img.data.byteOffset, img.data.byteOffset + img.data.byteLength);
      return (await call({ op: "read", buf, w: img.width, h: img.height, harder }, [buf], { role: "read", ms: 20000, kill: false })).texts;
    } catch { return null; }
  }

  return {
    look, locate, read,
    warm() { if (dead) return Promise.resolve(false); return call({ op: "warm" }, [], { role: "read", ms: 30000, kill: false }).then(() => true, () => false); },
    get where() { return dead ? "main" : "worker"; },
    close() { fail(new Error("closed")); },
  };
}
