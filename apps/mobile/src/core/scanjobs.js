// Heavy picture work that doesn't have to hold anything up, done away from the main thread:
// today the "clean scan" of a page (core/scanclean.js: even light, white paper, crisp ink),
// which on a 2400 px page is seconds of arithmetic on a phone. The review screen opens as
// soon as the page is straightened and upright; the clean scan arrives while it is read.
//
// The picture goes to the scan worker (core/scanworker.js) as a moved buffer and comes back
// the same way; nothing is stored, logged or sent anywhere. Where a phone's WebView has no
// worker, or the worker fails, the same function runs on the main thread, after the screen
// has had its turn (a timer), so the review still shows first.
import { cleanScan } from "./scanclean.js";
import { span } from "./perf.js";

const IDLE_MS = 15_000; // a worker nobody has used for this long is let go (its memory with it)
const CALL_MS = 60_000;

let worker = null, dead = false, seq = 0, idle = null;
const pending = new Map();

const canWork = () => !dead && typeof Worker === "function";

function drop(err) {
  dead = !!err;
  clearTimeout(idle); idle = null;
  const w = worker; worker = null;
  try { w?.terminate(); } catch { /* gone */ }
  for (const [, p] of pending) { clearTimeout(p.timer); p.reject(err || new Error("worker closed")); }
  pending.clear();
}

function spawn() {
  if (worker) return worker;
  const w = new Worker(new URL("./scanworker.js", import.meta.url), { type: "module" });
  w.onmessage = (e) => {
    const p = pending.get(e.data.id);
    if (!p) return;
    pending.delete(e.data.id); clearTimeout(p.timer);
    e.data.ok ? p.resolve(e.data) : p.reject(new Error(e.data.error || "worker"));
    if (!pending.size) { clearTimeout(idle); idle = setTimeout(() => { if (!pending.size) drop(null); }, IDLE_MS); }
  };
  w.onerror = () => drop(new Error("worker"));
  worker = w;
  return w;
}

function call(msg, transfer) {
  const w = spawn();
  clearTimeout(idle);
  return new Promise((resolve, reject) => {
    const id = ++seq;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("worker timed out")); }, CALL_MS);
    pending.set(id, { resolve, reject, timer });
    try { w.postMessage({ id, ...msg }, transfer); } catch (e) { pending.delete(id); clearTimeout(timer); reject(e); }
  });
}

/**
 * The clean scan of RGBA pixels { width, height, data }: resolves { width, height, data, paper }.
 * `img.data` is handed over (moved to the worker): don't use it afterwards. Never rejects
 * for want of a worker: the main thread does it instead.
 */
export async function cleanPixels(img) {
  const end = span("clean");
  try {
    if (canWork()) {
      try {
        const buf = img.data.buffer;
        const r = await call({ op: "clean", w: img.width, h: img.height, buf }, [buf]);
        return { width: r.w, height: r.h, data: new Uint8ClampedArray(r.buf), paper: r.paper };
      } catch (e) {
        if (img.data.buffer.byteLength === 0) throw e; // the pixels went with the message: nothing to fall back on
      }
    }
    await new Promise((r) => setTimeout(r, 30)); // let the screen that is waiting for it draw first
    return cleanScan(img);
  } finally { end(); }
}

/** Let the worker go now (for tests, and when the app locks). */
export const closeJobs = () => drop(null);
