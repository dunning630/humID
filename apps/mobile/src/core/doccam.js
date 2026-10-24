// The native document camera (5.0): tauri-plugin-humid-docscan (humid-docscan@2) runs the
// camera under a transparent web view; the camera screen (screens/add/camera.jsx) stays on top.
// Native owns focus, exposure, lens, zoom, torch, finding the document, sharp / steady / ready,
// the barcode and MRZ text, the zero-shutter-lag still and the cut-out. This file only moves
// requests and events, and turns the still's bytes into a canvas.
//
// The same interface as the web camera (core/webcam.js), so the screen has one code path:
//   { kind: "native", frame(), focus(x, y) → boolean, torch(on), capture(), take(id, which) → canvas,
//     pause(), resume(), again(), close() }
//
// Nothing here is logged or kept. The still arrives as raw bytes, once, and lives in memory.

/* global __HUMID_ALLOW_DEMO__ */
const inTauri = () => typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";
const onPhone = () => /\b(Android|iPhone|iPad|iPod)\b/i.test(globalThis.navigator?.userAgent || "");
// Development builds only: a browser test can stand in for the native camera (tests/browser/nativecam.mjs).
// Tested inline so release builds fold it to false and drop the stand-in (tests/bundle.test.js).
const fake = () => ((typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) ? globalThis.__humidFakeCamera || null : null);

/** Call a plugin command. Arguments with a channel go through a real Tauri Channel. */
async function call(cmd, args) {
  const f = fake();
  if (f) return f.invoke(cmd, args);
  return globalThis.__TAURI_INTERNALS__.invoke(`plugin:humid-docscan|${cmd}`, args);
}

const msg = (e) => (typeof e === "string" ? e : e?.message || String(e));

let probed = null;
/** Is the native camera here? { available, lenses, macro, torch, minFocusMm } (cached for the session). */
export function probeNative() {
  if (!fake() && !(inTauri() && onPhone())) return Promise.resolve({ available: false });
  probed ||= call("probe").catch((e) => ({ available: false, reason: msg(e) }));
  return probed;
}

/** The web view's size and the frame's rectangle, in CSS pixels. */
function geometry(frameEl) {
  const view = { w: innerWidth, h: innerHeight };
  if (!frameEl) return { view, frame: { x: 0, y: 0, w: view.w, h: view.h } };
  const r = frameEl.getBoundingClientRect();
  return { view, frame: { x: r.left, y: r.top, w: r.width, h: r.height } };
}

/** JPEG bytes → canvas (no base64 anywhere: the bytes come as an ArrayBuffer). */
async function toCanvas(bytes) {
  const blob = new Blob([bytes], { type: "image/jpeg" });
  const bmp = await createImageBitmap(blob);
  const c = document.createElement("canvas");
  c.width = bmp.width; c.height = bmp.height;
  c.getContext("2d").drawImage(bmp, 0, 0);
  bmp.close?.();
  return c;
}

/** What native's errors mean for the screen: "denied" | "busy" | "nocamera" | "failed". */
export function errorCode(e) {
  const m = msg(e).toLowerCase();
  if (/denied|not allowed|permission|authori/.test(m)) return "denied";
  if (/busy|in use|another app/.test(m)) return "busy";
  if (/unavailable|no camera|nocamera/.test(m)) return "nocamera";
  return "failed";
}

/**
 * Open the native camera.
 *   shape    "id1" | "td3" | "page" | "full"
 *   read     { barcode, mrz, spot }: what to read while it runs (spot: look out for a barcode, but don't wait for one)
 *   frameEl  the frame on screen (null for "full")
 *   auto     take the photo by itself when ready
 *   haptics  play the phone's haptics (the person's setting)
 *   onEvent  the camera's events (see plugins/humid-docscan/README.md)
 */
export async function openNative({ shape, read = {}, frameEl, auto = true, haptics = true, onEvent }) {
  let events;
  const deliver = (e) => { try { if (e && typeof e.t === "string") onEvent(e); } catch { /* the screen's problem */ } };
  if (fake()) events = { onmessage: deliver };
  else {
    const { Channel } = await import("@tauri-apps/api/core");
    events = new Channel(deliver);
  }
  const g = geometry(frameEl);
  let open = true;
  try {
    await call("open", { shape, read: { pdf417: !!(read.barcode || read.spot), mrz: !!read.mrz, require: !!(read.barcode || read.mrz) }, frame: g.frame, view: g.view, auto, haptics, events });
  } catch (e) {
    throw Object.assign(new Error(msg(e)), { code: errorCode(e) });
  }
  document.documentElement.classList.add("cam-native");
  const shut = () => { if (open) { open = false; document.documentElement.classList.remove("cam-native"); } };
  return {
    kind: "native",
    focusable: true,
    frame() { if (!open) return; const n = geometry(frameEl); call("frame", { frame: n.frame, view: n.view }).catch(() => {}); },
    /** One-shot focus there; true when the camera took it (its result comes as a `focus` event). */
    focus: (x, y) => (open ? call("focus", { x, y }).then(() => true, () => false) : Promise.resolve(false)),
    torch: (on) => call("torch", { on: !!on }),
    capture: () => call("capture"),
    async take(id, which = "doc") { return toCanvas(await call("take", { id, which })); },
    pause: () => call("pause").catch(() => {}),
    resume: () => call("resume").catch(() => {}),
    again: () => call("resume").catch(() => {}),
    close() { shut(); return call("close").catch(() => {}); },
  };
}
