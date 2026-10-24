// The web view's own camera (getUserMedia), for development, the browser tests and any place
// the native camera (core/doccam.js) isn't there. It speaks the native camera's events, so the
// camera screen has one code path. Kept small on purpose: the phones use the native camera.
//
// What it does differently from 4.x (audit 5-camera §3, the interim fixes):
//   - the tap ring only where the page can really move the focus (QW1, QW6: Chrome's
//     pointsOfInterest with continuous focus; never on iPhone, whose WebKit ignores both)
//   - the frame's centre is the video's centre, so a camera that meters the middle of the
//     sensor meters the document (QW3)
//   - zoom from the camera's own minimum focus distance, not a fixed table (QW4)
//   - "Move back a little" when the document overflows the frame; the frame never shrinks (QW5)
//   - no sharpness gate: a page can't see the autofocus, so it never says "Focusing…" (QW2)
//
// Looks run every ~150 ms on a small grey copy around the frame (core/docfind.js findDocument)
// and go through the same rules as the native cameras (core/lookstate.js). Nothing is logged
// or kept: frames live in memory until the photo is cut out, and the photo until it is taken.
import { findDocument, toGray, PAPER } from "./docfind.js";
import { grab, cornersIn, straighten, looksBlank, canvas as newCanvas } from "./scan.js";
import { guidance, fitOf, changed } from "./lookstate.js";
import { RATIO, WIDTH_MM } from "./doctpl.js";

/* global __HUMID_ALLOW_DEMO__ */

const LOOK_MS = 150;
const STEADY = { ms: 300, share: 0.015 };

/**
 * How far to zoom so the document fills the frame from beyond the lens's minimum focus distance
 * (Apple's AVCamBarcode advice; audit 5-camera §2.2): z = 1.25 × MFD / d_fill(1×), within 1..max.
 *   mfdMm      the camera's minimum focus distance (mm); unknown: no zoom
 *   docMm      the document's width across the frame (doctpl WIDTH_MM)
 *   frameFrac  the frame's width as a share of the picture's shown width
 *   fovDeg     the field of view across the picture's shown width at 1×
 */
export function zoomFor({ mfdMm, docMm, frameFrac, fovDeg, max = 2.5 }) {
  if (!(mfdMm > 0 && docMm > 0 && frameFrac > 0 && fovDeg > 0)) return 1;
  const half = Math.tan((fovDeg * Math.PI) / 360) * frameFrac;
  const dFill = docMm / 2 / half;
  const z = (1.25 * mfdMm) / dFill;
  return Math.round(Math.max(1, Math.min(max, 2.5, z)) * 100) / 100;
}

/**
 * A phone's main camera at 1× is about a 24-26 mm lens (full-frame equivalent): an estimate of the
 * field of view across a picture of vw × vh (the web can't ask for the real one; native can).
 */
export const fovAcross = (vw, vh) => (2 * Math.atan((17.3 / 24) * Math.min(1, vw / vh)) * 180) / Math.PI;

/** Where the shown video's pixels are on screen (object-fit: cover): { s (CSS px per video px), ox, oy, vr }. */
function coverMap(v) {
  const vr = v.getBoundingClientRect();
  const s = Math.max(vr.width / v.videoWidth, vr.height / v.videoHeight);
  return { s, ox: vr.left + (vr.width - v.videoWidth * s) / 2, oy: vr.top + (vr.height - v.videoHeight * s) / 2, vr };
}

/** Grey statistics inside a quad's middle (video pixels), on the analysis picture `im` (k: picture px per video px; at: its origin). */
function lightOf(im, quad, k, at, { page = false } = {}) {
  const xs = quad.map((p) => (p[0] - at.x) * k), ys = quad.map((p) => (p[1] - at.y) * k);
  const x0 = Math.max(0, Math.round(Math.min(...xs) + (Math.max(...xs) - Math.min(...xs)) * 0.08)), x1 = Math.min(im.w, Math.round(Math.max(...xs) - (Math.max(...xs) - Math.min(...xs)) * 0.08));
  const y0 = Math.max(0, Math.round(Math.min(...ys) + (Math.max(...ys) - Math.min(...ys)) * 0.08)), y1 = Math.min(im.h, Math.round(Math.max(...ys) - (Math.max(...ys) - Math.min(...ys)) * 0.08));
  const hist = new Uint32Array(256);
  // glare is a patch: a 6×4 grid of cells, a cell mostly blown out (white print on a white card is not glare)
  const CX = 6, CY = 4, cs = new Uint32Array(CX * CY), cn = new Uint32Array(CX * CY);
  let n = 0, sum = 0, sat = 0;
  for (let y = y0; y < y1; y++) {
    const cy = Math.min(CY - 1, (((y - y0) * CY) / Math.max(1, y1 - y0)) | 0);
    for (let x = x0; x < x1; x++) {
      const v = im.g[y * im.w + x], c = cy * CX + Math.min(CX - 1, (((x - x0) * CX) / Math.max(1, x1 - x0)) | 0);
      hist[v]++; sum += v; n++; cn[c]++;
      if (v >= 253) { sat++; cs[c]++; }
    }
  }
  if (!n) return "ok";
  const pct = (q) => { let a = 0; for (let v = 0; v < 256; v++) { a += hist[v]; if (a >= n * q) return v; } return 255; };
  const mean = sum / n, p95 = pct(0.95), p50 = pct(0.5);
  if (p95 < 85 || mean < 30) return "dark";
  let patches = 0;
  for (let i = 0; i < CX * CY; i++) if (cn[i] && cs[i] / cn[i] >= 0.5) patches++;
  const share = sat / n, white = p50 >= 228;
  if (!(page && share > 0.4) && patches >= (white ? 2 : 1) && share >= (white ? 0.1 : 0.025)) return "glare";
  return "ok";
}

/** The whole view is dark (nothing found because there's nothing to see). */
function darkAll(im) {
  let sum = 0, n = 0;
  const hist = new Uint32Array(256);
  for (let i = 0; i < im.g.length; i += 5) { sum += im.g[i]; hist[im.g[i]]++; n++; }
  let a = 0, p95 = 0;
  for (let v = 0; v < 256; v++) { a += hist[v]; if (a >= n * 0.95) { p95 = v; break; } }
  return sum / n < 28 && p95 < 50;
}

/**
 * Open the web camera. The same shape as core/doccam.js openNative():
 *   { kind: "web", frame(), focus(x, y) → boolean, torch(on), capture(), take(id, which) → canvas, pause(), resume(), close() }
 *   video     the <video> element to show it in
 *   frameEl   the frame on screen (null for the Photo shape)
 *   onEvent   the camera's events (ready, look, focus, captured, error)
 */
export async function openWeb({ shape, video, frameEl, auto = true, onEvent }) {
  const guided = shape !== "full";
  const ratio = shape === "page" ? RATIO.page : guided ? PAPER[shape] : null;
  const S = { stream: null, track: null, stop: false, paused: false, timer: 0, run: guidance(), last: null, quad: null, hist: [], stills: new Map(), n: 0, caps: {}, focusable: false };
  const emit = (e) => { try { onEvent(e); } catch { /* the screen's problem */ } };

  async function start() {
    if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("no camera"), { name: "NotFoundError" });
    // the long side only, never a crop (a width AND a height make a browser cut the frame); not 4K
    const stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: "environment" }, width: { ideal: 1920 }, frameRate: { ideal: 30, max: 30 }, resizeMode: "none" } });
    if (S.stop) { stream.getTracks().forEach((t) => t.stop()); return; }
    S.stream = stream; S.track = stream.getVideoTracks()[0];
    try { S.caps = S.track.getCapabilities?.() || {}; } catch { S.caps = {}; }
    let supported = {};
    try { supported = navigator.mediaDevices.getSupportedConstraints?.() || {}; } catch { /* none */ }
    // continuous focus with a point is the only control a page has that does anything (Chrome on Android)
    S.focusable = !!supported.pointsOfInterest && (S.caps.focusMode || []).includes("continuous");
    if ((S.caps.focusMode || []).includes("continuous")) await S.track.applyConstraints({ advanced: [{ focusMode: "continuous" }] }).catch(() => {});
    if ((S.caps.exposureMode || []).includes("continuous")) await S.track.applyConstraints({ advanced: [{ exposureMode: "continuous" }] }).catch(() => {});
    video.srcObject = stream;
    await video.play().catch(() => {});
    await new Promise((r) => (video.videoWidth ? r() : video.addEventListener("loadedmetadata", r, { once: true })));
    place();
    let zoom = 1;
    if (guided && S.caps.zoom?.max > 1 && frameEl) {
      const m = coverMap(video), fr = frameEl.getBoundingClientRect();
      const shownW = Math.min(m.vr.width, video.videoWidth * m.s);
      const fov = fovAcross(video.videoWidth, video.videoHeight) * Math.min(1, m.vr.width / (video.videoWidth * m.s));
      zoom = zoomFor({ mfdMm: (S.caps.focusDistance?.min || 0) * 1000, docMm: WIDTH_MM[shape], frameFrac: fr.width / shownW, fovDeg: fov, max: S.caps.zoom.max });
      if (zoom > 1) await S.track.applyConstraints({ advanced: [{ zoom }] }).catch(() => { zoom = 1; });
    }
    if (S.focusable && frameEl) aim(frameEl.getBoundingClientRect(), false);
    if (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) globalThis.__humidZoom = zoom;
    emit({ t: "ready", lens: "wide", zoom, torch: !!S.caps.torch, minFocusMm: S.caps.focusDistance?.min ? S.caps.focusDistance.min * 1000 : null });
    loop();
  }

  /**
   * The video, moved (not scaled) so its centre is the frame's centre: a camera that focuses and
   * meters the middle of its sensor then meters the document (audit QW3). The strip it uncovers
   * is under the dark shutter bar.
   */
  function place() {
    if (!frameEl) { video.style.transform = ""; return; }
    const fr = frameEl.getBoundingClientRect();
    const dy = Math.round(fr.top + fr.height / 2 - innerHeight / 2);
    video.style.transform = dy ? `translateY(${dy}px)` : "";
  }

  /** Move the camera's focus and exposure point (Chrome: pointsOfInterest, continuous focus). */
  function aim(pt, tap) {
    const m = coverMap(video);
    const x = ((tap ? pt.x : pt.left + pt.width / 2) - m.ox) / m.s / video.videoWidth, y = ((tap ? pt.y : pt.top + pt.height / 2) - m.oy) / m.s / video.videoHeight;
    if (!(x >= 0 && x <= 1 && y >= 0 && y <= 1)) return Promise.resolve(false);
    return S.track.applyConstraints({ advanced: [{ focusMode: "continuous", pointsOfInterest: [{ x, y }] }] }).then(() => true, () => false);
  }

  const ctx = (c) => c.getContext("2d", { willReadFrequently: true });
  let pic = null;
  /** One look: the document's corners and light, around the frame (or the whole view for Photo). */
  function measure() {
    const v = video, vw = v.videoWidth, vh = v.videoHeight;
    const m = coverMap(v);
    let area = { x: 0, y: 0, w: vw, h: vh }, frameV = null;
    if (frameEl) {
      const fr = frameEl.getBoundingClientRect();
      frameV = { x: (fr.left - m.ox) / m.s, y: (fr.top - m.oy) / m.s, w: fr.width / m.s, h: fr.height / m.s };
      const x0 = Math.max(0, frameV.x - frameV.w * 0.3), y0 = Math.max(0, frameV.y - frameV.h * 0.3);
      area = { x: x0, y: y0, w: Math.min(vw, frameV.x + frameV.w * 1.3) - x0, h: Math.min(vh, frameV.y + frameV.h * 1.3) - y0 };
    }
    const k = (guided ? 256 : 224) / Math.max(area.w, guided ? 0 : area.h);
    const w = Math.max(32, Math.round(area.w * k)), h = Math.max(32, Math.round(area.h * k));
    pic ||= newCanvas(w, h);
    if (pic.width !== w || pic.height !== h) { pic.width = w; pic.height = h; }
    const g = ctx(pic);
    g.imageSmoothingQuality = "medium";
    g.drawImage(v, area.x, area.y, area.w, area.h, 0, 0, w, h);
    const im = toGray(g.getImageData(0, 0, w, h));
    const d = findDocument(im, { minArea: guided ? 0.1 : 0.03, ratio });
    const now = performance.now();
    if (!d) { S.hist = []; return { found: false, light: darkAll(im) ? "dark" : "ok", vq: null }; }
    const vq = d.quad.map((p) => [area.x + p.x / k, area.y + p.y / k]);
    const css = vq.map(([x, y]) => [m.ox + x * m.s, m.oy + y * m.s]);
    // steady: the corners moved less than 1.5% of the document over the last 300 ms
    S.hist = [...S.hist.filter((e) => now - e.t < STEADY.ms * 2), { t: now, q: vq }];
    const old = S.hist.find((e) => now - e.t >= STEADY.ms * 0.8) || S.hist[0];
    const diag = Math.hypot(vq[0][0] - vq[2][0], vq[0][1] - vq[2][1]) || 1;
    const steady = old === S.hist.at(-1) ? true : Math.max(...vq.map((p, i) => Math.hypot(p[0] - old.q[i][0], p[1] - old.q[i][1]))) / diag < STEADY.share;
    let fit = null;
    if (frameV) fit = fitOf(vq, frameV, ratio);
    else if (d.area < 0.12) fit = "far";
    return { found: true, quad: css, vq, fit, light: lightOf(im, vq, k, area, { page: shape === "page" }), steady, focus: null, sharp: null, near: false };
  }

  function loop() {
    clearTimeout(S.timer);
    if (S.stop || S.paused) return;
    S.timer = setTimeout(() => {
      if (S.stop || S.paused) return;
      const go = () => {
        if (S.stop || S.paused) return;
        try {
          if (video.readyState >= 2 && video.videoWidth && !document.hidden) {
            const t0 = performance.now();
            const m = measure();
            S.quad = m.vq;
            const look = S.run.feed(m, Date.now());
            if (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) {
              globalThis.__humidLook = { found: m.found, quad: m.vq?.map(([x, y]) => ({ x, y })) || null, vw: video.videoWidth, vh: video.videoHeight, ms: Math.round(performance.now() - t0), where: "main", state: look.state, key: look.key, fit: m.fit, light: m.light, steady: m.steady };
            }
            const { fire, ...ev } = look;
            if (changed(S.last, ev)) { S.last = ev; emit(ev); }
            if (fire && auto) { capture("auto"); return; }
          }
        } catch { /* a bad frame: keep looking */ }
        loop();
      };
      try { if (typeof video.requestVideoFrameCallback === "function") video.requestVideoFrameCallback(go); else requestAnimationFrame(go); } catch { go(); }
    }, LOOK_MS);
  }

  /** The photo: the frame as it is now, cut to the document (its corners found again, finer). */
  async function capture(how = "shutter") {
    clearTimeout(S.timer);
    S.paused = true;
    let full = null;
    for (let i = 0; i < 6 && !full; i++) {
      if (video.readyState >= 2 && video.videoWidth) { const c = grab(video, null); if (!looksBlank(c)) full = c; }
      if (!full) await new Promise((r) => setTimeout(r, 150));
    }
    if (!full) { emit({ t: "error", code: "failed", message: "The camera gave a blank picture. Hold steady and try again.", soft: true }); return null; }
    const hint = S.quad?.map(([x, y]) => ({ x, y })) || null;
    let doc = null, cut = false;
    const quad = cornersIn(full, { hint, shape: guided && shape !== "page" ? shape : "full" });
    if (quad) { doc = straighten(full, quad, { prefer: guided && shape !== "page" ? shape : null }); cut = true; }
    else if (frameEl) {
      const m = coverMap(video), fr = frameEl.getBoundingClientRect();
      doc = grab(full, { x: Math.max(0, (fr.left - m.ox) / m.s), y: Math.max(0, (fr.top - m.oy) / m.s), w: Math.min(full.width, fr.width / m.s), h: Math.min(full.height, fr.height / m.s) });
    } else doc = full;
    const id = `w${++S.n}`;
    S.stills.clear();
    S.stills.set(id, { doc, full });
    let freeze = null;
    try { freeze = grab(doc, null, 720).toDataURL("image/jpeg", 0.72); } catch { /* none */ }
    const ev = { t: "captured", id, how, width: doc.width, height: doc.height, cut, freeze, codes: {}, quad: null };
    emit(ev);
    return { id, width: doc.width, height: doc.height };
  }

  const cam = {
    kind: "web",
    get focusable() { return S.focusable; },
    frame() { place(); },
    async focus(x, y) {
      if (!S.focusable || !S.track) return false;
      const ok = await aim({ x, y }, true);
      if (ok) emit({ t: "focus", x, y, af: "scanning" }); // a page is never told the result
      return ok;
    },
    async torch(on) { await S.track.applyConstraints({ advanced: [{ torch: !!on }] }); return { on: !!on }; },
    capture: () => capture("shutter"),
    async take(id, which = "doc") {
      const s = S.stills.get(id);
      if (!s) throw new Error("That photo is gone. Take it again.");
      const c = which === "full" ? s.full : s.doc;
      if (which === "full") s.full = null; else s.doc = null;
      if (!s.full && !s.doc) S.stills.delete(id);
      if (!c) throw new Error("That photo is gone. Take it again.");
      return c;
    },
    pause() { S.paused = true; clearTimeout(S.timer); S.stream?.getTracks().forEach((t) => t.stop()); S.stream = null; video.srcObject = null; },
    async resume() {
      S.paused = false; S.run.reset(); S.last = null; S.hist = []; S.stills.clear();
      if (!S.stream) { await start(); return; }
      loop();
    },
    close() { S.stop = true; clearTimeout(S.timer); S.stream?.getTracks().forEach((t) => t.stop()); S.stream = null; S.stills.clear(); if (video) video.srcObject = null; },
    /** Back to looking after a photo that wasn't kept: the same stream. */
    again() { S.paused = false; S.run.reset(); S.last = null; S.hist = []; S.stills.clear(); loop(); },
  };
  try { await start(); }
  catch (e) { cam.close(); throw e; }
  return cam;
}

/** The words for a camera that couldn't start. */
export function cameraError(e) {
  if (e?.name === "NotAllowedError" || e?.name === "SecurityError" || e?.code === "denied") return "Camera access is off for HumID. Allow it in your phone's settings, or choose a photo instead.";
  if (e?.name === "NotFoundError" || e?.name === "OverconstrainedError" || e?.code === "nocamera") return "No camera found here. Choose a photo instead.";
  if (e?.name === "NotReadableError" || e?.code === "busy") return "Another app is using the camera. Close it and try again, or choose a photo instead.";
  return "The camera couldn't start. Choose a photo instead.";
}
