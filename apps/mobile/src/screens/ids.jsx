// Identity documents: scan a driver's license, passport or ID card with the
// camera (and its chip, where there is one), check the details, and seal one
// record into the vault (IdFlow, a step inside the Add screen). Also the camera
// itself (DocCamera), which finds the document anywhere in view, straightens it
// and turns it upright; the Add screen opens it first for anything. And the card
// view for a sealed ID.
import { useEffect, useMemo, useReducer, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { ChipAccess } from "../ui.jsx";
import { Review, Push } from "./review.jsx";
import { ScanState } from "./scanui.jsx";
import * as S from "../core/state.js";
import { addIdRecord, chipReader, readChipInto, markPicking, toast, saveCopy, buzz as buzzPref } from "../core/controller.js";
import {
  KINDS, kindLabel, fieldsFor, newRecord, applyMrz, applyAamva, applyTyped, setImage, title as recordTitle, status as idStatus,
  provenance, fullName, niceName, countryName, regionName, parseAamva, MrzConsensus,
} from "@humid/idscan";
import {
  barcodeReader, mrzReader, releaseReaders, frameInVideo, grab, imageData, jpeg, imageUrl, fileToCanvas, imageBytes, mrzBand, portraitImage, looksBlank,
  grayOf, grayRegion, cornersIn, develop as developPhoto, straighten, rotateCanvas, canvas as newCanvas,
  createAnalyzer, liveMrzBand, scanOptions, warmScan, modesForKind,
} from "../core/scan.js";
import { LIGHT_TIP, mrzBandLikely } from "../core/addroute.js";
import { begin as flowBegin, step as flowStep, describe, gaveUp, pace } from "../core/scanflow.js";
import { tracker, scaleQuad, shrink } from "../core/docfind.js";
import { templateFor, liveConstraints, previewTurned, measure, judge, holdTracker, barcodeSignal, bottomBand, TH } from "../core/guide.js";
import { grabWindow, takeStill, uprightOf, deskewOf } from "../core/guidecap.js";
import { locateBarcodes, barTracker, boxCorners, readBox, searchBox, fromArea, overlap, barAngle } from "../core/barcodefind.js";
import { DEMO_BUILD } from "@humid/gate";
import { docScanner } from "../core/docscan.js";
import { confirmedByStill } from "../core/mrzseed.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- the camera ---------------- */

function cameraError(e) {
  if (e?.name === "NotAllowedError" || e?.name === "SecurityError") return "Camera access is off for HumID. Allow it in your phone's settings, or choose a photo instead.";
  if (e?.name === "NotFoundError" || e?.name === "OverconstrainedError") return "No camera found here. Choose a photo instead.";
  if (e?.name === "NotReadableError") return "Another app is using the camera. Close it and try again, or choose a photo instead.";
  return "The camera couldn't start. Choose a photo instead.";
}

/**
 * Read a still photo: barcode (tried hard) and the MRZ from a few versions of the image,
 * voting. A straightened card whose way up was a guess is also read turned round, since
 * the MRZ's check digits settle which way is right. Returns { barcode, mrz, consensus,
 * flipped } (flipped: the MRZ read only with the photo turned 180°).
 *   seed   the live loop's MrzConsensus, when it had a valid reading that wasn't yet confirmed
 *          (taking the photo by itself after a steady wait): the still's own read then only has
 *          to agree with it, one OCR pass instead of two. The still must read, valid and the same,
 *          on its own: what is stored is checked against its own page.
 */
export async function readStill(c, read, shape, wide = null, { tryFlip = false, seed = null } = {}) {
  const out = { barcode: null, mrz: null, consensus: false, flipped: false };
  if (read.barcode) {
    try {
      const bc = await barcodeReader();
      // where the barcode is, cropped and laid flat, first; then the wider shot (the
      // barcode may run past the card's edge), then the card. A license barcode wins
      // over any other barcode in the picture.
      let other = null;
      for (const src of [...barcodeSpots(wide || c), ...(wide ? [wide, c] : [c])]) {
        const texts = await bc.read(imageData(grab(src, null, 2400)));
        out.barcode = texts.find((t) => parseAamva(t)) || null;
        other ||= texts[0] || null;
        if (out.barcode) break;
      }
      out.barcode ||= other;
    } catch { /* reported as not found */ }
  }
  if (read.mrz && !out.barcode) {
    try {
      const ocr = await mrzReader();
      for (const turn of tryFlip ? [0, 180] : [0]) {
        const src = turn ? rotateCanvas(c, 180) : c;
        const vote = seed && !turn && seed.lastKey ? seed : new MrzConsensus();
        let mrz = null, stable = false;
        for (const opts of [{}, { threshold: true }, { scale: 1.3 }]) {
          const r = vote.add(await ocr.read(mrzBand(src, shape, opts)));
          if (r.result) mrz = r.result;
          // with the live reads behind it, "stable" also needs this page's own reading to be that result
          if (confirmedByStill(r, vote === seed)) { stable = true; break; }
        }
        if (mrz || stable) { out.mrz = mrz || vote.reads.at(-1) || null; out.consensus = stable; out.flipped = !!turn; break; }
        if (!out.mrz) out.mrz = vote.reads.at(-1) || null;
      }
    } catch { /* reported as not found */ }
  }
  return out;
}

/** A canvas drawn `k` times bigger (a far-away barcode's bars made wide enough to read). */
function enlarge(c, k) {
  if (k <= 1) return c;
  const out = newCanvas(c.width * k, c.height * k);
  const g = out.getContext("2d");
  g.imageSmoothingQuality = "high";
  g.drawImage(c, 0, 0, out.width, out.height);
  return out;
}

/**
 * Part of a video frame or picture around a found barcode, turned so its bars stand
 * exactly upright (even a slight tilt stops the reader) and big enough to read.
 */
function barcodeCrop(src, spot, W, H, cap = 2400) {
  const area = readBox(spot, W, H);
  const c = grab(src, area, cap), s = c.width / area.w;
  const g = grayOf(c, 800), k = g.w / c.width;
  const b = spot.box;
  const deg = barAngle(g, { x: (b.x - area.x) * s * k, y: (b.y - area.y) * s * k, w: b.w * s * k, h: b.h * s * k });
  const t = (-deg * Math.PI) / 180, cos = Math.abs(Math.cos(t)), sin = Math.abs(Math.sin(t));
  const out = newCanvas(c.width * cos + c.height * sin, c.width * sin + c.height * cos);
  const x = out.getContext("2d");
  x.fillStyle = "#fff";
  x.fillRect(0, 0, out.width, out.height);
  x.translate(out.width / 2, out.height / 2);
  x.rotate(t);
  x.drawImage(c, -c.width / 2, -c.height / 2);
  return enlarge(out, Math.min(2, 900 / out.width));
}

/**
 * Where's the barcode in a video frame or picture (W×H)? A quick look at a small copy
 * of all of it, then a closer look around what stood out (from far away only the
 * barcode's bold end bars show at first). Barcodes in `skip` (boxes, src's pixels:
 * one that turned out not to be a license's, or one that won't read) are passed over
 * for the next one in view. { box (in src's pixels), upright } or null.
 */
export function findBarcode(src, W, H, skip = []) {
  const im = grayOf(src, 400), k = W / im.w;
  const free = (b) => !skip.some((x) => overlap(b, x) > 0.5);
  const spot = locateBarcodes(im).map((c) => ({ box: fromArea(c.box, { x: 0, y: 0 }, k), upright: c.upright })).find((c) => free(c.box));
  if (!spot) return null;
  const win = searchBox(spot, W, H);
  if (win.w >= 16 && win.h >= 16) {
    const near = grayOf(grab(src, win), 720), kn = win.w / near.w;
    const closer = locateBarcodes(near).map((c) => ({ box: fromArea(c.box, win, kn), upright: c.upright }))
      .find((c) => overlap(c.box, spot.box) > 0.3 && free(c.box));
    if (closer) return closer;
  }
  return spot;
}

/** In a still photo: the barcode's spot, cropped (none if no barcode stands out). */
function barcodeSpots(c) {
  try {
    const spot = findBarcode(c, c.width, c.height);
    return spot ? [barcodeCrop(c, spot, c.width, c.height)] : [];
  } catch { return []; }
}

/** The document frame in the video's pixels, or null if the layout gives nothing usable. */
function frameRect(v, el, pad) {
  const r = el ? frameInVideo(v, el, pad) : null;
  return r && r.w >= 64 && r.h >= 40 ? r : null;
}

/** Corners in the video's pixels → points on screen (the video is shown with object-fit: cover). */
function onScreen(v, quad) {
  const vr = v.getBoundingClientRect(), vw = v.videoWidth, vh = v.videoHeight;
  if (!vw || !vh || !quad) return null;
  const s = Math.max(vr.width / vw, vr.height / vh);
  const ox = (vr.width - vw * s) / 2, oy = (vr.height - vh * s) / 2;
  return quad.map((p) => `${(p.x * s + ox).toFixed(1)},${(p.y * s + oy).toFixed(1)}`).join(" ");
}

/** The bounding box of some corners, grown by a share on every side and kept inside w×h. */
function around(quad, w, h, pad = 0.1) {
  const xs = quad.map((p) => p.x), ys = quad.map((p) => p.y);
  let x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const px = (x1 - x0) * pad, py = (y1 - y0) * pad;
  x0 = Math.max(0, x0 - px); y0 = Math.max(0, y0 - py); x1 = Math.min(w, x1 + px); y1 = Math.min(h, y1 + py);
  return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
}

/** Said when a reader couldn't start, instead of watching for a code it can never read. */
const NO_READER = "The reader couldn't start on this phone. Take the photo with the shutter and type the details.";

/**
 * With a barcode or MRZ to read: if a card has sat in view, steady, this long and still
 * no read, take the photo anyway, but never while a barcode is in view (it's about to
 * read, or the person is told to move closer): only when none has been seen for BAR_QUIET_MS.
 */
const FALLBACK_MS = 12000;
const BAR_QUIET_MS = 4000;

/**
 * While the phone's document scanner is on screen HumID isn't left, but it can't tell the
 * scanner from the person pressing Home from it: so it may stay off the screen this long
 * (a scan takes seconds) before it locks, and the allowance ends this long after it began.
 */
export const SCANNER_HIDDEN_MS = 60_000;
export const SCANNER_PICK_MS = 90_000;

/** Document photos (nothing to read): how long it must hold steady and sharp before the photo is taken. */
const HOLD_MS = 900;

/** With something to read, the readers need the CPU more than the outline does: look this far apart (ms) at the least, and further while a read is under way on a card already outlined. */
const CODES_LOOK_GAP = 150, READING_LOOK_GAP = 350;

/** Haptics (Android; iPhones have no web vibration), each its own shape: locked on, kept, and couldn't. */
const buzz = () => buzzPref(14);
const cheer = () => buzzPref([16, 45, 26]);
const oops = () => buzzPref([40, 70, 40]);
const nudge = () => buzzPref(8);

/** The next moment worth looking at the camera: a new video frame, or the next paint, never later than 300 ms (a paused or hidden video must not hang the loop). */
function nextFrame(v) {
  return new Promise((res) => {
    let done = false;
    const fin = () => { if (!done) { done = true; res(); } };
    setTimeout(fin, 300);
    try { if (typeof v?.requestVideoFrameCallback === "function") v.requestVideoFrameCallback(fin); else requestAnimationFrame(fin); } catch { fin(); }
  });
}

/**
 * Full-screen camera with two ways of taking a photo of a document.
 *
 * GUIDED (cards, licenses, ID cards, passports: shape "id1" / "td3"): like a bank's
 * check-deposit scan. A fixed outline at the document's real proportions sits in the middle
 * of the screen (core/guide.js: templates); the person lines the document up inside it and
 * is told, live and in plain words, what to change (Move closer, Hold steady, Too much glare…).
 * Lined up, steady and sharp for about 0.6 s, the photo is taken (or the round button
 * takes it at any time): a still, at the best resolution the phone gives (core/guidecap.js),
 * cropped to the outline's rectangle, so nothing live decides what the photo is. It is turned
 * upright by the outline (plus what was read) and handed on like any photo.
 *
 * FREE-FORM (shape "full": Add > Photo, and where the phone's scanner is used): finds the
 * document by itself, wherever it is in view and however it's tilted, draws its outline over
 * it and follows it (core/docfind.js); once it holds still, lit and in focus, the photo is
 * taken, straightened (the outline becomes a flat rectangle) and turned the way the text reads.
 *
 * What it is doing is always on screen (core/scanflow.js, screens/scanui.jsx):
 * Looking → Hold steady → Reading → Verifying → Done, or what to fix (Too dark, Too
 * far, Glare, Couldn't read it), with Try again and Take photo one tap away.
 *
 * The analysis is off the main thread where the phone allows it (core/analyzer.js), at
 * most one look at a time, paced by the video's own frames, and it stops the moment a
 * photo is taken. If nothing is read within the scan's time budget it stops and offers
 * Try again / Take photo instead of spinning on.
 *
 *   mode    "license" | "passport" | "card" (+ side): the shape and the readers for that
 *           document, from core/scan.js scanOptions(); shape, read, title and hint below
 *           override it when given
 *   shape   "id1" (cards), "td3" (passport photo page) or "full" (any document)
 *   read    { barcode, mrz } — what to look for while the camera runs; it captures
 *           by itself the moment it reads one, or when the shutter is pressed
 *   auto    take the photo by itself once a document is found and steady (on by
 *           default); with a barcode or MRZ to read, it waits for the read, and takes
 *           the photo anyway after the card has sat in view for a while without one
 *   onDone({ canvas, original, straightened, rotate, changed, barcode, mrz, consensus, how })
 *           canvas is the proposal (straightened and upright); original the photo as
 *           taken. May be async: the camera stays open (showing "Saving…") until it
 *           settles, shows a tick when it succeeds, and goes back to live with the
 *           reason if it throws, so a photo is never silently lost
 *   saved   { text, img } — what the previous step saved, shown briefly at the top
 *   native  on Android, use the phone's own document scanner (core/docscan.js) for the
 *           photo, and read it here like any photo. The scanner finds the edges, waits for a
 *           steady, focused shot at full resolution and flattens it; where it isn't available
 *           this camera is used instead. Off by default: the scanner's screen is Google Play
 *           services', which HumID's screenshot and recents protection doesn't cover, so IDs,
 *           passports and payment cards stay on this camera (docs/SECURITY.md).
 */
export function DocCamera(props) {
  const preset = props.mode ? scanOptions(props.mode, { side: props.side }) : {};
  const { auto = true, eyebrow, saved, onDone, onCancel, onSkip, onLook, label, tools, native = false, kind = "other" } = props;
  const shape = props.shape ?? preset.shape ?? "id1", read = props.read ?? preset.read ?? {}, title = props.title ?? preset.title, hint = props.hint ?? preset.hint ?? "";
  const side = props.side ?? preset.side ?? "front";
  const video = useRef(null), frame = useRef(null), file = useRef(null);
  const [phase, setPhase] = useState("starting"); // starting | live | reading | saved | error
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState("");
  const [noticeTitle, setNoticeTitle] = useState(null);
  const [torch, setTorch] = useState(null);
  const [scanner, setScanner] = useState(() => native && docScanner.available()); // the phone's document scanner takes the photo
  const [toldSaved, setToldSaved] = useState(!!saved);
  const [look, setLook] = useState(null);      // the last look: { ok, found, hint, progress, points (on screen) }
  const [bar, setBar] = useState(null);        // a barcode in view: { points (on screen), note }
  const codes = !!(read.barcode || read.mrz);
  const card = shape !== "full";
  // a fixed outline for every document with a known shape, unless the phone's own scanner is taking the photo
  const guided = card && !scanner;
  const tpl = useMemo(() => (guided ? templateFor({ kind, side, shape, read }) : null), [guided, kind, side, shape]);
  const [flow, setFlow] = useState(() => flowBegin({ codes }));
  const L = useRef({ stop: false, done: false, paused: false, gave: false, stream: null, track: null, running: new Set(), holdUntil: 0, quad: null, an: null, spots: null, readingAt: 0, flow: null, acq: 0, guided: false, hold: null, misses: 0, bestFocus: 0, guideNow: null }).current;
  L.flow ||= flow;
  /** Feed the state machine one event; what it says is what the card shows. */
  // development builds only: when things happened (ms since the camera opened), for finding what a scan waits on. Timings, never pictures or text.
  const trace = (name, extra) => { if (DEMO_BUILD) { const t = (globalThis.__humidTrace ||= { ev: [] }); t.ev.push([name, Math.round(performance.now()), extra]); } };
  const send = (ev) => {
    const next = flowStep(L.flow, ev, Date.now());
    if (next === L.flow) return;
    const was = L.flow;
    L.flow = next;
    if (next.id !== was.id || next.fail !== was.fail || next.manual !== was.manual || next.note !== was.note || next.loading !== was.loading || Math.abs(next.progress - was.progress) >= 0.05) setFlow(next);
  };
  const flash = (msg, ms = 4000, title = null) => { setNotice(msg); setNoticeTitle(title); setTimeout(() => setNotice((n) => (n === msg ? "" : n)), ms); };
  useEffect(() => { if (!saved) return; const t = setTimeout(() => setToldSaved(false), 2600); return () => clearTimeout(t); }, []);

  const stopStream = () => {
    L.stream?.getTracks().forEach((t) => t.stop());
    L.stream = null;
    if (video.current) video.current.srcObject = null; // the preview lets go too, so the camera light goes out
  };
  const inactive = () => L.stop || L.paused || L.gave || !video.current || video.current.readyState < 2 || !video.current.videoWidth;
  async function finish(result) {
    if (L.done) return;
    L.done = true; L.stop = true; L.paused = true;
    setPhase("reading");
    send({ t: "reading", note: codes ? "Checking what was read…" : "Saving…" });
    let then;
    try {
      then = await onDone(result);
      trace("kept");
      cheer();
      send({ t: "saved" });
      setPhase("saved");
      await sleep(200); // long enough to see the tick; the screen it leads to is what the person is waiting for
      stopStream();
    } catch (e) {
      // Keep the camera open and say why: never drop back to the list as if nothing happened.
      L.done = false; L.paused = false;
      L.holdUntil = Date.now() + 2500; // let the reason be read before trying again by itself
      oops();
      if (L.native) { setError(e?.message || "Couldn't keep that photo. Scan it again."); setPhase("error"); return; }
      flash(e?.message || "Couldn't keep that photo. Try again.");
      send({ t: "retry" });
      setPhase(L.stream ? "live" : "error");
      if (L.stream) { L.stop = false; loop(); }
      return;
    }
    if (typeof then === "function") then();
  }

  /** Start whichever of the loops aren't running (after a failed save or a Try again, only the ones that stopped). */
  function loop() {
    L.consensus ||= new MrzConsensus();
    L.tracker ||= tracker({ need: codes ? 3 : 4, hold: codes ? 0 : HOLD_MS });
    L.hold ||= holdTracker();
    L.retry = () => { L.consensus.reset(); L.tracker.reset(); L.hold.reset(); L.quad = null; L.spots = null; L.bestFocus = 0; L.guideNow = null; };
    // guided: one loop measures the outline's part of the frame; nothing live reads a barcode or MRZ (the still is read)
    const all = L.guided ? { guide: guideLoop } : { look: lookLoop, ...(read.barcode ? { barcode: barcodeLoop } : {}), ...(read.mrz ? { mrz: mrzLoop } : {}) };
    for (const [name, run] of Object.entries(all)) {
      if (L.running.has(name)) continue;
      L.running.add(name);
      run().catch((e) => { if (DEMO_BUILD) globalThis.__humidLoopStopped = name; }).finally(() => L.running.delete(name)); // development builds record which loop stopped (a name, never a picture)
    }
  }

  /**
   * The guided scan's loop: measure the outline's part of the frame (core/guide.js), say what to
   * change, and take the photo once it has been lined up, steady and sharp for about 0.6 s. On this
   * thread: the picture is a few hundred pixels and a look takes a few milliseconds.
   */
  async function guideLoop() {
    const needBar = !!(read.barcode || tpl?.forbid?.barcode);
    let prev = null, lastMs = 0, wasAligned = false;
    while (!L.stop) {
      await sleep(pace(lastMs, { min: 90, max: 280 }));
      const v = video.current;
      await nextFrame(v);
      if (document.hidden) { await sleep(400); continue; }
      if (inactive() || Date.now() < L.holdUntil) { prev = null; continue; }
      const rect = frameRect(v, frame.current, 0);
      if (!rect) continue;
      const t0 = performance.now();
      let m, verdict, win, extra;
      try {
        const got = grabWindow(v, rect);
        win = got.win;
        m = measure(got.im, win.guide, { prev });
        prev = got.im;
        // strong extra signals, where the document has them: a barcode in the outline (and how big), the lines of an MRZ
        extra = { bestFocus: L.bestFocus };
        if (needBar) extra.barcode = barcodeSignal(locateBarcodes(got.im), win.guide);
        if (read.mrz) extra.mrz = mrzBandLikely(bottomBand(got.im, win.guide));
        verdict = judge(m, tpl, extra);
      } catch { await sleep(150); continue; }
      lastMs = performance.now() - t0;
      if (inactive()) continue; // taken, or given up, while it was measuring: drop this one
      const now = Date.now();
      L.bestFocus = verdict.aligned && m.focus ? Math.max((L.bestFocus || 0) * 0.985, m.focus) : (L.bestFocus || 0) * 0.97;
      const h = L.hold.feed(verdict.ready, now);
      L.guideNow = { rect, verdict, at: now };
      if (DEMO_BUILD) globalThis.__humidGuide = { key: verdict.key, present: verdict.present, aligned: verdict.aligned, ready: verdict.ready, steady: verdict.steady, sharp: verdict.sharp, scale: m.scale, dx: m.dx, dy: m.dy, rot: m.rot, flatH: m.flatH, flatV: m.flatV, sides: m.sides, focus: m.focus, motion: m.motion, mean: m.mean, p95: m.p95, sat: m.sat, patch: m.patch, energy: m.energy, ms: Math.round(lastMs), rect, video: [v.videoWidth, v.videoHeight], extra: { bar: extra.barcode ? Math.round(extra.barcode.across * 100) / 100 : extra.barcode, mrz: extra.mrz } }; // development builds: tests can see what the guidance sees (numbers, never pictures)
      if (verdict.aligned && !wasAligned) nudge();
      wasAligned = verdict.aligned;
      send({ t: "look", look: { found: verdict.present, guide: verdict, hint: verdict.detail }, progress: h.progress });
      setLook({ ok: verdict.aligned, found: verdict.present, progress: h.progress, points: null, key: verdict.key });
      if (h.fire && !L.stop) { L.stop = true; trace("hold"); shoot("auto"); return; }
    }
  }

  /** Read PDF417 from a crop: in the barcode worker when there is one, else on this thread. */
  async function readBarcodes(img, harder) {
    const viaWorker = await L.an.read(img, { harder });
    if (viaWorker) return viaWorker;
    const main = await (L.bcMain ||= barcodeReader().catch(() => null));
    if (!main) throw new Error("no reader");
    return main.read(img, { harder });
  }

  /** Where's the document? Once per video frame at most, one look at a time, spaced by how long the last took. */
  async function lookLoop() {
    const track = L.tracker;
    let lastMs = 0, steadySince = 0, wasFound = false;
    let prevOk = false;
    while (!L.stop) {
      await sleep(pace(lastMs, { min: L.reading && L.quad ? READING_LOOK_GAP : codes ? CODES_LOOK_GAP : 70 }));
      const v = video.current;
      await nextFrame(v);
      if (document.hidden) { await sleep(400); continue; }
      if (inactive() || !auto || Date.now() < L.holdUntil) continue;
      const t0 = performance.now();
      let r;
      try { r = await L.an.look(v, { prior: track.quad }); } catch { await sleep(150); continue; }
      lastMs = performance.now() - t0;
      if (inactive()) continue; // taken, or given up, while it was thinking: drop this one
      try {
        const t = track.feed(r.look, r.w, r.h);
        L.quad = t.quad ? scaleQuad(t.quad, r.k) : null;
        if (read.barcode && r.spots) L.spots = { list: r.spots, k: v.videoWidth / r.bw, at: Date.now(), used: false };
        if (DEMO_BUILD) globalThis.__humidLook = { ...r.look, quad: L.quad, ms: Math.round(lastMs), where: L.an.where }; // development builds: tests can see why it waits
        const found = !!t.quad;
        if (found && !wasFound) { L.acq++; trace("found", Math.round(lastMs)); }
        wasFound = found;
        send({ t: "look", look: r.look, progress: track.progress, holdReading: Date.now() - L.readingAt < 1500 });
        setLook({ ok: r.look.ok, found, hint: r.look.hint, progress: track.progress, points: onScreen(v, L.quad), acq: L.acq });
        if (onLook) { try { onLook({ look: r.look, quad: L.quad, video: v }); } catch { /* a guess, never in the way */ } }
        if (found && r.look.ok && !prevOk) nudge();
        prevOk = found && r.look.ok;
        if (!codes) {
          if (t.fire && !L.stop) { L.stop = true; shoot("auto"); return; }
        } else {
          steadySince = r.look.ok ? steadySince || Date.now() : 0;
          const barQuiet = !read.barcode || Date.now() - (L.barSeen || 0) > BAR_QUIET_MS;
          if (steadySince && barQuiet && Date.now() - steadySince > FALLBACK_MS && !L.stop) { L.stop = true; shoot("auto"); return; }
        }
      } catch { /* a bad frame: keep looking */ }
    }
  }

  /** The barcode: found anywhere in view, highlighted, and read from just that spot, laid flat. */
  async function barcodeLoop() {
    const bars = barTracker();
    let barSince = 0, barTries = 0, barUpright = true, barFails = 0, lastSpot = null, idle = 0;
    const skips = []; // barcodes passed over for a while: { box, until }
    while (!L.stop) {
      await sleep(40);
      if (inactive()) continue;
      const fresh = L.spots && !L.spots.used && Date.now() - L.spots.at < 800 ? L.spots : null;
      if (!fresh) continue;
      fresh.used = true;
      const v = video.current;
      try {
        // Like a store's scan-and-go: find the barcode anywhere in view first (in the worker,
        // on a small grey copy), highlight it, and point the reader at just that spot, at
        // full resolution, laid flat: it reads from further away and at any angle.
        const now = Date.now(), W = v.videoWidth, H = v.videoHeight;
        const free = skips.filter((x) => x.until > now).map((x) => x.box);
        let spot = fresh.list.map((c) => ({ box: fromArea(c.box, { x: 0, y: 0 }, fresh.k), upright: c.upright })).find((c) => !free.some((x) => overlap(c.box, x) > 0.5)) || null;
        if (spot) spot = await closerLook(v, spot, W, H, free);
        if (spot) barUpright = spot.upright;
        const full = bars.feed(spot, now);
        let src, harder;
        if (full) {
          idle = 0;
          if (!L.barSeen || now - L.barSeen > 1500) barSince = now;
          L.barSeen = now; L.readingAt = now;
          src = barcodeCrop(v, { box: full, upright: barUpright }, W, H, 1600);
          harder = ++barTries % 3 === 0; // now and then, rotations and a closer search too
          const across = barUpright ? full.w : full.h;
          const note = now - barSince < 2200 ? "Barcode found. Reading…"
            : across < Math.min(W, H) * 0.3 ? "Move a little closer to the barcode"
            : "Hold steady on the barcode…";
          setBar({ points: onScreen(v, boxCorners(full)), note });
          send({ t: "reading", note });
        } else {
          setBar(null);
          // nothing stands out: every fourth look, the card's area (or the whole view) at a modest size
          if (++idle % 4 !== 0) continue;
          src = grab(v, L.quad ? around(L.quad, W, H, 0.12) : null, 1280);
          harder = idle % 12 === 0;
        }
        if (DEMO_BUILD) globalThis.__humidBar = { spot, box: full, harder, where: L.an.where }; // development builds: tests can see what it found
        const texts = await readBarcodes(imageData(src), harder);
        // only a license's barcode is taken: anything else in view is ignored
        const text = texts.find((t) => parseAamva(t));
        if (L.stop || L.paused) continue; // a photo was taken while it was reading: that one stands
        if (text) { L.stop = true; setBar(null); shoot("live", { barcode: text }); return; }
        if (spot) {
          // a barcode that isn't a license's (a store card beside it): look past it. One
          // that won't read after a while: give the next one in view a turn, then come back.
          barFails = lastSpot && overlap(spot.box, lastSpot) > 0.5 ? barFails + 1 : 1;
          lastSpot = spot.box;
          if (texts.length) { skips.push({ box: spot.box, until: now + 8000 }); barFails = 0; }
          else if (barFails >= 8) { skips.push({ box: spot.box, until: now + 2500 }); barFails = 0; }
          while (skips.length > 8) skips.shift();
        }
        if (texts.length && !text) { setBar((b) => ({ points: b?.points || null, note: "That isn't a license barcode. Show the back of the license." })); send({ t: "other" }); }
      } catch (e) {
        if (e?.message === "no reader") { L.gave = true; send({ t: "unreadable" }); flash(NO_READER, 8000); }
        /* otherwise a bad frame: keep looking */
      }
    }
  }

  /** A second, closer look around what stood out (from far away only a barcode's bold end bars show at first). */
  async function closerLook(v, spot, W, H, free) {
    const win = searchBox(spot, W, H);
    if (win.w < 16 || win.h < 16) return spot;
    const near = grayRegion(v, win, 560), kn = win.w / near.w;
    const spots = await L.an.locate(near);
    const closer = spots.map((c) => ({ box: fromArea(c.box, win, kn), upright: c.upright })).find((c) => overlap(c.box, spot.box) > 0.3 && !free.some((x) => overlap(c.box, x) > 0.5));
    return closer || spot;
  }

  /** The MRZ: the card's lines, straightened as a strip only, read in the OCR worker; two matching valid reads are needed. */
  async function mrzLoop() {
    const consensus = L.consensus;
    let mrzTurn = 0, verifyUntil = 0;
    const ocr = await mrzReader().catch(() => null);
    if (!ocr) { L.gave = true; send({ t: "unreadable" }); flash(NO_READER, 8000); return; }
    trace("mrz-ready");
    send({ t: "engine", loading: false });
    const ready = Date.now();
    while (!L.stop) {
      await sleep(30);
      if (inactive()) continue;
      // no card outlined yet: give the outline a moment before reading blind (a read of the wrong part of the picture is a wasted second)
      if (!L.quad && Date.now() - ready < 2000) continue;
      const v = video.current;
      try {
        // the card wherever it is; which way up isn't known yet, so every third try reads
        // it turned round (the check digits only agree one way)
        const flip = L.quad && ++mrzTurn % 3 === 0 ? 180 : 0;
        const strip = L.quad ? liveMrzBand(v, L.quad, shape, { turn: flip }) : mrzBand(grab(v, frameRect(v, frame.current, 0.05)), shape);
        if (L.quad) { L.readingAt = Date.now(); send({ t: "reading" }); }
        const t0 = performance.now();
        L.reading = true;
        let text;
        try { text = await ocr.read(strip); } finally { L.reading = false; }
        const res = consensus.add(text);
        trace("ocr", [Math.round(performance.now() - t0), !!res.best, res.stable]);
        if (L.stop) return;
        if (L.paused) continue;
        if (res.best) { verifyUntil = Date.now() + 2500; send({ t: "verifying" }); }
        else if (Date.now() > verifyUntil && L.quad) send({ t: "reading" });
        if (res.stable) { L.stop = true; shoot("live", { mrz: res.result, consensus: true, turn: flip }); return; }
      } catch { /* a bad frame: keep looking */ }
    }
  }

  // Leaving the screen (the app goes to the background, the page is hidden or put away)
  // frees the camera at once; coming back lands on the screen before, where "Start camera" asks again.
  useEffect(() => {
    const away = () => {
      if (!document.hidden || L.scanning) return; // the phone's scanner is on screen: HumID hasn't left
      L.stop = true; L.paused = true; stopStream();
      if (L.picking) { setPhase((p) => (p === "reading" || p === "saved" ? p : "error")); setError("The camera stopped while you chose a photo. Close this and start the camera again."); } // the photo picker is up: keep the screen so its file still arrives
      else onCancel?.();
    };
    const gone = () => { L.stop = true; stopStream(); };
    document.addEventListener("visibilitychange", away);
    addEventListener("pagehide", gone);
    return () => { document.removeEventListener("visibilitychange", away); removeEventListener("pagehide", gone); };
  }, []);

  useEffect(() => {
    // Engines first, in parallel with the camera: the camera's permission prompt and
    // start-up are the slow part of getting going, and the readers load during them.
    trace("mount");
    if (L.native === undefined) L.native = scanner;
    if (read.mrz) { send({ t: "engine", loading: true }); mrzReader().catch(() => null); }
    if (read.barcode && (L.native || guided)) barcodeReader().then(() => {}, () => {}); // the scanner's page, or the guided still, is read here, on this thread
    const tick = setInterval(() => {
      if (L.native) return; // the scanner has its own pace: no time budget, no live steps
      send({ t: "tick" });
      if (gaveUp(L.flow) && !L.gave) { L.gave = true; oops(); setLook((l) => l && { ...l, points: null }); }
    }, 500);
    if (L.native) scanNative();
    else startCamera();
    return () => { L.stop = true; clearInterval(tick); L.an?.close(); stopStream(); };
  }, []);

  /** This screen's own camera: the live view, the outline and the live reads. */
  function startCamera() {
    L.native = false;
    L.guided = card; // a card, license or passport page: the fixed outline (the screen's `guided` follows the scanner flag)
    if (!L.an && !L.guided) {
      L.an = createAnalyzer({ shape, bar: !!read.barcode });
      L.an.warm();
      if (read.barcode && L.an.where === "main") barcodeReader().then(() => {}, () => {}); // no worker on this phone: the reader runs here
    }
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("no camera"), { name: "NotFoundError" });
        // guided: 1080p (1440p for a passport page's small print), not 4K, which an Android WebView was unsteady on (2.1.1);
        // the photo is a still, not a frame of this. Free-form keeps the 4K frame it has always taken the photo from.
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: false, video: L.guided ? liveConstraints(tpl, { portrait: innerHeight >= innerWidth }) : { facingMode: { ideal: "environment" }, width: { ideal: 3840 }, height: { ideal: 2160 } },
        });
        if (L.stop) { stream.getTracks().forEach((t) => t.stop()); return; }
        L.stream = stream;
        L.track = stream.getVideoTracks()[0];
        try { await L.track.applyConstraints({ advanced: [{ focusMode: "continuous" }] }); } catch { /* not offered */ }
        try { if (L.track.getCapabilities?.().torch) setTorch(false); } catch { /* not offered */ }
        video.current.srcObject = stream;
        await video.current.play().catch(() => {});
        // guided: a preview that came back turned the wrong way for the screen leaves the outline a third of the pixels: ask once more, the other way round
        if (L.guided && previewTurned(video.current.videoWidth, video.current.videoHeight, innerHeight >= innerWidth)) {
          const w = liveConstraints(tpl, { portrait: innerHeight < innerWidth });
          try { await L.track.applyConstraints({ width: w.width, height: w.height }); await sleep(250); } catch { /* the first size stays */ }
        }
        setPhase("live");
        trace("camera");
        send({ t: "ready" });
        if (auto || codes) loop();
      } catch (e) { setPhase("error"); setError(cameraError(e)); }
    })();
  }

  /**
   * The phone's document scanner takes the photo (Android): edges found, a steady, focused
   * full-resolution shot, flattened. Then it is read here and saved like any photo. Backing
   * out of the scanner closes this screen; no scanner on this phone falls back to the camera.
   */
  async function scanNative() {
    L.native = true; L.stop = true; L.paused = true; L.done = false;
    setError(null); setPhase("starting");
    trace("scanner");
    markPicking({ forMs: SCANNER_PICK_MS, hiddenMs: SCANNER_HIDDEN_MS }); // the scanner is HumID's own step, not leaving it
    L.scanning = true;
    let page;
    try { page = await docScanner.scan({ maxSide: 3200 }); }
    catch (e) {
      L.scanning = false;
      if (e?.kind === "unavailable") { setScanner(false); flash(e.message, 5000); L.stop = false; L.paused = false; startCamera(); return; }
      oops(); setError(e?.message || "The scanner stopped. Scan again."); setPhase("error");
      return;
    }
    L.scanning = false;
    if (!page) { onCancel(); return; } // backed out of the scanner
    setPhase("reading");
    send({ t: "captured" });
    try {
      const c = await fileToCanvas(page.blob);
      await finish(await develop(c, null, "scan"));
    } catch (e) {
      oops(); setError(e?.message || "Couldn't read that page. Scan it again."); setPhase("error");
    }
  }

  /** From the scanner to this screen's own camera, for this document (the person asked). */
  function toCamera() {
    setScanner(false); setError(null); setPhase("starting");
    L.stop = false; L.paused = false; L.done = false;
    startCamera();
  }

  /**
   * Develop a photo: find the document's corners in it (helped by the live outline),
   * straighten it, turn it upright, and read it if there's something to read.
   *   known   what a live read already found ({ barcode } or { mrz, consensus, turn })
   *   guided  the photo is already the outline's crop (core/guidecap.js): nothing is found in it,
   *           it is only turned upright (the outline is landscape, so 0 or 180) and read
   */
  async function develop(original, hintQuad, how, known = {}, { guided: cropped = false, source = null } = {}) {
    await sleep(0); // let "Saving…" paint first: straightening a 4K photo takes a moment
    trace("develop");
    // the scanner hands back the page already found and flattened: only turned upright here
    const scanned = how === "scan";
    const quad = scanned || cropped ? null : cornersIn(original, { hint: hintQuad, shape });
    let dev;
    if (cropped) {
      const up = uprightOf(original);
      dev = { canvas: up.rotate ? rotateCanvas(original, up.rotate) : original, original, straightened: true, rotate: up.rotate, confidence: up.confidence, changed: true };
    } else if (scanned) {
      dev = { ...developPhoto(original, null, { shape }), straightened: true, changed: true };
    } else if (known.mrz && quad) {
      // read live from the straightened card turned known.turn: develop it the same way
      let flat = straighten(original, quad, { prefer: shape, max: 2000 });
      if (flat.height > flat.width) flat = rotateCanvas(flat, 90);
      dev = { canvas: known.turn ? rotateCanvas(flat, known.turn) : flat, original, straightened: true, rotate: known.turn || 0, confidence: 1, changed: true };
    } else dev = developPhoto(original, quad, { shape });
    // a card that wasn't found: what was inside the on-screen frame, as before
    if (card && !dev.straightened) {
      const v = video.current, r = v && how !== "file" && !scanned ? frameRect(v, frame.current, 0.02) : null;
      if (r) { const c = grab(original, r); dev = { canvas: c, original, straightened: false, rotate: 0, confidence: 0, changed: true }; }
    }
    let readOut = {};
    if (known.barcode || known.mrz) readOut = known;
    else if (codes) {
      send({ t: "verifying" }); // the photo is straight; now it is read closely and the details checked
      await sleep(0);
      readOut = await readStill(dev.canvas, read, shape, how === "file" || scanned || cropped ? null : grab(original, quad ? around(quad, original.width, original.height, 0.15) : null, 2400), { tryFlip: dev.straightened, seed: read.mrz ? L.consensus : null });
      if (readOut.flipped) dev = { ...dev, canvas: rotateCanvas(dev.canvas, 180), rotate: (dev.rotate + 180) % 360, changed: true };
      // guided, taken by itself, and what the outline holds wasn't read: say so and keep looking (twice; then the photo is kept as it is, and the shutter always keeps it)
      if (cropped && how === "auto" && !(readOut.barcode || readOut.mrz?.valid) && ++L.misses < 3) {
        throw Object.assign(new Error(read.barcode ? "Move a little closer to the barcode and hold steady." : "Keep the whole page inside the outline and hold steady."), { title: read.barcode ? "Couldn't read the barcode" : "Couldn't read the two lines" });
      }
    }
    const { turn, flipped, ...codesFound } = readOut;
    if (DEMO_BUILD) globalThis.__humidDevelop = { how, guided: cropped, source: source?.source, stillW: source?.width, why: source?.why, out: [dev.canvas.width, dev.canvas.height], straightened: dev.straightened, rotate: dev.rotate, confidence: dev.confidence, quad, png: globalThis.__humidKeepPng ? dev.canvas.toDataURL("image/png") : undefined }; // development builds: tests can see the proposal
    trace("developed");
    return { ...dev, ...codesFound, how };
  }

  /** The shutter, the auto-capture (how = "auto"), or a live read (how = "live"). */
  async function shoot(how = "shutter", known = {}) {
    const v = video.current;
    if (!v || L.done) return;
    trace("shoot-" + how);
    L.paused = true; L.stop = how === "shutter" ? L.stop : true;
    setPhase("reading");
    send({ t: "captured" });
    if (how === "auto") buzz();
    try {
      // Android can report a frame before it has one to give, or give a black one: wait briefly, try again.
      let c = null, still = null;
      // guided: the outline's part of the best still the phone gives (turned straight by the guidance's own small, reliable angle)
      const rect = L.guided ? frameRect(v, frame.current, 0) : null;
      const tilt = rect ? deskewOf(L.guideNow?.verdict?.deskew) : 0;
      for (let i = 0; i < 6 && !c; i++) {
        if (v.readyState >= 2 && v.videoWidth) {
          if (rect) { const st = await takeStill(v, L.track, rect, { tilt, photo: i === 0 }); if (!looksBlank(st.canvas)) { c = st.canvas; still = st; } }
          else { const got = grab(v, null); if (!looksBlank(got)) c = got; }
        }
        if (!c) await sleep(150);
      }
      if (!c) throw new Error("The camera gave a blank picture. Hold steady and try again.");
      await finish(await develop(c, L.quad, how, known, rect ? { guided: true, source: still } : {}));
    } catch (e) {
      L.paused = false; L.gave = false;
      L.holdUntil = Date.now() + 2500;
      oops();
      flash(e?.message || "Couldn't take the photo. Try again.", 4000, e?.title);
      send({ t: "retry" });
      L.retry?.();
      setPhase(L.stream ? "live" : "error");
      if (L.stream) { L.stop = false; loop(); }
    }
  }

  async function onFile(e) {
    L.picking = false;
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    if (!f) return;
    L.paused = true;
    setPhase("reading");
    send({ t: "captured" });
    try {
      const c = await fileToCanvas(f);
      await finish(await develop(c, null, "file"));
    } catch {
      L.paused = false;
      send({ t: "retry" });
      setPhase(L.stream ? "live" : "error");
      toast("That file isn't a photo HumID can open.", "warn");
    }
  }

  async function toggleTorch() {
    try { await L.track.applyConstraints({ advanced: [{ torch: !torch }] }); setTorch(!torch); } catch { setTorch(null); }
  }

  /** Try again: a fresh budget, fresh reads, the camera as it was. */
  function retry() {
    if (L.native) { scanNative(); return; }
    L.gave = false; L.holdUntil = 0; L.barSeen = 0; L.bcMain = null;
    L.retry?.();
    setNotice("");
    L.misses = 0;
    send({ t: "retry" });
    if (L.stream) { L.stop = false; loop(); }
  }

  const cancel = () => { L.stop = true; stopStream(); onCancel(); };
  const skip = () => { L.stop = true; stopStream(); onSkip(); };
  const live = phase === "live" && look;
  const lookState = !live ? undefined : look.ok ? "ok" : look.found ? "close" : "searching";
  const view = describe(flow, { shape, hint, guided, noun: tpl?.noun });
  const busy = phase === "reading" || phase === "saved";

  return (
    <div class="doccam" role="dialog" aria-modal="true" aria-label={title} data-scanner={scanner ? "1" : undefined} data-guided={guided ? "1" : undefined} data-phase={phase} data-shape={shape} data-look={lookState} data-bar={bar?.points ? "found" : undefined} data-flow={view.id} data-fail={view.fail || undefined}>
      <video ref={video} playsInline muted autoplay />
      {phase === "live" && !L.gave && (look?.points || bar?.points) && (
        <svg class="dc-outline" aria-hidden="true" style={{ "--p": look?.progress || 0 }}>
          {look?.points && <polygon key={`o${look.acq}`} class="dc-snap" points={look.points} />}
          {look?.points && <polyline class="dc-prog" points={`${look.points} ${look.points.split(" ")[0]}`} pathLength="100" style={{ strokeDashoffset: 100 - 100 * (look.progress || 0) }} />}
          {look?.points && look.points.split(" ").map((pt) => { const [x, y] = pt.split(","); return <circle cx={x} cy={y} r="6" />; })}
          {bar?.points && <polygon class="dc-bar" points={bar.points} />}
        </svg>
      )}
      <div class="dc-stage">
        <div class="dc-frame" data-shape={shape} data-template={tpl?.id} data-ready={guided && view.id === "steady" ? "1" : undefined} ref={frame}>
          <i class="c tl" /><i class="c tr" /><i class="c bl" /><i class="c br" />
          {guided && tpl.zones.map((z) => <span class="dc-zone" data-k={z.k} aria-hidden="true" style={{ left: `${z.x}%`, top: `${z.y}%`, width: `${z.w}%`, height: `${z.h}%` }} />)}
          {read.mrz && !guided && <span class="dc-mrz" data-shape={shape} />}
          {phase === "live" && (view.id === "reading" || view.id === "verifying") && <span class="dc-sweep" aria-hidden="true"><i /></span>}
          {phase === "reading" && <span class="dc-busy"><i /></span>}
          {phase === "saved" && <span class="dc-busy dc-saved" aria-hidden="true"><Icon name="check" /></span>}
        </div>
      </div>
      {toldSaved && saved && (
        <div class="dc-saved-chip" role="status">
          {saved.img && <img src={imageUrl(saved.img)} alt="" />}
          <span><Icon name="check" />{saved.text}</span>
        </div>
      )}
      <header class="dc-top">
        <button class="icon-btn" aria-label="Close the camera" data-back onClick={cancel}><Icon name="x" /></button>
        <div class="grow">{eyebrow && <div class="eyebrow">{eyebrow}</div>}<strong>{title}</strong></div>
        {torch != null && <button class="icon-btn" aria-label={torch ? "Turn the light off" : "Turn the light on"} aria-pressed={torch} onClick={toggleTorch}><Icon name="torch" /></button>}
      </header>
      {scanner && phase !== "reading" && phase !== "saved" ? (
        <div class="dc-status dc-state dc-scanner" data-tone={phase === "error" ? "warn" : undefined} data-state={phase === "error" ? "error" : "scanner"}>
          <div class="dc-msg">
            <span class="dc-ico" data-spin={phase === "error" ? undefined : "1"}><Icon name={phase === "error" ? "alert" : "scan"} /></span>
            <div class="dc-words" role="status" aria-atomic="true" aria-live={phase === "error" ? "assertive" : "polite"}>
              <strong>{phase === "error" ? "Couldn't keep that page" : "Opening the scanner…"}</strong>
              <span>{phase === "error" ? error : "Hold the document flat in good light. It takes the photo by itself."}</span>
            </div>
          </div>
          {phase === "error" && (
            <div class="dc-actions">
              <button type="button" class="dc-act primary" onClick={() => scanNative()}><Icon name="rotate" />Scan again</button>
              <button type="button" class="dc-act" onClick={toCamera}><Icon name="camera" />Use HumID's camera</button>
            </div>
          )}
        </div>
      ) : (
        <ScanState view={view} notice={notice} noticeTitle={noticeTitle} error={phase === "error" ? error : null} torch={torch} onTorch={torch != null ? toggleTorch : null} onRetry={retry} onShoot={() => shoot()} />
      )}
      {label && phase !== "reading" && phase !== "saved" && (
        <div class="dc-label" role="status">
          <span><Icon name={label.icon || "scan"} />{label.text}</span>
          {label.action && <button class="linklike" type="button" onClick={label.action.onClick}>{label.action.text}</button>}
        </div>
      )}
      <footer class="dc-bottom" data-tools={tools ? "1" : undefined}>
        {tools && <div class="dc-tools">{tools}</div>}
        <button class="dc-side" disabled={busy} onClick={() => { L.picking = true; markPicking(); file.current.click(); }}><Icon name="image" /><span>Photo</span></button>
        <button class="dc-shutter" aria-label="Take the photo" data-offer={view.manual ? "1" : undefined} disabled={phase !== "live"} onClick={() => shoot()}><i /></button>
        {onSkip ? <button class="dc-side" onClick={skip}><Icon name="chevron" /><span>Skip</span></button> : <span class="dc-side" aria-hidden="true" />}
      </footer>
      <input ref={file} type="file" accept="image/*" hidden onChange={onFile} />
    </div>
  );
}

/* ---------------- the ID flow ---------------- */

// What each kind of document asks the camera for, side by side.
export const PLAN = {
  passport: [{ side: "front", shape: "td3", read: { mrz: true }, title: "The photo page", hint: "Line the photo page up inside the outline, with the two lines of <<< at the bottom. It takes the photo by itself." }],
  driver_license: [
    { side: "front", shape: "id1", read: {}, title: "Front of the license", hint: "Line the card up inside the outline. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { barcode: true }, title: "Back of the license", hint: "Line the back up inside the outline, barcode showing. It takes the photo and reads the barcode by itself." },
  ],
  id_card: [
    { side: "front", shape: "id1", read: {}, title: "Front of the card", hint: "Line the card up inside the outline. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { barcode: true, mrz: true }, title: "Back of the card", hint: "Line the back up inside the outline. A barcode or the lines of <<< read by themselves.", optional: true },
  ],
  residence_permit: [
    { side: "front", shape: "id1", read: {}, title: "Front of the permit", hint: "Line the card up inside the outline. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { mrz: true }, title: "Back of the permit", hint: "Line the back up inside the outline, with the three lines of <<< showing. They read by themselves.", optional: true },
  ],
  other: [
    { side: "front", shape: "id1", read: {}, title: "Front", hint: "Line the card up inside the outline. It takes the photo by itself." },
    { side: "back", shape: "id1", read: {}, title: "Back", hint: "Line the card up inside the outline. It takes the photo by itself.", optional: true },
  ],
};

/** The ID kinds the picker offers. */
export const ID_CHOICES = [
  { kind: "driver_license", icon: "idcard", title: "Driver's license", sub: "US or Canada. Reads the barcode on the back." },
  { kind: "passport", icon: "passport", title: "Passport", sub: "Reads the photo page, and the chip on phones with NFC." },
  { kind: "id_card", icon: "idcard", title: "ID card", sub: "A state ID, or a national ID card with a chip." },
  { kind: "other", icon: "file", title: "Another card", sub: "Insurance, membership, anything with two sides." },
];

const SOURCE = { chip: "Chip", barcode: "Barcode", mrz: "Scanned", typed: "You" };

/**
 * A record started from what the Add camera found: the side it photographed (with
 * what it read), so the flow carries on from there. `found`: { kind, side, canvas,
 * barcode, mrz, consensus }. The record's kind can still change (an MRZ names it).
 */
export async function recordFrom(found) {
  const rc = newRecord(found.kind);
  if (found.canvas) {
    const img = await jpeg(found.canvas);
    setImage(rc, found.side, img);
  }
  let note = null;
  if (found.barcode) {
    const a = parseAamva(found.barcode);
    if (a) { applyAamva(rc, a); rc.raw.barcode = found.barcode; note = { tone: "ok", text: `Barcode read: ${[niceName(a.fields.given), niceName(a.fields.surname)].filter(Boolean).join(" ") || "details found"}.` }; }
  }
  if (found.mrz) {
    applyMrz(rc, found.mrz, { consensus: found.consensus });
    note = found.mrz.valid
      ? { tone: "ok", text: `Details read${found.consensus ? "" : " (check them)"}: ${fullName(rc) || found.mrz.number}.` }
      : { tone: "warn", text: "Read only part of the details. Check them, or retake the photo." };
  }
  return { rec: rc, note };
}

/**
 * The ID flow, inside the Add screen: capture each side (the camera reads a barcode or
 * MRZ as it goes), read the chip where there is one, check the details, seal.
 *   start   { rec, note, step } — a record to carry on with (from the camera's find, or
 *           a fresh newRecord(kind)); step: "capture" (default) or "chip"
 *   onExit  the flow is left from its first step (Back): the caller shows what was before
 */
export function IdFlow({ start, onExit }) {
  const rec = useRef(start.rec);
  const [, redraw] = useReducer((n) => n + 1, 0);
  const [step, setStep] = useState(start.step === "auto" ? "capture" : start.step || "capture"); // capture | chip | review
  const [cam, setCam] = useState(null);         // the plan entry the camera is open for
  // One camera per capture: keeps its identity while the photo is kept (so "Done" can show), and is new each time one is opened.
  const camRun = useRef({ cam: null, n: 0 });
  if (cam !== camRun.current.cam) camRun.current = { cam, n: camRun.current.n + 1 };
  const [saved, setSaved] = useState(null);     // { text, img } the camera shows for the side just taken
  const [note, setNote] = useState(start.note || null); // { tone, text } about the last capture
  const [nfc, setNfc] = useState(null);
  const [access, setAccess] = useState(null);
  const [name, setName] = useState("");
  const [tags, setTags] = useState(["identity"]);
  const fields = useRef(null);                  // { commit, missing } from IdFields
  const busy = S.sheet.value?.stage != null;

  const r = rec.current;
  const plan = PLAN[r.kind] || PLAN.other;
  const done = plan.filter((p) => r.images[p.side]);
  const next = plan.find((p) => !r.images[p.side] && !r.skipped?.includes(p.side));

  useEffect(() => {
    for (const m of modesForKind(r.kind)) warmScan(m); // the readers this kind will need load while the first screen is read
    if (KINDS[r.kind]?.chip || step === "chip") chipReader().then(setNfc).catch(() => setNfc({ available: false }));
    if (start.step === "auto") {
      // the Add camera already read one side: straight on to what's left, or past the capture
      if (next) { setStep("capture"); setSaved({ text: done.length ? `${done[0].side === "back" ? "Back" : "Front"} saved. Now the ${next.side}.` : null, img: done[0] ? r.images[done[0].side] : null }); setCam(next); }
      else afterCapture();
    } // otherwise the capture step says what to show and waits for "Start camera": nothing opens the camera until the person taps
    return () => { releaseReaders(); };
  }, []);
  useEffect(() => { if (step === "review") setName((n) => n || recordTitle(rec.current)); }, [step]);

  /**
   * The camera took a photo. Keep it (if this throws, the camera stays open and says
   * why), then return what happens once the camera has shown its tick: straight on to
   * the next side, or back to the screen when everything's in or a read needs a look.
   */
  async function captured(p, { canvas, barcode, mrz, consensus }) {
    const rc = rec.current;
    let img;
    try { img = await jpeg(canvas); }
    catch { throw new Error("Couldn't save that photo. Try again, or choose one with Photo."); }
    setImage(rc, p.side, img);
    let n = null;
    if (barcode) {
      const a = parseAamva(barcode);
      if (a) { applyAamva(rc, a); rc.raw.barcode = barcode; n = { tone: "ok", text: `Barcode read: ${[niceName(a.fields.given), niceName(a.fields.surname)].filter(Boolean).join(" ") || "details found"}.` }; }
      else n = { tone: "warn", text: "That barcode isn't a license barcode. Fill in the details yourself." };
    }
    if (mrz) {
      applyMrz(rc, mrz, { consensus });
      n = mrz.valid
        ? { tone: "ok", text: `Details read${consensus ? "" : " (check them)"}: ${fullName(rc) || mrz.number}.` }
        : { tone: "warn", text: "Read only part of the details. Check them, or retake the photo." };
    }
    if (!n && (p.read.barcode || p.read.mrz)) n = { tone: "warn", text: p.read.barcode && !p.read.mrz ? "Couldn't read the barcode. Retake the back, or fill in the details yourself." : "Couldn't read the details from the photo. Retake it, or fill them in yourself." };
    if (!n) n = { tone: "ok", text: `${p.title} saved.` };
    setNote(n);
    redraw();
    const left = (PLAN[rc.kind] || PLAN.other).find((x) => !rc.images[x.side] && !rc.skipped?.includes(x.side));
    if (left && n.tone === "ok") {
      return () => { setSaved({ text: p.side === "front" ? "Front saved. Now turn it over." : `${p.title} saved.`, img }); setCam(left); };
    }
    return () => { setSaved(null); setCam(null); afterCapture(); };
  }

  function afterCapture() {
    const rc = rec.current;
    const left = (PLAN[rc.kind] || PLAN.other).find((p) => !rc.images[p.side] && !rc.skipped?.includes(p.side));
    if (left) { setStep("capture"); return; }
    // The chip step shows whenever this device has a chip reader, even one that's off
    // ("Turn on NFC"), and only until the chip has been read.
    setStep(KINDS[rc.kind]?.chip && nfc?.kind !== "none" && !rc.verified.chip ? "chip" : "review");
    setName(recordTitle(rc));
  }

  const chipOffered = () => KINDS[r?.kind]?.chip && nfc && nfc.kind !== "none" && !r?.verified.chip;

  /** One step back, keeping what's been captured: review → chip (if offered) or capture; chip → capture; capture → out. */
  const stepBack = () => {
    if (step === "review") { fields.current?.commit(); setStep(chipOffered() ? "chip" : "capture"); return; }
    if (step === "chip") { if (start.step === "chip" && !done.length) onExit(); else setStep("capture"); return; }
    onExit();
  };

  function skipSide(p) {
    setCam(null);
    const rc = rec.current;
    rc.skipped = [...(rc.skipped || []), p.side];
    redraw();
    afterCapture();
  }

  async function readChipNow() {
    const ok = await readChipInto(rec.current, access, { portrait: portraitImage });
    if (ok === "unverified") {
      setNote({ tone: "warn", text: "Chip couldn't be verified. Its data was not used. You can try again, or continue with the printed details, which will be marked as not verified." });
      return;
    }
    if (ok) {
      setNote({ tone: "ok", text: "Chip data integrity-checked. Its files match the chip's own list of hashes; the issuing country's signature isn't checked on this phone." });
      setName(recordTitle(rec.current));
      setStep("review");
      redraw();
    }
  }

  const retake = (p) => { fields.current?.commit(); setCam(p); };
  // the outline settles which way up a card is held; the print and the reads turn the rest, and this turns what is left
  const rotate = async (p) => {
    const img = rec.current.images[p.side];
    if (!img) return;
    try { setImage(rec.current, p.side, await turnedImage(img)); redraw(); }
    catch { toast("Couldn't turn that photo. Retake it instead.", "warn"); }
  };
  const toChip = () => { fields.current?.commit(); setStep("chip"); };
  const seal = (place) => { fields.current?.commit(); addIdRecord(rec.current, name || recordTitle(rec.current), place, { tags }); };
  const missing = step === "review" ? (fields.current?.missing?.() || []) : [];

  return (
    <>
      <Push eyebrow={kindLabel(r.kind)} title={step === "chip" ? "Read the ID chip" : step === "review" ? "Check the details" : "Scan it"} onBack={stepBack} busy={busy} label="Add an ID">
        {step === "capture" && (
          <>
            {note && <Note {...note} />}
            <Thumbs rec={r} plan={plan} onRetake={(p) => setCam(p)} onRotate={rotate} />
            {next && (
              <div class="banner" data-guide={r.kind} style={{ marginTop: note ? 12 : 0 }}><span class="b-ico"><Icon name="camera" /></span><div><strong>{next.title}</strong><span>{next.hint}</span></div></div>
            )}
            {next && <p class="small muted" style={{ marginTop: 12 }}>{LIGHT_TIP}</p>}
            {next && (
              <div class="actions">
                <button class="btn primary block" data-start-camera onClick={() => setCam(next)}><Icon name="camera" />{done.length ? `Start camera: the ${next.side}` : "Start camera"}</button>
                {next.optional && <button class="btn ghost block" onClick={() => skipSide(next)}>No {next.side} to scan</button>}
              </div>
            )}
          </>
        )}

        {step === "chip" && (
          <>
            {note && <Note {...note} />}
            <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="nfc" /></span>
              <div><strong>The ID chip holds the details and photo (integrity-checked on this phone)</strong><span>{nfc?.kind === "reader" ? "Place the document on the card reader when asked." : "Hold the top of your phone flat against the document when asked."} It takes about 10 seconds.</span></div></div>
            {nfc && !nfc.available && <div class="banner warn" style={{ marginTop: 10 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Can't read chips right now</strong><span>{nfc.reason}</span></div></div>}
            <ChipAccess onChange={setAccess} initial={chipAccessFrom(r)} title="Details that open the chip" note="They only open the chip. What it holds is sealed with this record." />
            <div class="actions">
              <button class="btn primary block" disabled={!access || !nfc?.available} onClick={readChipNow}><Icon name="nfc" />Read the ID chip</button>
              {nfc && !nfc.available && <button class="btn quiet block" onClick={async () => setNfc(await chipReader({ fresh: true }))}>Check again</button>}
              <button class="btn ghost block" onClick={() => setStep("review")}>Continue with the printed details (not verified)</button>
            </div>
          </>
        )}

        {step === "review" && (
          <Review kind="id" name={name} setName={setName} tags={tags} setTags={setTags}
            preview={<><IdProof rec={r} /><Thumbs rec={r} plan={plan} onRetake={retake} onRotate={rotate} />{chipOffered() && <button class="btn quiet block" style={{ marginTop: 12 }} onClick={toChip}><Icon name="nfc" />Also read the ID chip</button>}</>}
            note={note && <Note {...note} />}
            fields={<IdFields rec={r} api={fields} onChange={redraw} />}
            disabled={missing.length > 0}
            error={missing.length > 0 ? `Add the ${missing.map((k) => (k === "number" ? "document number" : "surname")).join(" and ")} before sealing.` : null}
            onSeal={seal}
            secondary={next ? { label: `Scan the ${next.side}`, onClick: () => retake(next) } : done.length ? { label: "Retake", onClick: () => retake(plan[0]) } : null}
            fine={`One check seals the details, photos${r.raw.chip ? " and the chip's signed data" : ""} together on this phone.`} />
        )}
      </Push>
      {cam && (
        <DocCamera key={`${cam.side}-${camRun.current.n}`} kind={r.kind} side={cam.side} shape={cam.shape} read={cam.read} eyebrow={kindLabel(r.kind)} title={cam.title} hint={cam.hint} native={r.kind === "other"}
          saved={saved} onCancel={() => { setSaved(null); setCam(null); }} onSkip={cam.optional ? () => { setSaved(null); skipSide(cam); } : null} onDone={(res) => captured(cam, res)} />
      )}
    </>
  );
}

/** What opens the chip, from the details read so far (ChipAccess takes ISO dates). */
const chipAccessFrom = (r) => ({ number: r.fields.number || "", birth: r.fields.birth || "", expiry: r.fields.expiry || "" });

function Note({ tone, text }) {
  return <div class={`banner ${tone === "warn" ? "warn" : ""}`} role="status" style={{ marginTop: 4 }}><span class="b-ico"><Icon name={tone === "warn" ? "info" : "check"} /></span><div><span>{text}</span></div></div>;
}

/** A photo of a record turned a quarter clockwise, re-encoded: the Rotate control, for the rare card the outline couldn't tell the way up of. */
export async function turnedImage(img) {
  const c = await fileToCanvas(new Blob([imageBytes(img)], { type: img.type }), 3200);
  return jpeg(rotateCanvas(c, 90), { maxW: 1600 });
}

function Thumbs({ rec, plan, onRetake, onRotate }) {
  const sides = [...plan.map((p) => p.side), ...(rec.images.portrait ? ["portrait"] : [])];
  return (
    <div class="id-thumbs">
      {sides.map((side) => {
        const img = rec.images[side];
        const p = plan.find((x) => x.side === side);
        return (
          <figure data-shape={side === "portrait" ? "portrait" : p?.shape}>
            {img ? <img src={imageUrl(img)} alt={`${side} of the document`} /> : <span class="empty-thumb">{rec.skipped?.includes(side) ? "Skipped" : "Not yet"}</span>}
            <figcaption>{side === "portrait" ? "Chip photo" : side === "front" ? "Front" : "Back"}{img && p && <span class="id-thumb-acts">{onRotate && <button class="linklike" aria-label={`Rotate the ${side}`} onClick={() => onRotate(p)}>Rotate</button>}<button class="linklike" onClick={() => onRetake(p)}>Retake</button></span>}</figcaption>
          </figure>
        );
      })}
    </div>
  );
}

function IdProof({ rec }) {
  const p = provenance(rec);
  return <div class={`id-proof lvl-${p.level}`}><Icon name={p.level.startsWith("chip") ? "nfc" : p.level === "barcode" ? "barcode" : p.level.startsWith("mrz") ? "scan" : "pencil"} /><span>{p.text}</span></div>;
}

/* ---------------- check the details ---------------- */

/**
 * The ID's own fields on the review. `api.current` gets { commit, missing }: typed
 * changes go into the record before anything that leaves the form (sealing, a retake,
 * the chip), so nothing typed is lost.
 */
function IdFields({ rec, api, onChange }) {
  const [vals, setVals] = useState(() => Object.fromEntries(fieldsFor(rec.kind).map((f) => [f.key, rec.fields[f.key] ?? ""])));
  const [addr, setAddr] = useState(() => rec.address || { street: "", street2: "", city: "", region: "", postalCode: "", country: rec.fields.issuer || "" });
  const [more, setMore] = useState(false);
  const checks = rec.verified.mrz?.checks || {};
  const unsure = (k) => rec.source[k] === "mrz" && ((k === "number" && checks.number === false) || (k === "birth" && checks.birth === false) || (k === "expiry" && checks.expiry === false) || (k === "optional" && checks.optional === false));
  const set = (k) => (e) => setVals({ ...vals, [k]: e.currentTarget.type === "checkbox" ? e.currentTarget.checked : e.currentTarget.value });
  const fields = fieldsFor(rec.kind);
  const main = fields.filter((f) => !f.optional || vals[f.key] !== "" && vals[f.key] != null);
  const extra = fields.filter((f) => f.optional && (vals[f.key] === "" || vals[f.key] == null));
  const missing = () => (rec.kind === "other" ? [] : ["surname", "number"].filter((k) => !String(vals[k] || "").trim()));
  const commit = () => {
    const typed = Object.fromEntries(Object.entries(vals).map(([k, v]) => [k, typeof v === "string" ? v.trim() : v]).filter(([k, v]) => (rec.fields[k] ?? "") !== (v ?? "")));
    applyTyped(rec, typed);
    const a = Object.fromEntries(Object.entries(addr).map(([k, v]) => [k, String(v || "").trim()]));
    if (Object.values(a).some(Boolean) && JSON.stringify(a) !== JSON.stringify(rec.address || {})) { rec.address = a; rec.addressSource = "typed"; }
    onChange();
  };
  api.current = { commit, missing };
  useEffect(() => { onChange(); }, [vals.surname, vals.number]); // the Seal button follows what's typed

  return (
    <div class="id-form">
      {main.map((f) => <FieldInput f={f} value={vals[f.key]} onInput={set(f.key)} source={rec.source[f.key]} unsure={unsure(f.key)} />)}
      {rec.kind !== "passport" && (rec.address || rec.kind === "driver_license" || rec.kind === "id_card") && (
        <fieldset class="id-addr">
          <legend>Address</legend>
          <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="Street" placeholder="Street" value={addr.street} onInput={(e) => setAddr({ ...addr, street: e.currentTarget.value })} />
          <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="Apartment, suite" placeholder="Apartment, suite (optional)" value={addr.street2} onInput={(e) => setAddr({ ...addr, street2: e.currentTarget.value })} />
          <div class="split3">
            <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="City" placeholder="City" value={addr.city} onInput={(e) => setAddr({ ...addr, city: e.currentTarget.value })} />
            <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="State" placeholder="State" maxLength={3} class="up" value={addr.region} onInput={(e) => setAddr({ ...addr, region: e.currentTarget.value.toUpperCase() })} />
            <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="ZIP or postal code" placeholder="ZIP" value={addr.postalCode} onInput={(e) => setAddr({ ...addr, postalCode: e.currentTarget.value })} />
          </div>
        </fieldset>
      )}
      {extra.length > 0 && !more && <button class="linklike" style={{ marginTop: 12 }} onClick={() => setMore(true)}>Add more details ({extra.map((f) => f.label.toLowerCase()).slice(0, 3).join(", ")}…)</button>}
      {more && extra.map((f) => <FieldInput f={f} value={vals[f.key]} onInput={set(f.key)} source={null} />)}
    </div>
  );
}

function FieldInput({ f, value, onInput, source, unsure }) {
  const id = `idf-${f.key}`;
  const tag = source && <span class={`src src-${source}`} title={`From the ${SOURCE[source] || source}`}>{SOURCE[source] || source}</span>;
  let input;
  if (f.type === "date") input = <input id={id} type="date" value={value || ""} onInput={onInput} />;
  else if (f.type === "sex") input = (
    <select id={id} value={value || ""} onChange={onInput}><option value="">—</option><option value="F">Female</option><option value="M">Male</option><option value="X">Unspecified (X)</option></select>
  );
  else if (f.type === "bool") input = <label class="check"><input id={id} type="checkbox" checked={value === true} onChange={onInput} /><span>Yes</span></label>;
  else input = <input autocorrect="off" id={id} class={f.mono ? "mono up" : f.type === "country" || f.type === "region" ? "up" : ""} value={value ?? ""} onInput={onInput} autocomplete="off" spellcheck={false}
    maxLength={f.type === "country" ? 3 : f.type === "region" ? 3 : 80} />;
  const hint = f.type === "country" && value ? countryName(value) : f.type === "region" && value ? regionName(value) : null;
  return (
    <div class={`field id-field${unsure ? " unsure" : ""}`}>
      <label for={id}>{f.label}{tag}</label>
      {input}
      {unsure ? <span class="hint warn">Check this against the document: its check digit didn't agree.</span> : hint && hint !== value ? <span class="hint">{hint}</span> : null}
    </div>
  );
}

/* ---------------- a sealed ID, opened ---------------- */

const fmtDay = (iso) => {
  if (!iso) return "";
  const d = new Date(`${iso}T12:00:00Z`);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
};

export function IdView({ record: rec, item }) {
  const [side, setSide] = useState(rec.images.front ? "front" : rec.images.portrait ? "portrait" : "back");
  const st = idStatus(rec, new Date(), S.prefs.value.expiryWarnDays);
  const p = provenance(rec);
  const rows = fieldsFor(rec.kind).filter((f) => rec.fields[f.key] !== undefined && rec.fields[f.key] !== "" && rec.fields[f.key] !== null);
  const show = (f) => {
    const v = rec.fields[f.key];
    if (f.type === "date") return fmtDay(v);
    if (f.type === "country") return `${countryName(v)}${countryName(v) !== v ? ` (${v})` : ""}`;
    if (f.type === "region") return regionName(v);
    if (f.type === "bool") return v ? "Yes" : "No";
    if (f.type === "sex") return { M: "Male", F: "Female", X: "Unspecified" }[v] || v;
    if (f.key === "surname" || f.key === "given") return niceName(v);
    return String(v);
  };
  const sides = ["front", "back", "portrait"].filter((s) => rec.images[s]);
  return (
    <div class="id-view">
      <div class="id-card-hero">
        {rec.images[side] && <img src={imageUrl(rec.images[side])} alt={`${side === "portrait" ? "Photo from the chip" : `${side} of the document`}`} data-side={side} />}
        {sides.length > 1 && (
          <div class="cats" role="tablist" style={{ justifyContent: "center", marginTop: 10 }}>
            {sides.map((s) => <button role="tab" aria-pressed={side === s} onClick={() => setSide(s)}>{s === "portrait" ? "Chip photo" : s === "front" ? "Front" : "Back"}</button>)}
          </div>
        )}
      </div>
      <h2 style={{ marginTop: 14 }}>{fullName(rec) || recordTitle(rec)}</h2>
      <div class="id-badges">
        <span class={`pill ${st.state === "expired" ? "danger" : st.state === "expiring" ? "amber" : st.state === "valid" ? "mint" : ""}`}>
          <Icon name="clock" />{st.state === "expired" ? `Expired ${fmtDay(rec.fields.expiry)}` : st.state === "expiring" ? `Expires in ${st.days} days` : st.state === "valid" ? `Valid to ${fmtDay(rec.fields.expiry)}` : "No expiry date"}
        </span>
        <span class={`pill ${p.level === "barcode" || p.level === "mrz" ? "mint" : ""}`}><Icon name={p.level.startsWith("chip") ? "nfc" : p.level === "barcode" ? "barcode" : p.level.startsWith("mrz") ? "scan" : "pencil"} />{p.level === "chip-edited" ? "Chip, edited" : p.level === "chip" ? "Chip data integrity-checked" : p.level.startsWith("chip") ? "Not verified" : p.level === "mrz-unverified" ? "Not verified" : p.level === "barcode" ? "From the barcode" : p.level.startsWith("mrz") ? "Scanned from the document" : "Typed"}</span>
      </div>
      <div class="card" style={{ marginTop: 14 }}>
        {rows.map((f) => (
          <div class="row">
            <span class="k">{f.label}</span>
            <span class={`v${f.mono ? " mono" : ""}`}>{show(f)}</span>
          </div>
        ))}
        {rec.address && (
          <div class="row"><span class="k">Address</span><span class="v">{[rec.address.street, rec.address.street2].filter(Boolean).join(", ")}<br />{[rec.address.city, [rec.address.region, rec.address.postalCode].filter(Boolean).join(" ")].filter(Boolean).join(", ")}</span></div>
        )}
      </div>
      <p class="fine" style={{ marginTop: 12 }}>{p.text}.{rec.edited?.length ? ` You edited: ${rec.edited.map((k) => fieldsFor(rec.kind).find((f) => f.key === k)?.label.toLowerCase() || k).join(", ")}.` : ""}</p>
      {rec.raw?.mrz && <details class="pass-back" style={{ marginTop: 12 }}><summary>Details</summary><pre class="mrz-lines" aria-label="The lines read from the document">{rec.raw.mrz.join("\n")}</pre></details>}
      <div class="actions"><button class="btn quiet block" onClick={() => saveCopy(item)}><Icon name="download" />Save a copy (JSON with photos)</button></div>
    </div>
  );
}
