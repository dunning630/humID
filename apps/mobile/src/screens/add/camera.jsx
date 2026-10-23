// The document camera (3.0.3 rebuild). What it is for: a person holds a card, a license, a
// passport page or a sheet of paper up to the phone, and at every moment can see that the
// camera sees it, what to change, when the picture is taken, and what was read from it.
//
//   The frame        a fixed outline at the document's real proportions (core/guide.js), so the
//                    crop never moves; inside it a lock box follows the document the camera
//                    actually sees (four edges and an angle, eased: core/capture.js docBox) and
//                    settles onto the frame when it is lined up. A ring round the frame fills as
//                    it holds still.
//   The panel        right under the frame, where the eyes already are: one instruction, a row
//                    of live chips (Framed · Sharp · Steady · Light · Barcode), and the way
//                    forward. core/capture.js decides what it says.
//   Reading live     a license's barcode and a passport's lines are read from the live view as
//                    soon as they are in the frame (a worker reads the barcode; the MRZ reader
//                    has its own), so the photo is taken the moment the details are in, not
//                    before and not by guesswork. A license front that turns out to be the
//                    back (its barcode reads) is kept as the back.
//   The capture      a still at the sensor's resolution where the phone offers one
//                    (core/guidecap.js), cut to the frame; it freezes in the frame with a flash,
//                    then the panel lists what was read (name, date of birth, number, expiry)
//                    before moving on, or says plainly what's missing with Try again / Keep.
//   Focus            tap the picture to focus there; a blur that lasts while lined up asks the
//                    camera to focus again by itself.
//
// Photo (shape "full") has no outline: the camera finds a document anywhere in view
// (core/docfind.js, in a worker) and takes it once it holds still; same panel.
//
// Nothing is logged or kept: frames live in memory until the crop is made. The stream is
// released the moment the screen is left or the app goes to the background.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { useModal } from "../../ui/kit.jsx";
import { markPicking, toast, buzz as buzzPref } from "../../core/index.js";
import {
  barcodeReader, mrzReader, frameInVideo, grab, imageData, imageBytes, imageUrl, jpeg, fileToCanvas, mrzBand, looksBlank,
  grayOf, cornersIn, develop as developPhoto, rotateCanvas, canvas as newCanvas, createAnalyzer, scanOptions,
} from "../../core/scan.js";
import { mrzBandLikely } from "../../core/addroute.js";
import { templateFor, liveConstraints, previewTurned, measure, judge, holdTracker, barcodeSignal, bottomBand, zoomFor, TH } from "../../core/guide.js";
import { grabWindow, takeStill, deskewOf, focusAt, fitDocument } from "../../core/guidecap.js";
import { confirmedByStill } from "../../core/mrzseed.js";
import { begin, step as stepFlow, view as viewOf, summarize, docBox, easeBox, verdictOf, pace, isLive } from "../../core/capture.js";
import { tracker, scaleQuad } from "../../core/docfind.js";
import { locateBarcodes, readBox, fromArea, barAngle } from "../../core/barcodefind.js";
import { parseAamva, MrzConsensus } from "@humid/idscan";
import { DEMO_BUILD } from "../../core/config.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- reading a still ---------------- */

/**
 * Read a still photo: the barcode (tried hard) and the MRZ from a few versions of the image,
 * voting. Returns { barcode, mrz, consensus, flipped } (flipped: the MRZ read only with the
 * photo turned 180°).
 *   seed   the live reader's MrzConsensus, when it has a valid reading: the still's own read
 *          then has to agree with it (core/mrzseed.js), so what is stored is checked against
 *          its own page.
 */
export async function readStill(c, read, shape, { tryFlip = false, seed = null } = {}) {
  const out = { barcode: null, mrz: null, consensus: false, flipped: false };
  if (read.barcode) {
    try {
      const bc = await barcodeReader();
      let other = null;
      for (const src of [...barcodeSpots(c), c]) {
        const texts = await bc.read(imageData(grab(src, null, 2400)));
        out.barcode = texts.find((t) => parseAamva(t)) || null;
        other ||= texts[0] || null;
        if (out.barcode) break;
      }
      out.barcode ||= other;
    } catch { /* reported as not found */ }
  }
  if (read.mrz && !(out.barcode && parseAamva(out.barcode))) {
    try {
      const ocr = await mrzReader();
      for (const turn of tryFlip ? [0, 180] : [0]) {
        const src = turn ? rotateCanvas(c, 180) : c;
        const vote = seed && !turn && seed.lastKey ? seed : new MrzConsensus();
        let mrz = null, stable = false;
        for (const opts of [{}, { threshold: true }, { scale: 1.3 }]) {
          const r = vote.add(await ocr.read(mrzBand(src, shape, opts)));
          if (r.result) mrz = r.result;
          if (confirmedByStill(r, vote === seed)) { stable = true; break; }
        }
        if (mrz || stable) { out.mrz = mrz || vote.reads.at(-1) || null; out.consensus = stable; out.flipped = !!turn; break; }
        if (!out.mrz) out.mrz = vote.reads.at(-1) || null;
      }
    } catch { /* reported as not found */ }
  }
  return out;
}

/** A photo of a record turned clockwise by `deg` (180 for a card: it stays landscape), re-encoded: the Rotate control. */
export async function turnedImage(img, deg = 90) {
  const c = await fileToCanvas(new Blob([imageBytes(img)], { type: img.type }), 3200);
  return jpeg(rotateCanvas(c, deg), { maxW: 1600 });
}

function enlarge(c, k) {
  if (k <= 1) return c;
  const out = newCanvas(c.width * k, c.height * k);
  const g = out.getContext("2d");
  g.imageSmoothingQuality = "high";
  g.drawImage(c, 0, 0, out.width, out.height);
  return out;
}

/** Part of a picture around a found barcode, turned so its bars stand upright and big enough to read. */
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

/** The barcode's part of a still, cut and turned for the reader (none found: nothing). */
function barcodeSpots(c) {
  try {
    const im = grayOf(c, 400), k = c.width / im.w;
    const spot = locateBarcodes(im).map((s) => ({ box: fromArea(s.box, { x: 0, y: 0 }, k), upright: s.upright }))[0];
    return spot ? [barcodeCrop(c, spot, c.width, c.height)] : [];
  } catch { return []; }
}

function frameRect(v, el) {
  const r = el ? frameInVideo(v, el, 0) : null;
  return r && r.w >= 64 && r.h >= 40 ? r : null;
}

/** A small JPEG of the photo just taken, to freeze in the frame while it is read. */
function freezeOf(c) {
  try { return grab(c, null, 720).toDataURL("image/jpeg", 0.72); } catch { return null; }
}

function cameraError(e) {
  if (e?.name === "NotAllowedError" || e?.name === "SecurityError") return "Camera access is off for HumID. Allow it in your phone's settings, or choose a photo instead.";
  if (e?.name === "NotFoundError" || e?.name === "OverconstrainedError") return "No camera found here. Choose a photo instead.";
  if (e?.name === "NotReadableError") return "Another app is using the camera. Close it and try again, or choose a photo instead.";
  return "The camera couldn't start. Choose a photo instead.";
}

/** The next moment worth looking at the camera: a new video frame or the next paint, never later than 300 ms. */
function nextFrame(v) {
  return new Promise((res) => {
    let done = false;
    const fin = () => { if (!done) { done = true; res(); } };
    setTimeout(fin, 300);
    try { if (typeof v?.requestVideoFrameCallback === "function") v.requestVideoFrameCallback(fin); else requestAnimationFrame(fin); } catch { fin(); }
  });
}

const buzz = () => buzzPref(14);
const cheer = () => buzzPref([16, 45, 26]);
const oops = () => buzzPref([40, 70, 40]);
const nudge = () => buzzPref(8);

/** How long the "Got it" panel stays before moving on (Continue moves on at once). */
const DONE_MS = 1300, DONE_PHOTO_MS = 700;
/** The details are in but the document isn't lined up for the photo: it's taken anyway after this. */
const READ_THEN_PHOTO_MS = 2500;
/** A blur that lasts this long while lined up asks the camera to focus again (not more often than every REFOCUS_EVERY). */
const REFOCUS_AFTER = 600, REFOCUS_EVERY = 1800;
/** The sharpest look of this last moment is what "sharp enough" is measured against (core/guide.js TH.sharpRel). */
const PEAK_MS = 1200;
/**
 * Still not sharp after this long while lined up (and nothing else wrong): the phone is probably too close to
 * focus. The frame gets smaller, so the document is held farther away (3.1.1). Once per camera.
 */
const TOO_CLOSE_MS = 2600;
/** The scan gives up looking (and saves the battery) after this; Try again starts it again. */
const GIVE_UP_MS = 40_000;
const NO_READER = "The reader couldn't start on this phone. Take the photo with the round button and type the details.";

/* ---------------- the camera ---------------- */

/**
 * Full-screen document camera.
 *   kind     what the document is ("driver_license", "passport", "id_card", "residence_permit", "other",
 *            "card" for a payment card, "page"): picks the outline (core/guide.js templateFor)
 *   side     "front" | "back"
 *   shape    "id1" (cards), "td3" (a passport's photo page), "page" (paper) or "full" (Photo: no outline)
 *   read     { barcode, mrz }: what this side gives, read live and from the still
 *   expect   "card": a payment card's number is read after the photo (by onDone); said as such
 *   mode     a core/scan.js scanOptions() mode, for shape/read/title/hint in one go
 *   onDone(result)   result { canvas, original, straightened, rotate, changed, barcode, mrz, consensus, how, side };
 *            may be async; returns a function to run once the camera has said "Got it" (it closes then), or
 *            { next, result: { ok, title, detail, fields, tone } } to have the camera say what was read
 *            (ok false: it offers Try again / Keep). A throw keeps the camera open with the reason.
 *   onCancel, onSkip   leave; skip this side
 *   saved    { text, img }: what the previous step kept, shown for a moment at the top
 *   extra    more ways forward on the panel ({ text, icon, onClick }, or a list): the payment card's "Type it"
 *   auto     take the photo by itself (default)
 */
export function DocCamera(props) {
  const preset = props.mode ? scanOptions(props.mode, { side: props.side }) : {};
  const { auto = true, eyebrow, saved, onDone, onCancel, onSkip, extra, kind = "other" } = props;
  const shape = props.shape ?? preset.shape ?? "id1", read = props.read ?? preset.read ?? {}, title = props.title ?? preset.title, hint = props.hint ?? preset.hint ?? "";
  const side = props.side ?? preset.side ?? "front";
  const guided = shape !== "full";
  const tpl = useMemo(() => (guided ? templateFor({ kind, side, shape, read }) : null), []);
  const want = read.barcode ? "barcode" : read.mrz ? "mrz" : props.expect === "card" || props.expect === "cvv" ? props.expect : null;
  // a license or state ID's front: if its barcode is what's in view, it's the back, and it's read and kept as the back
  const spotBack = side === "front" && (kind === "driver_license" || kind === "id_card") && !read.barcode;
  const noun = tpl?.noun || "document";

  const video = useRef(null), frame = useRef(null), file = useRef(null), root = useRef(null);
  // The camera is a modal layer of its own (APP-12): it opens over, and beside, a pushed screen.
  useModal(root);
  const [flow, setFlow] = useState(() => begin({ expect: want }));
  const [box, setBox] = useState(null);           // the lock box, in shares of the frame
  const [freeze, setFreeze] = useState(null);     // the photo just taken, shown in the frame
  const [flash, setFlash] = useState(0);
  const [torch, setTorch] = useState(null);       // null: the phone has no light to offer
  const [tapAt, setTapAt] = useState(null);       // where the picture was tapped to focus
  const [size, setSize] = useState(null);         // the frame's size on screen, for the ring
  const [far, setFar] = useState(false);          // the frame made smaller: the phone was too close to focus
  const [toldSaved, setToldSaved] = useState(!!saved);
  const L = useRef({
    stop: false, done: false, busy: false, stream: null, track: null, running: new Set(), flow: null, an: null,
    hold: null, prev: null, peaks: [], blurSince: 0, focusedAt: 0, codeBusy: false, codeDone: null, zoom: 1, far: false, farAt: 0, prevAt: 0,
    consensus: null, barTries: 0, misses: 0, firePending: false, wasAligned: false, box: null, guideNow: null, startedAt: 0, pendingKeep: null,
  }).current;
  L.flow ||= flow;

  const send = (ev) => {
    const next = stepFlow(L.flow, ev, Date.now());
    if (next === L.flow) return;
    L.flow = next;
    setFlow(next);
  };
  const trace = (name, x) => { if (DEMO_BUILD) { const t = (globalThis.__humidTrace ||= { ev: [] }); t.ev.push([name, Math.round(performance.now()), x]); } };

  useEffect(() => { if (!saved) return; const t = setTimeout(() => setToldSaved(false), 2600); return () => clearTimeout(t); }, []);
  useLayoutEffect(() => {
    const el = frame.current;
    if (!el || typeof ResizeObserver !== "function") return;
    const ro = new ResizeObserver(() => { const r = el.getBoundingClientRect(); setSize({ w: r.width, h: r.height }); });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const stopStream = () => {
    L.stream?.getTracks().forEach((t) => t.stop());
    L.stream = null; L.track = null;
    if (video.current) video.current.srcObject = null;
  };
  const inactive = () => L.stop || L.busy || !video.current || video.current.readyState < 2 || !video.current.videoWidth;

  /* ---------------- starting and stopping ---------------- */

  useEffect(() => {
    trace("mount");
    L.consensus = new MrzConsensus();
    L.hold = holdTracker();
    // the readers this side needs start loading now, beside the camera
    if (read.mrz) mrzReader().catch(() => {});
    if (read.barcode || spotBack || !guided) {
      L.an = createAnalyzer({ shape: guided ? "full" : shape, bar: !!(read.barcode || spotBack) });
      L.an.warm();
      if (L.an.where === "main" && (read.barcode || spotBack)) barcodeReader().catch(() => {});
    }
    startCamera();
    // Leaving the screen frees the camera at once (the track, not only the loop). Choosing a photo
    // hides the app too: the camera stops and starts again on return if no photo was chosen.
    const away = () => {
      if (!document.hidden) {
        if (L.pickedAway) { L.pickedAway = false; setTimeout(() => { if (!L.busy && !L.stream) { L.stop = false; startCamera(); } }, 700); }
        return;
      }
      L.stop = true; stopStream();
      if (L.picking) { L.pickedAway = true; return; }
      onCancel?.();
    };
    const gone = () => { L.stop = true; stopStream(); };
    document.addEventListener("visibilitychange", away);
    addEventListener("pagehide", gone);
    return () => {
      L.stop = true; L.an?.close(); stopStream();
      document.removeEventListener("visibilitychange", away); removeEventListener("pagehide", gone);
    };
  }, []);

  function startCamera() {
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("no camera"), { name: "NotFoundError" });
        // The long side only, never a crop: a width AND a height make a browser cut the frame to that shape
        // (a portrait phone asked for 1920×1080 gets a square). 1080p for cards and pages, 1440p for a
        // passport's small print; Photo the same 1080p at a modest frame rate. Not 4K (PERF-03).
        const portrait = () => innerHeight >= innerWidth;
        const ask = guided ? liveConstraints(tpl, { portrait: portrait() }) : { width: { ideal: 1920 }, frameRate: { ideal: 24, max: 30 }, resizeMode: "none" };
        const stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: "environment" }, ...ask } });
        if (L.stop) { stream.getTracks().forEach((t) => t.stop()); return; }
        L.stream = stream;
        L.track = stream.getVideoTracks()[0];
        try { await L.track.applyConstraints({ advanced: [{ focusMode: "continuous" }] }); } catch { /* not offered */ }
        try { await L.track.applyConstraints({ advanced: [{ exposureMode: "continuous" }] }); } catch { /* not offered */ }
        let caps = {};
        try { caps = L.track.getCapabilities?.() || {}; } catch { /* not offered */ }
        if (caps.torch) setTorch(false);
        // zoomed in, a card fills the frame from about 25 cm: far enough for the camera to focus (core/guide.js zoomFor)
        const z = guided ? zoomFor(tpl, caps) : 1;
        if (z > 1) { try { await L.track.applyConstraints({ advanced: [{ zoom: z }] }); L.zoom = z; } catch { /* not offered */ } }
        if (DEMO_BUILD) globalThis.__humidZoom = L.zoom;
        video.current.srcObject = stream;
        await video.current.play().catch(() => {});
        // a preview that came back turned the wrong way for the screen leaves the frame a third of the pixels: ask once more
        if (guided && previewTurned(video.current.videoWidth, video.current.videoHeight, portrait())) {
          const w = liveConstraints(tpl, { portrait: portrait(), exact: true });
          try { await L.track.applyConstraints({ width: w.width, height: w.height }); await sleep(250); } catch { /* the first size stays */ }
        }
        trace("camera");
        // focus where the document will be, from the start (where the phone lets a page say so)
        if (guided && frame.current) { const r = frameRect(video.current, frame.current); if (r) focusAt(L.track, centreOf(r, video.current), { once: false }).catch(() => {}); }
        L.startedAt = Date.now();
        send({ t: "ready" });
        loop();
      } catch (e) { send({ t: "error", message: cameraError(e) }); }
    })();
  }

  function loop() {
    const name = guided ? "guide" : "photo";
    if (L.running.has(name) || L.stop) return;
    L.running.add(name);
    (guided ? guideLoop() : photoLoop())
      .catch(() => { if (DEMO_BUILD) globalThis.__humidLoopStopped = name; }) // development builds record which loop stopped (a name, never a picture)
      .finally(() => L.running.delete(name));
  }

  /** The time budget, folded into the look loop. Past GIVE_UP_MS the loop stops until Try again. */
  function tick(now) {
    send({ t: "tick" });
    if (now - L.startedAt > GIVE_UP_MS && isLive(L.flow)) {
      L.stop = true;
      send({ t: "fail", result: { title: "This is taking a while", detail: "Try again, or take the photo yourself with the round button.", keep: false } });
      oops();
      return true;
    }
    return false;
  }

  /* ---------------- the guided loop: documents with a known shape ---------------- */

  async function guideLoop() {
    const needBar = !!(read.barcode || tpl?.forbid?.barcode || spotBack);
    let lastMs = 0;
    while (!L.stop) {
      await sleep(pace(lastMs, { min: 80, max: 260 }));
      const v = video.current;
      await nextFrame(v);
      if (document.hidden) { await sleep(400); continue; }
      const now = Date.now();
      if (tick(now)) return;
      if (inactive()) { L.prev = null; continue; }
      const rect = frameRect(v, frame.current);
      if (!rect) continue;
      const t0 = performance.now();
      let got, m, verdict, extra, spots = null;
      try {
        got = grabWindow(v, rect);
        m = measure(got.im, got.win.guide, { prev: L.prev && L.prev.w === got.im.w ? L.prev : null });
        // movement per 150 ms, so a slow phone (looks far apart) isn't called shakier than a fast one
        if (m.motion != null && L.prevAt) m.motion *= Math.max(0.6, Math.min(1.6, 150 / Math.max(60, now - L.prevAt)));
        L.prev = got.im; L.prevAt = now;
        // the sharpest look of the last moment, while lined up: the photo waits for a frame near it
        L.peaks = L.peaks.filter((p) => now - p.t < PEAK_MS);
        extra = { bestFocus: L.peaks.reduce((x, p) => Math.max(x, p.f), 0) };
        if (needBar) { spots = locateBarcodes(got.im); extra.barcode = barcodeSignal(spots, got.win.guide); }
        if (read.mrz) extra.mrz = mrzBandLikely(bottomBand(got.im, got.win.guide));
        verdict = judge(m, tpl, extra);
      } catch { await sleep(150); continue; }
      lastMs = performance.now() - t0;
      if (inactive()) continue;
      if (verdict.aligned && m.focus) L.peaks.push({ t: now, f: m.focus });
      const ready = verdict.ready;
      const h = L.hold.feed(ready, now);

      // focus: a blur that lasts while lined up asks the camera to focus on the frame again; one that lasts
      // longer means the phone is too close to focus: the frame gets smaller, so it's held farther away
      const blurred = verdict.aligned && verdict.sharp === false && (m.focus ?? 1) < TH.sharp;
      L.blurSince = blurred ? L.blurSince || now : 0;
      if (blurred && now - L.blurSince > REFOCUS_AFTER && now - L.focusedAt > REFOCUS_EVERY) { L.focusedAt = now; focusAt(L.track, centreOf(rect, v)).catch(() => {}); trace("refocus"); }
      if (blurred && !L.far && shape !== "page" && now - L.blurSince > TOO_CLOSE_MS) {
        L.far = true; L.farAt = now; L.blurSince = 0; L.peaks = []; L.prev = null; L.hold.reset(); L.box = null;
        setFar(true); nudge(); trace("too-close");
        continue; // the frame moves: the next look measures the smaller one
      }

      // read what's there to read, as soon as it's in view
      const bar = extra.barcode;
      if (!L.codeDone && !L.codeBusy) {
        if (bar && (read.barcode || spotBack)) readBarLive(v, got.win, bar);
        else if (read.mrz && !bar && verdict.present && ((m.scale ?? 0) > 0.75 || extra.mrz)) readMrzLive(v, rect);
      }
      const codeSeen = want === "barcode" ? !!bar : want === "mrz" ? !!extra.mrz : false;

      // the lock box: where the document is, eased; on the frame once lined up
      L.box = verdict.present && !verdict.unsure ? easeBox(L.box, verdict.aligned ? { x: 0, y: 0, w: 1, h: 1, rot: 0 } : docBox(m), 0.55) : null;
      setBox(L.box);
      L.guideNow = { rect, verdict, at: now };
      if (DEMO_BUILD) globalThis.__humidGuide = { far: L.far, zoom: L.zoom, peak: extra.bestFocus, key: verdict.key, present: verdict.present, aligned: verdict.aligned, ready, steady: verdict.steady, sharp: verdict.sharp, scale: m.scale, dx: m.dx, dy: m.dy, rot: m.rot, flatH: m.flatH, flatV: m.flatV, sides: m.sides, focus: m.focus, motion: m.motion, mean: m.mean, p95: m.p95, sat: m.sat, patch: m.patch, energy: m.energy, ms: Math.round(lastMs), rect, video: [v.videoWidth, v.videoHeight], box: L.box, extra: { bar: bar ? Math.round(bar.across * 100) / 100 : bar, mrz: extra.mrz } }; // development builds: what the guidance sees (numbers, never pictures)
      if (verdict.aligned && !L.wasAligned) nudge();
      L.wasAligned = verdict.aligned;
      // a license front showing its barcode is the back: say so, and it's read and kept as the back;
      // and just after the frame got smaller, why it did
      const said = spotBack && bar && verdict.key === "showfront" ? { ...verdict, detail: "That's the back. Hold still to keep it as the back, or turn it over." }
        : L.far && now - L.farAt < 6000 && (verdict.key === "back" || verdict.key === "shift") ? { ...verdict, key: "back", detail: `Too close for the camera to focus. Hold the phone farther away and fit the ${noun} in the smaller frame.` }
        : verdict;
      send({ t: "look", v: { ...said, ready }, progress: h.progress, codeSeen });

      // the photo: the moment the details are in (lined up, or after a short wait), or when it has held still
      if (L.stop) return;
      if (L.codeDone && (verdict.aligned || now - L.codeDone.at > READ_THEN_PHOTO_MS)) { capture("auto", L.codeDone); return; }
      if (h.fire || L.firePending) {
        if (want && L.codeBusy) { L.firePending = true; continue; } // a read is under way: let it finish first
        L.firePending = false;
        if (auto) { capture("auto"); return; }
      }
    }
  }

  /** The middle of the frame, as a share of the video: where to focus. */
  const centreOf = (rect, v) => ({ x: (rect.x + rect.w / 2) / v.videoWidth, y: (rect.y + rect.h / 2) / v.videoHeight });

  async function readBarcodes(img, harder) {
    const viaWorker = L.an ? await L.an.read(img, { harder }) : null;
    if (viaWorker) return viaWorker;
    const main = await (L.bcMain ||= barcodeReader().catch(() => null));
    if (!main) throw new Error("no reader");
    return main.read(img, { harder });
  }

  /** The barcode in view, read from the video at full size (one read at a time, in the worker). */
  async function readBarLive(v, win, sig) {
    L.codeBusy = true;
    if (want === "barcode") send({ t: "code", state: "reading" });
    try {
      const s = 1 / win.scale;
      const spot = { box: { x: win.src.x + sig.box.x * s, y: win.src.y + sig.box.y * s, w: sig.box.w * s, h: sig.box.h * s }, upright: sig.upright };
      const crop = barcodeCrop(v, spot, v.videoWidth, v.videoHeight, 1600);
      const texts = await readBarcodes(imageData(crop), ++L.barTries % 3 === 0);
      if (DEMO_BUILD) globalThis.__humidCode = { what: "barcode", n: (globalThis.__humidCode?.n || 0) + 1, texts: texts.length, w: crop.width };
      if (L.stop || L.busy) return;
      const text = texts.find((t) => parseAamva(t));
      if (text) {
        L.codeDone = { barcode: text, at: Date.now(), side: spotBack ? "back" : side };
        const sum = summarize(kind, { barcode: text }, "barcode");
        send({ t: "code", state: "read", fields: sum.fields });
        trace("bar-read");
      } else if (want === "barcode") send({ t: "code", state: texts.length ? "miss" : "seen" });
    } catch (e) {
      if (e?.message === "no reader") { L.noReader = true; send({ t: "code", state: "miss" }); toast(NO_READER, "warn"); }
    } finally { L.codeBusy = false; }
  }

  /** The lines of <<< in the frame, read from the video (several reads must agree, MrzConsensus). */
  async function readMrzLive(v, rect) {
    L.codeBusy = true;
    try {
      const ocr = await mrzReader().catch(() => null);
      if (!ocr) { if (!L.noReader) { L.noReader = true; toast(NO_READER, "warn"); } await sleep(1000); return; }
      const strip = mrzBand(grab(v, rect, 1800), shape);
      const res = L.consensus.add(await ocr.read(strip));
      if (DEMO_BUILD) globalThis.__humidCode = { what: "mrz", n: (globalThis.__humidCode?.n || 0) + 1, best: !!res.best, valid: !!res.result, stable: res.stable };
      if (L.stop || L.busy) return;
      if (res.stable) {
        L.codeDone = { mrz: res.result, consensus: true, at: Date.now(), side };
        send({ t: "code", state: "read", fields: summarize(kind, { mrz: res.result, consensus: true }, "mrz").fields });
        trace("mrz-read");
      } else if (res.best) send({ t: "code", state: "reading" });
    } catch { /* a bad frame: keep looking */ } finally { L.codeBusy = false; }
  }

  /* ---------------- the Photo loop: anything, found anywhere in view ---------------- */

  async function photoLoop() {
    const track = (L.tracker ||= tracker({ need: 4, hold: 900 }));
    let lastMs = 0, prevOk = false;
    while (!L.stop) {
      await sleep(pace(lastMs, { min: 70 }));
      const v = video.current;
      await nextFrame(v);
      if (document.hidden) { await sleep(400); continue; }
      const now = Date.now();
      if (tick(now)) return;
      if (inactive() || !auto) continue;
      const t0 = performance.now();
      let r;
      try { r = await L.an.look(v, { prior: track.quad }); } catch { await sleep(150); continue; }
      lastMs = performance.now() - t0;
      if (inactive()) continue;
      const t = track.feed(r.look, r.w, r.h);
      L.quad = t.quad ? scaleQuad(t.quad, r.k) : null;
      if (DEMO_BUILD) globalThis.__humidLook = { ...r.look, quad: L.quad, ms: Math.round(lastMs), where: L.an.where, vw: v.videoWidth, vh: v.videoHeight };
      const v1 = verdictOf({ ...r.look, found: !!t.quad });
      if (v1.aligned && !prevOk) nudge();
      prevOk = v1.aligned;
      send({ t: "look", v: v1, progress: track.progress });
      if (t.fire && !L.stop) { capture("auto"); return; }
    }
  }

  /* ---------------- taking, reading and keeping the photo ---------------- */

  /**
   * Develop a photo: a guided one is already the frame's crop (core/guidecap.js); a Photo is
   * straightened from the corners found in it (helped by the live ones).
   */
  function develop(original, how, { cropped = false } = {}) {
    if (cropped) {
      // the document itself, cut out of the frame's crop: no table round it, at its own proportions (3.1.1)
      const fit = fitDocument(original, { shape });
      if (DEMO_BUILD) globalThis.__humidFit = { how: fit.how, out: [fit.canvas.width, fit.canvas.height] };
      return { canvas: fit.canvas, uncut: original, fit: fit.how, original, straightened: true, rotate: 0, confidence: 1, changed: true };
    }
    const quad = cornersIn(original, { hint: how === "file" ? null : L.quad, shape: guided ? shape : "full" });
    let dev = developPhoto(original, quad, { shape: guided ? shape : "full" });
    if (guided && !dev.straightened && how !== "file") {
      const r = frameRect(video.current, frame.current);
      if (r) dev = { canvas: grab(original, r), original, straightened: false, rotate: 0, confidence: 0, changed: true };
    }
    return dev;
  }

  /** Take the photo (how: "auto" | "shutter"), with what the live reader already has (`known`). */
  async function capture(how, known = null) {
    const v = video.current;
    if (!v || L.done || L.busy) return;
    L.busy = true; L.stop = true;
    trace("capture-" + how);
    send({ t: "capture", how });
    buzz();
    setFlash((n) => n + 1);
    let res, still = null;
    try {
      let c = null;
      const rect = guided ? frameRect(v, frame.current) : null;
      const tilt = rect ? deskewOf(L.guideNow?.verdict?.deskew) : 0;
      for (let i = 0; i < 6 && !c; i++) {
        if (v.readyState >= 2 && v.videoWidth) {
          if (rect) { const st = await takeStill(v, L.track, rect, { tilt, photo: i === 0 }); if (!looksBlank(st.canvas)) { c = st.canvas; still = st; } }
          else { const got = grab(v, null); if (!looksBlank(got)) c = got; }
        }
        if (!c) await sleep(150);
      }
      if (!c) throw new Error("The camera gave a blank picture. Hold steady and try again.");
      const dev = develop(c, how, { cropped: !!rect });
      setFreeze(freezeOf(dev.canvas));
      res = await readAndSay(dev, how, known, still);
    } catch (e) {
      oops();
      resume(e?.message || "Couldn't take the photo. Try again.");
      return;
    }
    if (res) await keep(res);
  }

  /**
   * Read what a photo has to give (unless the live reader already did), and decide: keep it,
   * look again by itself (once, when it was taken by itself), or ask (Try again / Keep).
   * Returns the result to keep, or null when it isn't kept (yet).
   */
  async function readAndSay(dev, how, known, still = null) {
    let readOut = {};
    if (known?.barcode) readOut = { barcode: known.barcode };
    else if (known?.mrz) {
      // the live lines: checked against the photo's own (one or two passes; on disagreement they're kept for review)
      send({ t: "check", note: "Checking the lines against the photo…" });
      const st = await readStill(dev.canvas, { mrz: true }, shape, { seed: L.consensus });
      readOut = st.mrz?.valid && st.consensus ? { mrz: st.mrz, consensus: true } : { mrz: known.mrz, consensus: false };
    } else if (read.barcode || read.mrz) {
      send({ t: "check" });
      readOut = await readStill(dev.canvas, read, shape, { tryFlip: dev.straightened, seed: read.mrz ? L.consensus : null });
      // the cut-out didn't read: the frame's whole crop, in case the cut went wrong (what's kept is still the cut-out)
      if (!readOut.barcode && !readOut.mrz?.valid && dev.uncut) {
        const wide = await readStill(dev.uncut, read, shape, { tryFlip: true });
        if (wide.barcode || wide.mrz?.valid) readOut = { ...wide, flipped: false };
      }
      if (readOut.flipped) dev = { ...dev, canvas: rotateCanvas(dev.canvas, 180), rotate: (dev.rotate + 180) % 360, changed: true };
    }
    const sideNow = known?.side || side;
    const { flipped, ...codes } = readOut;
    if (DEMO_BUILD) globalThis.__humidDevelop = { how, fit: dev.fit, guided: !!still || guided, source: still?.source, stillW: still?.width, why: still?.why, turned: still?.turned, out: [dev.canvas.width, dev.canvas.height], straightened: dev.straightened, rotate: dev.rotate, confidence: dev.confidence, live: !!known, side: sideNow, png: globalThis.__humidKeepPng ? dev.canvas.toDataURL("image/png") : undefined };
    const result = { ...dev, ...codes, how, side: sideNow };
    const codeWant = read.barcode && read.mrz ? (codes.barcode ? "barcode" : codes.mrz ? "mrz" : "both") : want === "card" || want === "cvv" ? null : want;
    const sum = summarize(kind, codes, sideNow !== side && known?.barcode ? "barcode" : codeWant);
    if (sideNow !== side) { sum.title = "That was the back"; sum.detail = "Read from its barcode. Now the front."; }
    L.summary = sum;
    if (sum.ok) return result;
    // taken by itself and nothing read: look again, once, without asking
    if (how === "auto" && ++L.misses < 2) { resume(null); return null; }
    oops();
    L.pendingKeep = result;
    send({ t: "fail", result: sum });
    return null;
  }

  /** Hand the photo over (onDone), say what it gave, then move on. */
  async function keep(result) {
    L.busy = true; L.stop = true;
    send({ t: "check", note: want === "card" ? "Reading the card number…" : want === "cvv" ? "Reading the security code…" : "Saving…" });
    let ret;
    try { ret = await onDone(result); }
    catch (e) { oops(); L.pendingKeep = null; send({ t: "fail", result: { title: e?.title || "Couldn't keep that photo", detail: e?.message || "Try again.", keep: false } }); return; }
    const then = typeof ret === "function" ? ret : ret?.next; // not "then": an object with a then() is a promise to await
    const said = ret?.result || L.summary || { title: "Got it", detail: "Photo captured." };
    if (said.ok === false) {
      // the screen it goes to says the reading failed: offer Try again here first
      oops();
      L.pendingThen = then;
      send({ t: "fail", result: said });
      return;
    }
    L.done = true;
    trace("kept");
    cheer();
    send({ t: "done", result: { ...said, detail: said.detail || (result.side === "back" ? "The back is captured." : "Photo captured.") } });
    const wait = said.fields?.length ? DONE_MS : DONE_PHOTO_MS;
    L.next = () => { if (L.moved) return; L.moved = true; stopStream(); if (typeof then === "function") then(); };
    await sleep(wait);
    L.next();
  }

  /** Back to the live view (after a miss, or Try again). `why`: said in the panel's place for a moment. */
  function resume(why) {
    L.busy = false; L.done = false; L.stop = false; L.codeDone = null; L.codeBusy = false; L.firePending = false;
    L.pendingKeep = null; L.pendingThen = null; L.peaks = []; L.prev = null; L.prevAt = 0; L.blurSince = 0;
    L.hold.reset(); L.consensus.reset(); L.tracker?.reset(); L.box = null;
    L.startedAt = Date.now();
    setFreeze(null); setBox(null);
    send({ t: "retry" });
    if (why) toast(why, "warn");
    if (L.stream) loop(); else startCamera(); // the camera stopped meanwhile (a photo was chosen): start it again
  }

  function retry() { L.misses = 0; resume(null); }
  async function keepAnyway() {
    if (L.pendingThen) { const then = L.pendingThen; L.pendingThen = null; L.done = true; send({ t: "done", result: { title: "Kept", detail: "Fill in the details on the next screen.", tone: "ok" } }); await sleep(DONE_PHOTO_MS); stopStream(); then(); return; }
    const r = L.pendingKeep;
    if (!r) return;
    L.pendingKeep = null;
    L.summary = { title: "Photo kept", detail: "Fill in the details on the next screen.", fields: [] };
    await keep(r);
  }

  async function onFile(e) {
    L.picking = false; L.pickedAway = false;
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    if (!f) return;
    L.busy = true; L.stop = true;
    send({ t: "capture", how: "file" });
    try {
      const c = await fileToCanvas(f);
      setFreeze(freezeOf(c));
      const res = await readAndSay(develop(c, "file"), "file");
      if (res) await keep(res);
    } catch {
      toast("That file isn't a photo HumID can open.", "warn");
      resume(null);
    }
  }

  async function toggleTorch() {
    try { await L.track.applyConstraints({ advanced: [{ torch: !torch }] }); setTorch(!torch); } catch { setTorch(null); }
  }

  /** Tap the picture: focus there (where the phone allows it), with a ring where it was tapped. */
  function tapFocus(e) {
    const v = video.current;
    if (!v?.videoWidth || !L.track || !isLive(L.flow)) return;
    const vr = v.getBoundingClientRect();
    const s = Math.max(vr.width / v.videoWidth, vr.height / v.videoHeight);
    const ox = (vr.width - v.videoWidth * s) / 2, oy = (vr.height - v.videoHeight * s) / 2;
    const x = (e.clientX - vr.left - ox) / s / v.videoWidth, y = (e.clientY - vr.top - oy) / s / v.videoHeight;
    if (x < 0 || x > 1 || y < 0 || y > 1) return;
    L.focusedAt = Date.now();
    setTapAt({ x: e.clientX - vr.left, y: e.clientY - vr.top, n: Date.now() });
    focusAt(L.track, { x, y }).catch(() => {});
  }
  useEffect(() => { if (!tapAt) return; const t = setTimeout(() => setTapAt(null), 900); return () => clearTimeout(t); }, [tapAt]);

  const cancel = () => { L.stop = true; stopStream(); onCancel(); };
  const skip = () => { L.stop = true; stopStream(); onSkip(); };

  /* ---------------- drawing ---------------- */

  const vw = viewOf(flow, { noun, hint, torch: torch != null, guided });
  const live = isLive(flow);
  const aligned = live && flow.chips.framed === "ok";
  const frameState = flow.phase === "capture" || flow.phase === "check" || flow.phase === "done" ? "ok" : flow.phase === "fail" ? "close" : !live ? undefined : aligned || flow.code?.state === "read" ? "ok" : box || flow.chips.framed === "warn" ? "close" : "searching";
  const zones = guided ? tpl.zones.filter((z) => z.k !== "line") : [];
  const ring = size && guided && vw.progress != null && vw.progress > 0 ? ringPath(size.w, size.h, guided && shape === "page" ? 6 : 14) : null;
  const extras = [].concat(extra || []);

  const panel = (
    <div class="dc-panel" data-tone={vw.tone} data-phase={flow.phase}>
      <div class="dc-say">
        <span class="dc-ico" data-spin={vw.tone === "busy" ? "1" : undefined}><Icon name={vw.icon} /></span>
        <div class="dc-words" role="status" aria-atomic="true" aria-live={flow.phase === "fail" || flow.phase === "error" ? "assertive" : "polite"}>
          <strong>{vw.headline}</strong>
          {vw.detail && <span>{vw.detail}</span>}
          {vw.fields?.length > 0 && <span class="sr">{vw.fields.map((f) => `${f.label}: ${f.value}.`).join(" ")}</span>}
        </div>
      </div>
      {vw.chips.length > 0 && (
        <ul class="dc-chips" aria-hidden="true">
          {vw.chips.map((c) => <li data-k={c.k} data-state={c.state}><i />{c.label}</li>)}
        </ul>
      )}
      {vw.fields?.length > 0 && (
        <dl class="dc-fields">
          {vw.fields.map((f) => <div><dt>{f.label}</dt><dd>{f.value}</dd></div>)}
        </dl>
      )}
      {(vw.actions.length > 0 || (live && extras.length > 0)) && (
        <div class="dc-actions">
          {vw.actions.includes("light") && <button type="button" class="dc-act" onClick={toggleTorch} aria-pressed={!!torch}><Icon name="torch" />{torch ? "Light off" : "Light on"}</button>}
          {vw.actions.includes("retry") && <button type="button" class="dc-act primary" onClick={retry}><Icon name="rotate" />Try again</button>}
          {vw.actions.includes("keep") && <button type="button" class="dc-act" onClick={keepAnyway}><Icon name="check" />Keep the photo</button>}
          {vw.actions.includes("continue") && <button type="button" class="dc-act primary" onClick={() => L.next?.()}><Icon name="chevron" />Continue</button>}
          {live && extras.map((x) => <button type="button" class="dc-act" onClick={x.onClick}><Icon name={x.icon || "file"} />{x.text}</button>)}
        </div>
      )}
    </div>
  );

  return (
    <div class="doccam" ref={root} role="dialog" aria-modal="true" aria-label={title} data-guided={guided ? "1" : undefined} data-phase={flow.phase} data-shape={shape} data-look={frameState} data-tone={vw.tone}>
      <video ref={video} playsInline muted autoplay onPointerDown={tapFocus} />
      <div class="dc-stage">
        <div class="dc-frame" data-shape={shape} data-template={tpl?.id} data-state={frameState} data-far={far ? "1" : undefined} ref={frame}>
          <i class="c tl" /><i class="c tr" /><i class="c bl" /><i class="c br" />
          {zones.map((z) => <span class="dc-zone" data-k={z.k} data-read={(z.k === "bar" || z.k === "mrz") && flow.code?.state === "read" ? "1" : undefined} aria-hidden="true" style={{ left: `${z.x}%`, top: `${z.y}%`, width: `${z.w}%`, height: `${z.h}%` }} />)}
          {box && live && !aligned && <span class="dc-lock" aria-hidden="true" style={{ left: `${box.x * 100}%`, top: `${box.y * 100}%`, width: `${box.w * 100}%`, height: `${box.h * 100}%`, transform: `rotate(${box.rot.toFixed(1)}deg)` }} />}
          {ring && <svg class="dc-ring" aria-hidden="true" viewBox={`0 0 ${size.w} ${size.h}`}><path d={ring.d} pathLength="100" style={{ strokeDasharray: `${Math.round(vw.progress * 100)} 100` }} /></svg>}
          <span class="dc-clip" aria-hidden="true">
            {freeze && <img class="dc-freeze" src={freeze} alt="" />}
            {flash > 0 && <span class="dc-flash" key={flash} />}
            {(flow.phase === "check" || flow.phase === "capture") && <span class="dc-sweep"><i /></span>}
          </span>
          {flow.phase === "done" && <span class="dc-stamp" aria-hidden="true"><Icon name="check" /></span>}
          {guided && panel}
        </div>
        {tapAt && <span class="dc-focus" key={tapAt.n} aria-hidden="true" style={{ left: `${tapAt.x}px`, top: `${tapAt.y}px` }} />}
      </div>
      {!guided && panel}
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
      <footer class="dc-bottom">
        <button class="dc-side" disabled={!live && flow.phase !== "error" && flow.phase !== "fail"} onClick={() => { L.picking = true; markPicking(); file.current.click(); }}><Icon name="image" /><span>Photo</span></button>
        <button class="dc-shutter" aria-label="Take the photo" data-offer={vw.offer ? "1" : undefined} disabled={!(live || (flow.phase === "fail" && L.stream && !L.pendingKeep && !L.pendingThen))} onClick={() => { if (flow.phase === "fail") resume(null); capture("shutter"); }}><i /></button>
        {onSkip ? <button class="dc-side" onClick={skip}><Icon name="chevron" /><span>Skip</span></button> : <span class="dc-side" aria-hidden="true" />}
      </footer>
      <input ref={file} type="file" accept="image/*" hidden onChange={onFile} />
    </div>
  );
}

/** A rounded rectangle's outline, starting at the top middle and going clockwise: the hold ring. */
function ringPath(w, h, r) {
  const x0 = 1.5, y0 = 1.5, x1 = w - 1.5, y1 = h - 1.5, rr = Math.min(r, (x1 - x0) / 2, (y1 - y0) / 2), cx = w / 2;
  return { d: `M${cx},${y0} H${x1 - rr} A${rr},${rr} 0 0 1 ${x1},${y0 + rr} V${y1 - rr} A${rr},${rr} 0 0 1 ${x1 - rr},${y1} H${x0 + rr} A${rr},${rr} 0 0 1 ${x0},${y1 - rr} V${y0 + rr} A${rr},${rr} 0 0 1 ${x0 + rr},${y0} Z` };
}
