// The document camera (5.0). What it is for: a person holds a card, a license, a passport page
// or a sheet of paper up to the phone, and at every moment can see that the camera sees it,
// what to change, when the picture is taken, and what was read from it.
//
//   The camera     on phones, the native camera (core/doccam.js, plugins/humid-docscan) under a
//                  transparent web view: real autofocus on the frame, the lens and zoom chosen
//                  for the document, the barcode and the lines of <<< read in the camera's own
//                  pipeline, a zero-shutter-lag still cut to the document. Elsewhere (development,
//                  the browser tests) the web view's camera (core/webcam.js), with the same events.
//   The frame      a fixed outline at the document's real proportions (core/doctpl.js); the
//                  document's corners, as the camera sees them, drawn over it until it lines up;
//                  a ring round the frame fills as it holds still. The frame never changes size.
//   The panel      right under the frame: one instruction, the live chips (Framed · Sharp ·
//                  Steady · Light · Barcode), and the way forward (core/capture.js says what).
//   Focus          the camera focuses on the frame by itself. "Focusing…" is said only while
//                  it really is. Tap to focus elsewhere: a ring shows where, only where the camera
//                  can do it, and turns mint when the camera says it's in focus.
//   The capture    taken by itself once it is lined up, in focus and steady (and, for a side
//                  with a barcode or lines, once they are read); it freezes in the frame with a
//                  flash, then the panel lists what was read before moving on, or says plainly
//                  what's missing with Try again / Keep.
//
// Photo (shape "full") has no outline: the camera finds a document anywhere in view.
//
// Nothing is logged or kept: the photo lives in memory until it is handed on. The camera is
// released the moment the screen is left or the app goes to the background.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { useModal } from "../../ui/kit.jsx";
import { markPicking, toast, buzz as buzzPref } from "../../core/index.js";
import * as S from "../../core/state.js";
import {
  barcodeReader, mrzReader, grab, imageData, imageBytes, imageUrl, jpeg, fileToCanvas, mrzBand,
  grayOf, cornersIn, develop as developPhoto, rotateCanvas, canvas as newCanvas, scanOptions,
} from "../../core/scan.js";
import { templateFor } from "../../core/doctpl.js";
import { probeNative, openNative } from "../../core/doccam.js";
import { openWeb, cameraError } from "../../core/webcam.js";
import { confirmedByStill } from "../../core/mrzseed.js";
import { begin, step as stepFlow, view as viewOf, summarize, isLive } from "../../core/capture.js";
import { locateBarcodes, readBox, fromArea, barAngle } from "../../core/barcodefind.js";
import { parseAamva, MrzConsensus } from "@humid/idscan";

/* global __HUMID_ALLOW_DEMO__ */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- reading a still ---------------- */

/**
 * Read a still photo: the barcode (tried hard) and the MRZ from a few versions of the image,
 * voting. Returns { barcode, mrz, consensus, flipped } (flipped: the MRZ read only with the
 * photo turned 180°). Used for imported photos, and for a camera photo whose details the
 * camera didn't read itself.
 *   seed   the camera's MrzConsensus, when it has a valid reading: the still's own read
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

/** A small JPEG of a picture, to freeze in the frame while it is read. */
function freezeOf(c) {
  try { return grab(c, null, 720).toDataURL("image/jpeg", 0.72); } catch { return null; }
}

/** How long the "Got it" panel stays before moving on (Continue moves on at once). */
const DONE_MS = 1300, DONE_PHOTO_MS = 700;
/** The scan stops looking after this; Try again starts it again. The round button still works. */
const GIVE_UP_MS = 40_000;

/* ---------------- the camera ---------------- */

/**
 * Full-screen document camera.
 *   kind     what the document is ("driver_license", "passport", "id_card", "residence_permit", "other",
 *            "card" for a payment card, "page"): picks the outline (core/doctpl.js templateFor)
 *   side     "front" | "back"
 *   shape    "id1" (cards), "td3" (a passport's photo page), "page" (paper) or "full" (Photo: no outline)
 *   read     { barcode, mrz }: what this side gives, read by the camera and from the still
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
  const [mode, setMode] = useState(null);         // "native" | "web", once the camera is open
  const [quad, setQuad] = useState(null);         // the document's corners as the camera sees them (CSS px)
  const [freeze, setFreeze] = useState(null);     // the photo just taken, shown in the frame
  const [flash, setFlash] = useState(0);
  const [torch, setTorch] = useState(null);       // null: the phone has no light to offer
  const [tapAt, setTapAt] = useState(null);       // a tap to focus: { x, y, n, af }
  const [size, setSize] = useState(null);         // the frame's size on screen, for the ring
  const [toldSaved, setToldSaved] = useState(!!saved);
  const L = useRef({
    cam: null, stop: false, done: false, busy: false, flow: null, consensus: null, codeDone: null, misses: 0,
    gaveUp: false, wasAligned: false, startedAt: 0, pendingKeep: null, pendingThen: null, summary: null, picking: false, pickedAway: false,
  }).current;
  L.flow ||= flow;

  const send = (ev) => {
    const next = stepFlow(L.flow, ev, Date.now());
    if (next === L.flow) return;
    L.flow = next;
    setFlow(next);
  };
  const trace = (name, x) => { if (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) { const t = (globalThis.__humidTrace ||= { ev: [] }); t.ev.push([name, Math.round(performance.now()), x]); } };
  // the web camera's haptics (Android's vibration); the native camera plays the phone's own
  const web = () => L.cam?.kind !== "native";
  const buzz = () => { if (web()) buzzPref(14); };
  const cheer = () => { if (web()) buzzPref([16, 45, 26]); };
  const oops = () => { if (web()) buzzPref([40, 70, 40]); };
  const nudge = () => { if (web()) buzzPref(8); };

  useEffect(() => { if (!saved) return; const t = setTimeout(() => setToldSaved(false), 2600); return () => clearTimeout(t); }, []);
  useLayoutEffect(() => {
    const el = frame.current;
    if (!el || typeof ResizeObserver !== "function") return;
    const ro = new ResizeObserver(() => { const r = el.getBoundingClientRect(); setSize({ w: r.width, h: r.height }); L.cam?.frame(); });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  /* ---------------- starting and stopping ---------------- */

  useEffect(() => {
    trace("mount");
    L.consensus = new MrzConsensus();
    if (read.mrz) mrzReader().catch(() => {}); // for the still, should the camera not read the lines itself
    startCamera();
    // Leaving the screen frees the camera at once. Choosing a photo hides the app too: the camera
    // pauses and starts again on return if no photo was chosen.
    const away = () => {
      if (!document.hidden) {
        if (L.pickedAway) { L.pickedAway = false; setTimeout(() => { if (!L.busy && L.cam) L.cam.resume(); }, 700); }
        return;
      }
      if (L.picking) { L.pickedAway = true; L.cam?.pause(); return; }
      stopCamera();
      onCancel?.();
    };
    const gone = () => stopCamera();
    const turned = () => L.cam?.frame();
    document.addEventListener("visibilitychange", away);
    addEventListener("pagehide", gone);
    addEventListener("orientationchange", turned);
    const clock = setInterval(tick, 1000);
    return () => {
      clearInterval(clock);
      stopCamera();
      document.removeEventListener("visibilitychange", away); removeEventListener("pagehide", gone); removeEventListener("orientationchange", turned);
    };
  }, []);

  function stopCamera() {
    L.stop = true;
    const c = L.cam; L.cam = null;
    c?.close();
  }

  async function startCamera() {
    try {
      const nat = await probeNative();
      const frameEl = guided ? frame.current : null;
      const onEvent = (e) => onCam(e);
      const cam = nat.available
        ? await openNative({ shape, read: { barcode: !!read.barcode, mrz: !!read.mrz, spot: spotBack }, frameEl, auto, haptics: !!S.prefs.value.haptics, onEvent })
        : await openWeb({ shape, video: video.current, frameEl, auto, onEvent });
      if (L.stop) { cam.close(); return; }
      L.cam = cam;
      setMode(cam.kind);
      trace("camera", cam.kind);
    } catch (e) {
      send({ t: "error", message: cameraError(e) });
    }
  }

  /** The time budget. Past GIVE_UP_MS the scan stops looking until Try again (the round button still works). */
  function tick() {
    send({ t: "tick" });
    if (!L.gaveUp && L.startedAt && Date.now() - L.startedAt > GIVE_UP_MS && isLive(L.flow)) {
      L.gaveUp = true;
      send({ t: "fail", result: { title: "This is taking a while", detail: "Try again, or take the photo yourself with the round button.", keep: false } });
      oops();
    }
  }

  /* ---------------- the camera's events ---------------- */

  function onCam(e) {
    switch (e.t) {
      case "ready":
        L.startedAt = Date.now();
        setTorch(e.torch ? false : null);
        send({ t: "ready" });
        return;
      case "look": {
        if (L.busy || L.gaveUp) return;
        send({ t: "look", look: e });
        setQuad(e.quad && !e.aligned ? e.quad : null);
        if (e.aligned && !L.wasAligned) nudge();
        L.wasAligned = !!e.aligned;
        return;
      }
      case "code": return onCode(e);
      case "focus":
        setTapAt((t) => (t ? { ...t, af: e.af } : t));
        return;
      case "captured": onCaptured(e); return;
      case "interrupted":
        if (e.reason) toast("The camera was interrupted. It starts again when it can.", "warn");
        return;
      case "error":
        if (e.soft) { oops(); resume(e.message); return; }
        send({ t: "error", message: e.message && e.code === "failed" ? e.message : cameraError(e) });
        return;
      default:
    }
  }

  /** The camera read (or saw) a barcode or the lines of <<<: raw text, parsed and checked here. */
  function onCode(e) {
    if (L.busy || L.codeDone) return;
    if (e.state !== "read") { if ((e.kind === "pdf417" && want === "barcode") || (e.kind === "mrz" && want === "mrz")) send({ t: "code", state: e.state === "seen" ? "seen" : "reading" }); return; }
    if (e.kind === "pdf417" && typeof e.text === "string") {
      if (!parseAamva(e.text)) { if (want === "barcode") send({ t: "code", state: "miss" }); return; }
      L.codeDone = { barcode: e.text, at: Date.now(), side: spotBack ? "back" : side };
      send({ t: "code", state: "read", fields: summarize(kind, { barcode: e.text }, "barcode").fields });
      trace("bar-read");
    } else if (e.kind === "mrz" && Array.isArray(e.lines)) {
      const res = L.consensus.add(e.lines.map(String).join("\n"));
      if (res.stable) {
        L.codeDone = { mrz: res.result, consensus: true, at: Date.now(), side };
        send({ t: "code", state: "read", fields: summarize(kind, { mrz: res.result, consensus: true }, "mrz").fields });
        trace("mrz-read");
      } else if (res.best) send({ t: "code", state: "reading" });
    }
  }

  /** What the camera read itself and handed over with the photo, checked like a live read. */
  function codesOf(codes = {}) {
    if (L.codeDone) return L.codeDone;
    if (typeof codes.pdf417 === "string" && parseAamva(codes.pdf417)) return { barcode: codes.pdf417, side: spotBack ? "back" : side };
    if (Array.isArray(codes.mrz) && codes.mrz.length) {
      const res = L.consensus.add(codes.mrz.map(String).join("\n"));
      if (res.result?.valid) return { mrz: res.result, consensus: !!res.stable, side };
    }
    return null;
  }

  /* ---------------- taking, reading and keeping the photo ---------------- */

  /** The round button: the camera focuses if it isn't in focus, then takes the photo (it arrives as `captured`). */
  async function shutter() {
    if (!L.cam) return;
    if (L.flow.phase === "fail") resume(null);
    else if (L.busy) return;
    try { await L.cam.capture(); } catch (e) { oops(); toast(e?.message || "Couldn't take the photo. Try again.", "warn"); }
  }

  async function onCaptured(e) {
    if (L.done || L.busy || !L.cam) return;
    if (L.gaveUp && e.how === "auto") return;
    L.busy = true;
    trace("capture-" + e.how);
    send({ t: "capture", how: e.how });
    buzz();
    setFlash((n) => n + 1);
    setQuad(null);
    if (e.freeze) setFreeze(e.freeze.startsWith("data:") ? e.freeze : `data:image/jpeg;base64,${e.freeze}`);
    let res;
    try {
      const cam = L.cam;
      const doc = await cam.take(e.id, "doc");
      // the whole picture, for a page or a photo's "Original", and for a web photo's second read
      const full = !guided || shape === "page" || cam.kind === "web" ? await cam.take(e.id, "full").catch(() => null) : null;
      const dev = developed(doc, full, e.cut !== false);
      if (!e.freeze) setFreeze(freezeOf(dev.canvas));
      res = await readAndSay(dev, e.how, codesOf(e.codes));
    } catch (err) {
      oops();
      resume(err?.message || "Couldn't take the photo. Try again.");
      return;
    }
    if (res) await keep(res);
  }

  /**
   * The photo, ready to keep: a card or passport page is the camera's cut-out as it is; a page or a
   * photo is turned the way it reads, and keeps the whole picture as its "Original".
   */
  function developed(doc, full, cut) {
    if (guided && shape !== "page") {
      if (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) globalThis.__humidFit = { how: cut ? "edges" : "frame", out: [doc.width, doc.height] };
      return { canvas: doc, uncut: full, original: doc, straightened: true, rotate: 0, confidence: 1, changed: true, fit: cut ? "edges" : "frame" };
    }
    const d = developPhoto(doc, null, { shape: "full" });
    return { ...d, original: full || doc, straightened: cut, changed: cut || d.changed };
  }

  /**
   * Read what a photo has to give (unless the camera already did), and decide: keep it,
   * look again by itself (once, when it was taken by itself), or ask (Try again / Keep).
   * Returns the result to keep, or null when it isn't kept (yet).
   */
  async function readAndSay(dev, how, known) {
    let readOut = {};
    if (known?.barcode) readOut = { barcode: known.barcode };
    else if (known?.mrz) {
      // the camera's lines: checked against the photo's own (one or two passes; on disagreement they're kept for review)
      send({ t: "check", note: "Checking the lines against the photo…" });
      const st = await readStill(dev.canvas, { mrz: true }, shape, { seed: L.consensus });
      readOut = st.mrz?.valid && st.consensus ? { mrz: st.mrz, consensus: true } : { mrz: known.mrz, consensus: known.consensus };
    } else if (read.barcode || read.mrz) {
      send({ t: "check" });
      readOut = await readStill(dev.canvas, read, shape, { tryFlip: dev.straightened, seed: read.mrz ? L.consensus : null });
      // the cut-out didn't read: the whole picture, in case the cut went wrong (what's kept is still the cut-out)
      if (!readOut.barcode && !readOut.mrz?.valid && dev.uncut) {
        const wide = await readStill(dev.uncut, read, shape, { tryFlip: true });
        if (wide.barcode || wide.mrz?.valid) readOut = { ...wide, flipped: false };
      }
      if (readOut.flipped) dev = { ...dev, canvas: rotateCanvas(dev.canvas, 180), rotate: (dev.rotate + 180) % 360, changed: true };
    }
    const sideNow = known?.side || side;
    const { flipped, ...codes } = readOut;
    void flipped;
    if (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) globalThis.__humidDevelop = { how, fit: dev.fit, camera: L.cam?.kind, out: [dev.canvas.width, dev.canvas.height], straightened: dev.straightened, rotate: dev.rotate, confidence: dev.confidence, live: !!known, side: sideNow, png: globalThis.__humidKeepPng ? dev.canvas.toDataURL("image/png") : undefined };
    const { uncut, ...kept } = dev;
    void uncut;
    const result = { ...kept, ...codes, how, side: sideNow };
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
    L.busy = true;
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
    L.next = () => { if (L.moved) return; L.moved = true; stopCamera(); if (typeof then === "function") then(); };
    await sleep(wait);
    L.next();
  }

  /** Back to the live view (after a miss, or Try again). `why`: said for a moment. */
  function resume(why) {
    L.busy = false; L.done = false; L.codeDone = null; L.gaveUp = false; L.wasAligned = false;
    L.pendingKeep = null; L.pendingThen = null;
    L.consensus.reset();
    L.startedAt = Date.now();
    setFreeze(null); setQuad(null);
    send({ t: "retry" });
    if (why) toast(why, "warn");
    L.cam?.again();
  }

  function retry() { L.misses = 0; resume(null); }
  async function keepAnyway() {
    if (L.pendingThen) { const then = L.pendingThen; L.pendingThen = null; L.done = true; send({ t: "done", result: { title: "Kept", detail: "Fill in the details on the next screen.", tone: "ok" } }); await sleep(DONE_PHOTO_MS); stopCamera(); then(); return; }
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
    if (!f) { L.cam?.resume(); return; }
    L.busy = true;
    send({ t: "capture", how: "file" });
    try {
      const c = await fileToCanvas(f);
      setFreeze(freezeOf(c));
      const quad = cornersIn(c, { shape: guided ? shape : "full" });
      const res = await readAndSay(developPhoto(c, quad, { shape: guided ? shape : "full" }), "file", null);
      if (res) await keep(res);
    } catch {
      toast("That file isn't a photo HumID can open.", "warn");
      resume(null);
    }
  }

  async function toggleTorch() {
    try { const r = await L.cam.torch(!torch); setTorch(!!r?.on); } catch { setTorch(null); }
  }

  /** Tap the picture: focus there, where the camera can. The ring shows only when it can, and follows its answer. */
  function tapFocus(e) {
    if (!L.cam?.focusable || !isLive(L.flow) || e.target.closest?.("button, a, input, .dc-panel, .dc-top, .dc-bottom")) return;
    const at = { x: e.clientX, y: e.clientY, n: Date.now(), af: "scanning" };
    L.cam.focus(at.x, at.y).then((ok) => { if (ok) setTapAt(at); });
  }
  useEffect(() => {
    if (!tapAt) return;
    const t = setTimeout(() => setTapAt(null), tapAt.af === "scanning" ? 2500 : 900);
    return () => clearTimeout(t);
  }, [tapAt]);

  const cancel = () => { stopCamera(); onCancel(); };
  const skip = () => { stopCamera(); onSkip(); };

  /* ---------------- drawing ---------------- */

  const vw = viewOf(flow, { noun, hint, torch: torch != null, guided });
  const live = isLive(flow);
  const aligned = live && flow.chips.framed === "ok";
  const frameState = flow.phase === "capture" || flow.phase === "check" || flow.phase === "done" ? "ok" : flow.phase === "fail" ? "close" : !live ? undefined : aligned || flow.code?.state === "read" ? "ok" : quad || flow.chips.framed === "warn" ? "close" : "searching";
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
    <div class="doccam" ref={root} role="dialog" aria-modal="true" aria-label={title} data-guided={guided ? "1" : undefined} data-camera={mode || undefined} data-phase={flow.phase} data-shape={shape} data-look={frameState} data-tone={vw.tone} onPointerDown={tapFocus}>
      {mode !== "native" && <video ref={video} playsInline muted autoplay />}
      {guided && quad && live && <svg class="dc-quad" aria-hidden="true"><polygon points={quad.map((p) => p.join(",")).join(" ")} /></svg>}
      <div class="dc-stage">
        <div class="dc-frame" data-shape={shape} data-template={tpl?.id} data-state={frameState} ref={frame}>
          <i class="c tl" /><i class="c tr" /><i class="c bl" /><i class="c br" />
          {zones.map((z) => <span class="dc-zone" data-k={z.k} data-read={(z.k === "bar" || z.k === "mrz") && flow.code?.state === "read" ? "1" : undefined} aria-hidden="true" style={{ left: `${z.x}%`, top: `${z.y}%`, width: `${z.w}%`, height: `${z.h}%` }} />)}
          {ring && <svg class="dc-ring" aria-hidden="true" viewBox={`0 0 ${size.w} ${size.h}`}><path d={ring.d} pathLength="100" style={{ strokeDasharray: `${Math.round(vw.progress * 100)} 100` }} /></svg>}
          <span class="dc-clip" aria-hidden="true">
            {freeze && <img class="dc-freeze" src={freeze} alt="" />}
            {flash > 0 && <span class="dc-flash" key={flash} />}
            {(flow.phase === "check" || flow.phase === "capture") && <span class="dc-sweep"><i /></span>}
          </span>
          {flow.phase === "done" && <span class="dc-stamp" aria-hidden="true"><Icon name="check" /></span>}
          {guided && panel}
        </div>
      </div>
      {tapAt && <span class="dc-focus" key={tapAt.n} data-af={tapAt.af} aria-hidden="true" style={{ left: `${tapAt.x}px`, top: `${tapAt.y}px` }} />}
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
        <button class="dc-shutter" aria-label="Take the photo" data-offer={vw.offer ? "1" : undefined} disabled={!(live || (flow.phase === "fail" && mode && !L.pendingKeep && !L.pendingThen))} onClick={shutter}><i /></button>
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
