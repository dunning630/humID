// The document camera (3.0). Finds the document wherever it is in view, outlines it,
// takes the photo by itself once it holds still, straightens it and turns it upright,
// and reads a license barcode or an MRZ live where the step asks for one. What it is
// doing is always on screen in one card (core/scanflow.js): Find · Steady · Read ·
// Verify · Done, or what to fix, with Try again / Take photo / Light on one tap away.
//
// 3.0 changes: the stream is 1080p at ≤ 30 fps (the analysis works on 224–400 px copies
// and the still is taken from the stream; 4K only cost battery); the step card is the
// one live region and carries the live label ("Looks like a card") in its title, so there
// is no second pill over the viewfinder; the separate UI tick timers are folded into the
// look loop; the camera's tools fold into one "More" chip; and the track is stopped,
// not only the loop, the moment the app leaves the screen.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { markPicking, toast, buzz as buzzPref } from "../../core/index.js";
import {
  barcodeReader, mrzReader, frameInVideo, grab, imageData, imageUrl, fileToCanvas, mrzBand, looksBlank,
  grayOf, grayRegion, cornersIn, develop as developPhoto, straighten, rotateCanvas, canvas as newCanvas,
  createAnalyzer, liveMrzBand, scanOptions,
} from "../../core/scan.js";
import { begin as flowBegin, step as flowStep, describe, gaveUp, pace, calmer } from "../../core/scanflow.js";
import { tracker, scaleQuad } from "../../core/docfind.js";
import { locateBarcodes, barTracker, boxCorners, readBox, searchBox, fromArea, overlap, barAngle } from "../../core/barcodefind.js";
import { docScanner } from "../../core/docscan.js";
import { parseAamva, MrzConsensus } from "@humid/idscan";
import { DEMO_BUILD } from "../../core/config.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- what the camera says ---------------- */

const ICON = { starting: "scan", looking: "scan", steady: "scan", reading: "scan", verifying: "shield", done: "check", problem: "alert", unreadable: "alert", timeout: "clock" };

/** The view to show: ordinary steps held for a moment, so the card (the one live region) is calm. */
function useCalm(view) {
  const c = useRef(null);
  c.current ||= calmer();
  const [, tick] = useState(0);
  const shown = c.current.show(view, Date.now());
  useEffect(() => {
    if (shown.id === view.id) return;
    const t = setTimeout(() => tick((n) => n + 1), 400);
    return () => clearTimeout(t);
  });
  return shown;
}

/**
 * The scan card: steps, the current state in words, progress, and the ways forward.
 *   lead     what the live view thinks it sees ("Looks like a card"), merged into the title
 *   extra    one more action for the card's row (the Add camera's "It's something else")
 */
function ScanState({ view: latest, notice, error, onRetry, onShoot, onTorch, torch, lead, extra }) {
  const view = useCalm(latest);
  const tone = error || notice ? "warn" : view.tone;
  const base = error ? "Camera problem" : notice ? "Couldn't keep that photo" : view.title;
  const title = lead && !error && !notice && view.id !== "done" ? `${lead} · ${base}` : base;
  const detail = error || notice || view.detail;
  const icon = error ? "alert" : notice ? "alert" : ICON[view.id] || "scan";
  const pct = Math.round(Math.max(0, Math.min(1, view.progress || 0)) * 100);
  const steps = view.steps;
  return (
    <div class="dc-status dc-state" data-tone={tone} data-state={error ? "error" : notice ? "notice" : view.id} data-fail={view.fail || undefined}>
      {!error && (
        <ol class="dc-steps" aria-hidden="true">
          {steps.map((s, i) => <li data-on={i === view.step ? "1" : undefined} data-past={view.step > i || view.id === "done" ? "1" : undefined}><i />{s.label}</li>)}
        </ol>
      )}
      <div class="dc-msg">
        <span class="dc-ico" data-spin={view.busy && !notice && !error ? "1" : undefined}><Icon name={icon} /></span>
        <div class="dc-words" role="status" aria-atomic="true" aria-live={error || notice || view.assertive ? "assertive" : "polite"}><strong>{title}</strong><span>{detail}</span></div>
      </div>
      {!error && !notice && (view.id === "steady" || view.busy) && view.id !== "done" && (
        <div class="dc-bar-track" role="progressbar" aria-label={view.title} aria-valuemin={0} aria-valuemax={100} aria-valuenow={view.busy && view.id !== "steady" ? undefined : pct} data-indeterminate={view.busy && view.id !== "steady" ? "1" : undefined}>
          <i style={view.id === "steady" ? { transform: `scaleX(${pct / 100})` } : undefined} />
        </div>
      )}
      {!error && (view.action || view.manual || extra) && (
        <div class="dc-actions">
          {view.action === "light" && onTorch && <button type="button" class="dc-act" onClick={onTorch} aria-pressed={!!torch}><Icon name="torch" />{torch ? "Light off" : "Light on"}</button>}
          {view.action === "retry" && <button type="button" class="dc-act primary" onClick={onRetry}><Icon name="rotate" />Try again</button>}
          {(view.action === "retry" || view.manual) && <button type="button" class="dc-act" onClick={onShoot}><Icon name="camera" />Take photo</button>}
          {extra && <button type="button" class="dc-act" onClick={extra.onClick}><Icon name={extra.icon || "file"} />{extra.text}</button>}
        </div>
      )}
    </div>
  );
}

/* ---------------- reading stills ---------------- */

function cameraError(e) {
  if (e?.name === "NotAllowedError" || e?.name === "SecurityError") return "Camera access is off for HumID. Allow it in your phone's settings, or choose a photo instead.";
  if (e?.name === "NotFoundError" || e?.name === "OverconstrainedError") return "No camera found here. Choose a photo instead.";
  if (e?.name === "NotReadableError") return "Another app is using the camera. Close it and try again, or choose a photo instead.";
  return "The camera couldn't start. Choose a photo instead.";
}

/**
 * Read a still photo: barcode (tried hard) and the MRZ from a few versions of the image,
 * voting. Returns { barcode, mrz, consensus, flipped } (flipped: the MRZ read only with
 * the photo turned 180°).
 */
export async function readStill(c, read, shape, wide = null, { tryFlip = false } = {}) {
  const out = { barcode: null, mrz: null, consensus: false, flipped: false };
  if (read.barcode) {
    try {
      const bc = await barcodeReader();
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
        const vote = new MrzConsensus();
        let mrz = null, stable = false;
        for (const opts of [{}, { threshold: true }, { scale: 1.3 }]) {
          const r = vote.add(await ocr.read(mrzBand(src, shape, opts)));
          if (r.result) mrz = r.result;
          if (r.stable) { stable = true; break; }
        }
        if (mrz || stable) { out.mrz = mrz || vote.reads.at(-1) || null; out.consensus = stable; out.flipped = !!turn; break; }
        if (!out.mrz) out.mrz = vote.reads.at(-1) || null;
      }
    } catch { /* reported as not found */ }
  }
  return out;
}

function enlarge(c, k) {
  if (k <= 1) return c;
  const out = newCanvas(c.width * k, c.height * k);
  const g = out.getContext("2d");
  g.imageSmoothingQuality = "high";
  g.drawImage(c, 0, 0, out.width, out.height);
  return out;
}

/** Part of a frame around a found barcode, turned so its bars stand upright and big enough to read. */
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

/** Where's the barcode in a frame (W×H)? { box, upright } or null. `skip`: boxes to pass over. */
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

function barcodeSpots(c) {
  try {
    const spot = findBarcode(c, c.width, c.height);
    return spot ? [barcodeCrop(c, spot, c.width, c.height)] : [];
  } catch { return []; }
}

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

function around(quad, w, h, pad = 0.1) {
  const xs = quad.map((p) => p.x), ys = quad.map((p) => p.y);
  let x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const px = (x1 - x0) * pad, py = (y1 - y0) * pad;
  x0 = Math.max(0, x0 - px); y0 = Math.max(0, y0 - py); x1 = Math.min(w, x1 + px); y1 = Math.min(h, y1 + py);
  return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
}

const NO_READER = "The reader couldn't start on this phone. Take the photo with the shutter and type the details.";
const FALLBACK_MS = 12000;
const BAR_QUIET_MS = 4000;
export const SCANNER_HIDDEN_MS = 60_000;
export const SCANNER_PICK_MS = 90_000;
const HOLD_MS = 900;
const CODES_LOOK_GAP = 150, READING_LOOK_GAP = 350;
const TICK_MS = 500;

const buzz = () => buzzPref(14);
const cheer = () => buzzPref([16, 45, 26]);
const oops = () => buzzPref([40, 70, 40]);
const nudge = () => buzzPref(8);

/** The next moment worth looking at the camera: a new video frame or the next paint, never later than 300 ms. */
function nextFrame(v) {
  return new Promise((res) => {
    let done = false;
    const fin = () => { if (!done) { done = true; res(); } };
    setTimeout(fin, 300);
    try { if (typeof v?.requestVideoFrameCallback === "function") v.requestVideoFrameCallback(fin); else requestAnimationFrame(fin); } catch { fin(); }
  });
}

/* ---------------- the camera ---------------- */

/**
 * Full-screen camera that finds the document by itself.
 *   mode     "license" | "passport" | "card" (+ side): shape and readers from core/scan.js scanOptions()
 *   shape    "id1" (cards), "td3" (passport photo page) or "full" (any document)
 *   read     { barcode, mrz } — what to look for while the camera runs
 *   auto     take the photo by itself once a document is found and steady (default)
 *   onDone({ canvas, original, straightened, rotate, changed, barcode, mrz, consensus, how })
 *            may be async: the camera stays open ("Saving…") until it settles; a throw keeps
 *            the camera open with the reason, so a photo is never silently lost
 *   onLook   ({ look, quad, video }) each look, for a live label
 *   lead     the live label's text, shown in the step card's title
 *   extra    one more action on the step card ({ text, icon, onClick })
 *   tools    extra controls on the camera bar (the Add camera's More chip)
 *   saved    { text, img } — what the previous step saved, shown briefly at the top
 *   native   on Android, use the phone's own document scanner for the photo (off by default:
 *            its screen isn't covered by HumID's screenshot protection; IDs and cards stay here)
 */
export function DocCamera(props) {
  const preset = props.mode ? scanOptions(props.mode, { side: props.side }) : {};
  const { auto = true, eyebrow, saved, onDone, onCancel, onSkip, onLook, lead, extra, tools, native = false } = props;
  const shape = props.shape ?? preset.shape ?? "id1", read = props.read ?? preset.read ?? {}, title = props.title ?? preset.title, hint = props.hint ?? preset.hint ?? "";
  const video = useRef(null), frame = useRef(null), file = useRef(null);
  const [phase, setPhase] = useState("starting"); // starting | live | reading | saved | error
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState("");
  const [torch, setTorch] = useState(null);
  const [scanner, setScanner] = useState(() => native && docScanner.available());
  const [toldSaved, setToldSaved] = useState(!!saved);
  const [look, setLook] = useState(null);
  const [bar, setBar] = useState(null);
  const codes = !!(read.barcode || read.mrz);
  const card = shape !== "full";
  const [flow, setFlow] = useState(() => flowBegin({ codes }));
  const L = useRef({ stop: false, done: false, paused: false, gave: false, stream: null, track: null, running: new Set(), holdUntil: 0, quad: null, an: null, spots: null, readingAt: 0, flow: null, acq: 0, tickAt: 0 }).current;
  L.flow ||= flow;
  const trace = (name, extra) => { if (DEMO_BUILD) { const t = (globalThis.__humidTrace ||= { ev: [] }); t.ev.push([name, Math.round(performance.now()), extra]); } };
  const send = (ev) => {
    const next = flowStep(L.flow, ev, Date.now());
    if (next === L.flow) return;
    const was = L.flow;
    L.flow = next;
    if (next.id !== was.id || next.fail !== was.fail || next.manual !== was.manual || next.note !== was.note || next.loading !== was.loading || Math.abs(next.progress - was.progress) >= 0.05) setFlow(next);
  };
  /** The time budget's tick, folded into the look loop (no separate timer). */
  const tick = () => {
    if (L.native || Date.now() - L.tickAt < TICK_MS) return;
    L.tickAt = Date.now();
    send({ t: "tick" });
    if (gaveUp(L.flow) && !L.gave) { L.gave = true; oops(); setLook((l) => l && { ...l, points: null }); }
  };
  const flash = (msg, ms = 4000) => { setNotice(msg); setTimeout(() => setNotice((n) => (n === msg ? "" : n)), ms); };
  useEffect(() => { if (!saved) return; const t = setTimeout(() => setToldSaved(false), 2600); return () => clearTimeout(t); }, []);

  const stopStream = () => {
    L.stream?.getTracks().forEach((t) => t.stop());
    L.stream = null; L.track = null;
    if (video.current) video.current.srcObject = null;
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
      await sleep(450);
      stopStream();
    } catch (e) {
      L.done = false; L.paused = false;
      L.holdUntil = Date.now() + 2500;
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

  function loop() {
    L.consensus ||= new MrzConsensus();
    L.tracker ||= tracker({ need: codes ? 3 : 4, hold: codes ? 0 : HOLD_MS });
    L.retry = () => { L.consensus.reset(); L.tracker.reset(); L.quad = null; L.spots = null; };
    const all = { look: lookLoop, ...(read.barcode ? { barcode: barcodeLoop } : {}), ...(read.mrz ? { mrz: mrzLoop } : {}) };
    for (const [name, run] of Object.entries(all)) {
      if (L.running.has(name)) continue;
      L.running.add(name);
      run().catch(() => {}).finally(() => L.running.delete(name));
    }
  }

  async function readBarcodes(img, harder) {
    const viaWorker = await L.an.read(img, { harder });
    if (viaWorker) return viaWorker;
    const main = await (L.bcMain ||= barcodeReader().catch(() => null));
    if (!main) throw new Error("no reader");
    return main.read(img, { harder });
  }

  async function lookLoop() {
    const track = L.tracker;
    let lastMs = 0, steadySince = 0, wasFound = false, prevOk = false;
    while (!L.stop) {
      await sleep(pace(lastMs, { min: L.reading && L.quad ? READING_LOOK_GAP : codes ? CODES_LOOK_GAP : 70 }));
      const v = video.current;
      await nextFrame(v);
      if (document.hidden) { await sleep(400); continue; }
      tick();
      if (inactive() || !auto || Date.now() < L.holdUntil) continue;
      const t0 = performance.now();
      let r;
      try { r = await L.an.look(v, { prior: track.quad }); } catch { await sleep(150); continue; }
      lastMs = performance.now() - t0;
      if (inactive()) continue;
      try {
        const t = track.feed(r.look, r.w, r.h);
        L.quad = t.quad ? scaleQuad(t.quad, r.k) : null;
        if (read.barcode && r.spots) L.spots = { list: r.spots, k: v.videoWidth / r.bw, at: Date.now(), used: false };
        if (DEMO_BUILD) globalThis.__humidLook = { ...r.look, quad: L.quad, ms: Math.round(lastMs), where: L.an.where };
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

  async function barcodeLoop() {
    const bars = barTracker();
    let barSince = 0, barTries = 0, barUpright = true, barFails = 0, lastSpot = null, idle = 0;
    const skips = [];
    while (!L.stop) {
      await sleep(40);
      if (inactive()) continue;
      const fresh = L.spots && !L.spots.used && Date.now() - L.spots.at < 800 ? L.spots : null;
      if (!fresh) continue;
      fresh.used = true;
      const v = video.current;
      try {
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
          harder = ++barTries % 3 === 0;
          const across = barUpright ? full.w : full.h;
          const note = now - barSince < 2200 ? "Barcode found. Reading…"
            : across < Math.min(W, H) * 0.3 ? "Move a little closer to the barcode"
            : "Hold steady on the barcode…";
          setBar({ points: onScreen(v, boxCorners(full)), note });
          send({ t: "reading", note });
        } else {
          setBar(null);
          if (++idle % 4 !== 0) continue;
          src = grab(v, L.quad ? around(L.quad, W, H, 0.12) : null, 1280);
          harder = idle % 12 === 0;
        }
        if (DEMO_BUILD) globalThis.__humidBar = { spot, box: full, harder, where: L.an.where };
        const texts = await readBarcodes(imageData(src), harder);
        const text = texts.find((t) => parseAamva(t));
        if (L.stop || L.paused) continue;
        if (text) { L.stop = true; setBar(null); shoot("live", { barcode: text }); return; }
        if (spot) {
          barFails = lastSpot && overlap(spot.box, lastSpot) > 0.5 ? barFails + 1 : 1;
          lastSpot = spot.box;
          if (texts.length) { skips.push({ box: spot.box, until: now + 8000 }); barFails = 0; }
          else if (barFails >= 8) { skips.push({ box: spot.box, until: now + 2500 }); barFails = 0; }
          while (skips.length > 8) skips.shift();
        }
        if (texts.length && !text) { setBar((b) => ({ points: b?.points || null, note: "That isn't a license barcode. Show the back of the license." })); send({ t: "other" }); }
      } catch (e) {
        if (e?.message === "no reader") { L.gave = true; send({ t: "unreadable" }); flash(NO_READER, 8000); }
      }
    }
  }

  async function closerLook(v, spot, W, H, free) {
    const win = searchBox(spot, W, H);
    if (win.w < 16 || win.h < 16) return spot;
    const near = grayRegion(v, win, 560), kn = win.w / near.w;
    const spots = await L.an.locate(near);
    const closer = spots.map((c) => ({ box: fromArea(c.box, win, kn), upright: c.upright })).find((c) => overlap(c.box, spot.box) > 0.3 && !free.some((x) => overlap(c.box, x) > 0.5));
    return closer || spot;
  }

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
      if (!L.quad && Date.now() - ready < 2000) continue;
      const v = video.current;
      try {
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

  // Leaving the screen frees the camera at once (the track, not only the loop). Coming
  // back lands on the screen before, which asks again.
  useEffect(() => {
    const away = () => {
      if (!document.hidden || L.scanning) return;
      L.stop = true; L.paused = true; stopStream();
      if (L.picking) { setPhase((p) => (p === "reading" || p === "saved" ? p : "error")); setError("The camera stopped while you chose a photo. Close this and start the camera again."); }
      else onCancel?.();
    };
    const gone = () => { L.stop = true; stopStream(); };
    document.addEventListener("visibilitychange", away);
    addEventListener("pagehide", gone);
    return () => { document.removeEventListener("visibilitychange", away); removeEventListener("pagehide", gone); };
  }, []);

  useEffect(() => {
    trace("mount");
    if (L.native === undefined) L.native = scanner;
    if (read.mrz) { send({ t: "engine", loading: true }); mrzReader().catch(() => null); }
    if (read.barcode && L.native) barcodeReader().then(() => {}, () => {});
    if (L.native) scanNative();
    else startCamera();
    return () => { L.stop = true; L.an?.close(); stopStream(); };
  }, []);

  function startCamera() {
    L.native = false;
    if (!L.an) {
      L.an = createAnalyzer({ shape, bar: !!read.barcode });
      L.an.warm();
      if (read.barcode && L.an.where === "main") barcodeReader().then(() => {}, () => {});
    }
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("no camera"), { name: "NotFoundError" });
        // 1080p at a modest frame rate: the analysis looks at small copies, and the still is
        // taken from this stream. More pixels only cost battery (PERF-03).
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: false, video: { facingMode: { ideal: "environment" }, width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 24, max: 30 } },
        });
        if (L.stop) { stream.getTracks().forEach((t) => t.stop()); return; }
        L.stream = stream;
        L.track = stream.getVideoTracks()[0];
        try { await L.track.applyConstraints({ advanced: [{ focusMode: "continuous" }] }); } catch { /* not offered */ }
        try { if (L.track.getCapabilities?.().torch) setTorch(false); } catch { /* not offered */ }
        video.current.srcObject = stream;
        await video.current.play().catch(() => {});
        setPhase("live");
        trace("camera");
        send({ t: "ready" });
        if (auto || codes) loop();
      } catch (e) { setPhase("error"); setError(cameraError(e)); }
    })();
  }

  async function scanNative() {
    L.native = true; L.stop = true; L.paused = true; L.done = false;
    setError(null); setPhase("starting");
    trace("scanner");
    markPicking({ forMs: SCANNER_PICK_MS, hiddenMs: SCANNER_HIDDEN_MS });
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
    if (!page) { onCancel(); return; }
    setPhase("reading");
    send({ t: "captured" });
    try {
      const c = await fileToCanvas(page.blob);
      await finish(await develop(c, null, "scan"));
    } catch (e) {
      oops(); setError(e?.message || "Couldn't read that page. Scan it again."); setPhase("error");
    }
  }

  function toCamera() {
    setScanner(false); setError(null); setPhase("starting");
    L.stop = false; L.paused = false; L.done = false;
    startCamera();
  }

  async function develop(original, hintQuad, how, known = {}) {
    await sleep(0);
    trace("develop");
    const scanned = how === "scan";
    const quad = scanned ? null : cornersIn(original, { hint: hintQuad, shape });
    let dev;
    if (scanned) {
      dev = { ...developPhoto(original, null, { shape }), straightened: true, changed: true };
    } else if (known.mrz && quad) {
      let flat = straighten(original, quad, { prefer: shape, max: 2000 });
      if (flat.height > flat.width) flat = rotateCanvas(flat, 90);
      dev = { canvas: known.turn ? rotateCanvas(flat, known.turn) : flat, original, straightened: true, rotate: known.turn || 0, confidence: 1, changed: true };
    } else dev = developPhoto(original, quad, { shape });
    if (card && !dev.straightened) {
      const v = video.current, r = v && how !== "file" && !scanned ? frameRect(v, frame.current, 0.02) : null;
      if (r) { const c = grab(original, r); dev = { canvas: c, original, straightened: false, rotate: 0, confidence: 0, changed: true }; }
    }
    let readOut = {};
    if (known.barcode || known.mrz) readOut = known;
    else if (codes) {
      send({ t: "verifying" });
      await sleep(0);
      readOut = await readStill(dev.canvas, read, shape, how === "file" || scanned ? null : grab(original, quad ? around(quad, original.width, original.height, 0.15) : null, 2400), { tryFlip: dev.straightened });
      if (readOut.flipped) dev = { ...dev, canvas: rotateCanvas(dev.canvas, 180), rotate: (dev.rotate + 180) % 360, changed: true };
    }
    const { turn, flipped, ...codesFound } = readOut;
    if (DEMO_BUILD) globalThis.__humidDevelop = { how, straightened: dev.straightened, rotate: dev.rotate, confidence: dev.confidence, quad, png: globalThis.__humidKeepPng ? dev.canvas.toDataURL("image/png") : undefined };
    trace("developed");
    return { ...dev, ...codesFound, how };
  }

  async function shoot(how = "shutter", known = {}) {
    const v = video.current;
    if (!v || L.done) return;
    trace("shoot-" + how);
    L.paused = true; L.stop = how === "shutter" ? L.stop : true;
    setPhase("reading");
    send({ t: "captured" });
    if (how === "auto") buzz();
    try {
      let c = null;
      for (let i = 0; i < 6 && !c; i++) {
        if (v.readyState >= 2 && v.videoWidth) { const got = grab(v, null); if (!looksBlank(got)) c = got; }
        if (!c) await sleep(150);
      }
      if (!c) throw new Error("The camera gave a blank picture. Hold steady and try again.");
      await finish(await develop(c, L.quad, how, known));
    } catch (e) {
      L.paused = false; L.gave = false;
      L.holdUntil = Date.now() + 2500;
      oops();
      flash(e?.message || "Couldn't take the photo. Try again.");
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

  function retry() {
    if (L.native) { scanNative(); return; }
    L.gave = false; L.holdUntil = 0; L.barSeen = 0; L.bcMain = null;
    L.retry?.();
    setNotice("");
    send({ t: "retry" });
    if (L.stream) { L.stop = false; loop(); }
  }

  const cancel = () => { L.stop = true; stopStream(); onCancel(); };
  const skip = () => { L.stop = true; stopStream(); onSkip(); };
  const live = phase === "live" && look;
  const lookState = !live ? undefined : look.ok ? "ok" : look.found ? "close" : "searching";
  const view = describe(flow, { shape, hint });
  const busy = phase === "reading" || phase === "saved";

  return (
    <div class="doccam" role="dialog" aria-modal="true" aria-label={title} data-scanner={scanner ? "1" : undefined} data-phase={phase} data-shape={shape} data-look={lookState} data-bar={bar?.points ? "found" : undefined} data-flow={view.id} data-fail={view.fail || undefined}>
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
        <div class="dc-frame" data-shape={shape} ref={frame}>
          <i class="c tl" /><i class="c tr" /><i class="c bl" /><i class="c br" />
          {read.mrz && <span class="dc-mrz" data-shape={shape} />}
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
        <ScanState view={view} notice={notice} error={phase === "error" ? error : null} torch={torch} onTorch={torch != null ? toggleTorch : null} onRetry={retry} onShoot={() => shoot()}
          lead={phase === "live" ? lead : null} extra={phase === "live" || phase === "error" ? extra : null} />
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
