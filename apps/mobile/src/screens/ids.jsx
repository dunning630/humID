// Identity documents: scan a driver's license, passport or ID card with the
// camera (and its chip, where there is one), check the details, and seal one
// record into the vault (IdFlow, a step inside the Add screen). Also the camera
// itself (DocCamera), which finds the document anywhere in view, straightens it
// and turns it upright; the Add screen opens it first for anything. And the card
// view for a sealed ID.
import { useEffect, useReducer, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { ChipAccess } from "../ui.jsx";
import { Review, Push } from "./review.jsx";
import * as S from "../core/state.js";
import { addIdRecord, chipReader, readChipInto, markPicking, toast, saveCopy, buzz as buzzPref } from "../core/controller.js";
import {
  KINDS, kindLabel, fieldsFor, newRecord, applyMrz, applyAamva, applyTyped, setImage, title as recordTitle, status as idStatus,
  provenance, fullName, niceName, countryName, regionName, parseAamva, MrzConsensus,
} from "@humid/idscan";
import {
  barcodeReader, mrzReader, releaseReaders, frameInVideo, grab, imageData, jpeg, imageUrl, fileToCanvas, mrzBand, portraitImage, looksBlank,
  grayOf, cornersIn, develop as developPhoto, straighten, rotateCanvas, canvas as newCanvas,
} from "../core/scan.js";
import { LIGHT_TIP } from "../core/addroute.js";
import { lookAt, tracker, scaleQuad } from "../core/docfind.js";
import { locateBarcodes, barTracker, boxCorners, readBox, searchBox, fromArea, overlap, barAngle } from "../core/barcodefind.js";
import { DEMO_BUILD } from "@humid/gate";

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
 */
export async function readStill(c, read, shape, wide = null, { tryFlip = false } = {}) {
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
function barcodeCrop(src, spot, W, H) {
  const area = readBox(spot, W, H);
  const c = grab(src, area, 2400), s = c.width / area.w;
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

/** Document photos (nothing to read): how long it must hold steady and sharp before the photo is taken. */
const HOLD_MS = 900;

/** A short buzz when a photo is taken (Android; iPhones have no web vibration). */
const buzz = () => buzzPref(14);

/**
 * Full-screen camera that finds the document by itself: wherever it is in view and
 * however it's tilted, its outline is drawn over it and follows it (core/docfind.js),
 * and once it holds still, lit and in focus, the photo is taken. Nobody has to line
 * anything up. The photo is then straightened (the outline becomes a flat rectangle)
 * and turned the way the text reads.
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
 */
export function DocCamera({ shape = "id1", read = {}, auto = true, eyebrow, title, hint, saved, onDone, onCancel, onSkip, onLook, label, tools }) {
  const video = useRef(null), frame = useRef(null), file = useRef(null);
  const [phase, setPhase] = useState("starting"); // starting | live | reading | saved | error
  const [error, setError] = useState(null);
  const [status, setStatus] = useState(hint || "");
  const [torch, setTorch] = useState(null);
  const [toldSaved, setToldSaved] = useState(!!saved);
  const [look, setLook] = useState(null);      // the last look: { ok, found, hint, progress, points (on screen) }
  const [bar, setBar] = useState(null);        // a barcode in view: { points (on screen), note }
  const L = useRef({ stop: false, done: false, paused: false, stream: null, track: null, looping: false, holdUntil: 0, quad: null }).current;
  const codes = !!(read.barcode || read.mrz);
  const card = shape !== "full";
  useEffect(() => { if (!saved) return; const t = setTimeout(() => setToldSaved(false), 2600); return () => clearTimeout(t); }, []);

  const stopStream = () => {
    L.stream?.getTracks().forEach((t) => t.stop());
    L.stream = null;
    if (video.current) video.current.srcObject = null; // the preview lets go too, so the camera light goes out
  };
  async function finish(result) {
    if (L.done) return;
    L.done = true; L.stop = true; L.paused = true;
    setPhase("reading");
    let then;
    try {
      then = await onDone(result);
      buzz();
      setPhase("saved");
      await sleep(450);
      stopStream();
    } catch (e) {
      // Keep the camera open and say why: never drop back to the list as if nothing happened.
      L.done = false; L.paused = false;
      L.holdUntil = Date.now() + 2500; // let the reason be read before trying again by itself
      setStatus(e?.message || "Couldn't keep that photo. Try again.");
      setTimeout(() => setStatus(hint || ""), 2600);
      setPhase(L.stream ? "live" : "error");
      if (L.stream) { L.stop = false; loop(); }
      return;
    }
    if (typeof then === "function") then();
  }

  async function loop() {
    if (L.looping) return;
    L.looping = true;
    try { await watch(); } finally { L.looping = false; }
  }

  /** The card, straightened from the live video and turned `turn`, for the MRZ reader. */
  function liveCard(v, quad, turn) {
    const box = around(quad, v.videoWidth, v.videoHeight, 0.04);
    const s = Math.min(1, 1600 / Math.max(box.w, box.h));
    const c = grab(v, box, box.w * s);
    const q = quad.map((p) => ({ x: (p.x - box.x) * (c.width / box.w), y: (p.y - box.y) * (c.height / box.h) }));
    let flat = straighten(c, q, { prefer: shape, max: 1400 });
    if (flat.height > flat.width) flat = rotateCanvas(flat, 90);
    return turn ? rotateCanvas(flat, turn) : flat;
  }

  async function watch() {
    const consensus = new MrzConsensus();
    const bc = read.barcode ? barcodeReader().catch(() => null) : null;
    const ocr = read.mrz ? mrzReader().catch(() => null) : null;
    if (read.mrz) setStatus("Getting the reader ready…");
    const track = tracker({ need: codes ? 3 : 4, hold: codes ? 0 : HOLD_MS });
    const bars = barTracker();
    let turn = 0, sawMrz = false, prev = null, steadySince = 0, mrzTurn = 0;
    let barSeen = 0, barSince = 0, barTries = 0, barUpright = true, barFails = 0, lastSpot = null;
    const skips = []; // barcodes passed over for a while: { box, until }
    while (!L.stop) {
      await sleep(read.mrz ? 60 : codes ? 120 : 90);
      const v = video.current;
      if (L.paused || !v || v.readyState < 2 || !v.videoWidth) continue;
      turn++;
      // Where's the document? Every look when there's nothing to read; every other one otherwise.
      if (auto && (!codes || turn % 2 === 0) && Date.now() >= L.holdUntil) {
        try {
          const im = grayOf(v, 320), k = v.videoWidth / im.w;
          const r = lookAt(im, { shape, prev, prior: track.quad });
          prev = im;
          const t = track.feed(r, im.w, im.h);
          L.quad = t.quad ? scaleQuad(t.quad, k) : null;
          if (DEMO_BUILD) globalThis.__humidLook = { ...r, quad: L.quad }; // development builds: tests can see why it waits
          setLook({ ok: r.ok, found: !!t.quad, hint: r.hint, progress: track.progress, points: onScreen(v, L.quad) });
          if (onLook) { try { onLook({ look: r, quad: L.quad, video: v }); } catch { /* a guess, never in the way */ } }
          if (!codes) {
            if (t.fire && !L.stop) { L.stop = true; shoot("auto"); return; }
          } else {
            steadySince = r.ok ? steadySince || Date.now() : 0;
            const barQuiet = !read.barcode || Date.now() - barSeen > BAR_QUIET_MS;
            if (steadySince && barQuiet && Date.now() - steadySince > FALLBACK_MS && !L.stop) { L.stop = true; shoot("auto"); return; }
          }
        } catch { /* a bad frame: keep looking */ }
        if (!codes) continue;
      }
      const barcodeTurn = read.barcode && (!read.mrz || turn % 2 === 0);
      try {
        if (barcodeTurn) {
          const r = await bc;
          if (!r) { setStatus(NO_READER); continue; }
          // Like a store's scan-and-go: find the barcode anywhere in view first (a few
          // milliseconds on a small grey copy), highlight it, and point the reader at just
          // that spot, at full resolution, laid flat: it reads from further away and at
          // any angle, and nobody has to line anything up.
          const now = Date.now(), W = v.videoWidth, H = v.videoHeight;
          const spot = findBarcode(v, W, H, skips.filter((x) => x.until > now).map((x) => x.box));
          if (spot) barUpright = spot.upright;
          const full = bars.feed(spot, now);
          let src, harder;
          if (full) {
            if (!barSeen || now - barSeen > 1500) barSince = now;
            barSeen = now;
            src = barcodeCrop(v, { box: full, upright: barUpright }, W, H);
            harder = ++barTries % 3 === 0; // now and then, rotations and a closer search too
            const across = barUpright ? full.w : full.h;
            const note = now - barSince < 2200 ? "Barcode found. Reading…"
              : across < Math.min(W, H) * 0.3 ? "Move a little closer to the barcode"
              : "Hold steady on the barcode…";
            setBar({ points: onScreen(v, boxCorners(full)), note });
          } else {
            setBar(null);
            // nothing stands out: around the card when it's been found, else the whole
            // view; every sixth try, the reader tries harder (rotations, more scanning)
            src = grab(v, L.quad ? around(L.quad, W, H, 0.12) : null, 2400);
            harder = turn % 6 === 0;
          }
          if (DEMO_BUILD) globalThis.__humidBar = { spot, box: full, harder }; // development builds: tests can see what it found
          const texts = await r.read(imageData(src), { harder });
          // only a license's barcode is taken: anything else in view is ignored
          const text = texts.find((t) => parseAamva(t));
          if (text && !L.stop) { L.stop = true; setBar(null); shoot("live", { barcode: text }); return; }
          if (spot) {
            // a barcode that isn't a license's (a store card beside it): look past it. One
            // that won't read after a while: give the next one in view a turn, then come back.
            barFails = lastSpot && overlap(spot.box, lastSpot) > 0.5 ? barFails + 1 : 1;
            lastSpot = spot.box;
            if (texts.length) { skips.push({ box: spot.box, until: now + 8000 }); barFails = 0; }
            else if (barFails >= 8) { skips.push({ box: spot.box, until: now + 2500 }); barFails = 0; }
            while (skips.length > 8) skips.shift();
          }
          if (texts.length && !text) setBar((b) => ({ points: b?.points || null, note: "That isn't a license barcode. Show the back of the license." }));
        } else if (read.mrz) {
          const r = await ocr;
          if (!r) { setStatus(NO_READER); continue; }
          // the card wherever it is, straightened; which way up isn't known yet, so every
          // third try reads it turned round (the check digits only agree one way)
          const flip = L.quad && ++mrzTurn % 3 === 0 ? 180 : 0;
          const src = L.quad ? liveCard(v, L.quad, flip) : grab(v, frameRect(v, frame.current, 0.05));
          const res = consensus.add(await r.read(mrzBand(src, shape)));
          if (res.best && !sawMrz) { sawMrz = true; setStatus("Reading… hold still"); }
          if (!res.best && !sawMrz) setStatus(hint || "");
          if (res.stable && !L.stop) { L.stop = true; shoot("live", { mrz: res.result, consensus: true, turn: flip }); return; }
        }
      } catch { /* a bad frame: keep looking */ }
    }
  }

  // Leaving the screen (the app goes to the background, the page is hidden or put away)
  // frees the camera at once; coming back lands on the screen before, where "Start camera" asks again.
  useEffect(() => {
    const away = () => {
      if (!document.hidden) return;
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
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("no camera"), { name: "NotFoundError" });
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: false, video: { facingMode: { ideal: "environment" }, width: { ideal: 3840 }, height: { ideal: 2160 } },
        });
        if (L.stop) { stream.getTracks().forEach((t) => t.stop()); return; }
        L.stream = stream;
        L.track = stream.getVideoTracks()[0];
        try { await L.track.applyConstraints({ advanced: [{ focusMode: "continuous" }] }); } catch { /* not offered */ }
        try { if (L.track.getCapabilities?.().torch) setTorch(false); } catch { /* not offered */ }
        video.current.srcObject = stream;
        await video.current.play().catch(() => {});
        setPhase("live");
        if (auto || codes) loop();
      } catch (e) { setPhase("error"); setError(cameraError(e)); }
    })();
    return () => { L.stop = true; stopStream(); };
  }, []);

  /**
   * Develop a photo: find the document's corners in it (helped by the live outline),
   * straighten it, turn it upright, and read it if there's something to read.
   *   known   what a live read already found ({ barcode } or { mrz, consensus, turn })
   */
  async function develop(original, hintQuad, how, known = {}) {
    await sleep(0); // let "Saving…" paint first: straightening a 4K photo takes a moment
    const quad = cornersIn(original, { hint: hintQuad, shape });
    let dev;
    if (known.mrz && quad) {
      // read live from the straightened card turned known.turn: develop it the same way
      let flat = straighten(original, quad, { prefer: shape, max: 2000 });
      if (flat.height > flat.width) flat = rotateCanvas(flat, 90);
      dev = { canvas: known.turn ? rotateCanvas(flat, known.turn) : flat, original, straightened: true, rotate: known.turn || 0, confidence: 1, changed: true };
    } else dev = developPhoto(original, quad, { shape });
    // a card that wasn't found: what was inside the on-screen frame, as before
    if (card && !dev.straightened) {
      const v = video.current, r = v && how !== "file" ? frameRect(v, frame.current, 0.02) : null;
      if (r) { const c = grab(original, r); dev = { canvas: c, original, straightened: false, rotate: 0, confidence: 0, changed: true }; }
    }
    let readOut = {};
    if (known.barcode || known.mrz) readOut = known;
    else if (codes) {
      readOut = await readStill(dev.canvas, read, shape, how === "file" ? null : grab(original, quad ? around(quad, original.width, original.height, 0.15) : null, 2400), { tryFlip: dev.straightened });
      if (readOut.flipped) dev = { ...dev, canvas: rotateCanvas(dev.canvas, 180), rotate: (dev.rotate + 180) % 360, changed: true };
    }
    const { turn, flipped, ...codesFound } = readOut;
    if (DEMO_BUILD) globalThis.__humidDevelop = { how, straightened: dev.straightened, rotate: dev.rotate, confidence: dev.confidence, quad, png: globalThis.__humidKeepPng ? dev.canvas.toDataURL("image/png") : undefined }; // development builds: tests can see the proposal
    return { ...dev, ...codesFound, how };
  }

  /** The shutter, the auto-capture (how = "auto"), or a live read (how = "live"). */
  async function shoot(how = "shutter", known = {}) {
    const v = video.current;
    if (!v || L.done) return;
    L.paused = true;
    setPhase("reading");
    if (how === "auto") buzz();
    try {
      // Android can report a frame before it has one to give, or give a black one: wait briefly, try again.
      let c = null;
      for (let i = 0; i < 6 && !c; i++) {
        if (v.readyState >= 2 && v.videoWidth) { const got = grab(v, null); if (!looksBlank(got)) c = got; }
        if (!c) await sleep(150);
      }
      if (!c) throw new Error("The camera gave a blank picture. Hold steady and try again.");
      await finish(await develop(c, L.quad, how, known));
    } catch (e) {
      L.paused = false;
      L.holdUntil = Date.now() + 2500;
      setStatus(e?.message || "Couldn't take the photo. Try again.");
      setTimeout(() => setStatus(hint || ""), 2600);
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
    try {
      const c = await fileToCanvas(f);
      await finish(await develop(c, null, "file"));
    } catch {
      L.paused = false;
      setPhase(L.stream ? "live" : "error");
      toast("That file isn't a photo HumID can open.", "warn");
    }
  }

  async function toggleTorch() {
    try { await L.track.applyConstraints({ advanced: [{ torch: !torch }] }); setTorch(!torch); } catch { setTorch(null); }
  }

  const cancel = () => { L.stop = true; stopStream(); onCancel(); };
  const skip = () => { L.stop = true; stopStream(); onSkip(); };
  const live = phase === "live" && look;
  const lookState = !live ? undefined : look.ok ? "ok" : look.found ? "close" : "searching";

  return (
    <div class="doccam" role="dialog" aria-modal="true" aria-label={title} data-phase={phase} data-shape={shape} data-look={lookState} data-bar={bar?.points ? "found" : undefined}>
      <video ref={video} playsInline muted autoplay />
      {phase === "live" && (look?.points || bar?.points) && (
        <svg class="dc-outline" aria-hidden="true" style={{ "--p": look?.progress || 0 }}>
          {look?.points && <polygon points={look.points} />}
          {look?.points && look.points.split(" ").map((pt) => { const [x, y] = pt.split(","); return <circle cx={x} cy={y} r="6" />; })}
          {bar?.points && <polygon class="dc-bar" points={bar.points} />}
        </svg>
      )}
      <div class="dc-stage">
        <div class="dc-frame" data-shape={shape} ref={frame}>
          <i class="c tl" /><i class="c tr" /><i class="c bl" /><i class="c br" />
          {read.mrz && <span class="dc-mrz" data-shape={shape} />}
          {phase === "reading" && <span class="dc-busy"><i /></span>}
          {phase === "saved" && <span class="dc-busy dc-saved" role="status" aria-label="Photo saved"><Icon name="check" /></span>}
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
      <div class="dc-status" aria-live="polite">
        {phase === "error" ? error : phase === "reading" ? (codes ? "Reading the photo…" : "Straightening the photo…") : phase === "saved" ? "Saved"
          : bar?.note && status === (hint || "") ? bar.note
          : auto && look && status === (hint || "") && (!codes || look.found) ? look.hint : status}
      </div>
      {label && phase !== "reading" && phase !== "saved" && (
        <div class="dc-label" role="status">
          <span><Icon name={label.icon || "scan"} />{label.text}</span>
          {label.action && <button class="linklike" type="button" onClick={label.action.onClick}>{label.action.text}</button>}
        </div>
      )}
      <footer class="dc-bottom" data-tools={tools ? "1" : undefined}>
        {tools && <div class="dc-tools">{tools}</div>}
        <button class="dc-side" disabled={phase === "reading" || phase === "saved"} onClick={() => { L.picking = true; markPicking(); file.current.click(); }}><Icon name="image" /><span>Photo</span></button>
        <button class="dc-shutter" aria-label="Take the photo" disabled={phase !== "live"} onClick={() => shoot()}><i /></button>
        {onSkip ? <button class="dc-side" onClick={skip}><Icon name="chevron" /><span>Skip</span></button> : <span class="dc-side" aria-hidden="true" />}
      </footer>
      <input ref={file} type="file" accept="image/*" hidden onChange={onFile} />
    </div>
  );
}

/* ---------------- the ID flow ---------------- */

// What each kind of document asks the camera for, side by side.
export const PLAN = {
  passport: [{ side: "front", shape: "td3", read: { mrz: true }, title: "The photo page", hint: "Show the photo page, with the two lines of <<<. It finds the page by itself." }],
  driver_license: [
    { side: "front", shape: "id1", read: {}, title: "Front of the license", hint: "Point the camera at the card, anywhere in view. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { barcode: true }, title: "Back of the license", hint: "Show the back, anywhere in view. It finds the barcode and reads it by itself." },
  ],
  id_card: [
    { side: "front", shape: "id1", read: {}, title: "Front of the card", hint: "Point the camera at the card, anywhere in view. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { barcode: true, mrz: true }, title: "Back of the card", hint: "Show the back. A barcode or the lines of <<< read by themselves.", optional: true },
  ],
  residence_permit: [
    { side: "front", shape: "id1", read: {}, title: "Front of the permit", hint: "Point the camera at the card, anywhere in view. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { mrz: true }, title: "Back of the permit", hint: "The three lines of <<< read by themselves.", optional: true },
  ],
  other: [
    { side: "front", shape: "id1", read: {}, title: "Front", hint: "Point the camera at the card, anywhere in view. It takes the photo by itself." },
    { side: "back", shape: "id1", read: {}, title: "Back", hint: "Point the camera at the card, anywhere in view. It takes the photo by itself.", optional: true },
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
    if (ok) {
      setNote({ tone: "ok", text: rec.current.verified.chip?.integrity ? "Chip read. Its files match the chip's own list of hashes." : "Chip read." });
      setName(recordTitle(rec.current));
      setStep("review");
      redraw();
    }
  }

  const retake = (p) => { fields.current?.commit(); setCam(p); };
  const toChip = () => { fields.current?.commit(); setStep("chip"); };
  const seal = (place) => { fields.current?.commit(); addIdRecord(rec.current, name || recordTitle(rec.current), place, { tags }); };
  const missing = step === "review" ? (fields.current?.missing?.() || []) : [];

  return (
    <>
      <Push eyebrow={kindLabel(r.kind)} title={step === "chip" ? "Read the ID chip" : step === "review" ? "Check the details" : "Scan it"} onBack={stepBack} busy={busy} label="Add an ID">
        {step === "capture" && (
          <>
            {note && <Note {...note} />}
            <Thumbs rec={r} plan={plan} onRetake={(p) => setCam(p)} />
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
              <div><strong>The ID chip has the verified details and photo</strong><span>{nfc?.kind === "reader" ? "Place the document on the card reader when asked." : "Hold the top of your phone flat against the document when asked."} It takes about 10 seconds.</span></div></div>
            {nfc && !nfc.available && <div class="banner warn" style={{ marginTop: 10 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Can't read chips right now</strong><span>{nfc.reason}</span></div></div>}
            <ChipAccess onChange={setAccess} initial={chipAccessFrom(r)} title="Details that open the chip" note="They only open the chip. What it holds is sealed with this record." />
            <div class="actions">
              <button class="btn primary block" disabled={!access || !nfc?.available} onClick={readChipNow}><Icon name="nfc" />Read the ID chip</button>
              {nfc && !nfc.available && <button class="btn quiet block" onClick={async () => setNfc(await chipReader({ fresh: true }))}>Check again</button>}
              <button class="btn ghost block" onClick={() => setStep("review")}>Skip, use the photo</button>
            </div>
          </>
        )}

        {step === "review" && (
          <Review kind="id" name={name} setName={setName} tags={tags} setTags={setTags}
            preview={<><IdProof rec={r} /><Thumbs rec={r} plan={plan} onRetake={retake} />{chipOffered() && <button class="btn quiet block" style={{ marginTop: 12 }} onClick={toChip}><Icon name="nfc" />Read the ID chip for verified details</button>}</>}
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
        <DocCamera key={cam.side + (r?.images[cam.side] ? "-again" : "")} shape={cam.shape} read={cam.read} eyebrow={kindLabel(r.kind)} title={cam.title} hint={cam.hint}
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

function Thumbs({ rec, plan, onRetake }) {
  const sides = [...plan.map((p) => p.side), ...(rec.images.portrait ? ["portrait"] : [])];
  return (
    <div class="id-thumbs">
      {sides.map((side) => {
        const img = rec.images[side];
        const p = plan.find((x) => x.side === side);
        return (
          <figure data-shape={side === "portrait" ? "portrait" : p?.shape}>
            {img ? <img src={imageUrl(img)} alt={`${side} of the document`} /> : <span class="empty-thumb">{rec.skipped?.includes(side) ? "Skipped" : "Not yet"}</span>}
            <figcaption>{side === "portrait" ? "Chip photo" : side === "front" ? "Front" : "Back"}{img && p && <button class="linklike" onClick={() => onRetake(p)}>Retake</button>}</figcaption>
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
        <span class={`pill ${p.level === "chip" || p.level === "barcode" || p.level === "mrz" ? "mint" : ""}`}><Icon name={p.level.startsWith("chip") ? "nfc" : p.level === "barcode" ? "barcode" : p.level.startsWith("mrz") ? "scan" : "pencil"} />{p.level === "chip-edited" ? "Chip, edited" : p.level.startsWith("chip") ? "From the chip" : p.level === "barcode" ? "From the barcode" : p.level.startsWith("mrz") ? "Scanned from the document" : "Typed"}</span>
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
