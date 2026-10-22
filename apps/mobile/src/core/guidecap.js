// The guided scan's camera side (core/guide.js has the maths): grab the small picture the guidance
// measures, take the still, and crop it to the outline.
//
//   grabWindow(video, rect)       the analysis picture: the outline and a margin, as a small grey picture
//   takeStill(video, track, rect) the best still the phone gives, cropped to the outline (and a margin),
//                                 turned straight by a small reliable angle; { canvas, source, ... }
//   fitDocument(crop)             that crop cut to the document itself: no background, at its proportions (3.1.1)
//   focusAt(track, point)         ask the camera to focus there, where the phone lets a page
//   uprightOf(canvas)             which way up a cropped card reads by its print: 0 or 180 (not used on guided
//                                 crops since 3.0.1: the outline's zones say which way up, and the print's
//                                 guess turned real license fronts upside down)
//
// The still: ImageCapture.takePhoto() (the sensor's full resolution, when the WebView offers it)
// is checked against the preview frame taken at the same moment (the two must show the same
// scene in the outline, or the photo is dropped) and cropped by the outline's rectangle mapped into
// it; otherwise the preview's own frame. Nothing is kept or logged: pictures live in memory until
// the crop is made, and only the crop leaves this file.
import { windowFor, stillMapping, rectInStill, agree, STILL_AGREES, TH, measure, inside, quadFromEdges, RATIO } from "./guide.js";
import { toGray, orientation } from "./docfind.js";
import { straighten, cornersIn } from "./scan.js";

/** The crop keeps this share of the outline's size beyond it on every side (a document a little off the outline is whole in it). */
export const CROP_MARGIN = 0.04;
/** The crop is at most this many pixels across (a 12 MP photo's outline is ~3000 px; the app keeps 1600 on seal). */
export const CROP_MAX = 2400;
/** A photo's long side is asked for at most this (a 48 MP photo would not decode on a phone with little memory). */
const PHOTO_MAX_SIDE = 4096;

const make = (w, h) => { const c = document.createElement("canvas"); c.width = Math.max(1, Math.round(w)); c.height = Math.max(1, Math.round(h)); return c; };
const ctxOf = (c) => c.getContext("2d", { willReadFrequently: true });

let shared = null;
/**
 * The analysis picture for the outline `rect` (in the video's pixels): { im (grey { w, h, g }), win (windowFor's) }.
 * One canvas is reused, drawn at its small size, so a frame costs one copy and one readback.
 */
export function grabWindow(video, rect) {
  const vw = video.videoWidth, vh = video.videoHeight;
  const win = windowFor(rect, vw, vh);
  const c = (shared ||= make(win.w, win.h));
  if (c.width !== win.w || c.height !== win.h) { c.width = win.w; c.height = win.h; }
  const g = ctxOf(c);
  g.imageSmoothingEnabled = true; g.imageSmoothingQuality = "high";
  g.drawImage(video, win.src.x, win.src.y, win.src.w, win.src.h, 0, 0, win.w, win.h);
  return { im: toGray(g.getImageData(0, 0, win.w, win.h)), win };
}

/** A small grey copy of part of a video or bitmap, `w` across: for comparing two pictures of one scene. */
function thumb(src, r, w = 64) {
  const h = Math.max(1, Math.round((w * r.h) / r.w));
  const c = make(w, h);
  const g = ctxOf(c);
  g.imageSmoothingQuality = "medium";
  g.drawImage(src, r.x, r.y, r.w, r.h, 0, 0, c.width, c.height);
  return toGray(g.getImageData(0, 0, c.width, c.height));
}

/**
 * The outline's rectangle (plus margin) cut out of `src` (a video or bitmap; `rect` in src's pixels),
 * turned by -tilt degrees about the outline's centre, at most `maxW` across.
 */
export function cropOut(src, rect, { tilt = 0, margin = CROP_MARGIN, maxW = CROP_MAX } = {}) {
  const mw = rect.w * (1 + 2 * margin), mh = rect.h * (1 + 2 * margin);
  const s = Math.min(1, maxW / mw);
  const out = make(mw * s, mh * s);
  const g = ctxOf(out);
  g.imageSmoothingQuality = "high";
  g.fillStyle = "#222";
  g.fillRect(0, 0, out.width, out.height);
  if (!tilt) {
    g.drawImage(src, rect.x - rect.w * margin, rect.y - rect.h * margin, mw, mh, 0, 0, out.width, out.height);
    return out;
  }
  g.translate(out.width / 2, out.height / 2);
  g.rotate((-tilt * Math.PI) / 180);
  g.scale(s, s);
  g.drawImage(src, -(rect.x + rect.w / 2), -(rect.y + rect.h / 2));
  return out;
}

const withTimeout = (p, ms, what) => new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error(`${what} timed out`)), ms);
  p.then((v) => { clearTimeout(t); res(v); }, (e) => { clearTimeout(t); rej(e); });
});

/** Photo settings asking for a big picture, but not the biggest a modern phone can make. */
async function photoSettings(ic) {
  try {
    const caps = await ic.getPhotoCapabilities();
    const W = caps.imageWidth, H = caps.imageHeight;
    if (W?.max && H?.max) {
      const k = Math.min(1, PHOTO_MAX_SIDE / Math.max(W.max, H.max));
      const fit = (v, r) => Math.max(r.min || 1, Math.min(r.max, Math.round(v / (r.step || 1)) * (r.step || 1)));
      return { imageWidth: fit(W.max * k, W), imageHeight: fit(H.max * k, H) };
    }
  } catch { /* the settings aren't offered: the default size */ }
  return {};
}

/**
 * Take the picture to keep: the outline's part of the best still available, as a canvas.
 *   video, track   the live <video> and its MediaStreamTrack (for ImageCapture)
 *   rect           the outline in the video's pixels
 *   tilt           degrees to turn the crop straight by (0 for none), from the guidance's reliable estimate
 *   photo          try ImageCapture.takePhoto first (default true)
 * Returns { canvas, source: "photo" | "frame", width, height (of the source still), turned (0 | 180: the photo
 * came back turned half round from the preview and was turned back), why? (why a photo wasn't used) }.
 * Never throws for a missing or failing ImageCapture: the preview's frame is the fallback.
 */
export async function takeStill(video, track, rect, { tilt = 0, photo = true, timeoutMs = 3000, burst = 3 } = {}) {
  const vw = video.videoWidth, vh = video.videoHeight;
  // the preview's frame, as it is now: the fallback, and what a photo is checked against
  const frameThumb = thumb(video, rect);
  // 3.1.1: the fallback is the sharpest of a few frames in a row, not whichever came first (a hand that
  // trembles blurs one frame and not the next)
  const fromFrame = async (why) => ({ ...(await sharpestFrame(video, rect, { tilt, n: burst })), source: "frame", width: vw, height: vh, why });
  if (!photo || typeof ImageCapture !== "function" || !track || track.readyState !== "live") return fromFrame(!photo ? "off" : "unsupported");
  let bmp = null;
  try {
    const ic = new ImageCapture(track);
    const settings = await photoSettings(ic);
    let blob;
    try { blob = await withTimeout(ic.takePhoto(settings), timeoutMs, "photo"); }
    catch (e) { if (Object.keys(settings).length) blob = await withTimeout(ic.takePhoto(), timeoutMs, "photo"); else throw e; }
    bmp = await createImageBitmap(blob);
    const map = stillMapping(vw, vh, bmp.width, bmp.height);
    // no more pixels than the preview has: nothing gained (and the framing is the less certain)
    if (map.scale < 1.2) return fromFrame("not bigger");
    // is it the same scene? compare a small copy of the outline's area in both (and correct a small offset).
    // Some phones hand the photo back turned 180° from the preview (a sensor mounted the other way up, or an
    // orientation tag read differently): the photo turned half round is compared too, and the better one wins,
    // so the still is always the way up the person lined it up in the preview.
    const a = rectInStill(rect, map);
    const ag0 = agree(frameThumb, thumb(bmp, a), 3);
    const ag180 = agree(frameThumb, turnGray(thumb(bmp, mirrored(a, bmp))), 3);
    const turned = ag180.score > ag0.score + 0.05;
    const ag = turned ? ag180 : ag0;
    if (ag.score < STILL_AGREES) return fromFrame(`different framing (${ag.score.toFixed(2)})`);
    const k = rect.w / frameThumb.w; // video pixels per thumbnail pixel
    const r = rectInStill(rect, map, ag.dx * k, ag.dy * k);
    const canvas = turned ? turn180(cropOut(bmp, mirrored(r, bmp), { tilt })) : cropOut(bmp, r, { tilt });
    return { canvas, source: "photo", width: bmp.width, height: bmp.height, score: ag.score, turned: turned ? 180 : 0 };
  } catch (e) {
    return fromFrame(String(e?.message || e).slice(0, 60));
  } finally {
    try { bmp?.close?.(); } catch { /* gone */ }
  }
}

/** How sharp the outline's part of a crop is (core/guide.js inside(): focus), on a small grey copy. */
export function sharpnessOf(c) {
  const w = 320, h = Math.max(8, Math.round((w * c.height) / c.width));
  const t = make(w, h);
  const g = ctxOf(t);
  g.imageSmoothingQuality = "medium";
  g.drawImage(c, 0, 0, w, h);
  const im = toGray(g.getImageData(0, 0, w, h));
  return inside(im, { x: w * 0.06, y: h * 0.06, w: w * 0.88, h: h * 0.88 }).focus || 0;
}

/** The sharpest of `n` frames in a row (about 70 ms apart), cropped to the outline: { canvas, sharpness, frames }. */
async function sharpestFrame(video, rect, { tilt = 0, n = 3 } = {}) {
  let best = null, frames = 0;
  for (let i = 0; i < Math.max(1, n); i++) {
    if (i) await new Promise((r) => setTimeout(r, 70));
    if (video.readyState < 2 || !video.videoWidth) continue;
    const canvas = cropOut(video, rect, { tilt });
    frames++;
    const sharpness = n > 1 ? sharpnessOf(canvas) : 0;
    if (!best || sharpness > best.sharpness) best = { canvas, sharpness };
  }
  return { ...(best || { canvas: cropOut(video, rect, { tilt }), sharpness: 0 }), frames };
}

/**
 * The document itself, out of a guided crop (the outline plus CROP_MARGIN on every side): no table
 * round it, straightened, at the document's proportions, so the picture is the card or the page and
 * nothing else (3.1.1). Its edges come from the same measurement the live guidance makes
 * (core/guide.js measure → quadFromEdges), refined by the finer corner finder near them; when they
 * can't be told, the outline itself (without the margin). Returns { canvas, how: "edges" | "frame", quad }.
 */
export function fitDocument(crop, { shape = "id1", margin = CROP_MARGIN } = {}) {
  const k = 1 + 2 * margin;
  const outline = { x: (crop.width * margin) / k, y: (crop.height * margin) / k, w: crop.width / k, h: crop.height / k };
  const rectQuad = (r) => [{ x: r.x, y: r.y }, { x: r.x + r.w, y: r.y }, { x: r.x + r.w, y: r.y + r.h }, { x: r.x, y: r.y + r.h }];
  const prefer = shape === "page" ? null : shape;
  let quad = null;
  try {
    const W = 360, s = W / crop.width, H = Math.max(8, Math.round(crop.height * s));
    const t = make(W, H);
    const g = ctxOf(t);
    g.imageSmoothingQuality = "high";
    g.drawImage(crop, 0, 0, W, H);
    const im = toGray(g.getImageData(0, 0, W, H));
    const guide = { x: outline.x * s, y: outline.y * s, w: outline.w * s, h: outline.h * s };
    const q = quadFromEdges(measure(im, guide).edges, guide);
    if (q && plausible(q, guide, shape)) {
      const big = q.map((p) => ({ x: Math.max(0, Math.min(crop.width, p.x / s)), y: Math.max(0, Math.min(crop.height, p.y / s)) }));
      quad = cornersIn(crop, { hint: big, shape: prefer || "full" }) || big;
      if (!plausible(quad, outline, shape)) quad = big;
    }
  } catch { quad = null; }
  const how = quad ? "edges" : "frame";
  quad ||= rectQuad(outline);
  return { canvas: straighten(crop, quad, { prefer }), how, quad };
}

/** A found document is believable: big enough, the right proportions, inside the picture. */
function plausible(q, guide, shape) {
  const d = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  const across = (d(q[0], q[1]) + d(q[3], q[2])) / 2, down = (d(q[0], q[3]) + d(q[1], q[2])) / 2;
  if (across < guide.w * 0.45 || down < guide.h * 0.45) return false;
  const want = shape === "page" ? 1 / RATIO.page : RATIO[shape] || RATIO.id1;
  return Math.abs(across / down / want - 1) < 0.12;
}

/** A rectangle's place in a picture turned half round (about its centre). */
const mirrored = (r, pic) => ({ x: pic.width - r.x - r.w, y: pic.height - r.y - r.h, w: r.w, h: r.h });
/** A grey picture turned 180°. */
const turnGray = (im) => ({ w: im.w, h: im.h, g: im.g.slice().reverse() });
/** A canvas turned 180°. */
function turn180(c) {
  const out = make(c.width, c.height);
  const g = ctxOf(out);
  g.translate(out.width, out.height);
  g.rotate(Math.PI);
  g.drawImage(c, 0, 0);
  return out;
}

/** A small grey copy of a canvas, at most `max` on its long side. */
function grayOfCanvas(c, max = 1100) {
  const s = Math.min(1, max / Math.max(c.width, c.height));
  const t = make(c.width * s, c.height * s);
  const g = ctxOf(t);
  g.imageSmoothingQuality = "medium";
  g.drawImage(c, 0, 0, t.width, t.height);
  return toGray(g.getImageData(0, 0, t.width, t.height));
}

/**
 * Which way up a card cropped to a landscape outline reads: 0 or 180. The outline is landscape, so
 * the card is too; only the print says if it is upside down. { rotate, confidence (0–1) }.
 */
export function uprightOf(c) {
  const o = orientation(grayOfCanvas(c), { landscape: true });
  const flip = o.rotate === 180 && o.confidence >= 0.25;
  return { rotate: flip ? 180 : 0, confidence: o.confidence };
}

/**
 * Ask the camera to focus at a point ({ x, y } as shares of the video, 0..1), where the phone lets the
 * page choose (Chrome on Android: pointsOfInterest and a one-off focus; elsewhere nothing happens).
 * Back to continuous focus a moment later. Resolves true when the camera took the request.
 */
export async function focusAt(track, { x = 0.5, y = 0.5 } = {}, { once = true } = {}) {
  if (!track || track.readyState !== "live") return false;
  let caps = {}, supported = {};
  try { caps = track.getCapabilities?.() || {}; } catch { /* none */ }
  try { supported = navigator.mediaDevices?.getSupportedConstraints?.() || {}; } catch { /* none */ }
  const modes = caps.focusMode || [];
  const ask = {};
  if (supported.pointsOfInterest) ask.pointsOfInterest = [{ x: Math.max(0, Math.min(1, x)), y: Math.max(0, Math.min(1, y)) }];
  if (once && modes.includes("single-shot")) ask.focusMode = "single-shot";
  else if (modes.includes("continuous") && ask.pointsOfInterest) ask.focusMode = "continuous";
  if (!Object.keys(ask).length) return false;
  try { await track.applyConstraints({ advanced: [ask] }); } catch { return false; }
  if (ask.focusMode === "single-shot" && modes.includes("continuous")) {
    setTimeout(() => { if (track.readyState === "live") track.applyConstraints({ advanced: [{ focusMode: "continuous" }] }).catch(() => {}); }, 1200);
  }
  return true;
}

/** The tilt the crop is turned by is only used when it is a small, believable angle. */
export const deskewOf = (v) => (v && Math.abs(v) >= TH.deskew[0] && Math.abs(v) <= TH.deskew[1] ? v : 0);
