// The document camera's guidance (5.0): what one look at the camera means, and when the photo
// is taken. One set of rules for every camera:
//
//   iPhone    plugins/humid-docscan/ios/…/Guidance.swift   (a line-by-line port of this file)
//   Android   plugins/humid-docscan/android/…/Guidance.kt  (the same)
//   browser   core/webcam.js, the web view's camera, for development and the browser tests
//
// A camera measures each frame and feeds the numbers in (`feed`); out come the `look` events the
// camera screen draws (core/capture.js). The rules, in order:
//
//   light       "dark" is said before anything else (nothing can be judged in the dark)
//   found       no document: state "searching"
//   fit         found but not lined up (closer, fill, back, shift, tilt, flat, shape): "aligning"
//   lined up    "focusing" only while the camera's autofocus has really been moving for
//               FOCUSING_MS (never from image statistics); otherwise "sharp", and the hold ring
//               fills while it is in focus, not blurred by motion, steady and in good light
//   too close   the lens at its near limit, or autofocus failing, for TOO_CLOSE_MS while lined up:
//               "Move back a little" (the frame never changes size)
//   ready       HOLD_MS of all that (a bad moment shorter than GRACE_MS doesn't restart it), and
//               for a side with a barcode or lines, their text read (or CODE_WAIT_MS lined up):
//               state "ready" once, and `fire`
//
// A problem is said only once it has lasted (SAY_MS), so a passing shadow isn't announced; one
// replacing another waits SWITCH_MS. Good news is said at once. Pure functions: tests/lookstate.test.js.

/** Every timing in one place (ms). The Swift and Kotlin ports copy these numbers. */
export const RULES = {
  sayMs: { default: 350, dark: 600, glare: 500, hold: 450, tooclose: 0, showback: 1200, showfront: 1200, showpage: 1500 },
  switchMs: 550,
  focusingMs: 250,
  tooCloseMs: 600,
  holdMs: 300,
  graceMs: 300,
  codeWaitMs: 2500,
};

/** Geometry thresholds, for cameras that measure a quad (iPhone, browser). Shares of the frame. */
export const FIT = { small: 0.78, snug: 0.88, big: 1.06, shift: 0.045, tilt: 6, flat: 0.1, ratio: 0.14 };

const sayAfter = (k) => RULES.sayMs[k] ?? RULES.sayMs.default;

/**
 * How a found document sits in the frame: a key of core/doctpl.js MESSAGES, or null when it is
 * lined up. quad [[x,y] ×4] clockwise from top-left and frame { x, y, w, h }, in the same units.
 * `ratio` is the document's long/short proportion (null: any shape, as a Photo).
 */
export function fitOf(quad, frame, ratio = null) {
  const d = (a, b) => Math.hypot(a[0] - b[0], a[1] - b[1]);
  const [tl, tr, br, bl] = quad;
  const top = d(tl, tr), bottom = d(bl, br), left = d(tl, bl), right = d(tr, br);
  const across = (top + bottom) / 2, down = (left + right) / 2;
  if (!(across > 0 && down > 0)) return "shape";
  if (ratio && Math.abs(across / down / ratio - 1) > FIT.ratio) return "shape";
  const scale = Math.max(across / frame.w, down / frame.h);
  if (scale < FIT.small) return "closer";
  if (scale < FIT.snug) return "fill";
  if (scale > FIT.big) return "back";
  const cx = (tl[0] + tr[0] + br[0] + bl[0]) / 4, cy = (tl[1] + tr[1] + br[1] + bl[1]) / 4;
  if (Math.abs(cx - (frame.x + frame.w / 2)) / frame.w > FIT.shift || Math.abs(cy - (frame.y + frame.h / 2)) / frame.h > FIT.shift) return "shift";
  const deg = (Math.atan2(tr[1] - tl[1], tr[0] - tl[0]) + Math.atan2(br[1] - bl[1], br[0] - bl[0])) / 2 * 180 / Math.PI;
  if (Math.abs(deg) > FIT.tilt) return "tilt";
  if (Math.abs(top - bottom) / across > FIT.flat || Math.abs(left - right) / down > FIT.flat) return "flat";
  return null;
}

/**
 * One guidance run. feed(m, now) takes one frame's measurements and returns the look:
 *   m.found     a document is in view
 *   m.quad      its corners (CSS pixels), or null
 *   m.fit       fitOf()'s key, or null when lined up (ignored when not found)
 *   m.light     "ok" | "dark" | "glare" | "bright"
 *   m.focus     "scanning" | "focused" | "failed" | null (unknown: a camera that can't say)
 *   m.near      the lens is at its near limit (too close to focus)
 *   m.sharp     false when the picture is blurred by motion (null: not measured)
 *   m.steady    the document isn't moving
 *   m.wrong     "showback" | "showfront" | "showpage" | null: the other side is in view
 *   m.wait      a side with a barcode or lines whose text isn't read yet: the photo waits (at most
 *               CODE_WAIT_MS after it lined up; the camera says when that has passed)
 * Returns { t: "look", state, key, aligned, quad, focus, steady, light, progress, fire }.
 * `changed(a, b)` says whether a look is worth sending (cameras send at most 10 a second).
 */
export function guidance() {
  // the moment each condition began (null: it isn't true now)
  let shown = null, cand = null, scanSince = null, closeSince = null, holdSince = null, lastGood = null, fired = false;
  return {
    feed(m, now) {
      const found = !!m.found;
      const light = m.light || "ok";
      const focus = m.focus ?? null;
      let state, raw = null, aligned = false, close = false;
      if (light === "dark") { state = found ? "aligning" : "searching"; raw = "dark"; }
      else if (!found) state = "searching";
      else if (m.fit) { state = "aligning"; raw = m.fit; }
      else if (m.wrong) { state = "aligning"; raw = m.wrong; }
      else {
        aligned = true;
        state = "sharp";
        if (focus === "scanning") { scanSince ??= now; if (now - scanSince >= RULES.focusingMs) state = "focusing"; } else scanSince = null;
        close = !!m.near || focus === "failed";
        if (close) closeSince ??= now; else closeSince = null;
        if (closeSince !== null && now - closeSince >= RULES.tooCloseMs) raw = "tooclose";
        else if (light === "glare" || light === "bright") raw = light;
        else if (m.steady === false || m.sharp === false) raw = state === "focusing" ? null : "hold";
      }
      if (!aligned) { scanSince = null; closeSince = null; }
      // the hold: lined up, in focus (not moving, not at its near limit), sharp, steady, in good light, nothing to say
      const good = aligned && !raw && !close && !m.wait && focus !== "scanning";
      // a moment that isn't good, shorter than the grace, doesn't restart it; losing the document does
      if (good) { holdSince ??= now; lastGood = now; } else if (!found || (holdSince !== null && now - lastGood > RULES.graceMs)) holdSince = null;
      let progress = holdSince !== null && good ? Math.min(1, (now - holdSince) / RULES.holdMs) : 0;
      let fire = false;
      if (good && now - holdSince >= RULES.holdMs && !fired) { fired = true; fire = true; state = "ready"; progress = 1; }
      else if (fired && aligned) { state = "ready"; progress = 1; }
      // say a problem once it has lasted; clear one at once
      if (!raw) { shown = null; cand = null; }
      else if (raw === shown) cand = null;
      else {
        cand = cand?.key === raw ? cand : { key: raw, since: now };
        const wait = shown ? Math.max(RULES.switchMs, sayAfter(raw)) : sayAfter(raw);
        if (now - cand.since >= wait) { shown = raw; cand = null; }
      }
      return { t: "look", state, key: shown, aligned, quad: found ? m.quad || null : null, focus, steady: m.steady !== false, light, progress, fire };
    },
    /** A new attempt: nothing held, nothing fired. */
    reset() { shown = null; cand = null; scanSince = null; closeSince = null; holdSince = null; lastGood = null; fired = false; },
  };
}

/** Is `b` worth sending after `a`? A new state, words, focus or light; the ring by a tenth; the quad by 1% of its size. */
export function changed(a, b) {
  if (!a) return true;
  if (a.state !== b.state || a.key !== b.key || a.focus !== b.focus || a.light !== b.light || a.steady !== b.steady || a.aligned !== b.aligned) return true;
  if (Math.round(a.progress * 10) !== Math.round(b.progress * 10)) return true;
  if (!a.quad !== !b.quad) return true;
  if (!b.quad) return false;
  const size = Math.hypot(b.quad[0][0] - b.quad[2][0], b.quad[0][1] - b.quad[2][1]) || 1;
  return b.quad.some((p, i) => Math.hypot(p[0] - a.quad[i][0], p[1] - a.quad[i][1]) > size * 0.01);
}
