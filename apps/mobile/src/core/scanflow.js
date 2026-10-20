// What the camera is doing, as a person should hear it: one visible state at a time,
//
//   Getting ready → Looking for the document → Hold steady → Reading → Verifying → Done
//
// with plain failures along the way (Too dark, Too far, Glare, Wrong document, Couldn't
// read it) that each say what to do next. Pure functions and plain objects, so the whole
// machine is tested in Node (tests/scanflow.test.js); the camera screen (ids.jsx,
// scanui.jsx) only feeds it what it saw and draws what it says.
//
//   begin / step    the state machine: step(state, event, now) → a new state
//   describe        a state → { title, detail, tone, step, steps, live, ... } to draw and announce
//   diagnose        a look (core/docfind.js lookAt) → why it isn't good yet, or null
//
// The guided scan (core/guide.js: a fixed outline the document is lined up in) feeds the same
// machine: its look carries `guide` (judge()'s verdict), and the problems it names (Move closer,
// Fill the outline, Move back a little, Line it up, Straighten the card, Hold the phone flat,
// Not sharp yet, Show the back…) are told in the same card.
//
// Nothing here sees a picture or a word read from one: only the verdicts.
import { MESSAGES, SAY_AFTER } from "./guide.js";

/** The steps shown, by what the camera has to do. */
export const STEP_LISTS = {
  photo: [{ id: "looking", label: "Find" }, { id: "steady", label: "Steady" }, { id: "reading", label: "Capture" }, { id: "done", label: "Done" }],
  read: [{ id: "looking", label: "Find" }, { id: "steady", label: "Steady" }, { id: "reading", label: "Read" }, { id: "verifying", label: "Verify" }, { id: "done", label: "Done" }],
  // the guided scan: the person lines the document up, rather than the camera finding it
  guidedPhoto: [{ id: "looking", label: "Line up" }, { id: "steady", label: "Steady" }, { id: "reading", label: "Capture" }, { id: "done", label: "Done" }],
  guidedRead: [{ id: "looking", label: "Line up" }, { id: "steady", label: "Steady" }, { id: "reading", label: "Read" }, { id: "verifying", label: "Verify" }, { id: "done", label: "Done" }],
};

/** Failures a person can fix by moving, lighting or holding differently; each with what to do. */
export const FAILS = {
  dark: MESSAGES.dark,
  bright: { title: "Too bright", detail: "Move out of direct light.", help: null },
  glare: MESSAGES.glare,
  far: { title: "Too far", detail: "Move closer until it fills the frame.", help: null },
  shape: { title: "Not the right document", detail: null, help: null }, // detail comes from the look
  other: { title: "Not a license barcode", detail: "Show the back of the license.", help: null },
  unreadable: { title: "Couldn't read it", detail: "Try again, or take the photo yourself and type the details.", help: "retry" },
  timeout: { title: "This is taking a while", detail: "Try again, or take the photo yourself.", help: "retry" },
  // the guided scan's own (core/guide.js MESSAGES)
  closer: MESSAGES.closer, fill: MESSAGES.fill, back: MESSAGES.back, shift: MESSAGES.shift, tilt: MESSAGES.tilt, flat: MESSAGES.flat,
  blur: MESSAGES.blur, showback: MESSAGES.showback, showfront: MESSAGES.showfront, showpage: MESSAGES.showpage,
};

/** Times (ms): a problem must last this long before it is shown (so it doesn't flicker), and the scan's budget. */
export const TIMING = {
  showProblemAfter: 700,   // a look that is "too far", "glare"… must hold this long before it is said
  offerManualAfter: 10000, // still no read: say the shutter is there
  giveUpAfter: 30000,      // stop looking and offer Try again / Take photo
  sayAfter: SAY_AFTER,     // a few guided problems wait longer than showProblemAfter (a blur is often just the focus settling)
};

/** Why a live look isn't good yet: a key of FAILS, "steady" (needs holding still), or null (it's good). */
export function diagnose(look, { codes = false } = {}) {
  if (!look) return null;
  if (look.guide) {
    // the guided scan: its own verdict (a message key), "steady" while lined up but not yet still and sharp, else good
    if (look.guide.key) return look.guide.key;
    return look.found && !look.guide.ready ? "steady" : null;
  }
  if (!look.found) return look.dim ? "dark" : null;
  if (look.fits === false) return "shape";
  if (look.big === false) return "far";
  if (look.glare) return "glare";
  if (look.light === false) return (look.mean ?? 128) < 128 ? "dark" : "bright";
  if (look.steady === false || look.sharp === false) return "steady";
  return null;
}

/** A fresh machine. */
export function begin({ codes = false, now = 0 } = {}) {
  return { id: "starting", fail: null, codes: !!codes, progress: 0, since: now, startedAt: now, cand: null, manual: false, capturing: false, loading: false, note: null, tries: 0 };
}

const set = (s, patch, now) => ({ ...s, ...patch, since: patch.id && patch.id !== s.id ? now : s.since });

/**
 * Events:
 *   { t: "ready" }                          the camera is live (engines may still be loading)
 *   { t: "look", look, progress, holdReading }  one look at the document (lookAt's result); holdReading: a
 *                                           reader has something in view, so a look must not pull the state back
 *   { t: "engine", loading }                the readers are loading / ready (said under "Looking" while they load)
 *   { t: "reading", note? }                 a reader is working on what it sees (a barcode found, lines of text found)
 *   { t: "verifying" }                      something was read; checking it (check digits, a second matching read)
 *   { t: "captured" }                       the photo is taken; being straightened
 *   { t: "saved" }                          kept
 *   { t: "other" }                          a barcode that isn't a license's
 *   { t: "unreadable", why? }               tried to read, couldn't
 *   { t: "retry" }                          Try again: a fresh budget
 *   { t: "tick" }                           time passes (the budget)
 */
export function step(s, ev, now) {
  if (s.id === "done") return s;
  switch (ev.t) {
    case "ready":
      return s.id === "starting" ? set({ ...s, startedAt: now }, { id: "looking" }, now) : s;
    case "look": {
      if (s.capturing || s.id === "timeout" || s.id === "unreadable" || (ev.holdReading && (s.id === "reading" || s.id === "verifying"))) {
        // taking the photo, a reader on something it sees, or waiting for a tap: the look only moves the ring
        return { ...s, progress: ev.progress ?? s.progress };
      }
      // "that isn't a license barcode" stays up long enough to be read
      if (s.id === "problem" && s.fail === "other" && now - s.since < 3500) return { ...s, progress: ev.progress ?? s.progress };
      const why = diagnose(ev.look, { codes: s.codes });
      const progress = ev.progress ?? 0;
      if (why && why !== "steady") {
        // a problem is said only once it has held for a moment
        const cand = s.cand?.id === why ? s.cand : { id: why, since: now };
        const shown = now - cand.since >= ((ev.look?.guide && TIMING.sayAfter[why]) || TIMING.showProblemAfter) || s.fail === why;
        return shown ? set({ ...s, cand, progress: 0 }, { id: "problem", fail: why, note: ev.look?.hint || null }, now) : { ...s, cand, progress: 0 };
      }
      const base = { ...s, cand: null, fail: null, progress };
      if (!ev.look?.found) return set({ ...base, progress: 0 }, { id: "looking" }, now);
      return set(base, { id: "steady" }, now);
    }
    case "engine":
      return s.loading === !!ev.loading ? s : { ...s, loading: !!ev.loading };
    case "reading":
      return set({ ...s, cand: null, fail: null, note: ev.note ?? null }, { id: "reading" }, now);
    case "verifying":
      return set({ ...s, cand: null, fail: null }, { id: "verifying" }, now);
    case "captured":
      return set({ ...s, cand: null, fail: null, progress: 1, capturing: true, note: null }, { id: "reading" }, now);
    case "saved":
      return set({ ...s, progress: 1 }, { id: "done" }, now);
    case "other":
      return set({ ...s, cand: null }, { id: "problem", fail: "other" }, now);
    case "unreadable":
      return set({ ...s, capturing: false, cand: null, fail: "unreadable", manual: true }, { id: "unreadable" }, now);
    case "retry":
      return set({ ...s, capturing: false, cand: null, fail: null, progress: 0, manual: false, startedAt: now, tries: s.tries + 1, note: null }, { id: "looking" }, now);
    case "tick": {
      const waited = now - s.startedAt;
      if (s.id === "starting" || s.capturing || s.id === "unreadable" || s.id === "timeout") return s;
      if (waited >= TIMING.giveUpAfter) return set({ ...s, fail: "timeout", manual: true }, { id: "timeout" }, now);
      if (waited >= TIMING.offerManualAfter && !s.manual) return { ...s, manual: true };
      return s;
    }
    default:
      return s;
  }
}

/** Whether the scan has run out of time and the camera should stop analysing (the person is offered Try again / Take photo). */
export const gaveUp = (s) => s.id === "timeout" || s.id === "unreadable";

/** What to draw and say for a state. */
export function describe(s, { shape = "id1", hint = "", guided = false, noun = "card" } = {}) {
  const list = guided ? (s.codes ? STEP_LISTS.guidedRead : STEP_LISTS.guidedPhoto) : s.codes ? STEP_LISTS.read : STEP_LISTS.photo;
  const idx = (id) => Math.max(0, list.findIndex((x) => x.id === id));
  const base = { id: s.id, steps: list, tone: "info", busy: false, progress: s.progress, fail: s.fail, manual: s.manual, action: null };
  switch (s.id) {
    case "starting":
      return { ...base, step: -1, title: "Getting ready", detail: s.codes ? "Starting the camera and the reader." : "Starting the camera.", busy: true, live: "Getting the camera ready." };
    case "looking": {
      if (guided) {
        const detail = s.manual ? "Taking a while? You can take the photo yourself with the round button." : s.loading ? "Getting the reader ready…" : (hint || `Hold the ${noun} flat inside the outline.`);
        return { ...base, step: 0, title: `Fit the ${noun} in the outline`, detail, live: `Fit the ${noun} in the outline.` };
      }
      const detail = s.manual ? "Taking a while? You can take the photo yourself with the round button."
        : s.loading ? "Getting the reader ready…" : (hint || (shape === "full" ? "Point the camera at the document." : "Point the camera at the card."));
      return { ...base, step: 0, title: "Looking for the document", detail, live: "Looking for the document." };
    }
    case "steady":
      return { ...base, step: 1, title: "Hold steady", detail: s.manual ? "Taking a while? You can take the photo yourself with the round button." : guided ? "Keep it lined up. The photo is taken by itself." : s.codes ? "Keep the document still. It reads by itself." : "Keep the document still. The photo is taken by itself.", live: "Hold steady." };
    case "reading":
      return { ...base, step: idx("reading"), title: s.codes ? "Reading" : "Capturing", detail: s.note || (s.codes ? "Keep the document in view." : "Straightening the photo."), busy: true, live: s.codes ? "Reading." : "Capturing." };
    case "verifying":
      return { ...base, step: idx("verifying"), title: "Verifying", detail: "Checking the details match.", busy: true, live: "Verifying the details." };
    case "done":
      return { ...base, step: list.length - 1, title: "Done", detail: "Photo saved.", tone: "ok", live: "Done. Photo saved." };
    case "problem": {
      const f = FAILS[s.fail] || FAILS.unreadable;
      const title = s.fail === "tilt" && guided && noun !== "card" ? `Straighten the ${noun}` : f.title;
      const detail = s.fail === "shape" ? (s.note || (shape === "td3" ? "Show the passport's photo page." : "Show just the card.")) : guided && s.note ? s.note : f.detail;
      return { ...base, step: 0, tone: "warn", title, detail, action: f.help, live: `${title}. ${detail}` };
    }
    case "unreadable":
    case "timeout": {
      const f = FAILS[s.fail];
      return { ...base, step: 0, tone: "warn", title: f.title, detail: f.detail, action: "retry", live: `${f.title}. ${f.detail}`, assertive: true };
    }
    default:
      return { ...base, step: 0, title: "", detail: "", live: "" };
  }
}

/**
 * Keeps the card calm: an ordinary step (looking, steady) is shown for at least `dwell`
 * ms before the next one replaces it, so a look that flickers between two verdicts
 * doesn't flicker on screen, and, because the card is the one live region that screen
 * readers announce, isn't read out twice in a second either. Problems, "Reading",
 * "Verifying", "Done" and the "couldn't read" states are shown (and announced) at once.
 * Same state, new progress or text: always shown.
 */
export function calmer({ dwell = 1200 } = {}) {
  let shown = null, at = -Infinity;
  const urgent = (v) => v.id === "done" || v.id === "problem" || v.id === "reading" || v.id === "verifying" || v.id === "unreadable" || v.id === "timeout" || v.id === "starting";
  return {
    /** The view to draw now, given the machine's latest. */
    show(view, now) {
      if (!shown || view.id === shown.id || urgent(view) || now - at >= dwell) {
        if (!shown || view.id !== shown.id) at = now;
        shown = view;
      } else shown = { ...shown, progress: view.progress, manual: view.manual };
      return shown;
    },
    reset() { shown = null; at = -Infinity; },
  };
}

/** The cadence of looks: spaced by how long the last one took, so a slow phone isn't drowned. */
export function pace(lastMs, { min = 70, max = 260, load = 2.2 } = {}) {
  return Math.max(min, Math.min(max, Math.round((lastMs || 0) * load)));
}
