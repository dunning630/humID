// What the document camera tells the person, moment by moment (3.0.3 rebuild). One small
// machine, fed by the camera screen (screens/add/camera.jsx), that answers four questions
// the person has while holding a document up to the phone:
//
//   Does it see my document?        the frame's lock box and the "Framed" chip, at once
//   What do I change?               one instruction, said only once it has held for a moment
//   Did it take the picture?        a freeze-frame of the photo in the frame, "Captured"
//   Did it get what it needs?       the barcode / lines chip while reading, then the details
//                                   it read, listed, before it moves on, or a plain choice
//
// Phases:   starting → aim ⇄ adjust ⇄ hold → capture → check → done
//                                          ↘ fail (Try again · Keep the photo)
// Positive changes show at once; problems wait a moment before they are said (so a passing
// shadow isn't announced), and one problem replacing another waits a little longer. The live
// chips (Framed · Sharp · Steady · Light · Barcode) change only when two looks in a row agree.
//
// Pure functions and plain objects: tested in Node (tests/capture.test.js). Nothing here sees
// a picture; the summary sees only what was read, and nothing is logged or kept.
import { MESSAGES } from "./guide.js";
import { newRecord, applyAamva, applyMrz, parseAamva, fullName } from "@humid/idscan";

/* ---------------- words ---------------- */

/** Everything the camera can ask the person to change. Titles are the instruction; details say how. */
export const TIPS = {
  ...MESSAGES,
  // the Photo camera's own (core/docfind.js looks)
  bright: { title: "Too bright", detail: "Move out of direct light." },
  far: { title: "Move closer", detail: "Let the document fill more of the screen." },
  shape: { title: "Show just the document", detail: "Nothing else in the picture." },
};

/** How long a problem must last before it is said (ms). A blur is usually the focus settling. */
export const SAY_AFTER = { default: 350, dark: 600, glare: 500, blur: 1500, showback: 1200, showfront: 1200, showpage: 1500 };
/** A problem replacing another one already on screen waits at least this long. */
export const SWITCH_AFTER = 550;
/** The time budget: after this the round button is pointed out, in words and with a pulse. */
export const TIMING = { offerShutterAfter: 8000 };
/** The chips change only when this many looks in a row agree. */
export const CHIP_AGREE = 2;

const LIVE = new Set(["aim", "adjust", "hold"]);
export const isLive = (s) => LIVE.has(s.phase);

/** What the camera reads, by name on the chip and in the words. */
const CODE = {
  barcode: { chip: "Barcode", reading: "Reading the barcode", read: "Barcode read", miss: "Couldn't read the barcode" },
  mrz: { chip: "ID lines", reading: "Reading the lines of <<<", read: "Lines read", miss: "Couldn't read the lines of <<<" },
  card: { chip: "Card number", reading: "Reading the card number", read: "Card number read", miss: "Couldn't read the card number" },
};

/* ---------------- the machine ---------------- */

/**
 * A fresh machine.
 *   expect   what this side has to give: "barcode", "mrz", "card" (read after the photo), or null (a photo)
 */
export function begin({ expect = null, now = 0 } = {}) {
  return {
    phase: "starting", since: now, startedAt: now,
    tip: null, tipDetail: null, cand: null, focusing: false,
    chips: { framed: "off", sharp: "off", steady: "off", light: "off" }, pending: {},
    code: expect ? { want: expect, state: "off", seen: 0 } : null,
    progress: 0, manual: false, note: null, result: null, error: null, how: null, tries: 0,
  };
}

const to = (s, phase, now, patch = {}) => ({ ...s, ...patch, phase, since: phase !== s.phase ? now : s.since });
const sayAfter = (key) => SAY_AFTER[key] ?? SAY_AFTER.default;

/** The chips this look would set, before the agreement rule. */
export function chipsOf(v) {
  if (!v) return { framed: "off", sharp: "off", steady: "off", light: "off" };
  const lightBad = v.key === "dark" || v.key === "glare" || v.key === "bright";
  return {
    framed: !v.present ? "off" : v.aligned ? "ok" : "warn",
    sharp: !v.aligned ? "off" : v.sharp ? "ok" : "warn",
    steady: !v.aligned ? "off" : v.steady ? "ok" : "warn",
    light: lightBad ? "warn" : v.present ? "ok" : "off",
  };
}

/** Apply the agreement rule: a chip moves to a new value once CHIP_AGREE looks in a row say so. */
function agreeChips(cur, pending, raw) {
  const chips = { ...cur }, next = {};
  for (const [k, val] of Object.entries(raw)) {
    if (val === cur[k]) continue;
    const n = pending[k]?.val === val ? pending[k].n + 1 : 1;
    if (n >= CHIP_AGREE) chips[k] = val; else next[k] = { val, n };
  }
  return { chips, pending: next };
}

/**
 * Events:
 *   { t: "ready" }                                the camera is live
 *   { t: "look", v, progress, codeSeen }          one look: v is core/guide.js judge()'s verdict (or the Photo
 *                                                 camera's in the same shape); progress 0..1 of the hold;
 *                                                 codeSeen: a barcode / the lines are in view
 *   { t: "code", state, fields? }                 the live reader: "reading" | "read" | "miss"
 *   { t: "capture", how }                         the photo is being taken
 *   { t: "check", note? }                         the photo is taken and being read / kept
 *   { t: "done", result }                         kept: result { title, detail, fields, tone }
 *   { t: "fail", result }                         taken, but it didn't give what it had to: { title, detail }
 *   { t: "retry" }                                back to the live view, a fresh budget
 *   { t: "tick" }                                 time passes
 *   { t: "error", message }                       the camera can't run
 */
export function step(s, ev, now) {
  switch (ev.t) {
    case "ready":
      return s.phase === "starting" ? to(s, "aim", now, { startedAt: now }) : s;
    case "look": {
      if (!isLive(s)) return s;
      const v = ev.v || {};
      const { chips, pending } = agreeChips(s.chips, s.pending, chipsOf(v));
      let code = s.code;
      if (code && (code.state === "off" || code.state === "seen")) {
        const seen = ev.codeSeen ? Math.min(3, code.seen + 1) : Math.max(0, code.seen - 1);
        code = { ...code, seen, state: seen >= CHIP_AGREE ? "seen" : seen === 0 ? "off" : code.state };
      }
      // the instruction: cleared at once when the problem goes; a new one said once it has held
      const want = v.key || null;
      let { tip, tipDetail, cand } = s;
      if (!want) { tip = null; tipDetail = null; cand = null; }
      else if (want === tip) { tipDetail = v.detail || null; cand = null; }
      else {
        cand = cand?.key === want ? cand : { key: want, since: now };
        const wait = tip ? Math.max(SWITCH_AFTER, sayAfter(want)) : sayAfter(want);
        if (now - cand.since >= wait) { tip = want; tipDetail = v.detail || null; cand = null; }
      }
      // a blur that hasn't been said yet is the camera focusing
      const focusing = !tip && (want === "blur" || (v.aligned && v.sharp === false));
      // "hold" only once it's lined up: something in view whose edges can't be told yet is still being aimed
      const phase = tip ? "adjust" : v.aligned ? "hold" : "aim";
      return to(s, phase, now, { chips, pending, code, tip, tipDetail, cand, focusing, progress: tip ? 0 : ev.progress ?? 0 });
    }
    case "code": {
      if (!s.code) return s;
      const code = { ...s.code, state: ev.state, fields: ev.fields ?? s.code.fields, at: ev.state === "read" ? now : s.code.at };
      return { ...s, code };
    }
    case "capture":
      return to(s, "capture", now, { how: ev.how || "auto", progress: 1, tip: null, cand: null, focusing: false });
    case "check":
      return to(s, "check", now, { note: ev.note || null });
    case "done":
      return to(s, "done", now, { result: ev.result || null });
    case "fail":
      return to(s, "fail", now, { result: ev.result || null });
    case "retry": {
      const fresh = begin({ expect: s.code?.want || null, now });
      return { ...fresh, phase: "aim", since: now, startedAt: now, tries: s.tries + 1 };
    }
    case "tick": {
      if (!isLive(s)) return s;
      const manual = now - s.startedAt >= TIMING.offerShutterAfter;
      return manual === s.manual ? s : { ...s, manual };
    }
    case "error":
      return to(s, "error", now, { error: ev.message || "The camera couldn't start." });
    default:
      return s;
  }
}

/* ---------------- what to draw and say ---------------- */

const CHIP_LABELS = { framed: "Framed", sharp: "Sharp", steady: "Steady", light: "Light" };

/**
 * A state → what the camera screen draws:
 *   { phase, headline, detail, tone ("info" | "warn" | "ok" | "busy"), icon, progress (0..1, or null),
 *     chips [{ k, label, state }], actions (keys: "light", "retry", "keep", "continue"),
 *     offer (point at the shutter), fields [{ label, value }], live (the words a screen reader hears) }
 *   noun    "card", "license", "passport page", "page", "document"
 *   hint    the step's own words for lining up (shown while aiming)
 *   torch   the phone has a light to turn on (offered when it's too dark)
 *   guided  there is a frame to line up in (false: Photo, which finds the document anywhere)
 */
export function view(s, { noun = "card", hint = "", torch = false, guided = true } = {}) {
  const code = s.code && CODE[s.code.want];
  const chips = Object.entries(s.chips).map(([k, state]) => ({ k, label: k === "framed" && !guided ? "Found" : CHIP_LABELS[k], state }));
  if (s.code && s.code.want !== "card") {
    const st = s.code.state;
    chips.push({ k: "code", label: code.chip, state: st === "read" ? "ok" : st === "miss" ? "warn" : st === "reading" ? "busy" : st === "seen" ? "seen" : "off" });
  }
  const out = { phase: s.phase, headline: "", detail: "", tone: "info", icon: "scan", progress: null, chips, actions: [], offer: false, fields: null, live: "" };
  const done = (o) => ({ ...out, ...o, live: o.live ?? [o.headline, o.detail].filter(Boolean).join(". ") });
  const slowWords = "Taking a while? Press the round button to take the photo yourself.";
  switch (s.phase) {
    case "starting":
      return done({ headline: "Starting the camera", detail: "One moment.", tone: "busy", icon: "camera", chips: [] });
    case "aim":
    case "adjust":
    case "hold": {
      const read = s.code?.state === "read";
      const reading = s.code && (s.code.state === "reading" || s.code.state === "seen");
      const actions = [];
      if (s.tip === "dark" && torch) actions.push("light");
      const base = { offer: s.manual, actions };
      if (read) {
        // the details are in; only the photo is left
        return done({ ...base, headline: `${code.read} ✓`, detail: s.tip ? `${TIPS[s.tip].title} for the photo.` : "Hold still for the photo.", tone: "ok", icon: "check", progress: s.progress });
      }
      if (s.phase === "adjust") {
        const t = TIPS[s.tip] || { title: s.tip, detail: "" };
        const title = s.tip === "tilt" && noun !== "card" ? `Straighten the ${noun}` : t.title;
        return done({ ...base, headline: title, detail: s.tipDetail || t.detail || "", tone: "warn", icon: ICON[s.tip] || "alert" });
      }
      if (reading && s.code.want !== "card") {
        return done({ ...base, headline: `${code.reading}…`, detail: "Hold still. It takes a second.", tone: "busy", icon: s.code.want === "barcode" ? "barcode" : "scan", progress: null });
      }
      if (s.phase === "aim") {
        const headline = guided ? `Place the ${noun} in the frame` : "Point the camera at the document";
        return done({ ...base, headline, detail: s.manual ? slowWords : hint || (guided ? "Hold it flat, filling the frame edge to edge." : "It's found anywhere in view."), icon: "scan" });
      }
      // hold
      if (s.focusing) return done({ ...base, headline: "Focusing…", detail: "Hold still while the camera focuses.", tone: "busy", icon: "scan" });
      return done({ ...base, headline: "Hold still", detail: s.progress > 0 ? "Taking the photo…" : s.manual ? slowWords : guided ? "Keep it lined up." : "Keep it in view.", tone: "ok", icon: "scan", progress: s.progress });
    }
    case "capture":
      return done({ headline: "Captured", detail: "Hold on a moment.", tone: "ok", icon: "camera", chips: [], live: "Photo captured." });
    case "check":
      return done({ headline: s.note || (code ? `${code.reading}…` : "Saving…"), detail: "From the photo just taken.", tone: "busy", icon: "scan", chips: [] });
    case "done": {
      const r = s.result || {};
      return done({ headline: r.title || "Got it", detail: r.detail || "", tone: r.tone || "ok", icon: "check", chips: [], fields: r.fields || null, actions: ["continue"],
        live: [r.title || "Got it", r.detail, ...(r.fields || []).map((f) => `${f.label}: ${f.value}`)].filter(Boolean).join(". ") });
    }
    case "fail": {
      const r = s.result || {};
      return done({ headline: r.title || (code ? code.miss : "Couldn't keep that photo"), detail: r.detail || "Try again, or keep the photo and type the details.", tone: "warn", icon: "alert", chips: [], fields: r.fields || null, actions: r.keep === false ? ["retry"] : ["retry", "keep"] });
    }
    case "error":
      return done({ headline: "Camera problem", detail: s.error, tone: "warn", icon: "alert", chips: [] });
    default:
      return out;
  }
}

/** An icon for each instruction (brand/icons.jsx names). */
const ICON = { dark: "torch", glare: "sun", closer: "zoomin", fill: "zoomin", far: "zoomin", back: "zoomout", shift: "move", tilt: "rotate", flat: "phone", blur: "scan", showback: "turn", showfront: "turn", showpage: "passport", bright: "sun", shape: "alert" };

/* ---------------- where the document is, for the frame's lock box ---------------- */

/**
 * Where the document sits relative to the frame, from core/guide.js measure(): { x, y, w, h } as shares of
 * the frame (0, 0, 1, 1 is the frame itself) and rot (degrees). Only from four sides, or three with the
 * fourth mirrored from its opposite; null when the edges can't be trusted (fewer sides, or a shape no
 * document has). It is four numbers and an angle, not four free corners, so it can't jump about.
 */
export function docBox(m) {
  if (!m || (m.sides ?? 0) < 3 || !m.edges) return null;
  const off = (k) => (m.edges[k]?.found ? m.edges[k].off : null);
  let L = off("left"), R = off("right"), T = off("top"), B = off("bottom");
  L ??= R; R ??= L; T ??= B; B ??= T;
  if ([L, R, T, B].some((x) => x == null)) return null;
  const box = { x: -L, y: -T, w: 1 + L + R, h: 1 + T + B, rot: Math.max(-20, Math.min(20, m.rot || 0)) };
  if (box.w < 0.35 || box.h < 0.35 || box.w > 1.5 || box.h > 1.5 || Math.abs(box.w - box.h) > 0.25) return null;
  return box;
}

/** Ease the lock box toward the newest measurement (k: how far each look moves it). A big jump snaps. */
export function easeBox(prev, next, k = 0.5) {
  if (!next) return null;
  if (!prev) return next;
  const far = Math.abs(next.x - prev.x) > 0.25 || Math.abs(next.y - prev.y) > 0.25 || Math.abs(next.w - prev.w) > 0.3;
  if (far) return next;
  const m = (a, b) => a + (b - a) * k;
  return { x: m(prev.x, next.x), y: m(prev.y, next.y), w: m(prev.w, next.w), h: m(prev.h, next.h), rot: m(prev.rot, next.rot) };
}

/* ---------------- what was read, said back ---------------- */

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** 1974-08-12 → 12 Aug 1974 (no locale: the same on every phone, and in tests). */
export function day(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(iso || ""));
  return m ? `${Number(m[3])} ${MONTHS[Number(m[2]) - 1] || m[2]} ${m[1]}` : String(iso || "");
}

/**
 * What a side gave, as the camera says it back before moving on.
 *   kind   the ID kind (driver_license, passport, id_card, residence_permit, other)
 *   read   { barcode, mrz, consensus } from the live reader or the still
 *   want   what the side had to give: "barcode", "mrz", both ("barcode+mrz"), or null
 * Returns { ok, what ("barcode" | "mrz" | null), title, detail, fields [{ label, value }], tone }.
 * ok is false only when something had to be read and nothing usable was.
 */
export function summarize(kind, { barcode = null, mrz = null, consensus = false } = {}, want = null) {
  const rec = newRecord(kind || "other");
  let what = null;
  const a = barcode ? parseAamva(barcode) : null;
  if (a) { applyAamva(rec, a); what = "barcode"; }
  else if (mrz) { applyMrz(rec, mrz, { consensus }); what = "mrz"; }
  const f = rec.fields;
  const fields = [];
  const put = (label, value) => { if (value) fields.push({ label, value: String(value) }); };
  put("Name", fullName(rec));
  if (what === "mrz") put("Nationality", f.nationality);
  put("Date of birth", f.birth && day(f.birth));
  put("Number", f.number);
  put("Expires", f.expiry && day(f.expiry));
  if (rec.address) put("Address", [rec.address.city, rec.address.region].filter(Boolean).join(", "));
  if (!want) return { ok: true, what, title: "Got it", detail: "Photo captured.", fields: fields.length ? fields : [], tone: "ok" };
  if (barcode && !a) return { ok: false, what: null, title: "That isn't an ID barcode", detail: "Show the side with the long barcode, or keep the photo and type the details.", fields: [], tone: "warn" };
  if (what === "barcode") return { ok: true, what, title: "Got it", detail: "Read from the barcode.", fields, tone: "ok" };
  if (what === "mrz" && mrz.valid) return { ok: true, what, title: "Got it", detail: consensus ? "Read from the lines of <<<, checked twice." : "Read from the lines of <<<. Check them on the next screen.", fields, tone: "ok" };
  if (what === "mrz") return { ok: false, what, title: "Read only part of it", detail: "Some check digits didn't agree. Try again for a cleaner read, or keep it and check the details.", fields, tone: "warn" };
  const miss = want === "barcode" ? CODE.barcode.miss : want === "mrz" ? CODE.mrz.miss : "Couldn't read the details";
  return { ok: false, what: null, title: miss, detail: "Try again closer and steadier, or keep the photo and type the details.", fields: [], tone: "warn" };
}

/* ---------------- the Photo camera's looks, in the guided shape ---------------- */

/** Why a Photo-camera look (core/docfind.js lookAt) isn't good yet: a TIPS key, or null. */
export function diagnose(look) {
  if (!look) return null;
  if (!look.found) return look.dim ? "dark" : null;
  if (look.fits === false) return "shape";
  if (look.big === false) return "far";
  if (look.glare) return "glare";
  if (look.light === false) return (look.mean ?? 128) < 128 ? "dark" : "bright";
  return null;
}

/** A Photo-camera look as a verdict the machine understands. */
export function verdictOf(look) {
  const key = diagnose(look);
  const found = !!look?.found;
  return { key, detail: key === "shape" ? look.hint || null : null, present: found, aligned: found && !key, steady: !!look?.steady, sharp: look?.sharp !== false, ready: found && !!look?.ok };
}

/** The cadence of looks: spaced by how long the last one took, so a slow phone isn't drowned. */
export function pace(lastMs, { min = 70, max = 260, load = 2.2 } = {}) {
  return Math.max(min, Math.min(max, Math.round((lastMs || 0) * load)));
}
