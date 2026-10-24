// What the document camera tells the person, moment by moment (5.0). One small machine, fed by
// the camera screen (screens/add/camera.jsx) with the camera's own events (the native camera,
// plugins/humid-docscan, or the web camera, core/webcam.js; both speak core/lookstate.js), that
// answers four questions the person has while holding a document up to the phone:
//
//   Does it see my document?        the frame and the "Framed" chip, at once
//   What do I change?               one instruction (the camera says it only once it has lasted)
//   Did it take the picture?        a freeze-frame of the photo in the frame, "Captured"
//   Did it get what it needs?       the barcode / lines chip while reading, then the details
//                                   it read, listed, before it moves on, or a plain choice
//
// Phases:   starting → aim ⇄ adjust ⇄ hold → capture → check → done
//                                          ↘ fail (Try again · Keep the photo)
// "Focusing…" is said only while the camera's autofocus is really moving (look.state
// "focusing"), never from a guess at sharpness. The camera's hysteresis is the only one: the
// chips follow each look as it comes.
//
// Pure functions and plain objects: tested in Node (tests/doccam.test.js). Nothing here sees a
// picture; the summary sees only what was read, and nothing is logged or kept.
import { MESSAGES, KEYS } from "./doctpl.js";
import { newRecord, applyAamva, applyMrz, parseAamva, fullName } from "@humid/idscan";

/* ---------------- words ---------------- */

/** Everything the camera can ask the person to change. Titles are the instruction; details say how. */
export const TIPS = MESSAGES;

/** The time budget: after this the round button is pointed out, in words and with a pulse. */
export const TIMING = { offerShutterAfter: 8000 };

const LIVE = new Set(["aim", "adjust", "hold"]);
export const isLive = (s) => LIVE.has(s.phase);

/** What the camera reads, by name on the chip and in the words. */
const CODE = {
  barcode: { chip: "Barcode", reading: "Reading the barcode", read: "Barcode read", miss: "Couldn't read the barcode" },
  mrz: { chip: "ID lines", reading: "Reading the lines of <<<", read: "Lines read", miss: "Couldn't read the lines of <<<" },
  card: { chip: "Card number", reading: "Reading the card number", read: "Card number read", miss: "Couldn't read the card number" },
  cvv: { chip: "Security code", reading: "Reading the security code", read: "Security code read", miss: "Couldn't read the security code" },
};

/* ---------------- the machine ---------------- */

/**
 * A fresh machine.
 *   expect   what this side has to give: "barcode", "mrz", "card" (read after the photo), or null (a photo)
 */
export function begin({ expect = null, now = 0 } = {}) {
  return {
    phase: "starting", since: now, startedAt: now,
    tip: null, focusing: false, look: null,
    chips: { framed: "off", sharp: "off", steady: "off", light: "off" },
    code: expect ? { want: expect, state: "off" } : null,
    progress: 0, manual: false, note: null, result: null, error: null, how: null, tries: 0,
  };
}

const to = (s, phase, now, patch = {}) => ({ ...s, ...patch, phase, since: phase !== s.phase ? now : s.since });

/**
 * The chips a look sets: Framed (lined up), Sharp (the camera's focus), Steady, Light.
 * "busy" on Sharp while the camera focuses.
 */
export function chipsOf(look) {
  if (!look) return { framed: "off", sharp: "off", steady: "off", light: "off" };
  const found = !!look.quad || look.state !== "searching";
  const lightBad = look.light && look.light !== "ok";
  const sharp = !look.aligned ? "off" : look.state === "focusing" ? "busy" : look.focus === "failed" || look.key === "tooclose" ? "warn" : "ok";
  return {
    framed: look.state === "searching" ? "off" : look.aligned ? "ok" : found ? "warn" : "off",
    sharp,
    steady: !look.aligned ? "off" : look.steady === false || look.key === "hold" ? "warn" : "ok",
    light: lightBad ? "warn" : found ? "ok" : "off",
  };
}

/**
 * Events:
 *   { t: "ready" }                          the camera is live
 *   { t: "look", look }                     one look from the camera (core/lookstate.js shape):
 *                                           { state, key, aligned, quad, focus, steady, light, progress }
 *   { t: "code", state, fields? }           the reader: "seen" | "reading" | "read" | "miss"
 *   { t: "capture", how }                   the photo is being taken
 *   { t: "check", note? }                   the photo is taken and being read / kept
 *   { t: "done", result }                   kept: result { title, detail, fields, tone }
 *   { t: "fail", result }                   taken, but it didn't give what it had to: { title, detail }
 *   { t: "retry" }                          back to the live view, a fresh budget
 *   { t: "tick" }                           time passes
 *   { t: "error", message }                 the camera can't run
 */
export function step(s, ev, now) {
  switch (ev.t) {
    case "ready":
      return s.phase === "starting" ? to(s, "aim", now, { startedAt: now }) : s;
    case "look": {
      if (!isLive(s)) return s;
      const l = ev.look || {};
      const tip = KEYS.has(l.key) ? l.key : null;
      const phase = tip ? "adjust" : l.aligned ? "hold" : "aim";
      return to(s, phase, now, { look: l, tip, focusing: !tip && l.state === "focusing", chips: chipsOf(l), progress: tip ? 0 : l.progress ?? 0 });
    }
    case "code": {
      if (!s.code) return s;
      if (s.code.state === "read" && ev.state !== "read") return s; // once read, it stays read
      return { ...s, code: { ...s.code, state: ev.state, fields: ev.fields ?? s.code.fields, at: ev.state === "read" ? now : s.code.at } };
    }
    case "capture":
      return to(s, "capture", now, { how: ev.how || "auto", progress: 1, tip: null, focusing: false });
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
  if (s.code && s.code.want !== "card" && s.code.want !== "cvv") {
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
        const t = TIPS[s.tip];
        const title = s.tip === "tilt" && noun !== "card" ? `Straighten the ${noun}` : t.title;
        return done({ ...base, headline: title, detail: t.detail, tone: "warn", icon: ICON[s.tip] || "alert" });
      }
      if (reading && s.code.want !== "card" && s.code.want !== "cvv") {
        return done({ ...base, headline: `${code.reading}…`, detail: "Hold still. It takes a second.", tone: "busy", icon: s.code.want === "barcode" ? "barcode" : "scan", progress: null });
      }
      if (s.phase === "aim") {
        const headline = guided ? `Place the ${noun} in the frame` : "Point the camera at the document";
        return done({ ...base, headline, detail: s.manual ? slowWords : hint || (guided ? "Hold it flat, filling the frame edge to edge." : "It's found anywhere in view."), icon: "scan" });
      }
      // hold: the camera is really focusing, or it's in focus and the ring fills
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
const ICON = { dark: "torch", glare: "sun", bright: "sun", closer: "zoomin", fill: "zoomin", far: "zoomin", back: "zoomout", tooclose: "zoomout", shift: "move", tilt: "rotate", flat: "phone", hold: "scan", showback: "turn", showfront: "turn", showpage: "passport", shape: "alert" };

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
 *   read   { barcode, mrz, consensus } from the camera's reader or the still
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
