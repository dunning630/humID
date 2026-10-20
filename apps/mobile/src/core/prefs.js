// Preferences: how HumID looks and behaves on this device. Nothing here is secret and
// nothing here can weaken protection: auto-lock can be made shorter, never longer than
// the 5-minute ceiling, and leaving the screen always locks. Kept on this device (each
// device can differ: a phone and a desktop rarely want the same lock time).
// What follows the person to every device — pins on vault items — lives inside each
// item's encrypted index entry instead (core/vault.js setPinned), sealed like the item.
//
// Pure functions are exported for tests (tests/prefs.test.js).

/** The longest auto-lock HumID allows, and the choices under it. */
export const MAX_IDLE_MS = 5 * 60_000;
export const IDLE_CHOICES = [60_000, 2 * 60_000, MAX_IDLE_MS];

export const CHOICES = Object.freeze({
  theme: ["system", "dark", "light"],
  text: ["standard", "large", "larger", "largest"], // 3.0: 100 · 120 · 145 · 175 %, on top of the OS text size
  sort: ["newest", "oldest", "name", "expiry"],
  expiryWarnDays: [30, 60, 90, 180],
});

export const DEFAULTS = Object.freeze({
  theme: "dark",
  text: "standard",
  motion: true,        // animations (rings, transitions); false = reduced
  haptics: true,       // a short buzz on checks and captures
  idleMs: MAX_IDLE_MS,
  sort: "newest",
  expiryWarnDays: 90,
  placeStamp: false,   // 3.0: the location stamp is opt-in, remembered per device
  lastKind: null,      // 3.0: what was last added (the Add flow starts there)
  readySeen: {},       // 3.0: kinds whose "Ready" explainer has been seen (shown once per kind)
});

const KIND_IDS = ["id", "card", "pass", "photo", "file"];

/** Anything stored (or tampered with) comes back as valid preferences: unknown keys dropped, bad values defaulted. */
export function sanitize(raw) {
  const r = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const pick = (k) => (CHOICES[k].includes(r[k]) ? r[k] : DEFAULTS[k]);
  return {
    theme: pick("theme"),
    text: pick("text"),
    motion: typeof r.motion === "boolean" ? r.motion : DEFAULTS.motion,
    haptics: typeof r.haptics === "boolean" ? r.haptics : DEFAULTS.haptics,
    idleMs: IDLE_CHOICES.includes(r.idleMs) ? r.idleMs : DEFAULTS.idleMs,
    sort: pick("sort"),
    expiryWarnDays: pick("expiryWarnDays"),
    placeStamp: typeof r.placeStamp === "boolean" ? r.placeStamp : DEFAULTS.placeStamp,
    lastKind: KIND_IDS.includes(r.lastKind) ? r.lastKind : null,
    readySeen: Object.fromEntries(KIND_IDS.filter((k) => r.readySeen && typeof r.readySeen === "object" && r.readySeen[k] === true).map((k) => [k, true])),
  };
}

const KEY = "humid.prefs.v1";

/** Does this device ask for less motion? (Only consulted before the person has chosen.) */
export function prefersReducedMotion() {
  try { return !!globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches; } catch { return false; }
}

/**
 * Read this device's preferences. Storage can be missing or refuse (private mode): defaults then.
 * On first launch (nothing chosen yet) animations follow the device's reduce-motion setting.
 */
export function loadPrefs(storage = globalThis.localStorage, reduced = prefersReducedMotion()) {
  let raw = null;
  try { raw = JSON.parse(storage?.getItem(KEY) || "null"); } catch { raw = null; }
  const p = sanitize(raw);
  if (typeof raw?.motion !== "boolean" && reduced) p.motion = false;
  return p;
}

export function savePrefs(prefs, storage = globalThis.localStorage) {
  const p = sanitize(prefs);
  try { storage?.setItem(KEY, JSON.stringify(p)); } catch { /* kept for this session only */ }
  return p;
}

/** Put the look on the page: <html data-theme data-text data-motion>. */
export function applyPrefs(p, root = globalThis.document?.documentElement) {
  if (!root) return;
  const dark = p.theme === "dark" || (p.theme === "system" && !globalThis.matchMedia?.("(prefers-color-scheme: light)").matches);
  root.dataset.theme = dark ? "dark" : "light";
  root.dataset.text = p.text;
  root.dataset.motion = p.motion ? "full" : "reduced";
}

/** "1 minute", "5 minutes". */
export const idleLabel = (ms) => { const m = Math.round(ms / 60_000); return `${m} minute${m === 1 ? "" : "s"}`; };

/**
 * Vault order: pinned items first, then by the chosen order. Stable for equal keys.
 * expiry: IDs by expiry date (soonest first), then everything else newest first.
 */
export function sortItems(items, sort = "newest") {
  const time = (i) => Date.parse(i.uploadedAt || i.addedAt || 0) || 0;
  const by = {
    newest: (a, b) => time(b) - time(a),
    oldest: (a, b) => time(a) - time(b),
    name: (a, b) => String(a.name || "").localeCompare(String(b.name || ""), undefined, { sensitivity: "base", numeric: true }),
    expiry: (a, b) => {
      const ea = a.idInfo?.expiry || "", eb = b.idInfo?.expiry || "";
      if (ea && eb) return ea.localeCompare(eb);
      if (ea || eb) return ea ? -1 : 1;
      return time(b) - time(a);
    },
  }[sort] || ((a, b) => time(b) - time(a));
  return items
    .map((it, n) => ({ it, n }))
    .sort((x, y) => (!!y.it.pinned - !!x.it.pinned) || by(x.it, y.it) || x.n - y.n)
    .map((x) => x.it);
}
