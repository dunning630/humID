// Settings (apps/mobile/src/core/prefs.js): stored preferences are always valid, can't
// stretch auto-lock past 5 minutes, and the vault order keeps pinned items on top.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitize, loadPrefs, savePrefs, applyPrefs, sortItems, DEFAULTS, MAX_IDLE_MS, IDLE_CHOICES, idleLabel } from "../apps/mobile/src/core/prefs.js";

const memory = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), m }; };

test("defaults: night theme, 5-minute lock", () => {
  assert.deepEqual(sanitize(null), { ...DEFAULTS });
  assert.equal(DEFAULTS.idleMs, MAX_IDLE_MS);
  assert.equal(MAX_IDLE_MS, 5 * 60_000);
});

test("auto-lock can only be shortened: anything longer or odd falls back to 5 minutes", () => {
  for (const ms of IDLE_CHOICES) assert.equal(sanitize({ idleMs: ms }).idleMs, ms);
  for (const bad of [10 * 60_000, 3_600_000, Infinity, 0, -1, 30_000, "60000", null]) assert.equal(sanitize({ idleMs: bad }).idleMs, MAX_IDLE_MS, String(bad));
  assert.ok(Math.max(...IDLE_CHOICES) <= MAX_IDLE_MS);
});

test("tampered or unknown values are replaced, unknown keys dropped (startTab is gone: the app always opens on the vault)", () => {
  const p = sanitize({ startTab: "settings", theme: "neon", text: 99, motion: "no", haptics: 0, sort: "random", expiryWarnDays: 7, evil: "<script>", __proto__: { idleMs: 1e9 } });
  assert.deepEqual(p, { ...DEFAULTS });
  assert.equal("evil" in p, false);
  assert.equal("startTab" in p, false);
  assert.deepEqual(sanitize([1, 2]), { ...DEFAULTS });
});

test("saved and loaded on this device; broken or missing storage gives defaults", () => {
  const s = memory();
  savePrefs({ ...DEFAULTS, theme: "light", idleMs: 60_000, sort: "name" }, s);
  assert.deepEqual(loadPrefs(s), { ...DEFAULTS, theme: "light", idleMs: 60_000, sort: "name" });
  s.m.set("humid.prefs.v1", "{not json");
  assert.deepEqual(loadPrefs(s), { ...DEFAULTS });
  const refusing = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } };
  assert.deepEqual(loadPrefs(refusing), { ...DEFAULTS });
  assert.equal(savePrefs({ theme: "light" }, refusing).theme, "light", "still applies for this session");
  assert.deepEqual(loadPrefs(undefined), { ...DEFAULTS });
});

test("the look is put on the page as data attributes", () => {
  const root = { dataset: {} };
  applyPrefs({ ...DEFAULTS, theme: "light", text: "large", motion: false }, root);
  assert.deepEqual(root.dataset, { theme: "light", text: "large", motion: "reduced" });
  applyPrefs({ ...DEFAULTS }, root);
  assert.deepEqual(root.dataset, { theme: "dark", text: "standard", motion: "full" });
});

test("vault order: pinned first, then the chosen order", () => {
  const items = [
    { id: "a", name: "Zeta lease", uploadedAt: "2026-01-03T00:00:00Z" },
    { id: "b", name: "alpha deed", uploadedAt: "2026-01-01T00:00:00Z", pinned: true },
    { id: "c", name: "Passport", uploadedAt: "2026-01-02T00:00:00Z", idInfo: { expiry: "2030-05-01" } },
    { id: "d", name: "License", uploadedAt: "2026-01-04T00:00:00Z", idInfo: { expiry: "2027-02-01" } },
    { id: "e", name: "item 10", uploadedAt: "2026-01-05T00:00:00Z" },
    { id: "f", name: "item 9", uploadedAt: "2026-01-05T00:00:00Z" },
  ];
  const ids = (s) => sortItems(items, s).map((i) => i.id).join("");
  assert.equal(ids("newest"), "befdac", "equal times keep their order");
  assert.equal(ids("oldest"), "bcadef");
  assert.equal(ids("name"), "bfedca", "case-insensitive, numbers in order");
  assert.equal(ids("expiry"), "bdcefa", "IDs by expiry, soonest first, then the rest newest first");
  assert.equal(ids("bogus"), ids("newest"));
  assert.notEqual(sortItems(items), items, "a new array; the original isn't reordered");
  assert.equal(items[0].id, "a");
});

test("labels", () => {
  assert.equal(idleLabel(60_000), "1 minute");
  assert.equal(idleLabel(MAX_IDLE_MS), "5 minutes");
});

test("first launch follows the device's reduce-motion setting; a choice, once made, wins", () => {
  const s = memory();
  assert.equal(loadPrefs(s, true).motion, false, "nothing chosen yet: reduced motion on the device turns animations off");
  assert.equal(loadPrefs(s, false).motion, true);
  savePrefs({ ...DEFAULTS, motion: true }, s);
  assert.equal(loadPrefs(s, true).motion, true, "the person chose animations: the device setting no longer overrides");
  savePrefs({ ...DEFAULTS, motion: false }, s);
  assert.equal(loadPrefs(s, false).motion, false);
});
