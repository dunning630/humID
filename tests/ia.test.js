// Information architecture of the app (apps/mobile/src): the words people read and the
// way sheets are dispatched. Static checks on the source, so they need no browser.
//   - no user-facing text in the screens uses the crypto or internal names (one word per concept)
//   - every sheet type is rendered by exactly one place, so two sheets can never open at once
//     (the recovery card sheet and the payment card sheet used to share the type "card")
//   - the tab bar has three tabs, and "security"/"settings" are gone from the tab ids
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const src = fileURLToPath(new URL("../apps/mobile/src/", import.meta.url));
const screens = readdirSync(`${src}screens`).filter((f) => f.endsWith(".jsx")).map((f) => `screens/${f}`);
const files = [...screens, "ui.jsx", "main.jsx"];
const read = (f) => readFileSync(`${src}${f}`, "utf8");

/** The source without its comments: what's left is code and the text people see. */
const noComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/[^\n]*/g, "$1");

const JARGON = /ML-KEM|ML-DSA|HTP\/1|AES-256|step-up|Biological interrupt|seal card/;

test("no user-facing string in the screens uses crypto or internal jargon", () => {
  const hits = [];
  for (const f of files) {
    noComments(read(f)).split("\n").forEach((line, i) => { if (JARGON.test(line)) hits.push(`${f}:${i + 1}: ${line.trim().slice(0, 120)}`); });
  }
  assert.deepEqual(hits, []);
});

test("the controller's toasts and prompts use the same words as the screens", () => {
  const s = noComments(read("core/controller.js"));
  // only string literals: the code itself may name things however it likes
  const strings = [...s.matchAll(/"((?:[^"\\]|\\.)*)"|`((?:[^`\\]|\\.)*)`/g)].map((m) => m[1] ?? m[2]);
  const bad = strings.filter((t) => /seal card|Seal card|HTP\/1|ML-KEM|ML-DSA|Something went wrong|\bPOC\b|biometric check|live check|recovery contact/.test(t));
  assert.deepEqual(bad, []);
});

test("every sheet type is rendered in exactly one place: the recovery card and payment card sheets can't open together", () => {
  const where = new Map(); // type → files that render it
  for (const f of files) {
    for (const m of noComments(read(f)).matchAll(/sheet\?\.type === "([a-zA-Z]+)"/g)) {
      if (!where.has(m[1])) where.set(m[1], new Set());
      where.get(m[1]).add(f);
    }
  }
  const shared = [...where].filter(([, fs]) => fs.size > 1).map(([t, fs]) => `${t}: ${[...fs].join(", ")}`);
  assert.deepEqual(shared, [], "a sheet type rendered from more than one file");
  assert.deepEqual([...where.get("card")], ["main.jsx"], "the payment card sheet");
  assert.deepEqual([...where.get("recoveryCard")], ["screens/you.jsx"], "the recovery card sheet");
  // and the controller opens the recovery card under its own type
  assert.match(read("core/controller.js"), /type: "recoveryCard"/);
  assert.doesNotMatch(noComments(read("core/controller.js")), /S\.sheet\.value = \{ type: "card"/);
});

test("three tabs: Vault, Activity, You", async () => {
  const ui = read("ui.jsx");
  const tabs = [...ui.matchAll(/\{ id: "([a-z]+)", label: "([A-Za-z]+)"/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(tabs, [["vault", "Vault"], ["activity", "Activity"], ["you", "You"]]);
  assert.match(ui, /role="tablist"/);
  assert.match(ui, /role="tab" aria-selected=/);
  for (const f of [...files, "core/controller.js", "core/back.js", "core/prefs.js"]) {
    assert.doesNotMatch(noComments(read(f)), /tab\.value = "(security|settings)"|=== "(security|settings)"/, `${f} still routes to an old tab id`);
  }
});

test("the check overlay names itself plainly and takes focus", () => {
  const ui = read("ui.jsx");
  assert.match(ui, /"Checking it's you"/);
  assert.match(ui, /class="interrupt"[^\n]*tabIndex=\{-1\}/);
});

test("the progress steppers say the three plain stages", () => {
  const ui = read("ui.jsx");
  assert.match(ui, /SEAL_STEPS = \["Sealing on this phone", "Sending", "Stored"\]/);
  for (const f of screens) assert.doesNotMatch(read(f), /steps=\{\[/, `${f} has its own stepper labels`);
});
