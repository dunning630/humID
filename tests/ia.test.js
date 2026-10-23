// Information architecture of the 3.0 app (apps/mobile/src): the words people read, the
// way screens are dispatched, and the boundaries that keep the app small. Static checks on
// the source, so they need no browser.
//   - no user-facing text uses crypto or internal names (one word per concept), and "check"
//     means the biometric only (Heartbeat, match code)
//   - screens talk to the kernel only through core/index.js and the few leaf modules
//   - every pushed-screen type and every sheet type is rendered by exactly one file
//   - three tabs; the check overlay names itself and takes focus
//   - no font files, no backdrop-filter, no console output, no clipboard writes
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const src = fileURLToPath(new URL("../apps/mobile/src/", import.meta.url));
const walk = (dir, out = []) => { for (const n of readdirSync(dir)) { const p = join(dir, n); statSync(p).isDirectory() ? walk(p, out) : out.push(p); } return out; };
const rel = (p) => relative(src, p).replaceAll("\\", "/");
const all = walk(src).map(rel).filter((f) => !f.startsWith("favicon/") && !f.startsWith("sim/"));
const screens = all.filter((f) => f.startsWith("screens/") && f.endsWith(".jsx"));
const ui = all.filter((f) => f.startsWith("ui/") && f.endsWith(".jsx"));
const faces = [...screens, ...ui, "main.jsx"];
const read = (f) => readFileSync(`${src}${f}`, "utf8");
const noComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/[^\n]*/g, "$1");

const JARGON = /ML-KEM|ML-DSA|HTP\/1|AES-256|step-up|Biological interrupt|seal card|recovery contact/;

test("no user-facing string in the screens uses crypto or internal jargon", () => {
  const hits = [];
  for (const f of faces) noComments(read(f)).split("\n").forEach((line, i) => { if (JARGON.test(line)) hits.push(`${f}:${i + 1}: ${line.trim().slice(0, 120)}`); });
  assert.deepEqual(hits, []);
});

test("one vocabulary: 'check' is the biometric; the timer is Heartbeat, the comparison is a match code", () => {
  const hits = [];
  for (const f of faces) {
    noComments(read(f)).split("\n").forEach((line, i) => {
      if (/Check-in|check-in|Account check|account check|Admin check|Check in by/.test(line)) hits.push(`${f}:${i + 1}: ${line.trim().slice(0, 120)}`);
    });
  }
  assert.deepEqual(hits, []);
  const lock = read("screens/lock.jsx") + read("screens/welcome.jsx");
  assert.match(lock, /password/i, "Welcome and Lock say that no password exists");
  // the duress unlock says what it is: "safe mode" sounded like the safer choice (APP-06)
  for (const f of faces) assert.doesNotMatch(noComments(read(f)), /safe mode/i, `${f} calls the duress unlock "safe mode"`);
});

// The honest promise (overnight review, Oct 2026): what the app and the documents an assessor
// reads first must not claim. Any enrolled face or finger opens a phone, two-proof recovery
// opens a vault, a computer's checks aren't chip-proven, and HumID does no liveness detection
// of its own: it relies on the phone's matcher.
const OVERCLAIM = [
  [/only your (live )?face or fingerprint/i, "any face or finger enrolled on the phone, and two-proof recovery, open it too"],
  [/living you|a live you\b/i, "a biometric match proves an enrolled face or finger, not a living person"],
  [/proven by your phone's (secure )?chip/i, "not on a computer or in the web app: say it only where the device's own assurance is hardware (ui/labels.js)"],
  [/zero[- ]knowledge/i, "the vault is end-to-end encrypted storage, not a zero-knowledge proof system"],
  [/verified human|liveness detection(?! of its own)(?!;)|live human ✓/i, "HumID performs no liveness detection; it proves a biometric match on a proven phone"],
  [/for your eyes only/i, "anyone the phone's owner enrolled can open it"],
];
const userText = (f) => noComments(read(f));
const DOCS = ["README.md", "docs/SECURITY.md", "docs/ARCHITECTURE.md"];
const docText = (f) => readFileSync(fileURLToPath(new URL(`../${f}`, import.meta.url)), "utf8");

test("no screen, toast or first-read document overclaims the promise", () => {
  const hits = [];
  const core = all.filter((x) => x.startsWith("core/") && x.endsWith(".js"));
  for (const f of [...faces, ...core, "ui/labels.js"]) userText(f).split("\n").forEach((line, i) => {
    for (const [re, why] of OVERCLAIM) if (re.test(line)) hits.push(`${f}:${i + 1}: ${why}: ${line.trim().slice(0, 100)}`);
  });
  for (const f of DOCS) docText(f).split("\n").forEach((line, i) => {
    // a doc may name a claim in order to deny it ("not a zero-knowledge proof system", "no additional liveness detection")
    if (/\bnot\b|\bno\b|n't|never/i.test(line)) return;
    for (const [re, why] of OVERCLAIM) if (re.test(line)) hits.push(`${f}:${i + 1}: ${why}: ${line.trim().slice(0, 100)}`);
  });
  assert.deepEqual(hits, []);
});

test("a past proof is described by the device that made it, not by this one (APP-09)", () => {
  const a = noComments(read("screens/activity.jsx"));
  assert.doesNotMatch(a, /S\.session\.value\?\.assurance/, "Activity reads the viewing device's assurance for past events");
  assert.match(a, /eventProof\(e\)/);
  // the chip claim is made only where the device's assurance is known to be hardware
  for (const f of faces) {
    for (const [i, line] of noComments(read(f)).split("\n").entries()) {
      if (/this phone's (secure )?chip/i.test(line)) assert.match(line, /hardware|mine/, `${f}:${i + 1} claims this phone's chip unconditionally`);
    }
  }
});

test("screens reach the kernel only through core/index.js (and a few leaf modules)", () => {
  const LEAVES = new Set(["index.js", "state.js", "config.js", "categories.js", "addroute.js", "capture.js", "scan.js", "docfind.js", "barcodefind.js", "sealtime.js", "place.js", "docscan.js", "nfc.js", "external.js", "prefs.js", "back.js", "guide.js", "guidecap.js", "mrzseed.js",
    // 4.0: the Messages screens load the messaging kernel with their own chunk, so the
    // protocol code never reaches the first paint (core/index.js says so)
    "messaging.js"]);
  const bad = [];
  for (const f of [...screens, ...ui]) {
    for (const m of noComments(read(f)).matchAll(/from "((?:\.\.\/)+core\/[^"]+)"/g)) {
      const name = m[1].split("/").pop();
      if (!LEAVES.has(name)) bad.push(`${f} imports ${m[1]}`);
    }
    assert.doesNotMatch(noComments(read(f)), /controller\.js|\.\.\/ui\.jsx|\.\.\/icons\.jsx|\.\.\/brand\.jsx/, `${f} imports a 2.x shell file`);
  }
  assert.deepEqual(bad, []);
  // and the kernel's internals never import a screen
  for (const f of all.filter((x) => x.startsWith("core/"))) assert.doesNotMatch(noComments(read(f)), /from "\.\.\/screens\//, `${f} imports a screen`);
});

test("the viewer calls no hook after an early return (APP-08: a hooks-order bug kept a stale question)", () => {
  const v = noComments(read("screens/vault.jsx"));
  const body = v.slice(v.indexOf("export function Viewer()"), v.indexOf("\n}\n", v.indexOf("export function Viewer()")));
  assert.ok(body.length > 50);
  assert.doesNotMatch(body, /\buse[A-Z]\w*\(/, "Viewer() returns early by kind, so it must not call hooks; FileViewer holds the state");
  assert.match(v, /<FileViewer key=\{/);
});

test("every pushed-screen type and every sheet type is rendered in exactly one place", () => {
  const where = (re) => {
    const m = new Map();
    for (const f of faces) for (const h of noComments(read(f)).matchAll(re)) { if (!m.has(h[1])) m.set(h[1], new Set()); m.get(h[1]).add(f); }
    return m;
  };
  const sheets = where(/sheet\?\.type === "([a-zA-Z]+)"/g);
  const shared = [...sheets].filter(([, fs]) => fs.size > 1).map(([t, fs]) => `${t}: ${[...fs].join(", ")}`);
  assert.deepEqual(shared, [], "a sheet type rendered from more than one file");
  // pushed screens: main.jsx owns add and item; You owns its own set
  const main = noComments(read("main.jsx"));
  assert.match(main, /push\?\.type === "add"/);
  assert.match(main, /push\?\.type === "item"/);
  const you = noComments(read("screens/you/index.jsx"));
  for (const t of ["protect", "devices", "recovery", "duress", "heartbeat", "help", "settings", "about"]) assert.match(you, new RegExp(`\\b${t}\\b`), `You routes ${t}`);
  for (const f of faces) assert.doesNotMatch(noComments(read(f)), /\bAddSheet\b|\bIdSheet\b|type: "id"|type: "card"/, `${f} still names a 1.x add sheet`);
});

test("tabs: Vault, Messages (only with a relay), Activity, You; and the add flow asks what it is first", () => {
  const kit = read("ui/kit.jsx");
  const tabs = [...kit.matchAll(/\{ id: "([a-z]+)", label: "([A-Za-z]+)"/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(tabs, [["vault", "Vault"], ["messages", "Messages"], ["activity", "Activity"], ["you", "You"]]);
  assert.match(kit, /id: "messages"[^\n]*when: \(\) => S\.messagingOn\.value/, "Messages shows only when the server runs a relay");
  assert.match(kit, /role="tablist"/);
  assert.match(kit, /role="tab" aria-selected=/);
  for (const f of [...faces, ...all.filter((x) => x.startsWith("core/"))]) {
    assert.doesNotMatch(noComments(read(f)), /tab\.value = "(security|settings)"|=== "(security|settings)"/, `${f} still routes to an old tab id`);
  }
  const add = noComments(read("screens/add/index.jsx"));
  assert.match(add, /What are you adding\?/, "the picker");
  assert.match(add, /: \{ at: "pick" \}\)/, "Add opens on the picker (3.0.1)");
  assert.doesNotMatch(add, /\bnative\b/, "the phone's own document scanner (and its four-point outline) isn't used to add");
  assert.doesNotMatch(noComments(read("screens/add/ids.jsx")), /\bnative=/, "nor for IDs");
  assert.doesNotMatch(noComments(read("screens/add/camera.jsx")), /dc-outline|<polygon/, "no four-point outline is drawn");
});

test("the check overlay names itself plainly and takes focus; steppers say the three plain stages", () => {
  const kit = read("ui/kit.jsx");
  assert.match(kit, /"Checking it's you"/);
  assert.match(kit, /class="interrupt"[^\n]*tabIndex=\{-1\}/);
  assert.match(kit, /SEAL_STEPS = \["Sealing on this phone", "Sending", "Stored"\]/);
  for (const f of screens) assert.doesNotMatch(read(f), /steps=\{\[/, `${f} has its own stepper labels`);
});

test("the brand is one token file; no font files; nothing filters or blurs what scrolls", () => {
  const css = all.filter((f) => f.endsWith(".css")).map((f) => [f, read(f)]);
  for (const [f, raw] of css) {
    const t = noComments(raw);
    assert.doesNotMatch(t, /@font-face|\.woff2?/, `${f} ships a font`);
    assert.doesNotMatch(t, /backdrop-filter/, `${f} uses backdrop-filter`);
    if (f !== "brand/tokens.css") assert.doesNotMatch(t, /#[0-9a-fA-F]{6}\b/, `${f} hard-codes a colour (use a token)`);
  }
  const tokens = read("brand/tokens.css");
  for (const c of ["#F5A623", "#6FE3B4", "#0B1410"]) assert.match(tokens, new RegExp(c), `the official ${c} is a token`);
  assert.match(tokens, /--f-ui: -apple-system/, "the system typeface");
  assert.doesNotMatch(read("main.jsx"), /fonts\.css|styles\/app\.css/);
});

test("nothing in the app logs, copies to the clipboard, or phones home", () => {
  const bad = [];
  for (const f of all.filter((x) => /\.(jsx?|mjs)$/.test(x) && !x.startsWith("sim/"))) {
    const t = noComments(read(f));
    if (/console\./.test(t)) bad.push(`${f}: console`);
    if (/clipboard\.write|execCommand\("copy"\)/.test(t)) bad.push(`${f}: clipboard`);
    if (/https?:\/\/(?!localhost|127\.0\.0\.1)[a-z0-9.-]+\.[a-z]{2,}/i.test(t) && !/external\.js|place\.js|about\.jsx|create\.jsx/.test(f)) bad.push(`${f}: a hard-coded URL`);
  }
  assert.deepEqual(bad, []);
});
