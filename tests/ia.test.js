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
// Windows checks files out with CRLF line endings; the checks below look for "\n}\n" and the like.
const read = (f) => readFileSync(`${src}${f}`, "utf8").replace(/\r\n/g, "\n");
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

/** The quoted strings and JSX text on each line of the screens, the kit and the kernel. */
function strings() {
  const out = [];
  const files = [...faces, ...all.filter((x) => x.startsWith("core/") && x.endsWith(".js")), "ui/labels.js"];
  for (const f of files) noComments(read(f)).split("\n").forEach((line, i) => {
    const s = [...line.matchAll(/"((?:[^"\\]|\\.)*)"|`([^`]*)`|>([^<>{}]+)</g)].map((m) => m[1] ?? m[2] ?? m[3]).join(" | ");
    if (s) out.push([`${f}:${i + 1}`, s]);
  });
  return out;
}

test("one vocabulary: the act is a 'live check'; helpers are witnesses; the duress unlock is the duress gesture", () => {
  const RULES = [
    // "a check", "one check", "a fresh check", "a face or fingerprint check" → "a live check" (app.md 3b)
    [/\b(?:a|one|its own|another|fresh|biometric) (?:face or fingerprint )?check\b(?![- ]?(?:in|box|list|ed|s)\b)/i, 'say "live check"'],
    [/(?<!live )face or fingerprint check/i, 'say "live check" (or "face or fingerprint match")'],
    [/biometric check/i, 'say "live check"'],
    [/\b(?:recovery |older )contacts\b/i, 'the people are "witnesses"'],
    [/duress unlock/i, 'say "the duress gesture"'],
    [/one of (?:the )?two (?:things|proofs)/i, "use RECOVERY_RULE / CARD_IS_ONE (ui/labels.js)"],
  ];
  const hits = [];
  for (const [where, s] of strings()) for (const [re, why] of RULES) if (re.test(s)) hits.push(`${where}: ${why}: ${s.slice(0, 110)}`);
  assert.deepEqual(hits, []);
});

test("label maps live once, in ui/labels.js (gate methods, how a device joined, recovery proofs)", () => {
  for (const f of [...faces, ...all.filter((x) => x.startsWith("core/") && x.endsWith(".js"))]) {
    const t = noComments(read(f));
    assert.doesNotMatch(t, /"ios-keychain-biometry":/, `${f} has its own gate-method names`);
    assert.doesNotMatch(t, /\{ register: "/, `${f} has its own "via" names`);
    assert.doesNotMatch(t, /\bquorum: "(?:t|T)wo proofs"/, `${f} has its own recovery-method names`);
    assert.doesNotMatch(t, /\{ witness: "witnesses"/, `${f} has its own proof-kind names`);
  }
  const labels = read("ui/labels.js");
  for (const k of ["gateName", "gateLabel", "gateDetail", "VIA", "RECOVERY_METHOD", "PROOF_KIND", "RECOVERY_RULE", "CARD_IS_ONE", "proofsSetUp"]) assert.match(labels, new RegExp(`export (?:const|function) ${k}\\b`));
  // ui/labels.js is words only: the kernel may import it, it imports nothing of the kernel's but state
  assert.doesNotMatch(noComments(labels), /from "\.\.\/core\/(?!state\.js)/);
  // the recovery proof count: the same sentence on create, Protection and Recovery
  for (const f of ["screens/create.jsx", "screens/you/protect.jsx", "screens/you/recovery.jsx"]) assert.match(read(f), /RECOVERY_RULE|RECOVERY_IF_LOST|CARD_IS_ONE/, `${f} says the recovery rule in its own words`);
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
const docText = (f) => readFileSync(fileURLToPath(new URL(`../${f}`, import.meta.url)), "utf8").replace(/\r\n/g, "\n");

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

test("the first paint's kernel never imports setting up, joining or recovery (R12: they load with their screens)", () => {
  const LAZY = ["enroll.js", "join.js", "recovery.js", "recmode.js", "seckey.js", "operators.js"];
  // what core/index.js reaches statically, module by module
  const seen = new Set(), stack = ["core/index.js"];
  while (stack.length) {
    const f = stack.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    for (const m of noComments(read(f)).matchAll(/(?:^|\n)\s*(?:import|export)\b[^;]*?from "(\.{1,2}\/[^"]+)"/g)) {
      const p = new URL(m[1], `file:///${f}`).pathname.slice(1);
      if (all.includes(p)) stack.push(p);
    }
  }
  assert.deepEqual(LAZY.filter((x) => seen.has(`core/${x}`)), [], "reached from core/index.js");
  assert.ok(seen.has("core/session.js") && seen.has("core/alerts.js"), "the walk found the kernel");
  // and the first-paint screens use only core/index.js
  for (const f of ["main.jsx", "screens/welcome.jsx", "screens/lock.jsx", "screens/vault.jsx", "ui/kit.jsx", "ui/shell.jsx"]) assert.doesNotMatch(read(f), /core\/setup\.js/, `${f} pulls core/setup.js into the first paint`);
});

test("small things the first paint and every second don't pay for (R12)", () => {
  // the web icon is a vector of the mark, not a 55 KB trace
  const fav = readFileSync(`${src}favicon/favicon.svg`, "utf8");
  assert.ok(fav.length < 3072, `favicon.svg is ${fav.length} bytes`);
  assert.doesNotMatch(fav, /<image|base64/, "no embedded raster");
  for (const c of ["#0B1410", "#F5A623", "#6FE3B4"]) assert.match(fav, new RegExp(c), `the mark's ${c}`);
  // the viewer's "Open for N s" ticks in its own leaf, not the whole document every second
  const v = noComments(read("screens/vault.jsx"));
  const shell = v.slice(v.indexOf("function ViewerShell("), v.indexOf("\n}\n", v.indexOf("function ViewerShell(")));
  assert.doesNotMatch(shell, /useNow\(/, "ViewerShell re-renders every second");
  assert.match(v, /function OpenFor\(/);
  // Activity describes its entries once per ledger page
  const a = noComments(read("screens/activity.jsx"));
  assert.match(a, /useMemo\(\(\) => \{[\s\S]*describe\(e, l\.names\)[\s\S]*\}, \[l\]\)/);
  // boot: the independent reads run together once the store is open
  const sess = noComments(read("core/session.js"));
  const boot = sess.slice(sess.indexOf("export async function boot()"), sess.indexOf("\n}\n", sess.indexOf("export async function boot()")));
  assert.match(boot, /Promise\.all\(\[\s*bestHardwareGate\(\)/);
});

test("screens reach the kernel only through core/index.js (and a few leaf modules)", () => {
  const LEAVES = new Set(["index.js", "setup.js", "state.js", "config.js", "categories.js", "addroute.js", "capture.js", "scan.js", "docfind.js", "barcodefind.js", "sealtime.js", "place.js", "doctpl.js", "doccam.js", "webcam.js", "nfc.js", "external.js", "prefs.js", "back.js", "mrzseed.js",
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
  // 5.0: the camera's own corners are drawn over a card or page until it lines up (they replace 3.0's lock box);
  // a Photo still gets no four-point outline over it
  const cam = noComments(read("screens/add/camera.jsx"));
  assert.doesNotMatch(cam, /dc-outline/, "no free-form outline");
  assert.equal([...cam.matchAll(/<polygon/g)].length, 1, "one polygon: the camera's corners");
  assert.match(cam, /\{guided && quad && live && <svg class="dc-quad"/, "only on a guided shape, while it is live");
});

test("the check overlay names itself plainly and takes focus; steppers say the three plain stages", () => {
  const kit = read("ui/kit.jsx");
  assert.match(kit, /"Checking it's you"/);
  assert.match(kit, /class="interrupt"[^\n]*tabIndex=\{-1\}/);
  assert.match(kit, /SEAL_STEPS = \["Sealing on this phone", "Sending", "Stored"\]/);
  for (const f of screens) assert.doesNotMatch(read(f), /steps=\{\[/, `${f} has its own stepper labels`);
});

test("every layer that takes the screen is modal: focus in, the rest inert, focus back (APP-12)", () => {
  const kit = noComments(read("ui/kit.jsx"));
  assert.match(kit, /export function useModal\(/);
  assert.match(kit, /\.inert = true/);
  for (const fn of ["Interrupt", "ChipReadOverlay", "Sheet", "Pushed"]) {
    const body = kit.slice(kit.indexOf(`export function ${fn}(`), kit.indexOf("\n}\n", kit.indexOf(`export function ${fn}(`)));
    assert.match(body, /useModal\(root/, `${fn} uses useModal`);
  }
  const v = noComments(read("screens/vault.jsx"));
  const shell = v.slice(v.indexOf("function ViewerShell("), v.indexOf("\n}\n", v.indexOf("function ViewerShell(")));
  assert.match(shell, /useModal\(root\)/, "the viewer uses useModal");
  assert.match(shell, /<section class="viewer"/, "the viewer is a section, so its header isn't a second page banner");
  // Welcome and Lock name the page
  for (const f of ["screens/welcome.jsx", "screens/lock.jsx"]) assert.match(read(f), /<h1 class="brand"><Wordmark/, `${f} has an h1`);
});

test("controls are the product's own 44 px: segmented controls, the search field, no inline min-height under it", () => {
  const css = noComments(read("brand/base.css"));
  assert.match(css, /\.seg button \{ min-height: var\(--tap\)/, ".seg buttons are 44 px");
  assert.doesNotMatch(css, /\.search input \{[^}]*min-height: 40px/);
  // (a link inside a sentence, like the location stamp's "Map", is exempt, as in WCAG 2.5.8)
  for (const f of faces) assert.doesNotMatch(noComments(read(f)).replace(/<button class="link" style=\{\{ minHeight: 0 \}\} type="button"/g, ""), /<button[^>]*minHeight: (?:[0-3]?\d|4[0-3])\b/, `${f} shrinks a button below 44 px`);
});

test("spacing is on the token grid: screens use the mt-/mb- utilities, never an off-grid inline margin", () => {
  const GRID = new Set([0, 4, 8, 12, 16, 20, 24, 32]);
  const bad = [], sole = [];
  for (const f of screens) noComments(read(f)).split("\n").forEach((line, i) => {
    for (const m of line.matchAll(/\bmargin(?:Top|Bottom|Left|Right): (\d+)\b/g)) if (!GRID.has(Number(m[1]))) bad.push(`${f}:${i + 1}: ${m[0]}`);
    // a margin alone in an element's style is what the utilities are for
    for (const m of line.matchAll(/<[a-z][a-z0-9]*\b[^<>]*\sstyle=\{\{ ?margin(?:Top|Bottom): ?\d+ ?\}\}/g)) sole.push(`${f}:${i + 1}: ${m[0].slice(0, 80)}`);
  });
  assert.deepEqual(bad, [], "off-grid margins");
  assert.deepEqual(sole, [], "use class mt-N / mb-N");
  const css = read("brand/base.css");
  for (const [k, v] of [["mt-1", "s-1"], ["mt-2", "s-2"], ["mt-3", "s-3"], ["mt-4", "s-4"], ["mt-5", "s-5"], ["mt-6", "s-6"], ["mb-2", "s-2"], ["mb-3", "s-3"]]) assert.match(css, new RegExp(`\\.${k} \\{ margin-(?:top|bottom): var\\(--${v}\\)`), `.${k} is --${v}`);
});

/** WCAG relative luminance contrast of two #rrggbb colours. */
function contrast(a, b) {
  const lum = (h) => { const c = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4)); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
/** `fg` at `alpha` over `bg`, as #rrggbb. */
const over = (fg, alpha, bg) => "#" + [1, 3, 5].map((i) => Math.round(parseInt(fg.slice(i, i + 2), 16) * alpha + parseInt(bg.slice(i, i + 2), 16) * (1 - alpha)).toString(16).padStart(2, "0")).join("");

test("light theme: mint text meets 4.5:1 on paper and on its own wash over every surface (axe, app review)", () => {
  const t = read("brand/tokens.css");
  const light = t.slice(t.indexOf(':root[data-theme="light"]'), t.indexOf("}", t.indexOf(':root[data-theme="light"]')));
  const v = (k) => new RegExp(`--${k}:\\s*(#[0-9A-Fa-f]{6})`).exec(light)[1];
  const mint = v("mint");
  const [, r, g, b, a] = /--mint-wash:\s*rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)/.exec(light);
  const washRgb = "#" + [r, g, b].map((n) => Number(n).toString(16).padStart(2, "0")).join("");
  assert.equal(washRgb.toLowerCase(), mint.toLowerCase(), "the wash is the mint itself, thinned");
  for (const s of ["ground", "surface", "surface-2", "surface-3"]) {
    assert.ok(contrast(mint, v(s)) >= 4.5, `mint on --${s}: ${contrast(mint, v(s)).toFixed(2)}`);
    const wash = over(mint, Number(a), v(s));
    assert.ok(contrast(mint, wash) >= 4.5, `mint on its wash over --${s}: ${contrast(mint, wash).toFixed(2)}`);
  }
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

// The recovery-mode copy the round-3 review caught overclaiming (verify-74b, V74B-02). Each
// phrasing made a promise the code doesn't keep: the passport piece is one the server CAN open
// (V74-03); switching to holder-only doesn't make old pieces stop fitting each other, and a new
// card doesn't make the old one stop working (V74-04); and a server that controls everything
// can show a phone that hasn't seen your latest choice an older one (V74B-01).
const RECOVERY_OVERCLAIM = [
  // ("locked so the server can't open it" is fine where the same line says the passport piece isn't)
  [/^(?!.*passport).*locked so (they|the servers?|HumID) can't open (it|them)/i, "the passport piece isn't locked against the server (V74-03)"],
  [/Only your own devices can open your vault now/i, "pieces made before the switch still fit each other (V74-04)"],
  [/the old one stops working/i, "an old card still fits the other pieces of its set; it only stops counting on the server (V74-04)"],
  [/so a server can't switch it on/i, "only as far as each device has seen (V74B-01)"],
  [/A server can't flip it quietly/i, "only as far as each device has seen (V74B-01)"],
  [/lp\(account id, mode, version, epoch\)/, "the statement names the one before it (prev)"],
];
const RECOVERY_DOCS = ["docs/RECOVERY.md", "docs/CONTINUITY.md", ".changeset/recovery-modes.md", ".changeset/recovery-mode-chain.md"];

test("recovery-mode copy says no more than the code keeps (V74B-02)", () => {
  const hits = [];
  const core = all.filter((x) => x.startsWith("core/") && x.endsWith(".js"));
  for (const f of [...faces, ...core, "ui/labels.js"]) userText(f).split("\n").forEach((line, i) => {
    for (const [re, why] of RECOVERY_OVERCLAIM) if (re.test(line)) hits.push(`${f}:${i + 1}: ${why}: ${line.trim().slice(0, 100)}`);
  });
  for (const f of RECOVERY_DOCS) docText(f).split("\n").forEach((line, i) => {
    for (const [re, why] of RECOVERY_OVERCLAIM) if (re.test(line)) hits.push(`${f}:${i + 1}: ${why}: ${line.trim().slice(0, 100)}`);
  });
  assert.deepEqual(hits, []);
  // and the changeset title says the limit
  assert.match(docText(".changeset/recovery-mode-chain.md"), /rolled back below what each device has seen/);
  // RECOVERY.md states the piece-making rule and its per-device limit
  const rec = docText("docs/RECOVERY.md");
  assert.match(rec, /### When a phone makes recovery pieces/);
  assert.match(rec, /lp\(account id, mode, u32 version, u32 epoch, prev\)/);
  assert.match(rec, /can't prove "nothing newer"/);
});
