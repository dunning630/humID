// How long does a person wait between the camera taking the picture and being back in the
// app (the review screen)? A repeatable measurement in Chromium, with a phone-sized fake
// camera, a throttled CPU and the app's own development-build trace.
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium     (or link a local copy)
//   python3 tests/bench/make-4k-fixtures.py $OUT/fixtures
//   node tests/bench/capture.mjs                       every scenario, 3 runs each, 4x CPU throttle
//   node tests/bench/capture.mjs photo passport        only these
//   RUNS=5 THROTTLE=6 LABEL=after OUT=/some/dir PORT=5333 node tests/bench/capture.mjs
//   PROFILE=1 …                                        also one profiled run per scenario (top functions)
//
// What it measures, per scenario and run (ms, medians and spread are printed at the end and
// written to $OUT/<LABEL>.json):
//   - "shoot" is the app's own trace event for the shutter or the auto-capture (the trace
//     helper in ids.jsx; development builds only, timings, never pictures or text);
//   - "ready" is when the screen the person is waiting for is on screen (the review, the
//     next camera's tick, the chip step), watched by a MutationObserver in the page;
//   - "long" is the main-thread time spent in tasks over 50 ms between the two (the page
//     frozen: no tap or scroll answered);
//   - the trace's own marks in between (develop, developed, kept…) and span marks from
//     core/perf.js, so a slow stage shows up by name.
// The sandbox CPU is not a phone: throttling 4x makes it a rough stand-in. Read the numbers
// as relative (before against after), not as what a phone will show.
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5333);
const BASE = `http://tauri.localhost:${PORT}`;
const RUNS = Number(process.env.RUNS || 3);
const THROTTLE = Number(process.env.THROTTLE || 4);
const LABEL = process.env.LABEL || "run";
const OUT = process.env.OUT || join(root, "tests/bench/out");
const FIX = process.env.FIXTURES || join(OUT, "fixtures");
const PROFILE = process.env.PROFILE === "1";
mkdirSync(OUT, { recursive: true });
if (!existsSync(join(FIX, "camera-letter-4k.mjpeg"))) throw new Error(`no fixtures in ${FIX}: python3 tests/bench/make-4k-fixtures.py ${FIX}`);
const profile = mkdtempSync(join(tmpdir(), "humid-bench-"));
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: bench timed out"); process.exit(1); }, 50 * 60_000).unref();
const contexts = [];

const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), HUMID_NO_MINIFY: process.env.HUMID_NO_MINIFY ?? "1" }, stdio: ["ignore", "pipe", "pipe"] });
let devLog = "";
dev.stdout.on("data", (d) => { devLog += d; });
dev.stderr.on("data", (d) => { devLog += d; });
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${devLog}`)), 180_000);
  const check = setInterval(() => { if (/HumID dev:/.test(devLog)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
  dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${devLog}`)); });
});
step("dev server up");

/* ---------------- in the page: what to watch ---------------- */

const WATCH = () => {
  const B = (globalThis.__bench = { ev: [], long: [], seen: new Set() });
  const t = () => Math.round(performance.now() * 10) / 10;
  B.mark = (k) => { if (!B.seen.has(k)) { B.seen.add(k); B.ev.push([k, t()]); } };
  B.reset = () => { B.ev = []; B.long = []; B.seen = new Set(); globalThis.__humidTrace = { ev: [] }; };
  try { new PerformanceObserver((l) => { for (const e of l.getEntries()) B.long.push([Math.round(e.startTime), Math.round(e.duration)]); }).observe({ entryTypes: ["longtask"] }); } catch { /* no long-task support */ }
  const q = (s) => document.querySelector(s);
  const check = () => {
    const img = q(".photo-preview img");
    if (img && img.complete && img.naturalWidth) B.mark("ui:photo-img");
    if (q(".dc-saved-chip")) B.mark("ui:saved-chip");
    if ([...document.querySelectorAll(".pushed h2")].some((h) => h.textContent === "Check the details")) B.mark("ui:check-details");
    if (q("#doc-num")) B.mark("ui:chip-step");
    if (B.sawCam && !q(".doccam")) B.mark("ui:camera-gone");
    if (q(".doccam")) B.sawCam = true;
    if (q(".interrupt .hold")) B.mark("ui:hold-prompt");
    if (q(".item[data-kind]")) B.mark("ui:item");
  };
  new MutationObserver(check).observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: ["src", "class", "data-phase"] });
  document.addEventListener("load", check, true);
};

/** The phone's document scanner, stood in: hands back the page in __scanData after a beat. */
const STANDIN = () => {
  globalThis.__humidFakeScanner = {
    async invoke(cmd) {
      if (cmd !== "scan") return { available: true };
      await new Promise((r) => setTimeout(r, 150));
      const d = globalThis.__scanData;
      globalThis.__bench.mark("scanner-returned");
      globalThis.__humidTrace ||= { ev: [] };
      globalThis.__humidTrace.ev.push(["scanner-returned", Math.round(performance.now()), null]);
      return { data: d.data, mime: "image/jpeg", width: d.width, height: d.height };
    },
  };
};

async function launch(cameraFile, { scanner = false } = {}) {
  const ctx = await chromium.launchPersistentContext(profile, {
    headless: true,
    viewport: { width: 412, height: 915 },
    deviceScaleFactor: 2,
    permissions: ["camera", "geolocation", "clipboard-read", "clipboard-write"],
    geolocation: { latitude: 41.914513, longitude: -88.308721, accuracy: 14 },
    args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", `--use-file-for-fake-video-capture=${cameraFile}`,
      "--host-resolver-rules=MAP tauri.localhost 127.0.0.1", `--unsafely-treat-insecure-origin-as-secure=${BASE}`],
  });
  contexts.push(ctx);
  const page = ctx.pages()[0] || await ctx.newPage();
  await page.addInitScript(WATCH);
  if (scanner) await page.addInitScript(STANDIN);
  page.on("pageerror", (e) => console.error("page error:", e.message));
  return { ctx, page };
}

async function hold(page, ms = 1500) {
  const b = page.locator(".interrupt .hold");
  await b.waitFor({ timeout: 30_000 });
  await b.focus();
  await page.keyboard.down(" ");
  await page.waitForTimeout(ms);
  await page.keyboard.up(" ");
}

async function enroll() {
  const { ctx, page } = await launch(join(FIX, "camera-letter-4k.mjpeg"));
  await page.goto(BASE);
  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByRole("button", { name: "Use a demo access code" }).click({ timeout: 30_000 });
  await page.getByText("Access pass ready").first().waitFor({ timeout: 60_000 });
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel(/Only I use/).check();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  const ask = await page.locator('label[for="card-check"]').innerText();
  const groups = await page.locator(".cardcode span").allInnerTexts();
  await page.fill("#card-check", groups[Number(/group (\d+)/.exec(ask)[1]) - 1]);
  await page.getByRole("button", { name: "I've saved it" }).click();
  await page.getByRole("button", { name: "Open my vault" }).click();
  await page.locator(".item, .empty, button.fab").first().waitFor({ timeout: 30_000 }).catch(() => {});
  await ctx.close();
  step("enrolled");
}

/** A fresh page, unlocked, CPU throttled, the watchers reset. */
async function session(camera, opts = {}) {
  const { ctx, page } = await launch(camera, opts);
  await page.goto(BASE);
  try {
  await page.getByRole("button", { name: /^Unlock$/ }).click();
  await hold(page);
  await page.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 30_000 });
  } catch (e) { if (process.env.SHOTS) await page.screenshot({ path: join(process.env.SHOTS, "fail-session.png") }); throw e; }
  await page.waitForTimeout(800);
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: THROTTLE });
  await page.evaluate(() => globalThis.__bench.reset());
  return { ctx, page, cdp };
}

const openAdd = async (page) => {
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".pushed").getByText("What are you adding?").waitFor({ timeout: 10_000 });
};
const pickKind = async (page, name) => {
  await openAdd(page);
  await page.locator(".pushed button.kind", { hasText: name }).click();
  await page.locator(".pushed [data-start-camera]").click();
};

/* ---------------- scenarios ---------------- */

// each: camera fixture, how to get to the capture, and which on-screen state ends the wait
const S = {
  // Add ▸ Photo, HumID's own camera, the page found and taken by itself
  photo: {
    camera: "camera-letter-4k.mjpeg",
    start: async (page) => pickKind(page, /^Photo/),
    ends: ["ui:photo-img"], settle: ".photo-preview img",
  },
  // driver's license front: the shutter pressed
  "license-front": {
    camera: "camera-license-back-4k.mjpeg",
    start: async (page) => { await pickKind(page, /Driver's license/); await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 60_000 }); await page.waitForTimeout(600); if (await page.locator(".dc-saved-chip").count() === 0) await page.locator(".doccam .dc-shutter:not([disabled])").click().catch(() => {}); },
    ends: ["ui:saved-chip"], settle: ".dc-saved-chip",
  },
  // …then the back: the barcode read live, then the check of the details
  "license-back": {
    camera: "camera-license-back-4k.mjpeg",
    start: async (page) => { await pickKind(page, /Driver's license/); await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 60_000 }); await page.waitForTimeout(600); if (await page.locator(".dc-saved-chip").count() === 0) await page.locator(".doccam .dc-shutter:not([disabled])").click().catch(() => {}); await page.locator(".dc-saved-chip").waitFor({ timeout: 90_000 }); await page.evaluate(() => globalThis.__bench.reset()); },
    ends: ["ui:check-details"], settle: ".pushed",
  },
  // passport: the machine-readable lines read live
  passport: {
    camera: "camera-passport-4k.mjpeg",
    start: async (page) => pickKind(page, /^Passport/),
    ends: ["ui:chip-step"], settle: "#doc-num", timeout: 240_000,
  },
  // Add ▸ Payment card: the front, photographed and its number read
  paycard: {
    camera: "camera-paycard-front-4k.mjpeg",
    start: async (page) => pickKind(page, /^Payment card/),
    ends: ["ui:check-details"], settle: ".pushed", timeout: 240_000,
  },
  // Android: the phone's own scanner hands back a 3200 px page; read here like any photo
  "scanner-page": {
    camera: "camera-empty.mjpeg", scanner: "scanner-page-3200.jpg",
    start: async (page) => pickKind(page, /^Photo/),
    ends: ["ui:photo-img"], settle: ".photo-preview img", from: "scanner-returned",
  },
  "scanner-passport": {
    camera: "camera-empty.mjpeg", scanner: "scanner-passport-3200.jpg",
    start: async (page) => pickKind(page, /^Photo/),
    ends: ["ui:chip-step", "ui:check-details", "ui:photo-img"], settle: ".pushed", from: "scanner-returned", timeout: 240_000,
  },
};
const cameraPath = (n) => (n === "camera-empty.mjpeg" ? join(root, "tests/fixtures/id/camera-empty.mjpeg") : join(FIX, n));

const median = (a) => { const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

/** Inclusive time per function in [t0, t1] (page ms) from a CDP CPU profile. */
function topFunctions(prof, offset, t0, t1, n = 22) {
  const byId = new Map(prof.nodes.map((x) => [x.id, x]));
  const parent = new Map();
  for (const x of prof.nodes) for (const c of x.children || []) parent.set(c, x.id);
  const incl = new Map(), self = new Map();
  let t = prof.startTime / 1000 - offset, total = 0;
  const name = (x) => { const f = x.callFrame; return `${f.functionName || "(anon)"} ${f.url.split("/").pop()}:${f.lineNumber + 1}`; };
  prof.samples.forEach((id, i) => {
    t += prof.timeDeltas[i] / 1000;
    if (t < t0 || t > t1) return;
    const dt = (prof.timeDeltas[i + 1] ?? prof.timeDeltas[i]) / 1000;
    total += dt;
    const seen = new Set();
    for (let k = id; k != null; k = parent.get(k)) { const nm = name(byId.get(k)); if (seen.has(nm)) continue; seen.add(nm); incl.set(nm, (incl.get(nm) || 0) + dt); }
    const sn = name(byId.get(id)); self.set(sn, (self.get(sn) || 0) + dt);
  });
  const rows = [...incl].filter(([k]) => !/^\((root|program|idle|garbage)/.test(k)).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ fn: k, incl: Math.round(v), self: Math.round(self.get(k) || 0) }));
  return { windowMs: Math.round(t1 - t0), sampledMs: Math.round(total), rows };
}

async function once(name, { profiled = false } = {}) {
  const sc = S[name];
  const { ctx, page, cdp } = await session(cameraPath(sc.camera), { scanner: !!sc.scanner });
  try {
    if (sc.scanner) {
      const data = readFileSync(join(FIX, sc.scanner)).toString("base64");
      await page.evaluate((data) => { globalThis.__scanData = { data, width: 0, height: 0 }; }, data);
    }
    if (profiled) {
      await cdp.send("Profiler.enable");
      await cdp.send("Profiler.setSamplingInterval", { interval: 250 });
      await cdp.send("Profiler.start");
    }
    await sc.start(page);
    const timeout = sc.timeout || 120_000;
    await page.waitForFunction((ends) => ends.some((k) => globalThis.__bench.seen.has(k)), sc.ends, { timeout, polling: 50 });
    await page.waitForTimeout(700); // whatever else the main thread was doing right after
    let profileOut = null;
    const data = await page.evaluate(() => ({ b: { ev: globalThis.__bench.ev, long: globalThis.__bench.long }, trace: globalThis.__humidTrace?.ev || [], now: performance.now() }));
    if (profiled) {
      const { profile: prof } = await cdp.send("Profiler.stop");
      profileOut = { prof, nowAtStop: data.now };
    }
    // the moment the wait begins
    const shoot = sc.from ? data.trace.find((e) => e[0] === sc.from) : data.trace.find((e) => /^shoot-/.test(e[0]));
    assert.ok(shoot, `no shoot event in the trace: ${JSON.stringify(data.trace.slice(0, 8))}`);
    const t0 = shoot[1];
    const endEv = data.b.ev.filter((e) => sc.ends.includes(e[0]) && e[1] >= t0 - 1).sort((a, b) => a[1] - b[1])[0];
    assert.ok(endEv, `never reached ${sc.ends}: ${JSON.stringify(data.b.ev)}`);
    const t1 = endEv[1];
    const long = data.b.long.filter(([s, d]) => s + d > t0 && s < t1).reduce((n, [s, d]) => n + Math.max(0, Math.min(s + d, t1) - Math.max(s, t0)), 0);
    const longest = Math.max(0, ...data.b.long.filter(([s, d]) => s + d > t0 && s < t1).map(([, d]) => d));
    const marks = data.trace.filter((e) => e[1] >= t0 - 1 && e[1] <= t1 + 1).map((e) => [e[0], Math.round(e[1] - t0), e[2]]);
    const camGone = data.b.ev.find((e) => e[0] === "ui:camera-gone" && e[1] >= t0);
    const out = { total: Math.round(t1 - t0), ready: endEv[0], cameraGone: camGone ? Math.round(camGone[1] - t0) : null, long: Math.round(long), longest, marks };
    if (profiled) {
      // the profile's clock → the page's: its last sample is the stop moment
      const p = profileOut.prof;
      const endUs = p.startTime + p.timeDeltas.reduce((a, b) => a + b, 0);
      const off = endUs / 1000 - profileOut.nowAtStop; // profile ms − page ms
      out.top = topFunctions(p, off, t0, t1);
    }
    return out;
  } catch (e) { if (process.env.SHOTS) await page.screenshot({ path: join(process.env.SHOTS, `fail-${name}.png`) }).catch(() => {}); throw e; } finally { await ctx.close().catch(() => {}); }
}

/* ---------------- the seal step ---------------- */

/** From Seal pressed to the item in the vault: what the person waits for after the review. */
async function sealRun() {
  const { ctx, page } = await session(cameraPath("camera-letter-4k.mjpeg"));
  try {
    await pickKind(page, /^Photo/);
    await page.locator(".photo-preview img").waitFor({ timeout: 120_000 });
    await page.waitForTimeout(1000);
    await page.evaluate(() => globalThis.__bench.reset());
    const t = {};
    t.click = await page.evaluate(() => performance.now());
    await page.getByRole("button", { name: "Seal", exact: true }).click();
    await page.locator(".interrupt .hold").waitFor({ timeout: 60_000 });
    t.prompt = await page.evaluate(() => performance.now());
    await page.waitForTimeout(300);
    const b = page.locator(".interrupt .hold");
    await b.focus();
    await page.keyboard.down(" ");
    await page.waitForTimeout(1500);
    t.release = await page.evaluate(() => performance.now());
    await page.keyboard.up(" ");
    await page.getByText(/sealed\. Only your face/).first().waitFor({ timeout: 120_000 });
    t.item = await page.evaluate(() => performance.now());
    const tr = await page.evaluate(() => globalThis.__humidTrace?.ev || []);
    return { toPrompt: Math.round(t.prompt - t.click), releaseToItem: Math.round(t.item - t.release), trace: tr.map((e) => [e[0], Math.round(e[1] - t.click), e[2]]) };
  } finally { await ctx.close().catch(() => {}); }
}

/* ---------------- run ---------------- */

const want = process.argv.slice(2).filter((a) => !a.startsWith("-"));
const names = want.length ? want : [...Object.keys(S), "seal"];
const results = {};
try {
  await enroll();
  for (const name of names) {
    results[name] = { runs: [] };
    for (let i = 0; i < RUNS; i++) {
      try {
        const r = name === "seal" ? await sealRun() : await once(name);
        results[name].runs.push(r);
        step(`${name} #${i + 1}: ${name === "seal" ? `prompt ${r.toPrompt} ms, release→item ${r.releaseToItem} ms` : `${r.total} ms (long tasks ${r.long} ms, longest ${r.longest} ms)`}`);
      } catch (e) { console.error(`${name} #${i + 1} failed:`, e.message.split("\n")[0]); results[name].error = e.message.split("\n")[0]; }
    }
    if (PROFILE && name !== "seal") {
      try { results[name].profile = (await once(name, { profiled: true })).top; } catch (e) { console.error(`${name} profile failed:`, e.message.split("\n")[0]); }
    }
    const rs = results[name].runs;
    if (rs.length) results[name].summary = name === "seal"
      ? { toPrompt: median(rs.map((r) => r.toPrompt)), releaseToItem: median(rs.map((r) => r.releaseToItem)) }
      : { median: median(rs.map((r) => r.total)), min: Math.min(...rs.map((r) => r.total)), max: Math.max(...rs.map((r) => r.total)), long: median(rs.map((r) => r.long)), longest: median(rs.map((r) => r.longest)), cameraGone: median(rs.map((r) => r.cameraGone ?? r.total)) };
  }
  writeFileSync(join(OUT, `${LABEL}.json`), JSON.stringify({ label: LABEL, throttle: THROTTLE, runs: RUNS, results }, null, 1));
  console.log(`\n${LABEL} (CPU ${THROTTLE}x, ${RUNS} runs): shoot → ready, ms`);
  for (const [n, r] of Object.entries(results)) {
    const s = r.summary;
    if (!s) { console.log(`${n.padEnd(18)} ${r.error || "no result"}`); continue; }
    console.log(n === "seal" ? `${n.padEnd(18)} Seal→prompt ${s.toPrompt}  release→item ${s.releaseToItem}` : `${n.padEnd(18)} median ${String(s.median).padStart(6)}  (${s.min}–${s.max})  frozen ${String(s.long).padStart(6)}  longest task ${s.longest}  camera gone ${s.cameraGone}`);
  }
} catch (e) {
  console.error(e);
  console.error(devLog.split("\n").slice(-15).join("\n"));
  process.exitCode = 1;
} finally {
  for (const c of contexts) await c.close().catch(() => {});
  dev.kill("SIGTERM");
  rmSync(profile, { recursive: true, force: true });
  process.exit(process.exitCode ?? 0);
}
