// The native document camera (5.0, plugins/humid-docscan) from the camera screen's side, in a real
// browser: the development build in Chromium with a stand-in for the plugin
// (globalThis.__humidFakeCamera, development builds only) that plays the events a phone's camera
// sends. No getUserMedia stream is opened. Checks that:
//   - the screen opens the native camera with the frame's place and the web view's size, and the
//     page turns see-through (html.cam-native)
//   - "Focusing…" is said only while the camera says its autofocus is moving, never from a look
//     that is merely lined up; the focus ring shows only after a tap, follows the camera's answer
//     (pulsing, then mint), and doesn't show when the camera refuses the tap
//   - the camera's "Move back a little" (tooclose) is said without the frame changing size
//   - a barcode read by the camera fills the license's details; the photo the camera took by
//     itself arrives as raw JPEG bytes (take), once, and the review opens with what was read
//   - closing the screen closes the camera
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/nativecam.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { enroll, pickId } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5207);
const BASE = `http://tauri.localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-nativecam-"));
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: nativecam timed out after 6 minutes"); process.exit(1); }, 6 * 60_000).unref();
const BARCODE = readFileSync(join(root, "tests/fixtures/id/card-back.barcode.txt"), "utf8");
const CARD = readFileSync(join(root, "tests/fixtures/id/card-back.jpg")).toString("base64");

const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "pipe", "pipe"] });
let devLog = "";
dev.stdout.on("data", (d) => { devLog += d; });
dev.stderr.on("data", (d) => { devLog += d; });
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${devLog}`)), 120_000);
  const check = setInterval(() => { if (/HumID dev:/.test(devLog)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
  dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${devLog}`)); });
});
step("dev server up");

// The stand-in plugin: records every call; the test sends events through the channel it was given.
const STANDIN = (card) => {
  globalThis.__cam = { calls: [], ch: null, refuseFocus: false, taken: 0 };
  const bytes = Uint8Array.from(atob(card), (c) => c.charCodeAt(0));
  globalThis.__humidFakeCamera = {
    async invoke(cmd, args) {
      const c = globalThis.__cam;
      c.calls.push([cmd, cmd === "open" ? { ...args, events: undefined } : args]);
      if (cmd === "probe") return { available: true, lenses: ["wide", "ultra"], macro: true, torch: true, minFocusMm: 200 };
      if (cmd === "open") { c.ch = args.events; return { session: "s1" }; }
      if (cmd === "focus") { if (c.refuseFocus) throw "invalid: the focus point is off the screen."; return null; }
      if (cmd === "capture") return { id: "p1", width: 1600, height: 1009 };
      if (cmd === "take") { c.taken++; if (c.taken > 2) throw "invalid: that photo is gone"; return bytes.buffer.slice(0); }
      if (cmd === "torch") return { on: !!args.on };
      return null;
    },
  };
  globalThis.__send = (e) => globalThis.__cam.ch.onmessage(e);
};

const contexts = [];
try {
  const ctx = await chromium.launchPersistentContext(profile, {
    headless: true, viewport: { width: 412, height: 915 }, deviceScaleFactor: 2,
    args: ["--host-resolver-rules=MAP tauri.localhost 127.0.0.1", `--unsafely-treat-insecure-origin-as-secure=${BASE}`],
  });
  contexts.push(ctx);
  await ctx.addInitScript(STANDIN, CARD);
  await ctx.addInitScript(() => {
    globalThis.__streams = 0;
    const real = navigator.mediaDevices?.getUserMedia?.bind(navigator.mediaDevices);
    if (real) navigator.mediaDevices.getUserMedia = (c) => { globalThis.__streams++; return real(c); };
  });
  const page = ctx.pages()[0] || await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => { errors.push(e.message); console.error("page error:", e.message); });
  const shot = async (name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
  const send = (e) => page.evaluate((x) => globalThis.__send(x), e);
  const headline = () => page.locator(".doccam .dc-panel strong").first().innerText();
  const calls = (cmd) => page.evaluate((c) => globalThis.__cam.calls.filter(([n]) => n === c), cmd);
  const frameBox = () => page.locator(".doccam .dc-frame").boundingBox();

  await page.goto(BASE);
  await enroll(page);
  step("enrolled (demo)");

  /* ---------------- 1. a license's back, through the native camera ---------------- */
  await pickId(page, "Driver's license");
  // the front first: the shutter takes it (the stand-in gives the same picture), then the back opens
  await page.waitForFunction(() => globalThis.__cam?.ch, null, { timeout: 15_000 });
  await send({ t: "ready", lens: "wide", zoom: 1.6, minFocusMm: 200, torch: true });
  await page.locator(".doccam[data-camera='native']").waitFor();
  assert.equal(await page.evaluate(() => document.documentElement.classList.contains("cam-native")), true, "the page is see-through over the camera");
  assert.equal(await page.locator(".doccam video").count(), 0, "no web video under a native camera");
  const [open] = await calls("open");
  assert.equal(open[1].shape, "id1");
  assert.deepEqual(open[1].view, { w: 412, h: 915 }, "the web view's size");
  const fb = await frameBox();
  assert.ok(Math.abs(open[1].frame.x - fb.x) < 1 && Math.abs(open[1].frame.w - fb.width) < 1, `the frame's place on screen: ${JSON.stringify(open[1].frame)}`);
  step(`native camera opened for the front with the frame at ${Math.round(fb.x)},${Math.round(fb.y)} ${Math.round(fb.width)}×${Math.round(fb.height)}; no web stream, page see-through`);
  await page.locator(".doccam .dc-shutter:not([disabled])").click();
  await page.waitForFunction(() => globalThis.__cam.calls.some(([c]) => c === "capture"));
  await send({ t: "captured", id: "p1", how: "shutter", width: 1600, height: 1009, codes: {}, freeze: null });
  await page.locator(".dc-saved-chip", { hasText: "Front saved" }).waitFor({ timeout: 20_000 });
  step("the front: the round button asked the camera for the photo, which came back as bytes and was kept");

  // the back: a new camera for it
  await page.waitForFunction(() => globalThis.__cam.calls.filter(([c]) => c === "open").length === 2, null, { timeout: 15_000 });
  const opens = await calls("open");
  assert.deepEqual(opens[1][1].read, { pdf417: true, mrz: false, require: true }, "the back asks the camera to read the PDF417, and to wait for it");
  assert.deepEqual(opens[0][1].read, { pdf417: true, mrz: false, require: false }, "the front looks out for a barcode (it would be the back) without waiting for one");
  assert.ok((await calls("close")).length >= 1, "the front's camera was closed");
  await send({ t: "ready", lens: "wide", zoom: 1.6, minFocusMm: 200, torch: true });
  const look = (o) => send({ t: "look", state: "aligning", key: null, aligned: false, quad: null, focus: "focused", steady: true, light: "ok", progress: 0, lens: "wide", ...o });
  const Q = [[40, 300], [372, 300], [372, 510], [40, 510]];
  await look({ state: "aligning", quad: Q });
  await page.locator(".doccam .dc-quad polygon").waitFor();
  assert.notEqual(await headline(), "Focusing…");
  // lined up and in focus: no "Focusing…"
  await look({ state: "sharp", aligned: true, quad: Q, focus: "focused" });
  assert.equal(await headline(), "Hold still");
  assert.equal(await page.locator(".doccam .dc-quad").count(), 0, "the corners give way to the frame once it lines up");
  // the camera says its autofocus is moving: then, and only then, "Focusing…"
  await look({ state: "focusing", aligned: true, quad: Q, focus: "scanning" });
  assert.equal(await headline(), "Focusing…");
  assert.equal(await page.locator('.dc-chips li[data-k="sharp"]').getAttribute("data-state"), "busy");
  await look({ state: "sharp", aligned: true, quad: Q, focus: "focused", progress: 0.5 });
  assert.equal(await headline(), "Hold still");
  assert.equal(await page.locator(".dc-ring").count(), 1, "the hold ring fills");
  step("Focusing… only while the camera's autofocus moves; Hold still and the ring otherwise");

  // too close: said, and the frame keeps its size
  const before = await frameBox();
  await look({ state: "sharp", aligned: true, key: "tooclose", focus: "failed" });
  assert.equal(await headline(), "Move back a little");
  assert.match(await page.locator(".doccam .dc-panel").innerText(), /Too close for the camera to focus/);
  assert.deepEqual(await frameBox(), before, "the frame doesn't change size");
  step("too close: Move back a little, with the frame unchanged");

  // tap to focus: a ring at the tap only when the camera takes it, and it follows the camera's answer
  await page.evaluate(() => { globalThis.__cam.refuseFocus = true; });
  await page.mouse.click(206, 400);
  await page.waitForTimeout(300);
  assert.equal(await page.locator(".dc-focus").count(), 0, "no ring when the camera can't focus there");
  await page.evaluate(() => { globalThis.__cam.refuseFocus = false; });
  await page.mouse.click(120, 380);
  await page.locator(".dc-focus[data-af='scanning']").waitFor({ timeout: 3000 });
  const [, fargs] = (await calls("focus")).at(-1);
  assert.deepEqual(fargs, { x: 120, y: 380 }, "the tap in CSS pixels");
  await send({ t: "focus", x: 120, y: 380, af: "focused" });
  await page.locator(".dc-focus[data-af='focused']").waitFor({ timeout: 3000 });
  await shot("1-native-focus");
  step("tap to focus: no ring when refused; a pulsing ring at the tap, then mint when the camera says it's in focus");

  // the camera reads the barcode, then takes the photo by itself
  await send({ t: "code", kind: "pdf417", state: "seen" });
  await send({ t: "code", kind: "pdf417", state: "read", text: BARCODE });
  await page.locator(".doccam .dc-panel strong", { hasText: "Barcode read ✓" }).waitFor({ timeout: 5000 });
  await send({ t: "captured", id: "p1", how: "auto", width: 1600, height: 1009, codes: { pdf417: BARCODE }, freeze: null });
  await page.getByText("Review, then seal").waitFor({ timeout: 30_000 });
  assert.equal(await page.locator("#idf-surname").inputValue(), "SPECIMEN");
  assert.equal(await page.locator("#idf-number").inputValue(), "S12345678901");
  assert.equal(await page.evaluate(() => globalThis.__humidDevelop?.camera), "native");
  const takes = await calls("take");
  assert.ok(takes.length >= 1 && takes.every(([, a]) => a.id === "p1"), "the photo was taken by its id");
  assert.equal(await page.evaluate(() => globalThis.__streams), 0, "no web camera stream at any point");
  assert.ok((await calls("close")).length >= 2, "the camera is closed when the screen goes");
  assert.equal(await page.evaluate(() => document.documentElement.classList.contains("cam-native")), false, "the page is opaque again");
  await shot("2-native-review");
  step("barcode read by the camera; the photo it took by itself arrived as bytes; review filled; camera closed");
  assert.deepEqual(errors, [], "no page errors");
  console.log("ok — the native camera's events drive the camera screen");
} catch (e) {
  console.error(e);
  console.error(devLog.split("\n").slice(-20).join("\n"));
  process.exitCode = 1;
} finally {
  for (const c of contexts) await c.close().catch(() => {});
  dev.kill("SIGTERM");
  rmSync(profile, { recursive: true, force: true });
  process.exit(process.exitCode ?? 0);
}
