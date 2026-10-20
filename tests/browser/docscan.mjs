// The phone's document scanner (Android; apps 2.1.1, narrowed in 2.1.2): the development
// build in Chromium with a stand-in for the scanner (globalThis.__humidFakeScanner,
// development builds only) that hands back flat pages the way ML Kit does. Checks that:
//   - IDs (the picker's ID entry: licenses, passports) use HumID's own camera, never the
//     scanner (its screen isn't covered by HumID's screenshot protection)
//   - the Add camera (3.0: camera first) uses the scanner: a passport page scanned there is
//     read (MRZ) and routed to the passport flow; Another card scans front and back
//   - backing out of the scanner closes the camera screen
//   - a page that can't be handed back offers Scan again and Use HumID's camera
//   - no scanner on the phone: HumID's own camera opens instead, for the rest of the session
//   - HumID doesn't lock during a scan, but does once it has been off the screen 60 s
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/docscan.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { hold, enroll, openAdd as openAddFlow, openPicker, pickKind as pick, startCamera } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = (n) => join(root, "tests/fixtures/id", n);
const PORT = Number(process.env.PORT || 5199);
const BASE = `http://tauri.localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-docscan-"));
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: docscan timed out after 8 minutes"); process.exit(1); }, 8 * 60_000).unref();
const contexts = [];
const b64 = (n) => readFileSync(fixture(n)).toString("base64");

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

// The stand-in scanner: each scan takes the next answer from a queue the test fills. While a
// scan is "on screen" HumID is hidden, as when the real scanner's activity covers it.
const STANDIN = () => {
  globalThis.__scanQueue = [];
  globalThis.__scans = 0;
  const hide = (on) => {
    Object.defineProperty(document, "hidden", { get: () => on, configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
  };
  globalThis.__humidFakeScanner = {
    async invoke(cmd, args) {
      if (cmd !== "scan") return { available: true };
      globalThis.__scans++;
      globalThis.__lastArgs = args;
      hide(true);
      await new Promise((r) => setTimeout(r, 400));
      for (let i = 0; i < 100 && !globalThis.__scanQueue.length; i++) await new Promise((r) => setTimeout(r, 100));
      const next = globalThis.__scanQueue.shift();
      if (next?.holdMs) await new Promise((r) => setTimeout(r, next.holdMs)); // the person left HumID from the scanner
      hide(false);
      if (!next) throw "cancelled";
      if (next.reject) throw next.reject;
      return { data: next.data, mime: "image/jpeg", width: next.width || 0, height: next.height || 0 };
    },
  };
};

async function launch() {
  const ctx = await chromium.launchPersistentContext(profile, {
    headless: true,
    viewport: { width: 412, height: 915 },
    deviceScaleFactor: 2,
    permissions: ["camera"],
    args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", `--use-file-for-fake-video-capture=${fixture("camera-empty.mjpeg")}`,
      "--host-resolver-rules=MAP tauri.localhost 127.0.0.1", `--unsafely-treat-insecure-origin-as-secure=${BASE}`],
  });
  contexts.push(ctx);
  await ctx.addInitScript(STANDIN);
  // count camera streams: the scanner path must never open the live camera
  await ctx.addInitScript(() => {
    globalThis.__streams = 0;
    const real = navigator.mediaDevices?.getUserMedia?.bind(navigator.mediaDevices);
    if (real) navigator.mediaDevices.getUserMedia = (c) => { globalThis.__streams++; return real(c); };
  });
  const page = ctx.pages()[0] || await ctx.newPage();
  page.on("pageerror", (e) => console.error("page error:", e.message));
  page.on("console", (m) => { if (m.type() === "error") console.error("console:", m.text()); });
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
const queue = (page, ...items) => page.evaluate((xs) => { globalThis.__scanQueue.push(...xs); }, items);

/** The Add camera (3.0, camera first; the first time, "what to show" with Start camera comes before it). */
async function openCamera(page) { await openAddFlow(page); await startCamera(page); }
/** The picker ("It's something else"), then ID: its own camera at once. */
async function pickId(page) { await openPicker(page); await pick(page, /^ID/); }

try {
  const { page } = await launch();
  await page.goto(BASE);
  await enroll(page);
  step("enrolled (demo)");

  const unlock = async () => {
    await page.goto(BASE);
    await page.getByRole("button", { name: /^Unlock$/ }).click();
    await hold(page);
    await page.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 20_000 });
  };
  const scans = () => page.evaluate(() => globalThis.__scans);
  const streams = () => page.evaluate(() => globalThis.__streams);
  const closeCamera = async () => { await page.getByRole("button", { name: "Close the camera" }).click(); await page.locator(".doccam").waitFor({ state: "detached" }); };

  /* ---------------- 1. IDs stay on HumID's own camera ---------------- */
  await pickId(page);
  await page.locator(".doccam:not([data-scanner]) .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await closeCamera();
  assert.equal(await streams(), 1, "HumID's own camera opened");
  assert.equal(await scans(), 0, "the scanner wasn't opened");
  await unlock(); // a fresh page: the counters start again
  step("IDs (licenses, passports): HumID's own camera, never the scanner");

  /* ---------------- 2. Add ▸ Photo: the scanner; a passport page scanned there is read ---------------- */
  await queue(page, { data: b64("passport-page.jpg") });
  await openCamera(page);
  await page.getByText("Read the ID chip").first().waitFor({ timeout: 90_000 });
  await shot(page, "2-photo-scanned-passport");
  assert.equal(await page.locator("#doc-num").inputValue(), "D00000001");
  assert.equal(await page.locator("#doc-birth").inputValue(), "1974-08-12");
  assert.equal(await scans(), 1);
  assert.equal(await page.locator(".interrupt .hold").count(), 0, "the vault didn't lock while the scanner was on screen");
  step("the Add camera: the scanner took the page; the MRZ was read from it and routed to the passport flow");
  await unlock();

  /* ---------------- 3. Another card: front and back from the scanner ---------------- */
  const before3 = await scans();
  await queue(page, { data: b64("card-front.jpg") }, { data: b64("card-back.jpg") });
  // 3.0: the scanner takes the front; nothing on it reads as an ID or a payment card, so it's offered as a
  // photo with "say what it is" → Which ID is it? → Another card, whose back then comes from the scanner too
  await openCamera(page);
  await page.getByRole("button", { name: "say what it is" }).click({ timeout: 90_000 });
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  await pick(page, /^ID/);
  await page.locator(".pushed").getByText("Which ID is it?").waitFor();
  await page.locator(".kinds .kind", { hasText: "Another card" }).click();
  await page.getByText("Review, then seal").waitFor({ timeout: 90_000 });
  await shot(page, "3-another-card");
  assert.equal(await scans() - before3, 2, "front, then back");
  step("Another card: front and back came from the scanner");
  await unlock();

  /* ---------------- 4. backing out ---------------- */
  const s0 = await streams();
  await openCamera(page);
  await page.locator(".doccam").waitFor({ timeout: 10_000 }).catch(() => {});
  await page.locator(".doccam").waitFor({ state: "detached", timeout: 20_000 }); // the empty queue answers "cancelled"
  await page.locator(".pushed").waitFor({ state: "detached", timeout: 5000 }); // 3.0: camera first, so backing out closes Add
  assert.equal(await streams(), s0, "no live camera");
  step("backing out of the scanner closes the camera screen, and Add with it");

  /* ---------------- 5. a page that couldn't be handed back ---------------- */
  await queue(page, { reject: "The scanned page couldn't be read: no data" });
  await openCamera(page);
  await page.locator(".dc-scanner[data-state='error']").waitFor({ timeout: 20_000 });
  await shot(page, "5-scan-failed");
  assert.match(await page.locator(".dc-scanner").innerText(), /Scan again/);
  assert.match(await page.locator(".dc-scanner").innerText(), /Use HumID's camera/);
  await queue(page, { data: b64("passport-page.jpg") });
  await page.getByRole("button", { name: "Scan again" }).click();
  await page.getByText("Read the ID chip").first().waitFor({ timeout: 90_000 });
  step("a failed hand-back offers Scan again, which worked");
  await unlock();

  /* ---------------- 6. off the screen too long from the scanner: locks ---------------- */
  await queue(page, { data: b64("passport-page.jpg"), holdMs: 63_000 });
  await openCamera(page);
  await page.getByRole("button", { name: /^Unlock$/ }).waitFor({ timeout: 90_000 });
  await shot(page, "6-locked-after-60s");
  step("off the screen 60 s from the scanner: HumID locked");
  await page.getByRole("button", { name: /^Unlock$/ }).click();
  await hold(page);
  await page.locator(".item").first().waitFor({ timeout: 20_000 }).catch(() => {});

  /* ---------------- 7. no scanner on this phone ---------------- */
  await queue(page, { reject: "unavailable: Google Play services isn't available" });
  const s7 = await streams();
  await openCamera(page);
  await page.locator(".doccam:not([data-scanner]) .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await shot(page, "7-fallback-camera");
  assert.equal(await streams(), s7 + 1, "HumID's own camera opened instead");
  await closeCamera();
  const scansBefore = await scans();
  await openCamera(page);
  await page.locator(".doccam:not([data-scanner]) .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  assert.equal(await scans(), scansBefore, "the scanner isn't tried again this session");
  step("no scanner: HumID's camera opened, and stays the camera for the session");

  console.log("ok — the phone's document scanner works end to end in the browser");
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
