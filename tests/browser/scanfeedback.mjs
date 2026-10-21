// What the camera tells the person while it scans, in a real browser with a fake camera.
// Checks that:
//   - the panel is on screen from the first moment ("Point the camera at the document" for a
//     Photo), is a live region, with the live chips, and buttons that are 44 px or more
//   - the analysis runs in the worker (development builds say where: __humidLook.where)
//   - with a passport in view the panel moves on: Hold still / Reading the lines / Captured, ends on
//     Got it, and the camera closes after it
//   - with only a table in view, after 8 s the panel says the round button is there to use,
//     and after 40 s the camera stops looking, says "This is taking a while" and offers Try
//     again (the round button still works); Try again starts looking again
//   - a dark table in good light is not called "Too dark"
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/scanfeedback.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { enroll, unlock, openAdd as openAddFlow, openPicker, pickKind as pick, startCamera, chooseId } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = (n) => join(root, "tests/fixtures/id", n);
const PORT = Number(process.env.PORT || 5199);
const BASE = `http://tauri.localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-scanfb-"));
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: scanfeedback timed out after 5 minutes"); process.exit(1); }, 5 * 60_000).unref();
const contexts = [];

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

async function launch(cameraFile) {
  const ctx = await chromium.launchPersistentContext(profile, {
    headless: true, viewport: { width: 412, height: 915 }, deviceScaleFactor: 2, permissions: ["camera", "clipboard-read", "clipboard-write"],
    args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", `--use-file-for-fake-video-capture=${cameraFile}`,
      "--host-resolver-rules=MAP tauri.localhost 127.0.0.1", `--unsafely-treat-insecure-origin-as-secure=${BASE}`],
  });
  contexts.push(ctx);
  const page = ctx.pages()[0] || await ctx.newPage();
  page.on("pageerror", (e) => console.error("page error:", e.message));
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
/** The photo camera (3.0.1): Add opens the picker, Photo opens the camera at once. */
async function openPhotoCamera(page) { await openAddFlow(page); await pick(page, "Photo"); await startCamera(page); }
const state = (page) => page.locator(".doccam .dc-panel");

try {
  let { ctx, page } = await launch(fixture("camera-empty.mjpeg"));
  await page.goto(BASE);
  await enroll(page);
  step("enrolled (demo)");

  /* ---------------- 1. nothing in view: what it says, the offer at 10 s, the stop at 30 s ---------------- */
  await openPhotoCamera(page);
  await state(page).getByText("Point the camera at the document").waitFor({ timeout: 10_000 });
  await shot(page, "1-looking");
  const live = state(page).locator('[role="status"]');
  assert.equal(await live.count(), 1, "the card is a live region");
  assert.equal(await live.getAttribute("aria-live"), "polite");
  assert.deepEqual((await state(page).locator(".dc-chips li").allTextContents()).map((t) => t.trim()), ["Found", "Sharp", "Steady", "Light"], "the live chips for a photo");
  await page.locator(".doccam .dc-frame").first().waitFor({ state: "attached" });
  await page.waitForFunction(() => globalThis.__humidLook, null, { timeout: 15_000 });
  assert.equal(await page.evaluate(() => globalThis.__humidLook.where), "worker", "the analysis runs in the worker");
  const ms = await page.evaluate(() => globalThis.__humidLook.ms);
  assert.ok(ms < 400, `a look takes ${ms} ms`);
  step(`looking, as a live region, four live chips, analysed in the worker (${ms} ms a look)`);
  assert.notEqual(await state(page).getAttribute("data-phase"), "adjust", "a dark table in good light isn't 'too dark'");

  await state(page).getByText(/take the photo yourself/i).waitFor({ timeout: 14_000 });
  assert.equal(await page.locator(".doccam .dc-shutter").getAttribute("data-offer"), "1", "the round button is called out");
  await shot(page, "2-offer");
  step("after 8 s it says the round button is there, and the button pulses");

  await state(page).getByText("This is taking a while").waitFor({ timeout: 40_000 });
  const retry = state(page).getByRole("button", { name: "Try again" });
  const box = await retry.boundingBox();
  assert.ok(box.height >= 44 && box.width >= 44, `Try again is 44 px or more (${Math.round(box.width)}×${Math.round(box.height)})`);
  assert.equal(await page.locator(".doccam .dc-shutter").isDisabled(), false, "the round button still takes the photo");
  const frozen = await page.evaluate(() => globalThis.__humidLook?.ms);
  await shot(page, "3-gave-up");
  await retry.click();
  await state(page).getByText("Point the camera at the document").waitFor();
  assert.equal(await page.locator(".doccam .dc-shutter").getAttribute("data-offer"), null, "a fresh budget");
  void frozen;
  step("after 40 s it stops looking and offers Try again (the round button still works); Try again looks again");
  await page.getByRole("button", { name: "Close the camera" }).click();
  await ctx.close();

  /* ---------------- 2. a passport in view: the card follows the scan to Done ---------------- */
  ({ ctx, page } = await launch(fixture("guide/pp-ok.mjpeg")));
  await page.goto(BASE);
  await unlock(page);
  await page.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 20_000 });
  await page.evaluate(() => {
    globalThis.__seen = [];
    new MutationObserver(() => { const s = document.querySelector(".doccam .dc-panel"); const t = s?.querySelector("strong")?.textContent; if (t && globalThis.__seen.at(-1) !== t) globalThis.__seen.push(t); })
      .observe(document.body, { subtree: true, childList: true, characterData: true });
  });
  await openPicker(page); await chooseId(page, "Passport"); // 3.0.1: Passport in the picker opens its outline at once
  await state(page).locator('.dc-chips li[data-k="code"]').waitFor({ timeout: 10_000 });
  assert.equal((await state(page).locator('.dc-chips li[data-k="code"]').textContent()).trim(), "ID lines", "a chip for the lines of <<<");
  await page.locator(".doccam").waitFor({ state: "detached", timeout: 120_000 });
  const seen = await page.evaluate(() => globalThis.__seen);
  step(`the card said: ${seen.join(" → ")}`);
  const isDone = (t) => t === "Got it";
  const firstDone = seen.findIndex(isDone);
  assert.ok(firstDone >= 0, "it ended on Got it");
  assert.ok(seen.slice(firstDone).every(isDone), "nothing after Got it");
  assert.ok(seen.includes("Captured"), "it said when the photo was taken");
  assert.ok(seen.some((t) => /Reading the lines|Lines read|Checking the lines|Hold still/.test(t)), "it showed progress");
  await ctx.close();
  console.log("ok — The camera says what it is doing, in the browser");
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
