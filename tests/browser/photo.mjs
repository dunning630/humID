// "Take a photo" in a real browser (apps 1.10.0): the camera finds a document anywhere
// in view and straightens it, and the document is stamped with where it was sealed.
// The fake camera shows a letter page lying sideways, tilted and off-centre on a
// grained table, nowhere near the middle. Checks that:
//   - Photo is picked first (3.0.1); nobody lines anything up: the page is found where it lies
//     (no four-point outline is drawn over it: the frame's corners go green) and the photo is taken by itself
//   - the proposal is the page straightened and turned upright (taller than wide);
//     a clean scan of it (apps 1.12.0: light evened out, paper white) is marked
//     Suggested; the straightened photo and the original are one tap away
//   - turning by hand works, and the choice is what gets sealed
//   - "Stamp where it's sealed" is on, shows the phone's location, and the sealed
//     document shows it ("Sealed at"); the vault server's copy of the index can't
//     be read for it (it's inside the encrypted index)
//   - with the stamp off, nothing is kept
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/photo.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { hold, enroll, openAdd as openAddFlow, pickKind, startCamera } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = (n) => join(root, "tests/fixtures/docs", n);
const PORT = Number(process.env.PORT || 5199);
// The page loads from http://tauri.localhost, the Android app's own origin, under the app's
// content security policy (tools/dev.mjs serves it): what the policy blocks in the app,
// such as the scan engines, it blocks here too.
const BASE = `http://tauri.localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-photo-"));
const step = (s) => console.log(`· ${s}`);
// A stuck browser must fail the run, not hold it: the whole check takes well under a minute.
setTimeout(() => { console.error("Error: photo timed out after 5 minutes"); process.exit(1); }, 5 * 60_000).unref();
const contexts = [];

/* ---------------- the dev server (whole stack, demo mode, simulated chips) ---------------- */

// the server's data in a folder of our own, to check afterwards that the location isn't readable in it
const data = mkdtempSync(join(tmpdir(), "humid-photo-data-"));
const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), HUMID_DEV_DATA: data }, stdio: ["ignore", "pipe", "pipe"] });
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
  page.on("pageerror", (e) => console.error("page error:", e.message));
  page.on("console", (m) => { if (m.type() === "error") console.error("console:", m.text()); });
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };

try {
  let { ctx, page } = await launch(fixture("camera-letter-tilted.mjpeg"));
  await page.goto(BASE);
  await enroll(page);
  step("enrolled (demo)");

  /* ---------------- 1. the camera finds the page by itself ---------------- */
  // one way in (3.0.1): the + button opens "What are you adding?"; Photo opens the camera at once
  const openCamera = async () => { await openAddFlow(page); await pickKind(page, "Photo"); await startCamera(page); };
  if (process.env.KEEP_PNG) await page.evaluate(() => { globalThis.__humidKeepPng = true; });
  await openCamera();
  await page.waitForFunction(() => globalThis.__humidLook?.found && globalThis.__humidLook?.quad, null, { timeout: 20_000 });
  const look = await page.evaluate(() => globalThis.__humidLook);
  assert.ok(look?.found, "the page is found");
  // the camera keeps its whole field of view: a portrait 1080×1920 source must arrive
  // portrait, never cropped to the shape the app asked for (a 1080×1080 square cut the top
  // and bottom of the page off in an early 3.0 build)
  assert.ok(Math.abs(look.vw / look.vh - 1080 / 1920) < 0.01, `the camera frame is ${look.vw}×${look.vh}: cropped`);
  // the outline sits where the page is: up and to the right of the middle, tilted. In
  // fractions of the frame, so it holds at any resolution: (540, 765) of 1080×1920.
  const q = look.quad;
  const cx = (q[0].x + q[1].x + q[2].x + q[3].x) / 4 / look.vw, cy = (q[0].y + q[1].y + q[2].y + q[3].y) / 4 / look.vh;
  assert.ok(Math.abs(cx - 0.5) < 0.056 && Math.abs(cy - 0.398) < 0.031, `outline centred at ${cx.toFixed(3)},${cy.toFixed(3)} of the frame`);
  await page.locator(".doccam[data-look='ok'], .doccam[data-look='close'], .doccam[data-phase='reading']").first().waitFor({ timeout: 10_000 });
  assert.equal(await page.locator(".dc-outline, .doccam > svg, .dc-stage polygon").count(), 0, "no four-point outline is drawn over the page");
  await shot(page, "1-found");
  step(`the page is found where it lies (${Math.round(cx * look.vw)}, ${Math.round(cy * look.vh)} of ${look.vw}×${look.vh}, uncropped); the frame's corners say so, with no outline drawn over it`);
  // nobody presses the shutter
  await page.locator(".photo-choice").waitFor({ timeout: 30_000 }).catch(async (e) => {
    const l = await page.evaluate(() => globalThis.__humidLook);
    throw new Error(`no photo taken: ${JSON.stringify({ ...l, quad: undefined })}`, { cause: e });
  });
  assert.match(await page.locator(".pushed .row").filter({ hasText: "Kind" }).innerText(), /Photo/, "the review says it's a photo");
  step("photo taken by itself once the page held still, on to the photo review");

  /* ---------------- 2. the proposal: straightened and upright; or the original ---------------- */
  const size = async () => page.locator(".photo-preview img").evaluate((img) => new Promise((res) => {
    const go = () => res({ w: img.naturalWidth, h: img.naturalHeight });
    img.complete && img.naturalWidth ? go() : img.addEventListener("load", go, { once: true });
  }));
  await page.locator(".photo-preview img").waitFor();
  // one preview of the suggested version; "Looks wrong?" reveals the other versions, turning and retake
  assert.equal(await page.getByRole("radio").count(), 0, "no version picker until asked");
  assert.equal(await page.getByRole("button", { name: "Turn right" }).count(), 0, "no turn buttons until asked");
  await page.getByRole("button", { name: "Looks wrong?" }).click();
  await page.getByRole("radio", { name: /Clean scan/ }).getByText("Suggested").waitFor();
  assert.equal(await page.getByRole("radio", { name: /Clean scan/ }).getAttribute("aria-checked"), "true");
  // the clean scan's paper is white and even; the straightened photo keeps the room's light
  const paper = async () => page.locator(".photo-preview img").evaluate((img) => new Promise((res) => {
    const go = () => {
      const c = document.createElement("canvas"); c.width = img.naturalWidth; c.height = img.naturalHeight;
      const g = c.getContext("2d"); g.drawImage(img, 0, 0);
      const d = g.getImageData(0, 0, c.width, c.height).data;
      // the margins (no text): the brightest-but-one level in each tenth across the top band
      const levels = [];
      for (let k = 0; k < 10; k++) {
        let sum = 0, n = 0;
        for (let y = Math.round(c.height * 0.01); y < c.height * 0.04; y++) for (let x = Math.round(c.width * (0.05 + k * 0.09)); x < c.width * (0.1 + k * 0.09); x++) { const i = (y * c.width + x) * 4; sum += (d[i] + d[i + 1] + d[i + 2]) / 3; n++; }
        levels.push(sum / n);
      }
      res({ mean: levels.reduce((a, b) => a + b) / levels.length, spread: Math.max(...levels) - Math.min(...levels) });
    };
    img.complete && img.naturalWidth ? go() : img.addEventListener("load", go, { once: true });
  }));
  const clean = await paper();
  const flat = await size();
  const developed = await page.evaluate(() => globalThis.__humidDevelop);
  if (developed?.png) { (await import("node:fs")).writeFileSync(process.env.KEEP_PNG, Buffer.from(developed.png.split(",")[1], "base64")); delete developed.png; }
  assert.ok(flat.h > flat.w * 1.2 && Math.abs(flat.h / flat.w - 1.294) < 0.03, `straightened page is upright letter-shaped: ${flat.w}×${flat.h} ${JSON.stringify(developed)}`);
  await shot(page, "2-proposal");
  step(`proposal: the page straightened and turned upright (${flat.w}×${flat.h}, letter proportions)`);
  await page.getByRole("radio", { name: /Straightened/ }).click();
  await page.waitForTimeout(500);
  const straight = await paper();
  assert.ok(clean.mean > 240 && clean.mean > straight.mean + 5, `clean scan's paper is white: ${clean.mean.toFixed(0)} (straightened ${straight.mean.toFixed(0)})`);
  assert.ok(clean.spread <= straight.spread + 2, `and even: spread ${clean.spread.toFixed(1)} (straightened ${straight.spread.toFixed(1)})`);
  assert.equal(await page.getByRole("button", { name: "Seal", exact: true }).count(), 1);
  await shot(page, "2b-straightened");
  step(`clean scan suggested: paper ${clean.mean.toFixed(0)}/255 against ${straight.mean.toFixed(0)} straightened`);
  await page.getByRole("radio", { name: /Original/ }).click();
  await page.waitForTimeout(400);
  const orig = await size();
  assert.ok(Math.abs(orig.w / orig.h - 1080 / 1920) < 0.02, `original is the camera's frame: ${orig.w}×${orig.h}`);
  await page.getByText("The photo exactly as the camera took it.").waitFor();
  await shot(page, "3-original");
  step("the original is the photo as taken, and the note says so");
  await page.getByRole("radio", { name: /Clean scan/ }).click();
  await page.getByRole("button", { name: "Turn right" }).click();
  await page.waitForTimeout(400);
  const turned = await size();
  assert.ok(turned.w > turned.h, "turned by hand");
  await page.getByRole("button", { name: "Turn left" }).click();
  await page.waitForTimeout(400);
  step("turning by hand works");

  /* ---------------- 3. sealed, stamped with where ---------------- */
  // 3.0: the stamp is off until the person turns it on, and remembered on this device; it
  // keeps about 110 m (the fake fix is 41.914513, −88.308721) and shows only those digits
  const HERE = /41\.915° N, 88\.309° W/;
  const stamp = page.locator(".place-stamp");
  assert.equal(await stamp.getByRole("switch").getAttribute("aria-checked"), "false", "off by default");
  await stamp.getByText(/Off\. Turn it on/).waitFor();
  await stamp.getByRole("switch").click();
  await stamp.getByText(HERE).waitFor({ timeout: 15_000 });
  await stamp.getByText(/within 110 m/).waitFor();
  assert.equal(await stamp.getByRole("switch").getAttribute("aria-checked"), "true");
  await page.fill("#doc-name", "Assessment notice");
  await shot(page, "4-stamp");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  await page.locator(".item").filter({ hasText: "Assessment notice" }).first().waitFor({ timeout: 30_000 });
  step("sealed, with the location stamp on");
  await page.locator(".item").filter({ hasText: "Assessment notice" }).first().click();
  await page.getByText("Location stamp", { exact: true }).waitFor();
  const placeRow = page.locator(".row").filter({ hasText: "Location stamp" });
  await placeRow.getByText(HERE).waitFor();
  await placeRow.getByText(/within 110 m/).waitFor();
  await shot(page, "5-sealed-at");
  step("the document shows where it was sealed (and how accurately)");
  // when: the vault server's clock (to the minute), not the phone's; the clocks agree, so no note
  const sealedRow = page.locator(".row").filter({ has: page.locator(".title", { hasText: /^Sealed$/ }) });
  const sealedText = await sealedRow.locator(".trail").innerText();
  assert.match(sealedText, /\d{1,2}:\d{2}/, `the seal time has the time of day: ${sealedText}`);
  assert.doesNotMatch(sealedText, /phone's clock/);
  assert.equal(await page.locator(".row").filter({ hasText: "Phone's clock" }).count(), 0, "no clock note when the clocks agree");
  step(`sealed ${sealedText}, by the vault server's clock`);
  // the server's view: everything it stores, every file; the coordinates are in none of it
  const files = (d) => readdirSync(d).flatMap((n) => { const f = join(d, n); return statSync(f).isDirectory() ? files(f) : [f]; });
  const stored = files(data);
  assert.ok(stored.length > 0, "the dev server keeps its data in the folder given");
  for (const f of stored) {
    const b = readFileSync(f);
    for (const needle of ["41.91451", "88.30872", "41.9145", "88.3087", "41.915", "88.309"]) assert.ok(!b.includes(needle), `${f} holds the location in readable form`);
  }
  step(`the vault server's data (${stored.length} files) holds no readable location`);
  // open it: the straightened, upright page
  await page.getByRole("button", { name: /^Open$/ }).click();
  await hold(page);
  const opened = await page.locator(".viewer .body img").evaluate((img) => new Promise((res) => {
    const go = () => res({ w: img.naturalWidth, h: img.naturalHeight });
    img.complete && img.naturalWidth ? go() : img.addEventListener("load", go, { once: true });
  }));
  assert.ok(opened.h > opened.w, `sealed photo is the upright page: ${opened.w}×${opened.h}`);
  await shot(page, "6-opened");
  await page.getByRole("button", { name: "Close and wipe" }).click();
  await page.locator(".viewer").waitFor({ state: "detached" });
  // 3.0: closing the viewer returns to the item; its Back returns to the vault
  await page.locator(".pushed [data-back]").first().click();
  await page.locator(".pushed").waitFor({ state: "detached", timeout: 10_000 });
  step(`opened: the sealed photo is the straightened, upright page (${opened.w}×${opened.h})`);

  /* ---------------- 4. stamp off: nothing kept ---------------- */
  await openCamera();
  await page.locator(".photo-choice").waitFor({ timeout: 40_000 });
  assert.equal(await page.locator(".place-stamp").getByRole("switch").getAttribute("aria-checked"), "true", "remembered on this device");
  await page.locator(".place-stamp").getByRole("switch").click();
  await page.locator(".place-stamp").getByText(/Off\. Turn it on/).waitFor();
  await page.fill("#doc-name", "No stamp");
  await page.getByRole("button", { name: "Looks wrong?" }).click();
  await page.getByRole("radio", { name: /Straightened/ }).click();
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  await page.locator(".item").filter({ hasText: "No stamp" }).first().waitFor({ timeout: 30_000 });
  await page.locator(".item").filter({ hasText: "No stamp" }).first().click();
  await page.getByText("Sealed with", { exact: true }).waitFor();
  assert.equal(await page.getByText("Location stamp", { exact: true }).count(), 0, "no location with the stamp off");
  step("with the stamp off, the document has no location");
  await ctx.close();
  console.log("ok — Take a photo finds, straightens and stamps documents in the browser");
} catch (e) {
  console.error(e);
  console.error(devLog.split("\n").slice(-20).join("\n"));
  process.exitCode = 1;
} finally {
  for (const c of contexts) await c.close().catch(() => {});
  dev.kill("SIGTERM");
  rmSync(profile, { recursive: true, force: true });
  rmSync(data, { recursive: true, force: true });
  process.exit(process.exitCode ?? 0);
}
