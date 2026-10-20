// The guided scan (apps 2.2.0) in a real browser, with a fake camera: a fixed outline for each
// kind of document, plain words on what to change, an automatic photo only when the document
// is lined up, steady and sharp, and a crop to the outline. Fixtures: tests/fixtures/id/guide/*
// (made by tests/fixtures/id/make-guided.py: a license back, a passport page and a payment card
// on a table, at known places relative to the outline).
//
// What it checks, in Chromium with a fake camera only (a real phone's focus, glare, torch,
// takePhoto and haptics are on the on-device checklist in docs/ID-SCANNING.md):
//   - the outline is on screen at ID-1 / ID-3 proportions, centred, with a dim mask and corner marks
//   - small → "Move closer", too big and cut off → "Move back a little", turned → "Straighten the
//     card", blurred → "Not sharp yet", glare → "Too much glare", dark → "Too dark", seen from an
//     angle → "Hold the phone flat", a shaking view → "Hold steady", the wrong side → "Show the back" /
//     "Show the photo page"; and none of them takes a photo by itself
//   - lined up: the photo is taken by itself, cropped to the outline (compared with where the
//     document is known to be), the barcode / MRZ / card number read from that still
//   - the shutter always works, whatever the camera sees
//   - nothing starts before Start camera; the stream is released on leaving
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/guided.mjs            (SHOTS=dir to keep screenshots, ONLY=regex to run some scenes)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { enroll, unlock as unlockV3, openPicker, pickKind, startCamera, chooseId } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = (n) => join(root, "tests/fixtures/id/guide", `${n}.mjpeg`);
const PORT = Number(process.env.PORT || 5199);
const BASE = `http://tauri.localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
const ONLY = process.env.ONLY ? new RegExp(process.env.ONLY) : null;
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-guided-"));
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: guided timed out after 14 minutes"); process.exit(1); }, 14 * 60_000).unref();
const contexts = [];

// where the outline falls in the 1080 x 1920 video at the 412 x 915 test viewport (brand/flows.css .dc-stage / .dc-frame: 3.0 keeps 2.2.0's layout);
// the fixtures (make-guided.py) put their documents by these numbers
const GUIDE = { id1: { x: 141, y: 526, w: 797, h: 503 }, td3: { x: 141, y: 497, w: 797, h: 561 } };
const MARGIN = 0.04;

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
  page.on("console", (m) => { if (m.type() === "error") console.error("console:", m.text()); });
  await page.addInitScript(() => { globalThis.__humidKeepPng = true; });
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
async function enrol(page) { await page.goto(BASE); await enroll(page); }
async function unlock(page) { await page.goto(BASE); await unlockV3(page); }
/** 3.0: the picker is behind Add's "It's something else"; an ID is chosen by which ID it is, then Start camera. */
async function pick(page, name) {
  await openPicker(page);
  if (name === "Payment card") { await pickKind(page, "Payment card"); await startCamera(page); return; }
  await chooseId(page, name);
}
const state = (page) => page.locator(".doccam .dc-state");
const title = async (page) => (await state(page).locator("strong").first().innerText()).trim();
const guide = (page) => page.evaluate(() => globalThis.__humidGuide || null);
const developed = (page) => page.evaluate(() => { const d = globalThis.__humidDevelop; return d ? { ...d, png: undefined } : null; });

/** Wait until the card says `text`, and report what the guidance saw. */
async function says(page, text, timeout = 20_000) {
  await state(page).locator("strong", { hasText: text }).waitFor({ timeout });
  return guide(page);
}

/** How well the cropped photo matches where the document is known to be: overlap of the bright shape with the expected rectangle. */
async function cropIoU(page, { size, ratio }, name = "") {
  if (SHOTS && name) { const png = await page.evaluate(() => globalThis.__humidDevelop?.png); if (png) writeFileSync(join(SHOTS, `crop-${name}.png`), Buffer.from(png.split(",")[1], "base64")); }
  return page.evaluate(async ({ size, ratio, MARGIN }) => {
    const d = globalThis.__humidDevelop;
    if (!d?.png) return null;
    const im = new Image();
    im.src = d.png;
    await im.decode();
    const c = document.createElement("canvas");
    c.width = im.naturalWidth; c.height = im.naturalHeight;
    const g = c.getContext("2d");
    g.drawImage(im, 0, 0);
    const { data, width: w, height: h } = g.getImageData(0, 0, c.width, c.height);
    // the document is the bright shape on the dark table (luma over 110), at a quarter of the size
    const mask = new Uint8Array(w * h);
    for (let i = 0; i < w * h; i++) mask[i] = (data[i * 4] * 0.3 + data[i * 4 + 1] * 0.59 + data[i * 4 + 2] * 0.11) > 110 ? 1 : 0;
    // expected: the outline plus margin fills the crop; the document is `size` of the outline wide, centred
    const cw = (size / (1 + 2 * MARGIN)) * w, ch = cw / ratio;
    const ex0 = (w - cw) / 2, ey0 = (h - ch) / 2;
    // the bright shape's extent (rows and columns with a share of bright pixels: the print inside has dark parts, the table none)
    const rows = new Float32Array(h), cols = new Float32Array(w);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) if (mask[y * w + x]) { rows[y]++; cols[x]++; }
    const ext = (v, n, min) => { let a = -1, b = -1; for (let i = 0; i < v.length; i++) if (v[i] / n > min) { if (a < 0) a = i; b = i; } return [a, b + 1]; };
    const [bx0, bx1] = ext(cols, h, 0.2), [by0, by1] = ext(rows, w, 0.2);
    const ix = Math.max(0, Math.min(bx1, ex0 + cw) - Math.max(bx0, ex0)), iy = Math.max(0, Math.min(by1, ey0 + ch) - Math.max(by0, ey0));
    const inter = ix * iy, a = (bx1 - bx0) * (by1 - by0), b = cw * ch;
    return { iou: inter / (a + b - inter), w, h, ratio: w / h };
  }, { size, ratio, MARGIN });
}

const scenes = [];
const scene = (name, run, file) => { if (!ONLY || ONLY.test(name)) scenes.push({ name, run, file }); };

/** A scene that must show `says`, and must not take a photo by itself for a while after. */
const problem = (name, file, kindName, text, { hold: ms = 4500, waitFor = 25_000 } = {}) => scene(name, async (page) => {
  await pick(page, kindName);
  const g = await says(page, text, waitFor);
  assert.equal(await state(page).getAttribute("data-state"), "problem", `${text} is a problem on the card`);
  await shot(page, name);
  await page.waitForTimeout(ms);
  assert.equal(await page.locator(".doccam").count(), 1, `${text}: the camera stays open: no photo by itself`);
  assert.equal(await developed(page), null, `${text}: nothing was taken`);
  step(`${name}: "${text}" (scale ${g?.scale?.toFixed?.(2)}, rot ${g?.rot?.toFixed?.(1)}, focus ${g?.focus?.toFixed?.(2)}), no photo by itself`);
}, file);

/* ---------------- what the scenes do ---------------- */

// 1. the outline itself, the first moments, and the stream's life (a license front: any picture will do)
scene("outline", async (page) => {
  const count = async () => page.evaluate(() => globalThis.__gum || 0);
  await page.evaluate(() => {
    globalThis.__tracks = []; globalThis.__gum = 0;
    const md = navigator.mediaDevices, real = md.getUserMedia.bind(md);
    md.getUserMedia = async (c) => { globalThis.__gum++; globalThis.__constraints = c; const st = await real(c); globalThis.__tracks.push(...st.getTracks()); return st; };
  });
  await openPicker(page);
  await pickKind(page, /^ID/);
  await page.locator(".pushed .kinds .kind", { hasText: /Passport/ }).click();
  await page.waitForTimeout(700);
  assert.equal(await count(), 0, "no camera request before Start camera");
  await page.locator(".pushed [data-start-camera]").click();
  await page.locator(".doccam[data-guided]").waitFor({ timeout: 10_000 });
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  assert.equal(await count(), 1, "one camera request");
  // not 4K; the long side only (2560 for a passport page's small print), never a crop: a width AND a height make a browser cut the frame to that shape
  const c = await page.evaluate(() => globalThis.__constraints.video);
  assert.equal(c.width.ideal, 2560); assert.equal(c.height, undefined); assert.equal(c.resizeMode, "none");
  const f = await page.locator(".dc-frame").boundingBox();
  const vp = page.viewportSize();
  assert.ok(Math.abs(f.width / f.height - 125 / 88) < 0.01, `a passport page's outline: ${(f.width / f.height).toFixed(3)}`);
  assert.ok(Math.abs(f.x + f.width / 2 - vp.width / 2) < 2, "centred across");
  const stage = await page.locator(".dc-stage").boundingBox();
  assert.ok(f.y > stage.y && f.y + f.height < stage.y + stage.height, "inside the stage");
  const mask = await page.locator(".dc-frame").evaluate((e) => getComputedStyle(e).boxShadow);
  assert.match(mask, /rgba\(4, 10, 7, 0\.62\)/, "the outside is dimmed (the brand's --cam-dim)");
  assert.equal(await page.locator(".dc-frame .c").count(), 4, "four corner marks");
  assert.equal(await page.locator(".dc-frame .dc-outline, .doccam > .dc-outline").count(), 0, "no free-form outline is drawn");
  const live = state(page).locator('[role="status"]');
  assert.equal(await live.getAttribute("aria-live"), "polite", "the card is a live region");
  assert.equal((await state(page).locator(".dc-steps li").first().textContent()).trim(), "Line up");
  // the rect the app uses for the crop, in the video's pixels, is where the fixtures put their documents
  const g = await page.evaluate(() => globalThis.__humidGuide?.rect);
  if (g) for (const k of ["x", "y", "w", "h"]) assert.ok(Math.abs(g[k] - GUIDE.td3[k]) < 10, `the outline's ${k} is ${g[k]} in the video; the fixtures assume ${GUIDE.td3[k]} (re-run make-guided.py if the layout moved)`);
  await shot(page, "outline-passport");
  // the stream is released on leaving
  await page.getByRole("button", { name: "Close the camera" }).click();
  await page.locator(".doccam").waitFor({ state: "detached" });
  assert.equal(await page.evaluate(() => globalThis.__tracks.every((t) => t.readyState === "ended")), true, "closing the camera releases the stream");
  step("the passport outline: 125:88, centred, dimmed outside, four corner marks, 1440p preview; no camera before Start; stream released");
  // a card's outline
  await page.locator(".pushed [data-start-camera]").waitFor();
  await page.getByRole("button", { name: "Back" }).first().click(); // the ID flow → the picker (3.0)
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  await chooseId(page, "Another card");
  await page.locator(".doccam[data-guided]").waitFor({ timeout: 10_000 });
  const f2 = await page.locator(".dc-frame").boundingBox();
  assert.ok(Math.abs(f2.width / f2.height - 85.6 / 54) < 0.01, `a card's outline: ${(f2.width / f2.height).toFixed(3)}`);
  // the camera is asked again for this card; wait for that request (the last one on record is still the passport's until it is made)
  await page.waitForFunction(() => globalThis.__constraints?.video?.width?.ideal === 1920, null, { timeout: 10_000 });
  const c2 = await page.evaluate(() => globalThis.__constraints.video);
  assert.equal(c2.width.ideal, 1920); assert.equal(c2.height, undefined);
  await state(page).locator("strong", { hasText: /Fit the card in the outline|Move closer/ }).waitFor(); // on a small card the first complaint can come at once
  // the app goes to the background: the stream is released at once
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { get: () => true, configurable: true }); document.dispatchEvent(new Event("visibilitychange")); });
  await page.waitForFunction(() => globalThis.__tracks.every((t) => t.readyState === "ended"), null, { timeout: 5000 });
  step("an ID-1 outline: 85.6:54, long-side-only preview; backgrounding releases the stream");
}, "lic-back-small");

// 2. what it says, for each way a card can be wrong
problem("card-small", "lic-back-small", "Another card", "Move closer");
problem("card-big", "lic-back-big", "Another card", "Move back a little");
problem("card-tilt", "lic-back-tilt", "Another card", "Straighten the card");
problem("card-keystone", "lic-back-keystone", "Another card", "Hold the phone flat");
problem("card-blur", "lic-back-blur", "Another card", "Not sharp yet");
problem("card-glare", "lic-back-glare", "Another card", "Too much glare");
problem("card-dark", "lic-back-dark", "Another card", "Too dark");
problem("passport-small", "pp-small", "Passport", "Move closer");
problem("passport-big", "pp-big", "Passport", "Move back a little");
problem("passport-tilt", "pp-tilt", "Passport", "Straighten the passport page");
problem("passport-blur", "pp-blur", "Passport", "Not sharp yet");
problem("passport-glare", "pp-glare", "Passport", "Too much glare");
problem("passport-dark", "pp-dark", "Passport", "Too dark");
problem("passport-wrongpage", "pp-wrongpage", "Passport", "Show the photo page");

// 3. a shaking view: lined up, but never steady, so never taken
scene("card-shaky", async (page) => {
  await pick(page, "Another card");
  await says(page, "Hold steady", 20_000);
  await page.waitForTimeout(5000);
  assert.equal(await page.locator(".doccam").count(), 1, "shaking: no photo by itself");
  assert.equal(await developed(page), null);
  const g = await guide(page);
  step(`a shaking view: "Hold steady", no photo (motion ${g?.motion?.toFixed?.(3)})`);
}, "lic-back-shaky");

// 4. the wrong side: a license's front where the back is asked for
scene("license-wrong-side", async (page) => {
  await pick(page, "Driver's license");
  // the front: whatever the camera sees, the shutter takes it
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.locator(".doccam .dc-shutter").click();
  // the back's camera opens by itself once the front is kept
  await says(page, "Show the back", 40_000);
  await page.waitForTimeout(3000);
  assert.equal(await page.locator(".doccam").count(), 1, "the front where the back is asked for isn't taken by itself");
  step('a license front where the back is asked for: "Show the back", no photo by itself');
}, "lic-front-ok");

// 5. the shutter always works: a card that is far too small is still taken when asked
scene("manual-shutter", async (page) => {
  await pick(page, "Another card");
  await says(page, "Move closer");
  await page.locator(".doccam .dc-shutter").click();
  await page.locator(".pushed", { hasText: "Review, then seal" }).or(page.locator(".pushed").getByText("Front saved")).first().waitFor({ timeout: 30_000 }).catch(() => {});
  await page.waitForFunction(() => globalThis.__humidDevelop, null, { timeout: 30_000 });
  const d = await developed(page);
  assert.equal(d.how, "shutter"); assert.equal(d.guided, true);
  const r = await cropIoU(page, { size: 0.58, ratio: 85.6 / 54 }, "small");
  assert.ok(r.iou > 0.85, `the small card is where it was in the outline: overlap ${r.iou.toFixed(2)}`);
  step(`the shutter takes a card the guidance called too small (overlap with where it lay: ${r.iou.toFixed(2)}, ${d.source} ${d.stillW}px)`);
}, "lic-back-small");

// 6. lined up: taken by itself, cropped to the outline, read from the still. The license back
scene("license-back-ok", async (page) => {
  await pick(page, "Driver's license");
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.locator(".doccam .dc-shutter").click(); // the front: any view
  await page.locator(".dc-saved-chip", { hasText: "Front saved" }).waitFor({ timeout: 30_000 });
  await page.evaluate(() => { globalThis.__humidDevelop = undefined; }); // the back's camera has opened by itself
  const seen = new Set();
  const watch = setInterval(() => page.evaluate(() => document.querySelector(".doccam .dc-state strong")?.textContent).then((t) => t && seen.add(t)).catch(() => {}), 120);
  await page.locator(".pushed", { hasText: "Review, then seal" }).waitFor({ timeout: 60_000 });
  clearInterval(watch);
  const d = await developed(page);
  assert.equal(d.how, "auto", "taken by itself");
  assert.equal(d.guided, true);
  assert.ok(seen.has("Hold steady") || seen.has("Reading") || seen.has("Verifying"), `it said ${[...seen].join(", ")}`);
  const r = await cropIoU(page, { size: 0.97, ratio: 85.6 / 54 }, "license-back");
  assert.ok(r.iou > 0.93, `the crop holds the whole card where it was: overlap ${r.iou.toFixed(3)}`);
  assert.ok(Math.abs(r.ratio - 85.6 / 54) < 0.02, `ID-1 proportions: ${r.ratio.toFixed(3)}`);
  assert.equal(await page.locator("#idf-surname").inputValue(), "SPECIMEN", "the barcode was read from the still");
  assert.equal(await page.locator("#idf-number").inputValue(), "S12345678901");
  await shot(page, "license-back-read");
  step(`license back: taken by itself, crop overlap ${r.iou.toFixed(3)}, barcode read from the ${d.source} (${d.stillW}px wide), rotate ${d.rotate}`);
  // the review has a Rotate control
  const rot = page.locator(".id-thumbs").getByRole("button", { name: /Rotate the back/ });
  assert.ok((await rot.boundingBox()).height >= 44, "Rotate is a 44 px target");
  const before = await page.locator(".id-thumbs figure[data-shape='id1'] img").nth(1).getAttribute("src").catch(() => null);
  await rot.click();
  await page.waitForFunction((b) => document.querySelectorAll(".id-thumbs img")[1]?.getAttribute("src") !== b, before, { timeout: 10_000 });
  step("the review's Rotate turns the photo");
}, "lic-back-ok");

// 7. a little tilt: the crop is turned straight
scene("license-back-tilt3", async (page) => {
  await pick(page, "Another card");
  await page.waitForFunction(() => globalThis.__humidDevelop, null, { timeout: 40_000 });
  const d = await developed(page);
  assert.equal(d.how, "auto");
  const r = await cropIoU(page, { size: 0.95, ratio: 85.6 / 54 });
  assert.ok(r.iou > 0.93, `a card turned 3.5° is cropped straight: overlap ${r.iou.toFixed(3)}`);
  step(`a card turned 3.5° is taken by itself and cropped straight (overlap ${r.iou.toFixed(3)})`);
}, "lic-back-tilt3");

// 8. a passport: taken by itself, the MRZ read from the still, on to the chip step
scene("passport-ok", async (page) => {
  await pick(page, "Passport");
  await page.getByText("Read the ID chip").first().waitFor({ timeout: 90_000 });
  const d = await developed(page);
  assert.equal(d.how, "auto"); assert.equal(d.guided, true);
  const r = await cropIoU(page, { size: 0.97, ratio: 125 / 88 });
  assert.ok(r.iou > 0.93, `the page is where it was in the crop: overlap ${r.iou.toFixed(3)}`);
  assert.equal(await page.locator("#doc-num").inputValue(), "D00000001");
  assert.equal(await page.locator("#doc-birth").inputValue(), "1974-08-12");
  step(`passport: taken by itself, crop overlap ${r.iou.toFixed(3)}, MRZ read from the ${d.source} (${d.stillW}px wide)`);
}, "pp-ok");

// 9. a payment card: Add > Payment card > Start camera
scene("pay-front", async (page) => {
  await pick(page, "Payment card");
  await page.locator("#cf-pan").waitFor({ timeout: 90_000 });
  await page.waitForFunction(() => document.querySelector("#cf-pan")?.value.replace(/\s/g, "").length >= 16, null, { timeout: 30_000 });
  assert.equal((await page.inputValue("#cf-pan")).replace(/\s/g, ""), "4111111111111111");
  const d = await developed(page);
  assert.equal(d.how, "auto"); assert.equal(d.guided, true);
  const r = await cropIoU(page, { size: 0.97, ratio: 85.6 / 54 });
  assert.ok(r.iou > 0.93, `overlap ${r.iou.toFixed(3)}`);
  const rot = page.locator(".id-thumbs").getByRole("button", { name: /Rotate the front/ });
  assert.ok(await rot.isVisible(), "the card review has Rotate");
  step(`payment card front: taken by itself, crop overlap ${r.iou.toFixed(3)}, number read`);
}, "pay-front-ok");

// the preview's resolution: the still is what is read, and 720p is already enough for these (docs/ID-SCANNING.md has the margins)
scene("passport-720p", async (page) => {
  await pick(page, "Passport");
  await page.getByText("Read the ID chip").first().waitFor({ timeout: 90_000 });
  const d = await developed(page);
  assert.equal(await page.locator("#doc-num").inputValue(), "D00000001");
  step(`passport at 720p: MRZ read (${d.source} ${d.stillW}px wide)`);
}, "pp-ok-720p");
scene("license-720p", async (page) => {
  await pick(page, "Driver's license");
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.locator(".doccam .dc-shutter").click();
  await page.locator(".dc-saved-chip", { hasText: "Front saved" }).waitFor({ timeout: 30_000 });
  await page.locator(".pushed", { hasText: "Review, then seal" }).waitFor({ timeout: 60_000 });
  const d = await developed(page);
  assert.equal(await page.locator("#idf-number").inputValue(), "S12345678901");
  step(`license back at 720p: barcode read (${d.source} ${d.stillW}px wide)`);
}, "lic-back-ok-720p");

// the still: ImageCapture.takePhoto where the WebView has it. The fake camera has none that matters, so a stand-in
// hands back the camera's own view at other sizes: the same framing at twice the pixels, a 3:4 photo with the video's
// field centred in it, and a photo of something else (which must be refused: the preview's frame is used instead).
for (const [mode, expectSource, why] of [["same", "photo", "twice the pixels, same framing"], ["wide", "photo", "a 3:4 photo with the preview's field centred in it"], ["other", "frame", "a photo of a different scene: refused"]]) {
  scene(`still-${mode}`, async (page) => {
    await page.evaluate((mode) => {
      globalThis.ImageCapture = class {
        constructor(track) { this.track = track; }
        async getPhotoCapabilities() { return { imageWidth: { min: 160, max: 6000, step: 1 }, imageHeight: { min: 120, max: 8000, step: 1 } }; }
        async takePhoto(settings) {
          globalThis.__photoSettings = settings;
          const v = document.querySelector(".doccam video");
          const vw = v.videoWidth, vh = v.videoHeight;
          const [pw, ph] = mode === "same" ? [vw * 2, vh * 2] : [3024, 4032];
          const sc = Math.min(pw / vw, ph / vh);
          const c = document.createElement("canvas");
          c.width = pw; c.height = ph;
          const g = c.getContext("2d");
          g.fillStyle = "#3a322c"; g.fillRect(0, 0, pw, ph);
          if (mode === "other") { for (let i = 0; i < 400; i++) { g.fillStyle = `hsl(${(i * 47) % 360} 60% ${20 + (i * 13) % 60}%)`; g.fillRect((i * 977) % pw, (i * 613) % ph, 40 + (i % 90), 30 + (i % 70)); } }
          else g.drawImage(v, (pw - vw * sc) / 2, (ph - vh * sc) / 2, vw * sc, vh * sc);
          return new Promise((r) => c.toBlob(r, "image/jpeg", 0.92));
        }
      };
    }, mode);
    await pick(page, "Another card");
    await page.waitForFunction(() => globalThis.__humidDevelop, null, { timeout: 40_000 });
    const d = await developed(page);
    assert.equal(d.how, "auto"); assert.equal(d.source, expectSource, `${why}: used the ${d.source} (${d.why || "ok"})`);
    const r = await cropIoU(page, { size: 0.97, ratio: 85.6 / 54 }, `still-${mode}`);
    assert.ok(r.iou > 0.93, `${why}: crop overlap ${r.iou.toFixed(3)}`);
    const s = await page.evaluate(() => globalThis.__photoSettings);
    assert.ok(s.imageWidth <= 4096 && s.imageHeight <= 4096, `the photo is asked for at a size a phone can decode: ${JSON.stringify(s)}`);
    step(`still, ${why}: used the ${d.source}${d.stillW ? ` (${d.stillW}px)` : ""}, crop overlap ${r.iou.toFixed(3)}${d.why ? `, "${d.why}"` : ""}`);
  }, "lic-back-ok");
}

/* ---------------- run ---------------- */

try {
  let enrolled = false;
  for (const s of scenes) {
    const file = s.file;
    const { ctx, page } = await launch(fixture(file));
    if (!enrolled) { await enrol(page); enrolled = true; step("enrolled (demo)"); } else await unlock(page);
    try { await s.run(page); } catch (e) { await shot(page, `FAIL-${s.name}`); console.error('guidance at failure:', JSON.stringify(await guide(page).catch(() => null)), 'card:', await title(page).catch(() => null)); console.error(`scene ${s.name} (${file}) failed`); throw e; }
    await ctx.close();
  }
  console.log(`ok — the guided scan works in the browser (${scenes.length} scenes)`);
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
