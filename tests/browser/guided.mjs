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
//   - nothing starts before a kind is picked; picking one opens its outline at once; the stream is released on leaving
//   - while the photo is read the outline stays green (no dark cover); no four-point outline is ever drawn
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
const GUIDE = { id1: { x: 141, y: 526, w: 797, h: 503 }, td3: { x: 141, y: 497, w: 797, h: 561 }, page: { x: 141, y: 239, w: 797, h: 1076 } };

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
/** 3.0.1: Add opens the picker; a kind opens its camera at once. */
async function pick(page, name) {
  await openPicker(page);
  if (name === "Payment card") { await pickKind(page, "Payment card"); await startCamera(page); return; }
  await chooseId(page, name);
}
const state = (page) => page.locator(".doccam .dc-panel");
const title = async (page) => (await state(page).locator("strong").first().innerText()).trim();
const guide = (page) => page.evaluate(() => globalThis.__humidGuide || null);
const developed = (page) => page.evaluate(() => { const d = globalThis.__humidDevelop; return d ? { ...d, png: undefined } : null; });

/** Wait until the card says `text`, and report what the guidance saw. */
async function says(page, text, timeout = 20_000) {
  await state(page).locator("strong", { hasText: text }).waitFor({ timeout });
  return guide(page);
}

/**
 * 3.1.1: the photo is the document itself, filling the whole picture: no table round it. The document is the
 * bright shape on the dark table; its extent (rows and columns that are mostly bright) is compared with the
 * whole picture. `ratio`: the document's proportions (the picture's must match).
 */
async function cropIoU(page, { ratio }, name = "") {
  if (SHOTS && name) { const png = await page.evaluate(() => globalThis.__humidDevelop?.png); if (png) writeFileSync(join(SHOTS, `crop-${name}.png`), Buffer.from(png.split(",")[1], "base64")); }
  return page.evaluate(async () => {
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
    const rows = new Float32Array(h), cols = new Float32Array(w);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { const i = (y * w + x) * 4; if (data[i] * 0.3 + data[i + 1] * 0.59 + data[i + 2] * 0.11 > 110) { rows[y]++; cols[x]++; } }
    const ext = (v, n, min) => { let a = -1, b = -1; for (let i = 0; i < v.length; i++) if (v[i] / n > min) { if (a < 0) a = i; b = i; } return [a, b + 1]; };
    const [bx0, bx1] = ext(cols, h, 0.2), [by0, by1] = ext(rows, w, 0.2);
    // the share of the picture the document covers, and the darkest margin left on any side
    const iou = ((bx1 - bx0) * (by1 - by0)) / (w * h);
    const margin = Math.max(bx0, w - bx1) / w > Math.max(by0, h - by1) / h ? Math.max(bx0, w - bx1) / w : Math.max(by0, h - by1) / h;
    return { iou, margin, w, h, ratio: w / h, fit: d.fit };
  });
}

const scenes = [];
const scene = (name, run, file) => { if (!ONLY || ONLY.test(name)) scenes.push({ name, run, file }); };

/** A scene that must show `says`, and must not take a photo by itself for a while after. */
const problem = (name, file, kindName, text, { hold: ms = 4500, waitFor = 25_000 } = {}) => scene(name, async (page) => {
  await pick(page, kindName);
  const g = await says(page, text, waitFor);
  assert.equal(await state(page).getAttribute("data-phase"), "adjust", `${text} is an instruction on the panel`);
  assert.equal(await state(page).getAttribute("data-tone"), "warn", `${text} is said in amber`);
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
  await page.waitForTimeout(700);
  assert.equal(await count(), 0, "no camera request before a kind is picked");
  await pickKind(page, "Passport");
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
  assert.equal(await page.locator(".dc-outline, .doccam > svg, .dc-stage polygon").count(), 0, "no four-point outline is drawn");
  const live = state(page).locator('[role="status"]');
  assert.equal(await live.getAttribute("aria-live"), "polite", "the card is a live region");
  assert.deepEqual((await state(page).locator(".dc-chips li").allTextContents()).map((t) => t.trim()).slice(0, 4), ["Framed", "Sharp", "Steady", "Light"], "the live chips");
  assert.equal((await state(page).locator(".dc-chips li").nth(4).textContent()).trim(), "ID lines", "a passport's chip for the lines of <<<");
  // the panel sits right under the frame
  const pb = await state(page).boundingBox();
  assert.ok(pb.y > f.y + f.height && pb.y - (f.y + f.height) < 30, `the panel is right under the frame (${Math.round(pb.y - (f.y + f.height))} px)`);
  // the rect the app uses for the crop, in the video's pixels, is where the fixtures put their documents
  const g = await page.evaluate(() => globalThis.__humidGuide?.rect);
  if (g) for (const k of ["x", "y", "w", "h"]) assert.ok(Math.abs(g[k] - GUIDE.td3[k]) < 10, `the outline's ${k} is ${g[k]} in the video; the fixtures assume ${GUIDE.td3[k]} (re-run make-guided.py if the layout moved)`);
  await shot(page, "outline-passport");
  // the stream is released on leaving
  await page.getByRole("button", { name: "Close the camera" }).click();
  await page.locator(".doccam").waitFor({ state: "detached" });
  assert.equal(await page.evaluate(() => globalThis.__tracks.every((t) => t.readyState === "ended")), true, "closing the camera releases the stream");
  step("the passport outline: 125:88, centred, dimmed outside, four corner marks, 1440p preview; no camera before a kind is picked; stream released");
  // closing the first camera goes back to the picker (3.0.1)
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  await chooseId(page, "Another card");
  await page.locator(".doccam[data-guided]").waitFor({ timeout: 10_000 });
  const f2 = await page.locator(".dc-frame").boundingBox();
  assert.ok(Math.abs(f2.width / f2.height - 85.6 / 54) < 0.01, `a card's outline: ${(f2.width / f2.height).toFixed(3)}`);
  // the camera is asked again for this card; wait for that request (the last one on record is still the passport's until it is made)
  await page.waitForFunction(() => globalThis.__constraints?.video?.width?.ideal === 1920, null, { timeout: 10_000 });
  const c2 = await page.evaluate(() => globalThis.__constraints.video);
  assert.equal(c2.width.ideal, 1920); assert.equal(c2.height, undefined);
  await state(page).locator("strong", { hasText: /Place the card in the frame|Move closer/ }).waitFor(); // on a small card the first complaint can come at once
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

// 3. a shaking view (the card jumping ±22 px every frame): "Hold still", with the Steady chip amber. 3.1.1: the photo no
//    longer waits for stillness, only for a sharp lined-up moment, so a frame between the jumps may be taken; when it
//    is, it must be the card, cut out cleanly. (A real shake that hard blurs every frame, which the sharpness check refuses;
//    these synthetic frames are all crisp.)
scene("card-shaky", async (page) => {
  await page.evaluate(() => {
    globalThis.__said = new Set();
    new MutationObserver(() => { const t = document.querySelector(".doccam .dc-panel strong")?.textContent; if (t) globalThis.__said.add(t); const c = document.querySelector('.doccam .dc-chips li[data-k="steady"][data-state="warn"]'); if (c) globalThis.__said.add("steady:warn"); })
      .observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true });
  });
  await pick(page, "Another card");
  await page.waitForTimeout(8000);
  const said = await page.evaluate(() => [...globalThis.__said]);
  assert.ok(said.includes("Hold still") && said.includes("steady:warn"), `it said to hold still, with the Steady chip amber: ${said.join(", ")}`);
  const d = await developed(page);
  const g = await guide(page);
  if (d) {
    const r = await cropIoU(page, { ratio: 85.6 / 54 }, "shaky");
    assert.ok(r.iou > 0.93, `taken between the jumps: the card cut out cleanly (${r.iou.toFixed(3)})`);
    step(`a shaking view: "Hold still" with the Steady chip amber; a sharp moment between the jumps was taken, the card filling ${(r.iou * 100).toFixed(1)}%`);
  } else step(`a shaking view: "Hold still" with the Steady chip amber, no photo (motion ${g?.motion?.toFixed?.(3)})`);
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
  const r = await cropIoU(page, { ratio: 85.6 / 54 }, "small");
  assert.equal(r.fit, "edges", "the card was found in the crop");
  assert.ok(r.iou > 0.93, `even a small card fills the picture once cut out: ${r.iou.toFixed(2)} (margin ${(r.margin * 100).toFixed(1)}%)`);
  step(`the shutter takes a card the guidance called too small, and cuts it out to fill the picture (${(r.iou * 100).toFixed(0)}%, ${d.source} ${d.stillW}px)`);
}, "lic-back-small");

// 6. lined up: taken by itself, cropped to the outline, read from the still. The license back
scene("license-back-ok", async (page) => {
  await pick(page, "Driver's license");
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.locator(".doccam .dc-shutter").click(); // the front: any view
  await page.locator(".dc-saved-chip", { hasText: "Front saved" }).waitFor({ timeout: 30_000 });
  await page.evaluate(() => { globalThis.__humidDevelop = undefined; }); // the back's camera has opened by itself
  const seen = new Set();
  const watch = setInterval(() => page.evaluate(() => document.querySelector(".doccam .dc-panel strong")?.textContent).then((t) => t && seen.add(t)).catch(() => {}), 60);
  // before moving on, the camera says what it read
  await state(page).locator("strong", { hasText: "Got it" }).waitFor({ timeout: 60_000 });
  const fields = await state(page).locator(".dc-fields div").allInnerTexts();
  assert.ok(fields.some((f) => /Name\s+Jordan Alex Specimen/.test(f)), `the read-back lists the name: ${fields.join(" | ")}`);
  assert.ok(fields.some((f) => /Number\s+S12345678901/.test(f)), "and the number");
  assert.ok(await page.locator(".doccam .dc-freeze").count(), "the photo is frozen in the frame");
  await shot(page, "license-back-readback");
  await page.locator(".pushed", { hasText: "Review, then seal" }).waitFor({ timeout: 60_000 });
  clearInterval(watch);
  const d = await developed(page);
  assert.equal(d.how, "auto", "taken by itself");
  assert.equal(d.guided, true);
  assert.ok(seen.has("Captured") && seen.has("Got it"), `it said ${[...seen].join(", ")}`);
  const code = await page.evaluate(() => globalThis.__humidCode);
  const r = await cropIoU(page, { ratio: 85.6 / 54 }, "license-back");
  assert.ok(r.iou > 0.93, `the card fills the picture:  ${r.iou.toFixed(3)}`);
  assert.ok(Math.abs(r.ratio - 85.6 / 54) < 0.02, `ID-1 proportions: ${r.ratio.toFixed(3)}`);
  assert.equal(await page.locator("#idf-surname").inputValue(), "SPECIMEN", "the barcode was read from the still");
  assert.equal(await page.locator("#idf-number").inputValue(), "S12345678901");
  await shot(page, "license-back-read");
  step(`license back: taken by itself, the card fills ${(r.iou * 100).toFixed(1)}% of the picture, barcode read ${d.live ? `live, before the photo (${code?.n} reads)` : `from the ${d.source}`}; said: ${[...seen].join(" → ")}`);
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
  const r = await cropIoU(page, { ratio: 85.6 / 54 });
  assert.ok(r.iou > 0.93, `a card turned 3.5° is cut out straight, filling the picture: ${r.iou.toFixed(3)}`);
  step(`a card turned 3.5° is taken by itself and cropped straight (overlap ${r.iou.toFixed(3)})`);
}, "lic-back-tilt3");

// 8. a passport: taken by itself, the MRZ read from the still, on to the chip step
scene("passport-ok", async (page) => {
  await pick(page, "Passport");
  await page.getByText("Read the ID chip").first().waitFor({ timeout: 90_000 });
  const d = await developed(page);
  assert.equal(d.how, "auto"); assert.equal(d.guided, true);
  const r = await cropIoU(page, { ratio: 125 / 88 });
  assert.ok(r.iou > 0.93, `the page fills the picture: ${r.iou.toFixed(3)}`);
  assert.equal(await page.locator("#doc-num").inputValue(), "D00000001");
  assert.equal(await page.locator("#doc-birth").inputValue(), "1974-08-12");
  step(`passport: taken by itself, the card fills ${(r.iou * 100).toFixed(1)}% of the picture, MRZ read from the ${d.source} (${d.stillW}px wide)`);
}, "pp-ok");

// 9. a payment card: Add > Payment card > Start camera
scene("pay-front", async (page) => {
  await pick(page, "Payment card");
  await page.locator("#cf-pan").waitFor({ timeout: 90_000 });
  await page.waitForFunction(() => document.querySelector("#cf-pan")?.value.replace(/\s/g, "").length >= 16, null, { timeout: 30_000 });
  assert.equal((await page.inputValue("#cf-pan")).replace(/\s/g, ""), "4111111111111111");
  const d = await developed(page);
  assert.equal(d.how, "auto"); assert.equal(d.guided, true);
  const r = await cropIoU(page, { ratio: 85.6 / 54 });
  assert.ok(r.iou > 0.93, `overlap ${r.iou.toFixed(3)}`);
  const rot = page.locator(".id-thumbs").getByRole("button", { name: /Rotate the front/ });
  assert.ok(await rot.isVisible(), "the card review has Rotate");
  step(`payment card front: taken by itself, the card fills ${(r.iou * 100).toFixed(1)}% of the picture, number read`);
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
    const r = await cropIoU(page, { ratio: 85.6 / 54 }, `still-${mode}`);
    assert.ok(r.iou > 0.93, `${why}: the card fills ${(r.iou * 100).toFixed(1)}% of the picture`);
    const s = await page.evaluate(() => globalThis.__photoSettings);
    assert.ok(s.imageWidth <= 4096 && s.imageHeight <= 4096, `the photo is asked for at a size a phone can decode: ${JSON.stringify(s)}`);
    step(`still, ${why}: used the ${d.source}${d.stillW ? ` (${d.stillW}px)` : ""}, the card fills ${(r.iou * 100).toFixed(1)}% of the picture${d.why ? `, "${d.why}"` : ""}`);
  }, "lic-back-ok");
}

// 3.0.1: a phone that hands the photo back upside down (a sensor mounted the other way up): the still is turned back,
// so the crop is the way up the card was lined up in the preview
scene("still-upside-down", async (page) => {
  await page.evaluate(() => {
    globalThis.ImageCapture = class {
      constructor(track) { this.track = track; }
      async getPhotoCapabilities() { return { imageWidth: { min: 160, max: 6000, step: 1 }, imageHeight: { min: 120, max: 8000, step: 1 } }; }
      async takePhoto() {
        const v = document.querySelector(".doccam video");
        const c = document.createElement("canvas");
        c.width = v.videoWidth * 2; c.height = v.videoHeight * 2;
        const g = c.getContext("2d");
        g.translate(c.width, c.height); g.rotate(Math.PI);
        g.drawImage(v, 0, 0, c.width, c.height);
        return new Promise((r) => c.toBlob(r, "image/jpeg", 0.92));
      }
    };
  });
  await pick(page, "Payment card");
  await page.waitForFunction(() => globalThis.__humidDevelop, null, { timeout: 40_000 });
  const d = await developed(page);
  assert.equal(d.source, "photo", `the turned photo is recognised as the same scene (${d.why || "ok"})`);
  assert.equal(d.turned, 180, "and turned back");
  // the crop agrees with the preview the right way up, not upside down
  const way = await page.evaluate(async () => {
    const v = document.querySelector(".doccam video"), r = globalThis.__humidGuide.rect;
    const thumb = (src, x, y, w, h) => { const c = document.createElement("canvas"); c.width = 64; c.height = 40; const g = c.getContext("2d"); g.drawImage(src, x, y, w, h, 0, 0, 64, 40); const d = g.getImageData(0, 0, 64, 40).data; const o = []; for (let i = 0; i < d.length; i += 4) o.push(d[i] + d[i + 1] + d[i + 2]); return o; };
    const im = new Image(); im.src = globalThis.__humidDevelop.png; await im.decode();
    const m = 0;
    const a = thumb(v, r.x, r.y, r.w, r.h), b = thumb(im, im.naturalWidth * m, im.naturalHeight * m, im.naturalWidth * (1 - 2 * m), im.naturalHeight * (1 - 2 * m));
    const ncc = (p, q) => { const n = p.length, mp = p.reduce((t, x) => t + x, 0) / n, mq = q.reduce((t, x) => t + x, 0) / n; let s = 0, sp = 0, sq = 0; for (let i = 0; i < n; i++) { s += (p[i] - mp) * (q[i] - mq); sp += (p[i] - mp) ** 2; sq += (q[i] - mq) ** 2; } return s / Math.sqrt(sp * sq); };
    return { upright: ncc(a, b), flipped: ncc(a, b.slice().reverse()) };
  });
  assert.ok(way.upright > way.flipped + 0.2, `the crop is the right way up: ${JSON.stringify(way)}`);
  step(`a photo handed back upside down is turned back: the crop matches the preview upright (${way.upright.toFixed(2)} vs ${way.flipped.toFixed(2)} turned)`);
}, "pay-front-ok");

// 3.0.1: while the photo is read the outline is green, with no dark cover over the document
scene("green-while-reading", async (page) => {
  await page.evaluate(() => {
    globalThis.__looks = new Set();
    new MutationObserver(() => { const c = document.querySelector(".doccam"); if (c) globalThis.__looks.add(`${c.dataset.phase}:${c.dataset.look}:${!!c.querySelector(".dc-freeze")}:${!!c.querySelector(".dc-sweep")}`); })
      .observe(document.body, { subtree: true, attributes: true, childList: true });
  });
  await pick(page, "Passport");
  await page.getByText("Read the ID chip").first().waitFor({ timeout: 90_000 });
  const looks = await page.evaluate(() => [...globalThis.__looks]);
  const reading = looks.filter((l) => l.startsWith("check:"));
  assert.ok(reading.length, `the photo was read: ${looks.join(" ")}`);
  assert.ok(reading.every((l) => l.startsWith("check:ok:true")), `green, with the photo frozen in the frame, while reading: ${reading.join(" ")}`);
  assert.ok(reading.some((l) => l.endsWith(":true")), "a green line sweeps the frame while it is read");
  assert.ok(looks.some((l) => l.startsWith("done:ok")), `then it says it's done: ${looks.join(" ")}`);
  step(`while the passport page is read the frame is green, the photo frozen in it, a line sweeping it (${reading.join(", ")})`);
}, "pp-ok");

// 3.0.1: a document page: the page outline (between US Letter and A4), taken by itself, to the photo review with a clean scan
scene("page", async (page) => {
  await openPicker(page);
  await pickKind(page, "Document");
  await page.locator(".doccam[data-guided][data-shape='page']").waitFor({ timeout: 10_000 });
  const f = await page.locator(".dc-frame").boundingBox();
  assert.ok(Math.abs(f.height / f.width - 1.35) < 0.01, `a page's outline stands up, 1:1.35: ${(f.height / f.width).toFixed(3)}`);
  await page.waitForFunction(() => globalThis.__humidGuide?.rect, null, { timeout: 20_000 });
  const g = await guide(page);
  for (const k of ["x", "y", "w", "h"]) assert.ok(Math.abs(g.rect[k] - GUIDE.page[k]) < 10, `the page outline's ${k} is ${g.rect[k]} in the video; the fixtures assume ${GUIDE.page[k]}`);
  await shot(page, "page-outline");
  await page.locator(".pushed", { hasText: "Review, then seal" }).waitFor({ timeout: 60_000 });
  const d = await developed(page);
  assert.equal(d.how, "auto", "taken by itself"); assert.equal(d.guided, true);
  const r = await cropIoU(page, { ratio: 8.5 / 11 }, "page");
  assert.ok(r.iou > 0.9, `the page fills the picture: ${r.iou.toFixed(3)}`);
  assert.equal(await page.locator(".pushed .eyebrow", { hasText: "Document" }).count() > 0, true, "reviewed as a document");
  step(`a Letter page: the page outline (1:1.35), taken by itself, the card fills ${(r.iou * 100).toFixed(1)}% of the picture, reviewed as a document`);
}, "page-letter-ok");

// 3.0.3: the lock box follows the document the camera sees inside the frame (four edges and an angle, eased), amber while it isn't lined up
scene("lock-box", async (page) => {
  await pick(page, "Another card");
  await says(page, "Move closer");
  await page.locator(".dc-lock").waitFor({ timeout: 10_000 });
  await page.waitForTimeout(800); // eased onto where the card is
  const f = await page.locator(".dc-frame").boundingBox(), b = await page.locator(".dc-lock").boundingBox();
  const share = b.width / f.width, cx = (b.x + b.width / 2 - f.x) / f.width;
  assert.ok(Math.abs(share - 0.58) < 0.06, `the lock box is the card's size: ${share.toFixed(2)} of the frame (the card is 0.58)`);
  assert.ok(Math.abs(cx - 0.5) < 0.05, `and where it is: centre at ${cx.toFixed(2)}`);
  assert.equal(await page.locator('.dc-frame[data-state="close"]').count(), 1, "the frame says close (amber)");
  assert.equal(await state(page).locator('.dc-chips li[data-k="framed"]').getAttribute("data-state"), "warn", "Framed: amber");
  await shot(page, "lock-box");
  step(`the lock box sits on the card the camera sees: ${share.toFixed(2)} of the frame wide, centred at ${cx.toFixed(2)}; frame and Framed chip amber`);
}, "lic-back-small");

// 3.0.3: a license back held up when the front is asked for: its barcode is read live and it's kept as the back, then the front is asked for
scene("front-is-back", async (page) => {
  await pick(page, "Driver's license");
  await state(page).locator("strong", { hasText: "That was the back" }).waitFor({ timeout: 60_000 });
  const fields = await state(page).locator(".dc-fields div").allInnerTexts();
  assert.ok(fields.some((f) => /Name\s+Jordan Alex Specimen/.test(f)), `read from its barcode: ${fields.join(" | ")}`);
  await shot(page, "front-is-back");
  await page.locator(".dc-saved-chip", { hasText: "Back saved. Now the front." }).waitFor({ timeout: 20_000 });
  const d = await developed(page);
  assert.equal(d.side, "back"); assert.equal(d.live, true, "read live, before the photo");
  step("a license back held up for the front: read live, kept as the back, and the front's camera opens (\"Back saved. Now the front.\")");
}, "lic-back-ok");

// 3.0.3: nothing to read in the photo: the camera says so plainly and offers Try again or Keep the photo, never a silent loop
scene("no-read-choice", async (page) => {
  await pick(page, "Driver's license");
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.locator(".doccam .dc-shutter").click(); // the front
  await page.locator(".dc-saved-chip", { hasText: "Front saved" }).waitFor({ timeout: 30_000 });
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.locator(".doccam .dc-shutter").click(); // the back, far too blurred to read
  await state(page).locator("strong", { hasText: "Couldn't read the barcode" }).waitFor({ timeout: 60_000 });
  assert.equal(await state(page).getAttribute("data-phase"), "fail");
  await shot(page, "no-read-choice");
  // Try again goes back to the live view
  await state(page).getByRole("button", { name: "Try again" }).click();
  await page.waitForFunction(() => ["aim", "adjust", "hold"].includes(document.querySelector(".doccam")?.dataset.phase), null, { timeout: 10_000 });
  // the shutter again, then Keep the photo: on to the review, to type the details
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.locator(".doccam .dc-shutter").click();
  await state(page).getByRole("button", { name: "Keep the photo" }).click({ timeout: 60_000 });
  await page.locator(".pushed", { hasText: "Review, then seal" }).waitFor({ timeout: 30_000 });
  step("a back that can't be read: \"Couldn't read the barcode\" with Try again (back to live) and Keep the photo (on to type the details)");
}, "lic-back-blur");

// 3.0.3: the payment card's number is said back on the camera before the form
scene("card-readback", async (page) => {
  await page.evaluate(() => {
    globalThis.__said = [];
    new MutationObserver(() => { const t = document.querySelector(".doccam .dc-panel strong")?.textContent; if (t && globalThis.__said.at(-1) !== t) globalThis.__said.push(t); }).observe(document.body, { subtree: true, childList: true, characterData: true });
  });
  await pick(page, "Payment card");
  await state(page).locator("strong", { hasText: "Got it" }).waitFor({ timeout: 90_000 }).catch(async (e) => { console.error("said: " + JSON.stringify(await page.evaluate(() => globalThis.__said))); throw e; });
  const fields = await state(page).locator(".dc-fields div").allInnerTexts();
  assert.ok(fields.some((f) => /Card\s+Visa ending 1111/.test(f)), `the card is said back: ${fields.join(" | ")}`);
  await shot(page, "card-readback");
  await page.locator("#cf-pan").waitFor({ timeout: 30_000 });
  step(`payment card: "${fields.join(" · ").replace(/\n/g, " ")}" said on the camera, then the form`);
}, "pay-front-ok");

// 3.1.1: a hand that trembles a little: the sharpest lined-up frame is taken, without waiting for the hand to be still
scene("tremor", async (page) => {
  await pick(page, "Another card");
  const t0 = Date.now();
  await page.waitForFunction(() => globalThis.__humidDevelop, null, { timeout: 20_000 });
  const ms = Date.now() - t0;
  const d = await developed(page);
  assert.equal(d.how, "auto", "taken by itself");
  const r = await cropIoU(page, { ratio: 85.6 / 54 }, "tremor");
  assert.ok(r.iou > 0.93, `cut out to the card: ${r.iou.toFixed(3)}`);
  step(`a trembling hand: taken by itself ${(ms / 1000).toFixed(1)} s after the camera opened, the card filling ${(r.iou * 100).toFixed(1)}% of the picture`);
}, "lic-back-tremor");

// 3.1.1: lined up but never sharp (the phone too close to focus): the frame gets smaller, so the card is held farther away
scene("too-close", async (page) => {
  await pick(page, "Another card");
  const before = await page.locator(".dc-frame").boundingBox();
  await page.locator(".dc-frame[data-far]").waitFor({ timeout: 15_000 });
  await page.waitForTimeout(500);
  const after = await page.locator(".dc-frame").boundingBox();
  assert.ok(after.width < before.width * 0.8, `the frame got smaller: ${Math.round(before.width)} → ${Math.round(after.width)} px`);
  assert.ok(Math.abs(after.width / after.height - 85.6 / 54) < 0.02, "still a card's shape");
  await state(page).locator("span", { hasText: "Too close for the camera to focus" }).waitFor({ timeout: 10_000 });
  assert.equal((await state(page).locator("strong").innerText()).trim(), "Move back a little");
  await shot(page, "too-close");
  assert.equal(await developed(page), null, "nothing taken while it's blurred");
  step(`never sharp while lined up: the frame shrinks (${Math.round(before.width)} → ${Math.round(after.width)} px) and says "Move back a little: too close for the camera to focus"`);
}, "lic-back-blur");

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
