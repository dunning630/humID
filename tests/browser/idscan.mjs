// "Scan an ID" in a real browser: the development build of the app in Chromium,
// with a fake camera that shows a specimen card or passport page. Checks the
// whole path a person takes: camera → barcode or MRZ read live → chip read
// (the dev server's simulated chip, with its photo) → review → sealed into the
// vault → opened again as an ID card.
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/idscan.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = (n) => join(root, "tests/fixtures/id", n);
const PORT = Number(process.env.PORT || 5199);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-idscan-"));
const step = (s) => console.log(`· ${s}`);
// A stuck browser must fail the run, not hold it: the whole check takes well under a minute.
setTimeout(() => { console.error("Error: idscan timed out after 6 minutes"); process.exit(1); }, 6 * 60_000).unref();
const contexts = [];

/* ---------------- the dev server (whole stack, demo mode, simulated chips) ---------------- */

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
    headless: true,
    viewport: { width: 412, height: 915 },
    deviceScaleFactor: 2,
    permissions: ["camera", "clipboard-read", "clipboard-write"],
    args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", `--use-file-for-fake-video-capture=${cameraFile}`],
  });
  contexts.push(ctx);
  const page = ctx.pages()[0] || await ctx.newPage();
  page.on("pageerror", (e) => console.error("page error:", e.message));
  page.on("console", (m) => { if (m.type() === "error") console.error("console:", m.text()); });
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };

/** The demo "biometric": press and hold. */
async function hold(page) {
  const b = page.locator(".interrupt .hold");
  await b.waitFor({ timeout: 20_000 });
  await b.focus();
  await page.keyboard.down(" ");
  await page.waitForTimeout(1500);
  await page.keyboard.up(" ");
}

async function scanIdButton(page) {
  const add = page.locator("button.fab");
  if (await add.isVisible().catch(() => false)) { await add.click(); await page.getByRole("button", { name: /Scan an ID/ }).click(); }
  else await page.getByRole("button", { name: /Scan an ID/ }).first().click();
}

try {
  /* ---------------- 1. a driver's license: front photo, barcode read live ---------------- */
  let { ctx, page } = await launch(fixture("camera-card-back.mjpeg"));
  await page.goto(BASE);
  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByRole("button", { name: "Trust this server" }).click();
  // the dev server, like production, needs an access pass to create a HumID (docs/ANONYMITY.md)
  await page.getByRole("button", { name: "Use a demo access code" }).click({ timeout: 20_000 });
  await page.getByText("Access pass ready").first().waitFor({ timeout: 30_000 });
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel(/Only my own face or fingerprints/).check();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  // confirm the seal card by typing back the group the app asks for
  const ask = await page.locator('label[for="card-check"]').innerText();
  const groups = await page.locator(".cardcode span").allInnerTexts();
  await page.fill("#card-check", groups[Number(/group (\d+)/.exec(ask)[1]) - 1]);
  await page.getByRole("button", { name: "Open my vault" }).click();
  step("enrolled (demo)");

  await scanIdButton(page);
  await page.getByRole("button", { name: /Driver's license/ }).click();
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await shot(page, "1-camera-front");
  // A photo that can't be saved (Android ran out of memory encoding it, say) keeps the
  // camera open and says so, instead of dropping back to "Scan the front" as if nothing happened.
  await page.evaluate(() => {
    const real = HTMLCanvasElement.prototype.toBlob;
    let fail = 2; // jpeg() tries twice (full size, then smaller)
    HTMLCanvasElement.prototype.toBlob = function (cb, ...a) { if (fail-- > 0) return setTimeout(() => cb(null)); return real.call(this, cb, ...a); };
  });
  await page.locator(".doccam .dc-shutter").click();
  await page.getByText(/Couldn't save that photo/).waitFor({ timeout: 10_000 });
  assert.ok(await page.locator(".doccam").isVisible(), "the camera stays open after a failed save");
  step("a photo that can't be saved: the camera stays open and says so");
  await page.locator(".doccam .dc-shutter:not([disabled])").click();
  // saved: a tick, then straight on to the back, with the front shown as done
  await page.locator(".dc-saved-chip", { hasText: "Front saved. Now turn it over." }).waitFor({ timeout: 10_000 });
  await shot(page, "1b-front-saved");
  step("front photographed and confirmed; back camera open, reading the barcode live…");
  await page.locator(".doccam").waitFor();
  await page.locator(".doccam").waitFor({ state: "detached", timeout: 45_000 });
  await page.getByText("Check the details").waitFor({ timeout: 10_000 });
  await shot(page, "2-license-review");
  const val = (id) => page.locator(`#idf-${id}`).inputValue();
  assert.equal(await val("surname"), "SPECIMEN");
  assert.equal(await val("given"), "JORDAN ALEX");
  assert.equal(await val("number"), "S12345678901");
  assert.equal(await val("birth"), "1980-07-04");
  assert.equal(await val("expiry"), "2029-07-04");
  assert.equal(await page.getByLabel("City").inputValue(), "ST CHARLES");
  assert.equal(await page.getByLabel("ZIP or postal code").inputValue(), "60174");
  assert.match(await page.locator(".id-proof").innerText(), /barcode/i);
  step("barcode read: details filled");

  await page.getByRole("button", { name: /Seal & store/ }).click();
  await hold(page);
  const lic = page.locator(".item", { hasText: "Driver's license · Illinois" });
  await lic.waitFor({ timeout: 30_000 });
  assert.match(await lic.innerText(), /expires/);
  step("sealed into the vault");

  await lic.click();
  await page.getByRole("button", { name: "Open" }).click();
  await hold(page);
  await page.locator(".id-view").waitFor({ timeout: 20_000 });
  await shot(page, "3-license-view");
  const view = await page.locator(".id-view").innerText();
  assert.match(view, /Jordan Alex Specimen/);
  assert.match(view, /From the barcode/);
  assert.match(view, /S12345678901/);
  await page.getByRole("button", { name: "Close and wipe" }).click();
  step("opened again as an ID card");
  await ctx.close();

  /* ---------------- 2. a passport: MRZ read live, then the chip with its photo ---------------- */
  ({ ctx, page } = await launch(fixture("camera-passport.mjpeg")));
  await page.goto(BASE);
  await page.getByRole("button", { name: /^Unlock$/ }).click();
  await hold(page);
  await page.locator(".item").first().waitFor({ timeout: 20_000 });
  step("unlocked again (new camera)");

  await scanIdButton(page);
  await page.getByRole("button", { name: /^Passport/ }).click();
  step("passport camera open, reading the MRZ live…");
  await page.locator(".doccam").waitFor();
  await shot(page, "4-camera-passport");
  await page.locator(".doccam").waitFor({ state: "detached", timeout: 90_000 });
  await page.getByText("Read the chip").first().waitFor({ timeout: 10_000 });
  await shot(page, "5-chip-step");
  assert.equal(await page.locator("#doc-num").inputValue(), "D00000001");
  assert.equal(await page.locator("#doc-birth").inputValue(), "1974-08-12");
  assert.equal(await page.locator("#doc-exp").inputValue(), "2034-12-31");
  step("MRZ read: the chip's access details are filled in");

  await page.getByRole("button", { name: /^Read the chip$/ }).click();
  await page.getByText("Check the details").waitFor({ timeout: 60_000 });
  await shot(page, "6-passport-review");
  assert.equal(await val("surname"), "PERSON");
  assert.equal(await val("given"), "DEMO");
  assert.match(await page.locator(".id-proof").innerText(), /chip/i);
  assert.equal(await page.locator(".id-thumbs figure[data-shape='portrait'] img").count(), 1, "chip photo shown");
  step("chip read: details from the chip, photo copied, hashes match");

  await page.getByRole("button", { name: /Seal & store/ }).click();
  await hold(page);
  const pp = page.locator(".item", { hasText: "Passport ·" });
  await pp.waitFor({ timeout: 30_000 });
  await pp.click();
  await page.getByRole("button", { name: "Open" }).click();
  await hold(page);
  await page.locator(".id-view").waitFor({ timeout: 20_000 });
  await page.getByRole("tab", { name: "Chip photo" }).click();
  await shot(page, "7-passport-view");
  const pview = await page.locator(".id-view").innerText();
  assert.match(pview, /Demo Person/);
  assert.match(pview, /From the chip/);
  assert.match(pview, /P<UTOPERSON<<DEMO/);
  step("passport sealed and opened, with the chip photo");
  await ctx.close();
  console.log("ok — Scan an ID works end to end in the browser");
} catch (e) {
  console.error(e);
  console.error(devLog.split("\n").slice(-20).join("\n"));
  process.exitCode = 1;
} finally {
  // an open browser keeps node alive: close everything, then exit with the result
  for (const c of contexts) await c.close().catch(() => {});
  dev.kill("SIGTERM");
  rmSync(profile, { recursive: true, force: true });
  process.exit(process.exitCode ?? 0);
}
