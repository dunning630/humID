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
// The page loads from http://tauri.localhost, the Android app's own origin, under the app's
// content security policy (tools/dev.mjs serves it): what the policy blocks in the app,
// such as the scan engines, it blocks here too.
const BASE = `http://tauri.localhost:${PORT}`;
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

/** The demo "biometric": press and hold. */
async function hold(page) {
  const b = page.locator(".interrupt .hold");
  await b.waitFor({ timeout: 20_000 });
  await b.focus();
  await page.keyboard.down(" ");
  await page.waitForTimeout(1500);
  await page.keyboard.up(" ");
}

/** One way in: the + button (or the empty vault's one primary) opens the list of what to add; Photo, then Start camera, opens the camera. */
async function openAdd(page) {
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".pushed").getByText("What are you adding?").waitFor({ timeout: 10_000 });
  assert.equal(await page.locator(".doccam").count(), 0, "the camera doesn't start until a kind is chosen");
  await page.locator(".pushed button.kind", { hasText: /^Photo/ }).click();
  await page.locator(".pushed [data-start-camera]").click();
  await page.locator(".doccam").waitFor({ timeout: 10_000 });
}
async function pickKind(page, name) {
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  await page.locator(".pushed button.kind", { hasText: name }).click();
  assert.equal(await page.locator(".doccam").count(), 0, "choosing a kind doesn't start the camera");
  await page.locator(".pushed [data-start-camera]").click();
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
  await page.getByLabel(/Only I use/).check();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  // confirm the recovery card by typing back the group the app asks for
  const ask = await page.locator('label[for="card-check"]').innerText();
  const groups = await page.locator(".cardcode span").allInnerTexts();
  await page.fill("#card-check", groups[Number(/group (\d+)/.exec(ask)[1]) - 1]);
  await page.getByRole("button", { name: "I've saved it" }).click();
  await page.getByRole("button", { name: "Open my vault" }).click();
  step("enrolled (demo)");

  // A photo that can't be saved (Android ran out of memory encoding it, say) keeps the
  // camera open and says so, instead of dropping back to "Scan the front" as if nothing happened.
  await page.evaluate(() => {
    const real = HTMLCanvasElement.prototype.toBlob;
    let fail = 2; // jpeg() tries twice (full size, then smaller)
    HTMLCanvasElement.prototype.toBlob = function (cb, ...a) { if (fail-- > 0) return setTimeout(() => cb(null)); return real.call(this, cb, ...a); };
  });
  await openAdd(page);
  await shot(page, "1-camera-add");
  // nobody presses the shutter, and nobody says what it is: the camera finds the card, takes
  // the photo by itself, reads the license barcode on it and opens the ID flow for the front
  await page.getByText(/Couldn't save that photo/).waitFor({ timeout: 40_000 });
  assert.ok(await page.locator(".doccam").isVisible(), "the camera stays open after a failed save");
  step("auto-capture took the back; the save failed, and the camera stayed open and said so");
  // …then, after a pause to read that, takes it again; saved: a tick, then the front is asked for
  await page.locator(".dc-saved-chip", { hasText: "Back saved. Now the front." }).waitFor({ timeout: 40_000 });
  assert.equal((await page.evaluate(() => globalThis.__humidRoute))?.found, "driver_license", "routed by the barcode");
  await shot(page, "1b-back-saved");
  step("the Add camera read the license barcode and routed to the ID flow; front camera open…");
  // the front camera is open (showing the same back, which is fine for a photo of a card)
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  await page.waitForTimeout(500);
  if (await page.locator(".doccam").isVisible()) await page.locator(".doccam .dc-shutter:not([disabled])").click().catch(() => {});
  await page.getByText("Check the details").waitFor({ timeout: 45_000 });
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

  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  const lic = page.locator(".item", { hasText: "Driver's license · Illinois" });
  await lic.waitFor({ timeout: 30_000 });
  assert.match(await lic.innerText(), /expires/);
  assert.equal(await lic.getAttribute("data-kind"), "id");
  assert.deepEqual((await page.locator(".chips[aria-label='Filter by kind'] .chip").allInnerTexts()).map((t) => t.replace(/\s*\d+$/, "").trim()), ["All", "IDs"], "the chip row shows kinds");
  step("sealed into the vault as an ID; the chip row says so");

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
  ({ ctx, page } = await launch(fixture("guide/pp-ok.mjpeg")));
  await page.goto(BASE);
  await page.getByRole("button", { name: /^Unlock$/ }).click();
  await hold(page);
  await page.locator(".item").first().waitFor({ timeout: 20_000 });
  step("unlocked again (new camera)");

  await pickKind(page, /^Passport/);
  step("passport chosen from the picker; camera open, reading the MRZ live…");
  await page.locator(".doccam").waitFor({ timeout: 10_000 }).catch(() => {}); // may already be done
  await shot(page, "4-camera-passport");
  await page.locator(".doccam").waitFor({ state: "detached", timeout: 90_000 });
  await page.getByText("Read the ID chip").first().waitFor({ timeout: 10_000 });
  await shot(page, "5-chip-step");
  assert.equal(await page.locator("#doc-num").inputValue(), "D00000001");
  assert.equal(await page.locator("#doc-birth").inputValue(), "1974-08-12");
  assert.equal(await page.locator("#doc-exp").inputValue(), "2034-12-31");
  step("MRZ read: the chip's access details are filled in");

  await page.getByRole("button", { name: /^Read the ID chip$/ }).click();
  await page.getByText("Check the details").waitFor({ timeout: 60_000 });
  await shot(page, "6-passport-review");
  assert.equal(await val("surname"), "PERSON");
  assert.equal(await val("given"), "DEMO");
  assert.match(await page.locator(".id-proof").innerText(), /chip/i);
  assert.equal(await page.locator(".id-thumbs figure[data-shape='portrait'] img").count(), 1, "chip photo shown");
  step("chip read: details from the chip, photo copied, hashes match");

  await page.getByRole("button", { name: "Seal", exact: true }).click();
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
  assert.match(pview, /Chip data integrity-checked/);
  assert.doesNotMatch(pview, /P<UTOPERSON<<DEMO/, "the raw lines from the document are folded away");
  await page.locator(".id-view details summary", { hasText: "Details" }).click();
  assert.match(await page.locator(".id-view").innerText(), /P<UTOPERSON<<DEMO/);
  step("passport sealed and opened, with the chip photo");
  await ctx.close();

  /* ---------------- 2b. the barcode anywhere in view (apps 1.12.0) ---------------- */
  // A licence's back lined up in the outline: the camera reads the PDF417 from the still and takes the photo by itself
  // (the front step is taken with the round button). Reading the barcode anywhere in view is gone with the free-form outline.
  ({ ctx, page } = await launch(fixture("guide/lic-back-ok.mjpeg")));
  await page.goto(BASE);
  await page.getByRole("button", { name: /^Unlock$/ }).click();
  await hold(page);
  await page.locator(".item").first().waitFor({ timeout: 20_000 });
  await pickKind(page, /Driver's license/);
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  if (await page.locator(".dc-saved-chip").count() === 0) await page.locator(".doccam .dc-shutter:not([disabled])").click().catch(() => {});
  await page.locator(".dc-saved-chip", { hasText: "Front saved" }).waitFor({ timeout: 20_000 });
  await page.getByText("Check the details").waitFor({ timeout: 45_000 });
  const how = await page.evaluate(() => globalThis.__humidDevelop?.how);
  assert.equal(how, "auto", "taken by itself once lined up, steady and sharp");
  assert.equal(await page.locator("#idf-surname").inputValue(), "SPECIMEN");
  assert.equal(await page.locator("#idf-number").inputValue(), "S12345678901");
  await shot(page, "7b-desk-read");
  step("licence back lined up in the outline: taken by itself, the barcode read from the still");
  // Android Back inside the ID flow steps back (review → capture), rather than closing Add
  const back = () => page.evaluate(() => globalThis.__humidBack());
  assert.equal(await back(), "pushed", "back inside the ID flow is a step");
  await page.locator(".pushed").getByText("Scan it").waitFor();
  assert.equal(await back(), "pushed", "back from the first step leaves the ID flow for the picker");
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  assert.equal(await page.locator(".doccam").count(), 0, "no camera behind the picker");
  assert.equal(await back(), "pushed", "back from the picker closes Add");
  await page.locator(".pushed").waitFor({ state: "detached" });
  assert.equal(await page.locator(".pushed").count(), 0, "Add is closed");
  step("Android Back: review → capture → picker → closed, one level at a time");
  await ctx.close();

  /* ---------------- 3. nothing but a table in view: it never takes a photo by itself ---------------- */
  ({ ctx, page } = await launch(fixture("camera-empty.mjpeg")));
  await page.goto(BASE);
  await page.getByRole("button", { name: /^Unlock$/ }).click();
  await hold(page);
  await page.locator(".item").first().waitFor({ timeout: 20_000 });
  // count the camera streams the page opens, to show none starts before a kind is chosen and all are released
  await page.evaluate(() => {
    globalThis.__tracks = []; globalThis.__gum = 0;
    const md = navigator.mediaDevices, real = md.getUserMedia.bind(md);
    md.getUserMedia = async (c) => { globalThis.__gum++; const st = await real(c); globalThis.__tracks.push(...st.getTracks()); return st; };
  });
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  await page.waitForTimeout(800);
  assert.equal(await page.evaluate(() => globalThis.__gum), 0, "no camera request while the picker is up");
  await page.locator(".pushed button.kind", { hasText: /Another card/ }).click();
  await page.locator(".pushed [data-start-camera]").waitFor();
  await page.waitForTimeout(800);
  assert.equal(await page.evaluate(() => globalThis.__gum), 0, "no camera request on the what-to-show screen");
  await page.locator(".pushed [data-start-camera]").click();
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  assert.equal(await page.evaluate(() => globalThis.__gum), 1, "one camera request after Start camera");
  await page.waitForTimeout(5000);
  assert.ok(await page.locator(".doccam").isVisible(), "no document, no photo");
  assert.equal(await page.locator(".doccam").getAttribute("data-look"), "searching");
  await page.locator(".doccam .dc-state strong", { hasText: /Fit the card in the outline|Too dark/ }).waitFor(); // this fixture is a dim table: "Too dark" is the honest answer
  await shot(page, "8-empty-table");
  await page.getByRole("button", { name: "Close the camera" }).click();
  await page.locator(".doccam").waitFor({ state: "detached" });
  assert.equal(await page.evaluate(() => globalThis.__tracks.every((t) => t.readyState === "ended")), true, "closing the camera releases the stream");
  await page.locator(".pushed [data-start-camera]").click();
  await page.locator(".doccam .dc-shutter:not([disabled])").waitFor({ timeout: 20_000 });
  assert.equal(await page.evaluate(() => globalThis.__tracks.some((t) => t.readyState === "live")), true, "the camera is on again");
  // the app goes to the background: the stream is released at once
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { get: () => true, configurable: true }); document.dispatchEvent(new Event("visibilitychange")); });
  await page.waitForFunction(() => globalThis.__tracks.every((t) => t.readyState === "ended"), null, { timeout: 5000 });
  step("an empty table: the camera keeps waiting and says what it needs; nothing starts before Start camera; closing or backgrounding releases the stream");
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
