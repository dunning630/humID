// "Add a payment card" in a real browser: the development build in Chromium, under the
// Android app's origin and content security policy, with a fake camera showing a
// specimen card (tests/fixtures/id/make-paycard.py; the Visa test number, not a real card).
//   1. the front: Payment card picked, the card lined up in its outline is taken by itself; the number, expiry and name are read
//      on this device; sealed; the list shows only the network and last four digits
//   2. the back (the browser restarted with the back on camera): the security code and the
//      bank's phone number are read, the code kept because the back was scanned, and no
//      photo of the back is stored; opened with the biometric, masked until revealed,
//      hidden again; no copy button anywhere
//   3. a Wallet pass (.pkpass): checked (files, signature, chain) before it's sealed, shown
//      with who signed it; a tampered one refused; opened as a pass with its QR code.
//      Signed under a test root, which only a development build can be told to trust.
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/cards.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { hold, enroll, unlock, openAdd as openAddFlow, pickKind, startCamera } from "./_v3.mjs";
import { writeFileSync } from "node:fs";
import { passChain, makePass, passJson } from "../support/pkpass.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = (n) => join(root, "tests/fixtures/id", n);
const PORT = Number(process.env.PORT || 5197);
const BASE = `http://tauri.localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-cards-"));
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: cards timed out after 6 minutes"); process.exit(1); }, 6 * 60_000).unref();
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

const errors = [];
async function launch(cameraFile) {
  const ctx = await chromium.launchPersistentContext(profile, {
    headless: true, viewport: { width: 412, height: 915 }, deviceScaleFactor: 2, permissions: ["camera"],
    args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", `--use-file-for-fake-video-capture=${cameraFile}`,
      "--host-resolver-rules=MAP tauri.localhost 127.0.0.1", `--unsafely-treat-insecure-origin-as-secure=${BASE}`],
  });
  contexts.push(ctx);
  const page = ctx.pages()[0] || await ctx.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
/** 3.0.1: Add opens "What are you adding?"; Payment card opens its outline at once. */
async function openCardCamera(page) {
  await openAddFlow(page);
  await pickKind(page, "Payment card");
  await startCamera(page);
}

try {
  /* ---------------- 1. the front ---------------- */
  let { ctx, page } = await launch(fixture("guide/pay-front-ok.mjpeg"));
  await page.goto(BASE);
  await enroll(page);
  step("enrolled (demo)");

  await openCardCamera(page);
  // nobody presses the shutter: lined up in the outline, the photo is taken by itself and the number read
  await page.locator(".doccam[data-guided] .dc-frame[data-template='card-front']").waitFor({ timeout: 10_000 });
  await page.locator("#cf-pan").waitFor({ timeout: 90_000 });
  await page.waitForFunction(() => document.querySelector("#cf-pan")?.value.replace(/\s/g, "").length >= 16, null, { timeout: 30_000 });
  assert.equal((await page.inputValue("#cf-pan")).replace(/\s/g, ""), "4111111111111111", "the number, read on this device");
  assert.equal(await page.inputValue("#cf-exp"), "08/29", "the expiry");
  assert.equal(await page.inputValue("#cf-name"), "JANE SPECIMEN", "the name");
  assert.match(await page.locator(".pushed [role=status]").first().innerText(), /Read Visa ending 1111/);
  // 3.1.1: with the number in, the back's camera opens by itself for the security code (a chip never gives it out)
  await page.locator(".doccam .dc-saved-chip", { hasText: "Now turn it over for the security code" }).waitFor({ timeout: 20_000 });
  assert.match(await page.locator(".doccam .dc-top").innerText(), /card · back/i);
  await shot(page, "1b-back-asked");
  await page.locator(".doccam").getByRole("button", { name: "Skip" }).click();
  await page.locator(".doccam").waitFor({ state: "detached" });
  await page.getByLabel("Nickname").fill("Travel card");
  await shot(page, "1-front-read");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  const row = page.locator(".item", { hasText: "Travel card" });
  await row.waitFor({ timeout: 30_000 });
  assert.match(await row.innerText(), /Visa •••• 1111/);
  assert.ok(!(await row.innerText()).includes("4111 1111"), "the list never shows the number");
  await shot(page, "2-vault-list");
  step("the front: number, expiry and name read by the camera; the back's camera then opens by itself for the security code (skipped here); the list shows the last four only");
  await ctx.close();

  /* ---------------- 2. the back ---------------- */
  ({ ctx, page } = await launch(fixture("guide/pay-back-ok.mjpeg")));
  await page.goto(BASE);
  await unlock(page);
  await page.locator(".item", { hasText: "Travel card" }).waitFor({ timeout: 30_000 });
  await openCardCamera(page);
  await page.locator(".dc-panel").getByRole("button", { name: "Type it" }).click();
  await page.locator(".doccam").waitFor({ state: "detached" });
  await page.fill("#cf-pan", "4111 1111 1111 1112");
  assert.ok(await page.getByText("That number has a typo").isVisible(), "a typo is caught");
  assert.ok(await page.getByRole("button", { name: "Seal", exact: true }).isDisabled(), "a bad number can't be sealed");
  await page.fill("#cf-pan", "4111 1111 1111 1111");
  await page.fill("#cf-exp", "08/29");
  await page.getByLabel("Nickname").fill("Backup card");
  await page.getByRole("button", { name: /Scan the back/ }).click();
  await page.getByText(/Read the security code/).waitFor({ timeout: 90_000 });
  assert.equal(await page.inputValue("#cf-cvv"), "123", "the security code, read from the back");
  assert.equal(await page.inputValue("#cf-phone"), "1-800-555-0123", "the bank's phone number");
  assert.equal(await page.getByRole("switch", { name: /Keep the security code/ }).getAttribute("aria-checked"), "true", "kept, because the back was scanned");
  assert.match(await page.locator(".pushed [role=status]").first().innerText(), /photo of the back wasn't kept/);
  assert.equal(await page.locator(".id-thumbs figure").count(), 0, "no photo of the back on screen");
  await shot(page, "3-back-read");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  await page.locator(".item", { hasText: "Backup card" }).click();
  // the item screen: the masked number with one "Show the number" (one check), never the number itself
  assert.equal((await page.locator('.pushed [data-card="number"]').innerText()).trim(), "•••• 1111");
  await page.locator(".pushed").getByRole("button", { name: "Show the number", exact: true }).click();
  await hold(page);
  await page.locator(".viewer .pay-card").waitFor({ timeout: 30_000 });
  assert.equal((await page.locator('.viewer [data-card="number"]').innerText()).trim(), "•••• 1111");
  assert.equal((await page.locator('.viewer [data-card="cvv"]').innerText()).trim(), "•••");
  assert.match(await page.locator(".viewer").innerText(), /1-800-555-0123/);
  await page.getByRole("button", { name: /Show the number and code/ }).click();
  assert.equal((await page.locator('.viewer [data-card="number"]').innerText()).trim(), "4111 1111 1111 1111");
  assert.equal((await page.locator('.viewer [data-card="cvv"]').innerText()).trim(), "123");
  await shot(page, "4-card-revealed");
  assert.equal(await page.getByRole("button", { name: /Copy/ }).count(), 0, "no copy buttons: the clipboard isn't safe");
  await page.getByRole("button", { name: /Hide now/ }).click();
  assert.equal((await page.locator('.viewer [data-card="number"]').innerText()).trim(), "•••• 1111");
  step("the back: security code and bank phone read, the photo not kept; masked until revealed; no copying");

  /* ---------------- 3. a Wallet pass ---------------- */
  const chain = passChain();
  const good = join(profile, "Concert.pkpass"), forged = join(profile, "Forged.pkpass");
  writeFileSync(good, makePass(chain));
  writeFileSync(forged, makePass(chain, { change: { "pass.json": Buffer.from(JSON.stringify(passJson({ description: "Free entry" }))) } }));
  await page.locator("button[aria-label*=Close]").first().click();
  // 3.0: the viewer sits over the pushed item screen; leave that too, back to the vault
  await page.locator(".pushed [data-back]").first().click();
  await page.locator(".pushed").waitFor({ state: "detached", timeout: 10_000 });
  await page.evaluate((der) => { globalThis.__humidExtraPassRoots = [der]; }, Buffer.from(chain.root.der).toString("base64"));
  // File in the picker: a .pkpass goes to the pass check
  const addPassFile = async (path) => {
    await openAddFlow(page);
    const chooser = page.waitForEvent("filechooser");
    await pickKind(page, "File");
    await (await chooser).setFiles(path);
  };
  await addPassFile(forged);
  await page.getByText("HumID won't add this as a Wallet pass").waitFor({ timeout: 20_000 });
  assert.match(await page.locator(".pushed [role=alert]").innerText(), /changed after it was signed/);
  assert.ok(await page.getByRole("button", { name: "Seal", exact: true }).isDisabled(), "a forged pass can't be sealed as a pass");
  await shot(page, "5-pass-forged");
  await page.getByRole("button", { name: "Choose another file" }).waitFor();
  // Back leaves the pass review for the picker it came from, and one more Back closes Add
  assert.equal(await page.evaluate(() => globalThis.__humidBack()), "pushed");
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  assert.equal(await page.evaluate(() => globalThis.__humidBack()), "pushed");
  await page.locator(".pushed").waitFor({ state: "detached" });
  await addPassFile(good);
  await page.getByText(/verified through Apple/).waitFor({ timeout: 20_000 });
  assert.match(await page.locator(".pass-face").innerText(), /The Specimen Tour/);
  assert.equal(await page.inputValue("#doc-name"), "Concert ticket");
  await shot(page, "6-pass-verified");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  const passRow = page.locator(".item", { hasText: "Concert ticket" });
  await passRow.waitFor({ timeout: 30_000 });
  assert.match(await passRow.innerText(), /Ticket · Example Events/);
  assert.equal(await passRow.getAttribute("data-kind"), "pass");
  assert.deepEqual((await page.locator(".chips[aria-label='Filter by kind'] .chip").allInnerTexts()).map((t) => t.replace(/\s*\d+$/, "").trim()), ["All", "Cards", "Passes"], "the chip row shows the kinds that exist");
  await page.locator(".chips[aria-label='Filter by kind'] .chip", { hasText: "Cards" }).click();
  assert.equal(await page.locator(".rows .item").count(), 2, "Cards shows the two cards");
  await page.locator(".chips[aria-label='Filter by kind'] .chip", { hasText: "All" }).click();
  await passRow.click();
  await page.getByRole("button", { name: "Open", exact: true }).click();
  await hold(page);
  await page.locator(".pass-view").waitFor({ timeout: 30_000 });
  assert.match(await page.locator(".pass-view").innerText(), /Fox Valley Arena[\s\S]*Verified through Apple/);
  assert.equal(await page.locator(".pass-code svg").count(), 1, "the QR code is drawn");
  assert.equal(await page.locator(".pass-view a").count(), 0, "links in a pass aren't links");
  await shot(page, "7-pass-open");
  step("a Wallet pass: a forged one refused, a genuine one checked, sealed and opened with its QR code");
  assert.deepEqual(errors, [], "no page errors");
  console.log("ok — payment cards work end to end in the browser");
} catch (e) {
  for (const c of contexts) { const p = c.pages()[0]; if (p) await shot(p, "failure").catch(() => {}); }
  console.error(e);
  console.error(errors.join("\n"));
  process.exitCode = 1;
} finally {
  for (const c of contexts) await c.close().catch(() => {});
  dev.kill();
  rmSync(profile, { recursive: true, force: true });
}
process.exit(process.exitCode || 0);
