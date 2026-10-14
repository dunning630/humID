// "Add a payment card" in a real browser: the development build in Chromium.
// Type a test card (with the security code turned on), seal it, see it in the
// list with only its last four digits, open it with the (demo) biometric,
// reveal the number, copy it, and close.
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

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5198);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-cards-"));
const step = (s) => console.log(`· ${s}`);

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

const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
async function hold(page) {
  const b = page.locator(".interrupt .hold");
  await b.waitFor({ timeout: 20_000 });
  await b.focus();
  await page.keyboard.down(" ");
  await page.waitForTimeout(1500);
  await page.keyboard.up(" ");
}

const ctx = await chromium.launchPersistentContext(profile, {
  headless: true, viewport: { width: 412, height: 915 }, deviceScaleFactor: 2, permissions: ["clipboard-read", "clipboard-write"],
});
const page = ctx.pages()[0] || await ctx.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));

try {
  await page.goto(BASE);
  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByLabel(/Only my own face or fingerprints/).check();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  await page.getByLabel(/stored my card somewhere safe/).check();
  await page.getByRole("button", { name: "Open my vault" }).click();
  step("HumID created");

  await page.getByRole("button", { name: /Add a payment card/ }).first().click();
  await page.getByRole("button", { name: /Type it/ }).click();
  await page.getByLabel(/Card number/).fill("4111 1111 1111 1112");
  assert.ok(await page.getByText("That number has a typo").isVisible(), "a typo is caught");
  assert.ok(await page.getByRole("button", { name: /Seal/ }).isDisabled(), "can't seal a bad number");
  await page.getByLabel(/Card number/).fill("4111 1111 1111 1111");
  await page.getByLabel("Expires").fill("08/29");
  await page.getByLabel("Name on card").fill("JANE SPECIMEN");
  await page.getByLabel("Nickname").fill("Travel card");
  await page.getByLabel("Bank", { exact: true }).fill("First HumID Bank");
  await page.locator("label.toggle", { hasText: "Keep the security code" }).click();
  await page.getByLabel("Security code", { exact: true }).fill("123");
  await shot(page, "1-add-card");
  await page.getByRole("button", { name: /Seal/ }).click();
  await hold(page);
  await page.locator(".item", { hasText: "Travel card" }).waitFor({ timeout: 30_000 });
  const row = await page.locator(".item", { hasText: "Travel card" }).innerText();
  assert.match(row, /Visa •••• 1111/);
  assert.ok(!row.includes("4111 1111"), "the list never shows the number");
  await shot(page, "2-vault-list");
  step("card sealed; list shows last four only");

  await page.locator(".item", { hasText: "Travel card" }).click();
  await page.getByRole("button", { name: "Open" }).click();
  await hold(page);
  await page.locator(".pay-card").waitFor({ timeout: 30_000 });
  assert.equal((await page.locator(".pc-number").innerText()).trim(), "•••• 1111");
  await shot(page, "3-card-masked");
  await page.getByRole("button", { name: /Show the number/ }).click();
  assert.equal((await page.locator(".pc-number").innerText()).trim(), "4111 1111 1111 1111");
  await shot(page, "4-card-revealed");
  await page.getByRole("button", { name: /Copy number/ }).click();
  await page.waitForTimeout(300);
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "4111111111111111");
  await page.getByRole("button", { name: /Hide now/ }).click();
  assert.equal((await page.locator(".pc-number").innerText()).trim(), "•••• 1111");
  step("opened with a biometric check; reveal, copy and hide work");
  assert.deepEqual(errors, [], "no page errors");
  console.log("cards: ok");
} catch (e) {
  await shot(page, "failure");
  console.error(e);
  console.error(errors.join("\n"));
  process.exitCode = 1;
} finally {
  await ctx.close();
  dev.kill();
  rmSync(profile, { recursive: true, force: true });
}
