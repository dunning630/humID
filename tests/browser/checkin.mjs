// Check-in, in a real browser (apps 1.14.0, docs/CHECKIN.md). Checks that:
//   - Security shows Check-in when the server offers it; turning it on takes one live check
//   - while it's armed, every tab shows when the next check-in is due, with Check in
//   - nothing is kept on the device while it's armed (no offline copy)
//   - the duress setting is sealed on the device: no gesture readable in its storage (F1)
//   - checking in moves the deadline; a longer window can be chosen for the night
//   - a duress unlock erases the vault at once, while the duress session looks calm and
//     still shows Check-in on, and the decoy document
//   - the next ordinary unlock says the vault was erased; only the decoy is left; Activity agrees
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/checkin.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5196);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const step = (s) => console.log(`· ${s}`);
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };

const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), HUMID_REGISTRATION: "open", HUMID_CHECKIN: "on" }, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
dev.stdout.on("data", (d) => { log += d; });
dev.stderr.on("data", (d) => { log += d; });
const stop = () => new Promise((r) => { if (dev.exitCode !== null) return r(); dev.once("exit", r); dev.kill(); });

async function hold(page) {
  const b = page.locator(".interrupt .hold");
  await b.waitFor({ timeout: 20_000 });
  await b.focus(); await page.keyboard.down(" "); await page.waitForTimeout(1500); await page.keyboard.up(" ");
  await page.locator(".interrupt").waitFor({ state: "detached", timeout: 20_000 });
}
async function addDoc(page, name) {
  await page.getByRole("button", { name: "Add a document" }).first().click();
  await page.locator('input[type="file"]').setInputFiles({ name, mimeType: "text/plain", buffer: Buffer.from(`${name}: keep this safe.\n`) });
  await page.getByRole("button", { name: /Seal & store/ }).click();
  await hold(page);
  await page.locator(".item", { hasText: name.replace(/\.\w+$/, "") }).waitFor({ timeout: 30_000 });
}
const names = (page) => page.locator(".list .item .name").allInnerTexts();
const tab = (page, label) => page.locator(".tabbar button", { hasText: label }).click();
const closeSheet = (page) => page.locator(".sheet button[aria-label=Close], .sheet .icon-btn").first().click().catch(() => page.keyboard.press("Escape"));
const toast = (page, re) => page.locator(".toast", { hasText: re }).first().waitFor({ timeout: 20_000 });
/** Everything this origin keeps in IndexedDB, as text. */
const idbDump = (page) => page.evaluate(async () => {
  const db = await new Promise((r, j) => { const q = indexedDB.open("humid"); q.onsuccess = () => r(q.result); q.onerror = () => j(q.error); });
  const out = {};
  for (const name of db.objectStoreNames) {
    out[name] = await new Promise((r) => {
      const tx = db.transaction(name).objectStore(name);
      const keys = tx.getAllKeys(), vals = tx.getAll();
      vals.onsuccess = () => r(keys.result.map((k, i) => [k, vals.result[i]]));
    });
  }
  db.close();
  return out;
});
const deadlineText = (page) => page.locator(".banner.checkin strong").innerText();

const browser = await chromium.launch();
try {
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${log}`)), 120_000);
    const check = setInterval(() => { if (/HumID dev:/.test(log)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
    dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${log}`)); });
  });
  step("dev server up (Check-in on)");
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => { throw new Error(`page error: ${e.message}`); });

  /* ---------------- a HumID with a real document and a decoy ---------------- */
  await page.goto(BASE);
  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByText("Your body becomes the key").waitFor({ timeout: 30_000 });
  await page.getByLabel(/Only my own face or fingerprints/).check();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  await page.getByText("You're all set").waitFor({ timeout: 30_000 });
  const ask = await page.locator('label[for="card-check"]').innerText();
  const groups = await page.locator(".cardcode span").allInnerTexts();
  await page.fill("#card-check", groups[Number(/group (\d+)/.exec(ask)[1]) - 1]);
  await page.locator(".foot button:not([disabled])", { hasText: "Open my vault" }).click();
  await page.getByRole("button", { name: "Add a document" }).first().click();
  await page.locator(".sheet").waitFor();
  await closeSheet(page);
  await page.locator(".sheet").waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await addDoc(page, "Passport scan.txt");
  await addDoc(page, "Library card.txt");

  await tab(page, "Security");
  await page.locator(".card", { hasText: "Duress protection" }).getByRole("button").first().click();
  await page.locator(".sheet label.toggle", { hasText: "Duress gesture" }).click();
  await page.getByRole("button", { name: /Tap the mark three times/ }).click();
  await page.locator(".sheet").getByRole("button", { name: "Save" }).click();
  await tab(page, "Vault");
  await page.locator(".item", { hasText: "Library card" }).click();
  await page.locator(".sheet label.toggle", { hasText: "Show in decoy view" }).click();
  await toast(page, /will show in the decoy view/);
  await closeSheet(page);
  step("enrolled; two documents, the library card marked as the decoy; duress = three taps");

  const before = JSON.stringify(await idbDump(page));
  assert.ok(!/"gesture"\s*:\s*"taps"/.test(before) && !before.includes('"taps"'), "the duress gesture isn't readable on the device");
  assert.match(before, /duressSealed/, "the duress setting is sealed in the identity record");
  step("F1: the duress setting is sealed on the device; no gesture in its storage");

  /* ---------------- turn on Check-in ---------------- */
  await tab(page, "Security");
  const card = page.locator(".card#checkin");
  await card.waitFor();
  assert.match(await card.innerText(), /Off/);
  await card.getByRole("button", { name: /Set up/ }).click();
  await page.locator(".sheet").getByText("If you can't check in, erase your vault").waitFor();
  await page.locator(".sheet .seg", { hasText: "24 h" }).first().getByRole("radio", { name: "1 h" }).click();
  await page.locator(".sheet").getByRole("radio", { name: "None" }).click();
  await shot(page, "1-checkin-setup");
  assert.ok(await page.getByRole("button", { name: "Turn on Check-in" }).isDisabled(), "not until the risk is acknowledged");
  await page.locator(".sheet label.toggle", { hasText: "I understand" }).click();
  await page.getByRole("button", { name: "Turn on Check-in" }).click();
  await hold(page);
  await toast(page, /Check-in is on/);
  await page.locator(".banner.checkin").waitFor();
  assert.match(await deadlineText(page), /^Check in by /);
  assert.match(await card.innerText(), /On/);
  await tab(page, "Vault");
  await page.locator(".banner.checkin").waitFor();
  await tab(page, "Activity");
  await page.locator(".banner.checkin").waitFor();
  await page.getByText(/Check-in on · every 1 h/).waitFor({ timeout: 15_000 });
  await shot(page, "2-checkin-armed");
  step("turned on with one live check; the next check-in shows on every tab; Activity has it");

  const armed = await idbDump(page);
  assert.equal((armed.offline || []).length, 0, "no offline copy while armed");
  step("nothing kept on the device while it's armed (no offline copy)");

  /* ---------------- check in, and a longer window for the night ---------------- */
  const first = await deadlineText(page);
  await page.locator(".banner.checkin").getByRole("button", { name: "Check in" }).click();
  await hold(page);
  await toast(page, /Checked in\. Next by/);
  await tab(page, "Security");
  await page.locator(".card#checkin").getByRole("button", { name: /Settings/ }).click();
  await page.locator(".sheet").getByRole("radiogroup", { name: /Next window/ }).getByRole("radio", { name: "1 h" }).waitFor();
  assert.equal(await page.locator(".sheet").getByRole("radiogroup", { name: /Next window/ }).getByRole("radio").count(), 4, "up to the 8 h maximum");
  await page.locator(".sheet").getByRole("radiogroup", { name: /Next window/ }).getByRole("radio", { name: "8 h" }).click();
  await page.getByRole("button", { name: "Check in now" }).click();
  await hold(page);
  await toast(page, /Checked in\. Next by/);
  const night = await deadlineText(page);
  assert.notEqual(night, first, "the deadline moved");
  await shot(page, "3-checked-in");
  step(`checked in from the bar, then chose 8 h for the night (${first} → ${night})`);

  /* ---------------- a forced unlock: duress ---------------- */
  await page.getByRole("button", { name: "Lock now" }).first().click();
  const mark = page.getByRole("button", { name: "Unlock HumID" });
  for (let i = 0; i < 3; i++) await mark.click({ delay: 20 });
  await hold(page);
  await page.locator(".list .item").first().waitFor({ timeout: 20_000 });
  assert.deepEqual(await names(page), ["Library card"], "only the decoy");
  await page.locator(".banner.checkin").waitFor();
  assert.match(await deadlineText(page), /^Check in by /, "the duress session still shows Check-in on, calmly");
  await page.locator(".banner.checkin").getByRole("button", { name: "Check in" }).click();
  await hold(page);
  await toast(page, /Checked in\. Next by/);
  await shot(page, "4-duress-session");
  step("duress unlock: only the decoy, Check-in still looks on, and checking in looks normal");

  /* ---------------- the holder, safe again ---------------- */
  await page.getByRole("button", { name: "Lock now" }).first().click();
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.getByText("Your vault was erased by Check-in").first().waitFor({ timeout: 20_000 });
  assert.deepEqual(await names(page), ["Library card"], "the real document is gone; the decoy stayed");
  assert.equal(await page.locator(".banner.checkin").count(), 0, "no check-in due any more");
  await shot(page, "5-erased");
  await tab(page, "Activity");
  await page.getByText("Vault erased by Check-in").waitFor({ timeout: 15_000 });
  await tab(page, "Security");
  assert.match(await page.locator(".card#checkin").innerText(), /Off[\s\S]*erased/i);
  step("ordinary unlock: the vault says it was erased; only the decoy is left; Activity agrees");

  console.log("ok — Check-in checks pass");
} finally {
  await browser.close();
  await stop();
}
