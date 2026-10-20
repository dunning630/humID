// Heartbeat (Check-in until 3.0), in a real browser (docs/CHECKIN.md). Checks that:
//   - You shows Heartbeat when the server offers it; turning it on takes one live check
//   - while it's armed, every tab shows when the next heartbeat is due, with a button
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
import { hold, confirmCard, youScreen, backOut } from "./_v3.mjs";

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

async function addDoc(page, name) {
  // 3.0 is camera first; a file goes in from the "what to show" screen the first time, or the camera's More chip after
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".pushed, .doccam").first().waitFor();
  const fileBtn = page.getByRole("button", { name: "Choose a file or photo instead" });
  if (await fileBtn.count()) await fileBtn.click();
  else { await page.locator(".dc-tools").getByRole("button", { name: "More" }).click(); await page.locator(".dc-tools").getByRole("button", { name: "File" }).click(); }
  await page.locator("#add-file").setInputFiles({ name, mimeType: "text/plain", buffer: Buffer.from(`${name}: kept for the test.\n`) });
  await page.locator(".pushed").getByText("Review, then seal").waitFor();
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  await page.locator(".item", { hasText: name.replace(/\.\w+$/, "") }).waitFor({ timeout: 30_000 });
}
const names = (page) => page.locator(".rows .item .name").allInnerTexts();
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
const hbBar = (page) => page.locator(".banner", { hasText: /Heartbeat due by|Heartbeat missed/ });
const deadlineText = (page) => hbBar(page).locator("strong").innerText();

const browser = await chromium.launch();
try {
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${log}`)), 120_000);
    const check = setInterval(() => { if (/HumID dev:/.test(log)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
    dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${log}`)); });
  });
  step("dev server up (Heartbeat on)");
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => { throw new Error(`page error: ${e.message}`); });

  /* ---------------- a HumID with a real document and a decoy ---------------- */
  await page.goto(BASE);
  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByText("Your body becomes the key").waitFor({ timeout: 30_000 });
  await page.getByRole("checkbox").first().click();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  await page.getByText("Your recovery card").first().waitFor({ timeout: 30_000 });
  await confirmCard(page);
  await page.getByRole("button", { name: "I've written it down" }).click();
  await page.getByRole("button", { name: "Open my vault" }).click();
  await page.getByRole("button", { name: "Add to your vault" }).first().click(); // empty state → Add (what to show; no camera yet)
  await page.locator(".pushed [data-start-camera]").waitFor();
  assert.equal(await page.locator(".doccam").count(), 0, "no camera before Start camera");
  await page.locator(".pushed [data-back]").first().click();
  await page.locator(".pushed").waitFor({ state: "detached", timeout: 5000 });
  await addDoc(page, "Passport scan.txt");
  await addDoc(page, "Library card.txt");

  await youScreen(page, "Duress gesture");
  await page.getByRole("switch", { name: "Duress gesture" }).click();
  await page.getByRole("radio", { name: /Tap the mark three times/ }).click();
  await page.locator(".pushed").getByRole("button", { name: "Save", exact: true }).click();
  await toast(page, /Duress protection is on/);
  await tab(page, "Vault");
  // the item is pushed over the vault; its overflow menu holds the decoy switch (a live check, 3.0)
  await page.locator(".item", { hasText: "Library card" }).click();
  await page.locator(".pushed").getByRole("button", { name: "More", exact: true }).click();
  await page.locator(".sheet .row", { hasText: "Show in decoy view" }).click();
  await hold(page);
  await toast(page, /will show in the decoy view/);
  await backOut(page);
  await page.locator(".pushed").waitFor({ state: "detached" });
  step("enrolled; two documents, the library card marked as the decoy; duress = three taps");

  const before = JSON.stringify(await idbDump(page));
  assert.ok(!/"gesture"\s*:\s*"taps"/.test(before) && !before.includes('"taps"'), "the duress gesture isn't readable on the device");
  assert.match(before, /duressSealed/, "the duress setting is sealed in the identity record");
  step("F1: the duress setting is sealed on the device; no gesture in its storage");

  /* ---------------- turn on Check-in ---------------- */
  await tab(page, "You");
  const hubRow = page.locator(".row", { hasText: "Heartbeat" });
  await hubRow.waitFor();
  assert.match(await hubRow.innerText(), /Off/);
  await hubRow.click();
  await page.locator(".pushed").getByText("If you can't send a heartbeat, erase your vault").waitFor();
  await page.locator('[data-pref="hb-win:3600000"]').click();
  await page.locator('[data-pref="hb-grace:0"]').click();
  await shot(page, "1-heartbeat-setup");
  assert.ok(await page.getByRole("button", { name: "Turn on Heartbeat" }).isDisabled(), "not until the risk is acknowledged");
  await page.getByRole("switch", { name: /I understand/ }).click();
  await page.getByRole("button", { name: "Turn on Heartbeat" }).click();
  await hold(page);
  await toast(page, /Heartbeat is on/);
  await page.locator(".pushed").waitFor({ state: "detached" });
  await hbBar(page).waitFor();
  assert.match(await deadlineText(page), /^Heartbeat due by /);
  assert.match(await hubRow.innerText(), /On/);
  await tab(page, "Vault");
  await hbBar(page).waitFor();
  await tab(page, "Activity");
  await hbBar(page).waitFor();
  await page.getByText(/Heartbeat on · every 1 h/).waitFor({ timeout: 15_000 });
  await shot(page, "2-checkin-armed");
  step("turned on with one live check; the next heartbeat shows on every tab; Activity has it");

  const armed = await idbDump(page);
  assert.equal((armed.offline || []).length, 0, "no offline copy while armed");
  step("nothing kept on the device while it's armed (no offline copy)");

  /* ---------------- check in, and a longer window for the night ---------------- */
  const first = await deadlineText(page);
  await hbBar(page).getByRole("button", { name: "Heartbeat" }).click();
  await hold(page);
  await toast(page, /Heartbeat sent\. Next by/);
  await youScreen(page, "Heartbeat");
  await page.locator(".pushed").getByRole("radiogroup", { name: /Next window/ }).getByRole("radio", { name: "1 h" }).waitFor();
  assert.equal(await page.locator(".pushed").getByRole("radiogroup", { name: /Next window/ }).getByRole("radio").count(), 4, "up to the 8 h maximum");
  await page.locator(".pushed").getByRole("radiogroup", { name: /Next window/ }).getByRole("radio", { name: "8 h" }).click();
  await page.getByRole("button", { name: "Send a heartbeat now" }).click();
  await hold(page);
  await toast(page, /Heartbeat sent\. Next by/);
  await page.locator(".pushed").waitFor({ state: "detached" });
  const night = await deadlineText(page);
  assert.notEqual(night, first, "the deadline moved");
  await shot(page, "3-checked-in");
  step(`a heartbeat from the bar, then 8 h chosen for the night (${first} → ${night})`);

  /* ---------------- a forced unlock: duress ---------------- */
  await page.getByRole("button", { name: "Lock now" }).first().click();
  const mark = page.getByRole("button", { name: "Unlock HumID" });
  for (let i = 0; i < 3; i++) await mark.click({ delay: 20 });
  await hold(page);
  await page.locator(".rows .item").first().waitFor({ timeout: 20_000 });
  assert.deepEqual(await names(page), ["Library card"], "only the decoy");
  await hbBar(page).waitFor();
  assert.match(await deadlineText(page), /^Heartbeat due by /, "the duress session still shows Heartbeat on, calmly");
  await hbBar(page).getByRole("button", { name: "Heartbeat" }).click();
  await hold(page);
  await toast(page, /Heartbeat sent\. Next by/);
  await shot(page, "4-duress-session");
  step("duress unlock: only the decoy, Heartbeat still looks on, and a heartbeat looks normal");

  /* ---------------- the holder, safe again ---------------- */
  await page.getByRole("button", { name: "Lock now" }).first().click();
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.getByText("Your vault was erased by Heartbeat").first().waitFor({ timeout: 20_000 });
  await page.locator(".rows .item").first().waitFor({ timeout: 20_000 }); // the list loads after the banner
  assert.deepEqual(await names(page), ["Library card"], "the real document is gone; the decoy stayed");
  assert.equal(await hbBar(page).count(), 0, "no heartbeat due any more");
  await shot(page, "5-erased");
  await tab(page, "Activity");
  await page.getByText("Vault erased by Heartbeat").waitFor({ timeout: 15_000 });
  await youScreen(page, "Heartbeat");
  assert.match(await page.locator(".pushed").innerText(), /erased/i);
  assert.match(await page.locator(".pushed .eyebrow").first().innerText(), /Off/);
  step("ordinary unlock: the vault says it was erased; only the decoy is left; Activity agrees");

  console.log("ok — Heartbeat checks pass");
} finally {
  await browser.close();
  await stop();
}
