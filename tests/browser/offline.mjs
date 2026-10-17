// Offline, in a real browser (apps 1.7.0). With no connection, the same live check
// opens a read-only copy kept on the device: the document list, Activity and You
// as of the last sync. Checks that:
//   - the copy on the device holds no readable document name (it's sealed)
//   - offline (no network), Unlock shows the list, read only, with a banner
//   - a document can't be opened, saved, renamed or deleted offline, and nothing new added
//   - Activity and You show the saved state, and say they're offline
//   - the duress gesture offline still shows only the decoy documents
//   - with the vault server down (but a network), Unlock falls back to the copy too
//   - Reconnect signs in with one live check, and documents open again
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/offline.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5197);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const step = (s) => console.log(`· ${s}`);

async function startDev(env = {}) {
  const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  dev.stdout.on("data", (d) => { log += d; });
  dev.stderr.on("data", (d) => { log += d; });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${log}`)), 120_000);
    const check = setInterval(() => { if (/HumID dev:/.test(log)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
    dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${log}`)); });
  });
  return { dev, log: () => log, stop: () => new Promise((r) => { if (dev.exitCode !== null) return r(); dev.once("exit", r); dev.kill(); }) };
}

const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
async function hold(page) {
  const b = page.locator(".interrupt .hold");
  await b.waitFor({ timeout: 20_000 });
  await b.focus(); await page.keyboard.down(" "); await page.waitForTimeout(1500); await page.keyboard.up(" ");
  await page.locator(".interrupt").waitFor({ state: "detached", timeout: 20_000 });
}
async function addDoc(page, name) {
  await page.getByRole("button", { name: "Add a document" }).first().click();
  await page.locator('input[type="file"]').setInputFiles({ name, mimeType: "text/plain", buffer: Buffer.from(`${name}: the walnut desk goes to Sam.\n`) });
  await page.getByRole("button", { name: /Seal & store/ }).click();
  await hold(page);
  await page.locator(".item", { hasText: name.replace(/\.\w+$/, "") }).waitFor({ timeout: 30_000 });
}
const names = (page) => page.locator(".list .item .name").allInnerTexts();
const tab = (page, label) => page.locator(".tabbar button", { hasText: label }).click();
/** Everything this origin keeps in IndexedDB, as text (Uint8Arrays as latin1). */
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
  return JSON.stringify(out, (k, v) => (v instanceof Uint8Array ? String.fromCharCode(...v) : v));
});

let current = null;
const data = mkdtempSync(join(tmpdir(), "humid-offline-"));
const browser = await chromium.launch();
try {
  current = await startDev({ HUMID_DEV_DATA: data });
  step("dev server up");
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => { throw new Error(`page error: ${e.message}`); });

  /* ---------------- set up: a HumID with two documents, one of them a decoy ---------------- */
  await page.goto(BASE);
  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByRole("button", { name: "Use a demo access code" }).click({ timeout: 20_000 });
  await page.getByText("Access pass ready").first().waitFor({ timeout: 30_000 });
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel(/Only my own face or fingerprints/).check();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  const ask = await page.locator('label[for="card-check"]').innerText();
  const groups = await page.locator(".cardcode span").allInnerTexts();
  await page.fill("#card-check", groups[Number(/group (\d+)/.exec(ask)[1]) - 1]);
  await page.getByRole("button", { name: "Open my vault" }).click();
  step("enrolled (demo)");

  await page.getByRole("button", { name: "Add a document" }).first().click(); // empty state → Add sheet
  await page.locator(".sheet").waitFor();
  await page.keyboard.press("Escape").catch(() => {});
  await page.locator(".sheet").waitFor({ state: "detached", timeout: 5000 }).catch(() => page.locator(".sheet button[aria-label=Close]").first().click());
  await addDoc(page, "Last will.txt");
  await addDoc(page, "Gym membership.txt");

  // duress: three taps on the mark; the gym card is the decoy
  await tab(page, "You");
  await page.getByRole("button", { name: /Set up|Settings/ }).filter({ hasText: /Set up|Settings/ }).first().waitFor();
  await page.locator(".card", { hasText: "Duress protection" }).getByRole("button").first().click();
  await page.locator(".sheet label.toggle", { hasText: "Duress gesture" }).click();
  await page.getByRole("button", { name: /Tap the mark three times/ }).click();
  await page.locator(".sheet").getByRole("button", { name: "Save" }).click();
  await tab(page, "Vault");
  await page.locator(".item", { hasText: "Gym membership" }).click();
  await page.locator(".sheet label.toggle", { hasText: "Show in decoy view" }).click();
  await page.getByText(/will show in the decoy view/).waitFor({ timeout: 15_000 });
  await page.locator(".sheet button[aria-label=Close], .sheet .icon-btn").first().click().catch(() => page.keyboard.press("Escape"));
  // visit each tab so its state is in the copy
  await tab(page, "Activity"); await page.locator(".tl, .timeline, .entry, li").first().waitFor({ timeout: 15_000 }).catch(() => {});
  await page.waitForTimeout(800);
  await tab(page, "You"); await page.locator("details.about summary").click(); await page.getByText("Pinned server key").waitFor();
  await page.waitForTimeout(1200);
  await tab(page, "Vault");
  step("two documents sealed, the gym card marked as the decoy, duress gesture set");

  /* ---------------- the copy on the device is sealed ---------------- */
  const dump = await idbDump(page);
  assert.match(dump, /"offline"/, "an offline copy was saved");
  for (const secret of ["Last will", "Gym membership", "walnut", "Pinned"]) assert.ok(!dump.includes(secret), `"${secret}" is readable on the device`);
  step("the offline copy is on the device, and no document name in it is readable");

  /* ---------------- 1. no network at all ---------------- */
  await page.getByRole("button", { name: "Lock now" }).first().click();
  await ctx.setOffline(true);
  await page.getByText(/No connection\. You can still unlock to see your vault/).waitFor({ timeout: 10_000 });
  await shot(page, "1-locked-offline");
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.locator(".banner.offline").waitFor({ timeout: 15_000 });
  assert.deepEqual((await names(page)).sort(), ["Gym membership", "Last will"]);
  assert.match(await page.locator(".banner.offline").innerText(), /Offline · read only/);
  assert.equal(await page.locator(".banner.offline button").count(), 0, "no Reconnect while there's no network");
  assert.equal(await page.locator("button.fab").count(), 0, "nothing can be added offline");
  assert.equal(await page.locator("section.protect").count(), 0, "no to-do list that can't be done offline");
  await shot(page, "2-vault-offline");
  step("offline: a live check opens the list, read only, with no way to add");

  await page.locator(".item", { hasText: "Last will" }).click();
  await page.getByText("Opening needs a connection").waitFor();
  for (const b of ["Open", "Save copy", "Rename", "Sealed copy", "Delete"]) assert.ok(await page.locator(".sheet").getByRole("button", { name: b, exact: true }).isDisabled(), `${b} is disabled offline`);
  assert.equal(await page.locator(".sheet").getByText("Show in decoy view").count(), 0);
  await shot(page, "3-item-offline");
  await page.locator(".sheet button[aria-label=Close], .sheet .icon-btn").first().click().catch(() => page.keyboard.press("Escape"));
  step("a document can't be opened, saved, renamed or deleted offline");

  await tab(page, "Activity");
  await page.locator(".banner.offline").waitFor();
  await page.getByText("Ledger as verified when last online").waitFor({ timeout: 10_000 });
  await page.getByText(/Sealed Last will/).waitFor();
  await shot(page, "4-activity-offline");
  await tab(page, "You");
  await page.locator("details.about summary").click();
  await page.getByText(/Offline · read only · auto-locks/).waitFor();
  await page.getByText(/This device|Web|Chrome|Linux/).first().waitFor();
  await shot(page, "5-security-offline");
  assert.equal(await page.locator(".toast").count(), 0, "no error toasts from screens loading offline");
  step("Activity and You show the saved state, marked offline; no errors");

  // the duress gesture, offline: only the decoy
  await tab(page, "Vault");
  await page.getByRole("button", { name: "Lock now" }).first().click();
  const mark = page.getByRole("button", { name: "Unlock HumID" });
  for (let i = 0; i < 3; i++) await mark.click({ delay: 20 });
  await hold(page);
  await page.locator(".banner.offline").waitFor({ timeout: 15_000 });
  assert.deepEqual(await names(page), ["Gym membership"], "duress offline shows only the decoy");
  assert.equal(await page.locator("section.protect").count(), 0);
  await shot(page, "6-duress-offline");
  await page.getByRole("button", { name: "Lock now" }).first().click();
  step("duress gesture offline: only the decoy document");

  /* ---------------- 2. a network, but the vault server is down ---------------- */
  await ctx.setOffline(false);
  await current.stop();
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.locator(".banner.offline").waitFor({ timeout: 20_000 });
  assert.equal((await names(page)).length, 2);
  step("vault server down: Unlock falls back to the copy");

  // still down: Reconnect fails and the copy stays open
  await page.locator(".banner.offline").getByRole("button", { name: "Reconnect" }).click();
  await page.locator(".interrupt").waitFor({ state: "detached", timeout: 20_000 });
  await page.locator(".banner.offline").waitFor();
  assert.equal((await names(page)).length, 2, "a failed reconnect keeps the copy open");

  /* ---------------- 3. back online: Reconnect ---------------- */
  current = await startDev({ HUMID_DEV_DATA: data });
  await page.locator(".banner.offline").getByRole("button", { name: "Reconnect" }).click();
  await hold(page);
  await page.locator(".banner.offline").waitFor({ state: "detached", timeout: 20_000 });
  await page.locator("button.fab").waitFor();
  await page.locator(".item", { hasText: "Last will" }).click();
  await page.locator(".sheet").getByRole("button", { name: "Open", exact: true }).click();
  await hold(page);
  await page.getByText(/walnut desk goes to Sam/).waitFor({ timeout: 20_000 });
  await shot(page, "7-reconnected-open");
  step("Reconnect: one live check, back online, and the document opens");
  await page.getByRole("button", { name: "Close and wipe" }).click();

  /* ---------------- 4. signed in: the connection drops and comes back ---------------- */
  const bar = page.locator(".linkbar");
  await ctx.setOffline(true);
  await bar.getByText("No internet connection").waitFor({ timeout: 10_000 });
  await shot(page, "8-no-internet");
  await ctx.setOffline(false);
  await bar.waitFor({ state: "detached", timeout: 15_000 });
  await tab(page, "Activity");
  await page.getByText(/Sealed Last will/).waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".banner.offline").count(), 0, "still signed in, not the offline copy");
  step("a network drop: the bar says so, and when it's back the same session carries on");
  // healthy and idle: HumID sends nothing just to check the connection
  await page.waitForTimeout(3000); // let Activity finish loading (the public-log check follows the ledger)
  let sent = 0;
  const urls = [];
  const count = (req) => { if (req.url().startsWith(BASE)) { sent++; urls.push(`${req.method()} ${req.url().slice(BASE.length)}`); } };
  page.on("request", count);
  await page.waitForTimeout(35_000); // longer than any old heartbeat interval
  page.off("request", count);
  assert.equal(sent, 0, `idle and healthy, yet ${sent} requests went to the server: ${urls.join(", ")}`);
  step("idle and connected: no requests at all for 35 s");

  /* ---------------- 5. signed in: the server goes away, and comes back having forgotten the session ---------------- */
  await current.stop();
  await page.getByRole("button", { name: "Refresh" }).click(); // any request notices
  await bar.getByText("Can't reach your vault").waitFor({ timeout: 15_000 });
  await bar.getByText(/Trying again in \d+ s|Reconnecting…/).waitFor();
  await shot(page, "9-server-gone");
  assert.equal(await page.getByText("Public log check failed").count(), 0, "an unreachable server isn't reported as tampering");
  assert.equal(await page.locator(".toast", { hasText: "Can't reach your vault server" }).count(), 0, "the bar says it; no toast on top");
  const attemptsBefore = await page.evaluate(() => document.querySelector(".linkbar")?.textContent);
  assert.ok(attemptsBefore);
  step("the server stops: the bar says HumID is retrying, with Reconnect now");
  // the restarted server has no record of the session: the app locks, the usual way back in
  const ended = page.getByText(/Your session ended/).waitFor({ timeout: 80_000 });
  current = await startDev({ HUMID_DEV_DATA: data });
  await bar.getByRole("button", { name: "Reconnect now" }).click({ timeout: 35_000 }).catch(() => {}); // or the next retry gets there first
  await ended;
  await page.getByRole("button", { name: "Unlock", exact: true }).waitFor({ timeout: 10_000 });
  await bar.waitFor({ state: "detached", timeout: 10_000 });
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.locator(".tabbar").waitFor({ timeout: 20_000 });
  await tab(page, "Vault");
  await page.locator(".list .item").first().waitFor({ timeout: 20_000 });
  step("the server is back: reconnected by itself; its forgotten session asks for one live check");

  await ctx.close();
  console.log("ok — offline mode checks pass");
} finally {
  await browser.close().catch(() => {});
  await current?.stop().catch(() => {});
  rmSync(data, { recursive: true, force: true });
}
process.exit(0);
