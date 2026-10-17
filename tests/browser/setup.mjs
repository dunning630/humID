// Getting set up, in a real browser: the onboarding and first-run fixes from the
// user flow review. Checks, on a small phone (375×667) and a common one (390×844):
//   - each step's main button is on screen without scrolling
//   - the seal card is confirmed by typing back one group of it
//   - the vault shows what's left to protect, and each button opens the right place
//   - a new document's category is suggested from its name, not always "Identity"
//   - toasts appear at the bottom, never over the back button or progress bar
//   - every button, link and checkbox is at least 44 px in both directions
//   - an app built with a pinned server skips the "trust this server" step
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/setup.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5198);
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
  return { dev, kid: /key id ([0-9a-f]{64})/.exec(log)?.[1], stop: () => new Promise((r) => { dev.once("exit", r); dev.kill(); }) };
}

const browser = await chromium.launch();
async function phone(width, height) {
  const ctx = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => { throw new Error(`page error: ${e.message}`); });
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
async function hold(page) {
  const b = page.locator(".interrupt .hold");
  await b.waitFor({ timeout: 20_000 });
  await b.focus(); await page.keyboard.down(" "); await page.waitForTimeout(1500); await page.keyboard.up(" ");
  await page.locator(".interrupt").waitFor({ state: "detached", timeout: 20_000 });
}
/** The button is fully inside the viewport, with no scrolling. */
async function onScreen(page, locator, what) {
  await page.evaluate(() => window.scrollTo(0, 0));
  const box = await locator.boundingBox();
  const vh = page.viewportSize().height;
  assert.ok(box && box.y >= 0 && box.y + box.height <= vh, `${what} is off screen (y ${box && Math.round(box.y)}–${box && Math.round(box.y + box.height)}, screen ${vh})`);
}
/** Every interactive control on screen is at least 44 × 44 px. */
async function targets(page, where) {
  const small = await page.evaluate(() => [...document.querySelectorAll("button, a[href], input:not([type=checkbox]):not([type=file]), label.check, [role=button]")]
    .filter((el) => {
      const r = el.getBoundingClientRect(), s = getComputedStyle(el);
      if (!r.width || !r.height || s.visibility === "hidden" || el.closest("[aria-hidden=true]")) return false;
      if (el.matches(".linklike") || el.closest(".field, .search, .tabbar")) return false; // inline text links; fields and the tab bar are taller than 44 by their containers
      return r.width < 44 || r.height < 44;
    })
    .map((el) => { const r = el.getBoundingClientRect(); return `${el.tagName.toLowerCase()}.${String(el.className).replace(/\s+/g, ".")} "${(el.innerText || el.getAttribute("aria-label") || "").trim().slice(0, 24)}" ${Math.round(r.width)}×${Math.round(r.height)}`; }));
  assert.deepEqual(small, [], `controls under 44 px on ${where}`);
}
async function confirmCard(page) {
  // until the card is checked, the button says so and takes you to the check instead of opening the vault
  const go = page.locator(".foot button.btn.secure");
  assert.equal((await go.innerText()).trim(), "Check your card to continue");
  await go.click();
  await page.waitForFunction(() => document.activeElement?.id === "card-check");
  assert.ok(await page.getByText("You're all set").isVisible(), "still on the seal card");
  const ask = await page.locator('label[for="card-check"]').innerText();
  const n = Number(/group (\d+)/.exec(ask)[1]);
  const groups = await page.locator(".cardcode span").allInnerTexts();
  await page.fill("#card-check", groups[n % groups.length]); // the wrong group
  await page.getByText(/isn't group/).waitFor();
  assert.equal((await go.innerText()).trim(), "Check your card to continue");
  await page.fill("#card-check", groups[n - 1].toLowerCase().replace(/0/g, "O")); // the right one, as someone might write it
  await page.getByText("That matches").waitFor();
  await page.locator(".foot button:not([disabled])", { hasText: "Open my vault" }).waitFor({ timeout: 5000 }); // enables on the next render
}

let current = null; // the running dev server, stopped whatever happens
const data = mkdtempSync(join(tmpdir(), "humid-setup-"));
try {
  /* ---------------- 1. a small phone, a server that isn't pinned (web build) ---------------- */
  let dev = current = await startDev({ HUMID_DEV_DATA: data });
  step("dev server up");
  const kid = dev.kid;
  assert.match(kid, /^[0-9a-f]{64}$/);
  const { ctx, page } = await phone(375, 667);
  await page.goto(BASE);
  await onScreen(page, page.getByRole("button", { name: "Create my HumID" }), "Create my HumID on a 375×667 phone");
  await targets(page, "Welcome"); await shot(page, "small-welcome");
  step("welcome: the main button is on screen on a small phone");

  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByText("Connect to the vault you'll trust").waitFor();
  assert.equal(await page.locator(".stepper").getAttribute("role"), "progressbar");
  assert.equal(await page.locator(".stepper").getAttribute("aria-valuemax"), "4");
  await onScreen(page, page.getByRole("button", { name: "Trust this server" }), "Trust this server");
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByRole("button", { name: "Use a demo access code" }).click();
  await page.getByText("Access pass ready").first().waitFor({ timeout: 30_000 });
  assert.equal(await page.locator(".toast").count(), 0, "no toast on top of the Access pass ready banner");
  await targets(page, "Access pass");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByText("Your body becomes the key").waitFor();
  await onScreen(page, page.getByRole("button", { name: /Use demo mode/ }), "the bind button on a 375×667 phone");
  await targets(page, "Bind"); await shot(page, "small-bind");
  step("server step shown (not pinned); no duplicate toast; bind button on screen");

  await page.getByLabel(/Only my own face or fingerprints/).check();
  await page.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(page);
  await page.getByText("You're all set").waitFor({ timeout: 30_000 });
  await confirmCard(page);
  await onScreen(page, page.getByRole("button", { name: "Open my vault" }), "Open my vault");
  await targets(page, "Seal card"); await shot(page, "small-seal-card");
  await page.getByRole("button", { name: "Open my vault" }).click();
  step("seal card: a wrong group is refused, the right one (written with O for 0, lower case) accepted");

  // the vault: what's left to protect
  const protect = page.locator("section.protect");
  await protect.waitFor({ timeout: 15_000 });
  await protect.getByText("1 of 3").waitFor();
  assert.ok(await protect.locator("button.proof-row", { hasText: "Seal card" }).isDisabled(), "the seal card is done");
  await protect.getByText("Optional: duress gesture").waitFor();
  await targets(page, "Vault"); await shot(page, "small-vault-checklist");
  await protect.locator("button.proof-row", { hasText: "A second device" }).click();
  await page.getByText("Enter the code from your new device").waitFor();
  assert.equal(await page.locator(".tabbar [aria-current=page]").innerText(), "Security");
  await page.locator(".sheet .icon-btn, .sheet button[aria-label=Close]").first().click().catch(() => page.keyboard.press("Escape"));
  await page.locator(".tabbar button", { hasText: "Vault" }).click();
  await page.locator("section.protect button.proof-row", { hasText: "A second proof" }).click();
  await page.waitForTimeout(800);
  const rec = await page.locator("#recovery").boundingBox();
  assert.ok(rec && rec.y < page.viewportSize().height / 2, "A second proof scrolls to the Recovery card");
  await targets(page, "Security");
  step("vault checklist: 1 of 3, and each button opens the right place in Security");

  // Android's back button / edge swipe (wired to the same handler): closes what's on top, never leaves HumID
  const back = () => page.evaluate(() => globalThis.__humidBack());
  assert.equal(await back(), "tab", "back from Security goes to the Vault tab");
  assert.equal(await page.locator(".tabbar [aria-current=page]").innerText(), "Vault");
  assert.equal(await back(), "stay", "back at the Vault stays in HumID");
  assert.ok(await page.locator("section.protect").isVisible());
  await page.getByRole("button", { name: "Add a document" }).first().click();
  await page.locator(".sheet").waitFor();
  assert.equal(await back(), "sheet");
  await page.locator(".sheet").waitFor({ state: "detached" });
  await page.locator("section.protect button.proof-row", { hasText: "A second device" }).click();
  await page.locator(".sheet").waitFor();
  assert.equal(await back(), "sheet", "back closes a sheet opened from another tab");
  await page.locator(".sheet").waitFor({ state: "detached" });
  assert.equal(await back(), "tab");
  // the camera: back closes the camera first, then the sheet behind it
  await page.getByRole("button", { name: /Scan an ID/ }).first().click().catch(async () => { await page.locator("button.fab").click(); await page.getByRole("button", { name: /Scan an ID/ }).click(); });
  await page.getByRole("button", { name: /Driver's license/ }).click();
  await page.locator(".doccam").waitFor();
  assert.equal(await back(), ".doccam");
  await page.locator(".doccam").waitFor({ state: "detached" });
  assert.ok(await page.locator(".sheet").isVisible(), "the ID sheet is still open behind the camera");
  assert.equal(await back(), "sheet");
  await page.locator(".sheet").waitFor({ state: "detached" });
  assert.equal(await page.locator(".tabbar").count(), 1, "still in the app");
  step("back gesture: camera, then sheet, then tab; at the Vault it stays put");

  // a document's category is suggested from its name; the toast sits at the bottom
  await page.locator(".tabbar button", { hasText: "Vault" }).click();
  await page.getByRole("button", { name: "Add a document" }).first().click();
  await page.locator('input[type="file"]').setInputFiles({ name: "Apartment lease.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.4\n%lease\n") });
  await page.locator(".cats button[aria-pressed=true]", { hasText: "Home" }).waitFor();
  await targets(page, "Add a document");
  await page.getByRole("button", { name: /Seal & store/ }).click();
  await hold(page);
  const toast = page.locator(".toast").first();
  await toast.waitFor({ timeout: 30_000 });
  const tb = await toast.boundingBox();
  assert.ok(tb.y > page.viewportSize().height / 2, `the toast is at the bottom (y ${Math.round(tb.y)})`);
  const bar = await page.locator(".tabbar nav").boundingBox();
  assert.ok(tb.y + tb.height <= bar.y + 1, "and above the tab bar");
  await shot(page, "small-toast");
  step("a lease is filed under Home; the toast shows at the bottom, above the tab bar");

  // Settings: how it looks and locks, kept on this device; pins sealed with the item
  await page.locator(".tabbar button", { hasText: "Settings" }).click();
  await page.getByRole("heading", { name: "Settings", level: 1 }).waitFor();
  await targets(page, "Settings");
  const html = (k) => page.evaluate((key) => document.documentElement.dataset[key], k);
  assert.equal(await html("theme"), "dark", "night by default");
  await page.locator('[data-pref="theme:light"]').click();
  assert.equal(await html("theme"), "light");
  await page.locator('[data-pref="text:large"]').click();
  assert.equal(await html("text"), "large");
  await page.locator('[data-pref="motion"]').uncheck({ force: true });
  assert.equal(await html("motion"), "reduced");
  await page.locator('[data-pref="idle:60000"]').click();
  await page.locator('[data-pref="startTab:settings"]').click();
  await page.locator('[data-pref="sort:name"]').click();
  assert.equal(await page.locator('[data-pref="idle:600000"]').count(), 0, "no lock time longer than 5 minutes is offered");
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("humid.prefs.v1")));
  assert.deepEqual([saved.theme, saved.text, saved.motion, saved.idleMs, saved.startTab, saved.sort], ["light", "large", false, 60000, "settings", "name"]);
  assert.match(await page.locator("main").innerText(), /auto-locks in 0?[01]:/, "the session shows the shorter lock");
  await shot(page, "small-settings-day");
  step("settings: day theme, larger text, animations off, 1-minute lock, open on Settings, sort by name");

  // a second document, so there's an order to change
  await page.locator(".tabbar button", { hasText: "Vault" }).click();
  await page.getByRole("button", { name: "Add a document" }).first().click();
  await page.locator('input[type="file"]').setInputFiles({ name: "Zoo membership.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.4\n%zoo\n") });
  await page.getByRole("button", { name: /Seal & store/ }).click();
  await hold(page);
  const rows = page.locator(".list .item");
  await page.waitForFunction(() => document.querySelectorAll(".list .item").length === 2, null, { timeout: 30_000 });
  assert.deepEqual((await rows.locator(".name").allInnerTexts()).map((t) => t.trim()), ["Apartment lease", "Zoo membership"], "sorted by name");
  const last = 1, lastName = "Zoo membership";
  await rows.nth(last).click();
  await page.getByText("Pin to the top").click();
  await page.locator(".list .item[data-pinned]").first().waitFor({ timeout: 10_000 });
  await page.evaluate(() => globalThis.__humidBack());
  assert.equal((await rows.first().locator(".name").innerText()).trim(), lastName, "a pinned item goes to the top");
  await shot(page, "small-vault-pinned-day");
  step("a pinned item moves to the top of the vault");

  await page.reload();
  await page.getByRole("button", { name: "Unlock", exact: true }).waitFor({ timeout: 15_000 });
  assert.equal(await html("theme"), "light", "the theme is there before unlocking");
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.getByRole("heading", { name: "Settings", level: 1 }).waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".tabbar [aria-current=page]").innerText(), "Settings", "opens on the chosen tab");
  await page.locator(".tabbar button", { hasText: "Vault" }).click();
  await page.locator(".list .item[data-pinned]").first().waitFor({ timeout: 10_000 });
  step("after a restart: same look, opens on Settings, the pin came back from the vault");
  await page.locator(".tabbar button", { hasText: "Settings" }).click();
  await page.locator('[data-pref="theme:dark"]').click();
  await page.locator('[data-pref="text:standard"]').click();

  // the phone deleted HumID's key (fingerprints changed, or a reinstall restored old data):
  // a clear screen and a way to start again, not an unlock that fails forever
  await page.getByRole("button", { name: "Lock now" }).first().click();
  await page.evaluate(() => { globalThis.__humidDemoKeyGone = true; });
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.getByRole("heading", { name: "This phone's HumID key is gone" }).waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".toast.error, .toast[data-kind=error]").count(), 0, "no error toast over the screen's buttons");
  await shot(page, "small-key-gone");
  await page.evaluate(() => { globalThis.__humidDemoKeyGone = false; });
  await page.getByRole("button", { name: "Set up HumID again" }).click();
  await page.getByRole("button", { name: "Remove this identity from this phone" }).click();
  await page.getByRole("button", { name: "Create my HumID" }).waitFor({ timeout: 15_000 });
  step("a deleted biometric key: says so, and setting up again starts from Welcome");
  await ctx.close();
  await dev.stop();

  /* ---------------- 2. an app build that pins this server ---------------- */
  dev = current = await startDev({ HUMID_DEV_DATA: data, HUMID_SERVER_KID: kid });
  const p2 = await phone(390, 844);
  await p2.page.goto(BASE);
  await p2.page.getByRole("button", { name: "Create my HumID" }).click();
  await p2.page.getByText("Pay without being known").waitFor({ timeout: 15_000 });
  assert.equal(await p2.page.locator(".stepper").getAttribute("aria-valuemax"), "3", "access, bind, done");
  assert.match(await p2.page.locator(".eyebrow").first().innerText(), /Step 1/i);
  assert.equal(await p2.page.evaluate(() => globalThis.__humidBack()), "screen", "the back gesture does what the Back button does");
  await p2.page.getByRole("button", { name: "I already have HumID" }).click();
  await p2.page.getByText("How do you want to get in?").waitFor({ timeout: 15_000 });
  await p2.page.getByRole("button", { name: "Back" }).click();
  await p2.page.getByRole("button", { name: "Create my HumID" }).waitFor();
  await shot(p2.page, "pinned-welcome");
  step("pinned server: Create starts at the access pass, Join at the choice of route; Back returns to Welcome");
  await p2.ctx.close();
  console.log("ok — setup flow checks pass");
} finally {
  await browser.close().catch(() => {});
  await current?.stop().catch(() => {});
  rmSync(data, { recursive: true, force: true });
}
process.exit(0);
