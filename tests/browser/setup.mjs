// Getting set up, in a real browser: the onboarding and first-run fixes from the
// user flow review. Checks, on a small phone (375×667) and a common one (390×844):
//   - each step's main button is on screen without scrolling
//   - the recovery card is confirmed by typing back one group of it
//   - the You tab shows what's left to protect, and each button opens the right place
//   - a new document's tag is suggested from its name, not always "Identity"
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
  assert.ok(await page.getByText("You're all set").isVisible(), "still on the recovery card");
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
  await targets(page, "Recovery card"); await shot(page, "small-recovery-card");
  await page.getByRole("button", { name: "Open my vault" }).click();
  step("recovery card: a wrong group is refused, the right one (written with O for 0, lower case) accepted");

  // the vault: one way to add, and nothing to protect here (that's under You)
  await page.getByRole("button", { name: "Add to your vault" }).waitFor({ timeout: 15_000 });
  assert.equal(await page.locator("section.protect").count(), 0, "the checklist lives under You, not in the vault");
  assert.equal(await page.locator(".tabbar [role=tab]").count(), 3, "three tabs");
  assert.equal(await page.locator(".tabbar [role=tablist]").count(), 1);
  await targets(page, "Vault"); await shot(page, "small-vault-empty");

  // You: what's left to protect, with a button for each
  await page.locator(".tabbar button", { hasText: "You" }).click();
  assert.equal(await page.locator(".tabbar [aria-selected=true]").innerText(), "You");
  const protect = page.locator("section.protect");
  await protect.waitFor({ timeout: 15_000 });
  await protect.getByText("1 of 3").waitFor();
  assert.ok(await protect.locator("button.proof-row", { hasText: "Recovery card" }).isDisabled(), "the recovery card is done");
  await protect.getByText("Optional: duress gesture").waitFor();
  await targets(page, "You"); await shot(page, "small-you-checklist");
  await protect.locator("button.proof-row", { hasText: "A second device" }).click();
  await page.getByText("Enter the code from your new device").waitFor();
  await page.locator(".sheet .icon-btn, .sheet button[aria-label=Close]").first().click().catch(() => page.keyboard.press("Escape"));
  await page.locator("section.protect button.proof-row", { hasText: "A second proof" }).click();
  await page.waitForTimeout(800);
  const rec = await page.locator("#recovery").boundingBox();
  assert.ok(rec && rec.y < page.viewportSize().height / 2, "A second proof scrolls to the Recovery card");
  // the plain-English security facts, from one place
  await page.getByRole("button", { name: "How HumID protects you" }).click();
  await page.locator(".sheet").getByText("Sealed on this phone first").waitFor();
  await page.locator(".sheet").getByRole("button", { name: "Got it" }).click();
  await page.locator(".sheet").waitFor({ state: "detached" });
  // a new recovery card opens its own sheet, never the payment card sheet beside it
  await page.locator("#recovery button.proof-row", { hasText: "Recovery card" }).click();
  await page.locator(".sheet").getByRole("button", { name: /Make a new card/ }).click();
  await hold(page);
  await page.locator(".sheet").getByText("Write this down").waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".sheet").count(), 1, "one sheet: the recovery card");
  assert.equal(await page.getByText("Add a payment card").count(), 0, "the payment card sheet didn't open with it");
  await page.locator(".sheet .cardcode").waitFor();
  await page.evaluate(() => globalThis.__humidBack());
  await page.locator(".sheet").waitFor({ state: "detached" });
  // the diagnostics are folded away
  assert.equal(await page.getByText("Pinned server key").isVisible(), false, "About is collapsed");
  await page.locator("details.about summary").click();
  await page.getByText("Pinned server key").waitFor();
  await page.locator("details.about summary").click();
  step("You: checklist 1 of 3, each button opens the right place, protection facts in one sheet, About collapsed");

  // Android's back button / edge swipe (wired to the same handler): closes what's on top, never leaves HumID
  const back = () => page.evaluate(() => globalThis.__humidBack());
  assert.equal(await back(), "tab", "back from You goes to the Vault tab");
  assert.equal(await page.locator(".tabbar [aria-current=page]").innerText(), "Vault");
  assert.equal(await back(), "stay", "back at the Vault stays in HumID");
  // Add opens the camera at once (no camera on this headless browser: it says so and waits); back closes it
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".doccam").waitFor();
  assert.equal(await back(), ".doccam");
  await page.locator(".doccam").waitFor({ state: "detached" });
  assert.equal(await page.locator(".pushed").count(), 0, "Add closed with its camera");
  await page.locator(".tabbar button", { hasText: "You" }).click();
  await page.locator("section.protect button.proof-row", { hasText: "A second device" }).click();
  await page.locator(".sheet").waitFor();
  assert.equal(await back(), "sheet", "back closes a sheet opened from another tab");
  await page.locator(".sheet").waitFor({ state: "detached" });
  assert.equal(await back(), "tab");
  // inside Add: "It's something else" opens the picker; a kind opens its own camera; back
  // closes that camera first, then steps back through the flow one level at a time
  await page.getByRole("button", { name: "Add to your vault" }).first().click();
  await page.locator(".doccam").waitFor();
  await page.getByRole("button", { name: "It's something else" }).click();
  await page.locator(".pushed").getByText("What is it?").waitFor();
  await targets(page, "What is it?"); await shot(page, "small-add-picker");
  await page.locator(".pushed button.kind", { hasText: "Driver's license" }).click();
  await page.locator(".doccam").waitFor();
  assert.equal(await back(), ".doccam");
  await page.locator(".doccam").waitFor({ state: "detached" });
  await page.locator(".pushed").getByText("Scan it").waitFor();
  assert.equal(await back(), "pushed", "back inside the ID flow steps back to the picker");
  await page.locator(".pushed").getByText("What is it?").waitFor();
  assert.equal(await back(), "pushed", "back from the picker returns to the camera");
  await page.locator(".doccam").waitFor();
  assert.equal(await back(), ".doccam", "back from the camera closes Add");
  await page.locator(".doccam").waitFor({ state: "detached" });
  assert.equal(await page.locator(".pushed").count(), 0);
  assert.equal(await page.locator(".tabbar").count(), 1, "still in the app");
  step("back gesture: camera, then each step of Add, then tab; at the Vault it stays put");

  // a document's tag is suggested from its name; the toast sits at the bottom
  await page.locator(".tabbar button", { hasText: "Vault" }).click();
  const addFile = async (file) => {
    await page.getByRole("button", { name: "Add to your vault" }).first().click();
    await page.locator(".doccam").waitFor();
    await page.locator(".dc-tools").getByRole("button", { name: "File" }).click();
    await page.locator("#add-file").setInputFiles(file);
    await page.locator(".pushed .review").waitFor();
  };
  await addFile({ name: "Apartment lease.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.4\n%lease\n") });
  await page.locator(".tagpick .chip[aria-pressed=true]", { hasText: "Home" }).waitFor();
  assert.match(await page.locator(".pushed .kindrow").innerText(), /File/, "a PDF is a file");
  await targets(page, "Add to your vault"); await shot(page, "small-add-file-review");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  const toast = page.locator(".toast").first();
  await toast.waitFor({ timeout: 30_000 });
  const tb = await toast.boundingBox();
  assert.ok(tb.y > page.viewportSize().height / 2, `the toast is at the bottom (y ${Math.round(tb.y)})`);
  const bar = await page.locator(".tabbar nav").boundingBox();
  assert.ok(tb.y + tb.height <= bar.y + 1, "and above the tab bar");
  await shot(page, "small-toast");
  step("a lease is tagged Home; the toast shows at the bottom, above the tab bar");

  // Preferences (under You): how it looks and locks, kept on this device; pins sealed with the item
  await page.locator(".tabbar button", { hasText: "You" }).click();
  await page.getByRole("heading", { name: "You", level: 1 }).waitFor();
  await targets(page, "You");
  const html = (k) => page.evaluate((key) => document.documentElement.dataset[key], k);
  assert.equal(await html("theme"), "dark", "night by default");
  await page.locator('[data-pref="theme:light"]').click();
  assert.equal(await html("theme"), "light");
  await page.locator('[data-pref="text:large"]').click();
  assert.equal(await html("text"), "large");
  await page.locator('[data-pref="motion"]').uncheck({ force: true });
  assert.equal(await html("motion"), "reduced");
  await page.locator('[data-pref="idle:60000"]').click();
  await page.locator('[data-pref="sort:name"]').click();
  assert.equal(await page.locator('[data-pref="idle:600000"]').count(), 0, "no lock time longer than 5 minutes is offered");
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("humid.prefs.v1")));
  assert.deepEqual([saved.theme, saved.text, saved.motion, saved.idleMs, saved.sort], ["light", "large", false, 60000, "name"]);
  assert.equal("startTab" in saved, false, "no start-tab preference any more");
  await page.locator("details.about summary").click();
  assert.match(await page.locator("main").innerText(), /auto-locks in 0?[01]:/, "the session shows the shorter lock");
  await shot(page, "small-settings-day");
  step("preferences: day theme, larger text, animations off, 1-minute lock, sort by name");

  // a second document, so there's an order to change
  await page.locator(".tabbar button", { hasText: "Vault" }).click();
  await addFile({ name: "Zoo membership.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.4\n%zoo\n") });
  assert.equal(await page.locator(".tagpick .chip[aria-pressed=true]").count(), 0, "nothing in the name says what it's about: no tag");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  const rows = page.locator(".list .item");
  await page.waitForFunction(() => document.querySelectorAll(".list .item").length === 2, null, { timeout: 30_000 });
  assert.deepEqual((await rows.locator(".name").allInnerTexts()).map((t) => t.trim()), ["Apartment lease", "Zoo membership"], "sorted by name");
  const last = 1, lastName = "Zoo membership";
  // the lease carries its tag; the tag row appears only now that something has a tag
  assert.match(await rows.first().innerText(), /Home/, "the tag shows on the row");
  await page.getByRole("button", { name: "More filters" }).click();
  await page.locator(".chips[aria-label='Filter by tag'] .chip", { hasText: "Home" }).click();
  await page.waitForFunction(() => document.querySelectorAll(".list .item").length === 1);
  await page.locator(".chips[aria-label='Filter by tag'] .chip", { hasText: "Any tag" }).click();
  await page.waitForFunction(() => document.querySelectorAll(".list .item").length === 2);
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
  await page.getByRole("heading", { name: "Vault", level: 1 }).waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".tabbar [aria-current=page]").innerText(), "Vault", "always opens on the vault");
  await page.locator(".list .item[data-pinned]").first().waitFor({ timeout: 10_000 });
  step("after a restart: same look, opens on the Vault, the pin came back from the vault");
  await page.locator(".tabbar button", { hasText: "You" }).click();
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
