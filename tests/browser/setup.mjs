// Getting set up, in a real browser (3.0): the onboarding and first-run flow. Checks, on a
// small phone (375×667) and a common one (390×844):
//   - each step's main button is on screen without scrolling
//   - the main button is never a dead grey one: tapping it points at what's missing
//   - the recovery card is confirmed by typing back one group of it; a new one asks before it's
//     closed unchecked, and survives a lock into the next real unlock (APP-02, APP-03)
//   - the You hub shows what's left to protect, and each row opens the right screen
//   - a new document's tag is suggested from its name, not always "Identity"
//   - toasts drop in at the top, never over a back button, the stepper or the primary action
//   - every button, link and checkbox is at least 44 px in both directions, segmented controls too
//   - Welcome and Lock have an h1; the viewer and its question are modal: focus goes in, stays in,
//     the rest is inert, and focus comes back to what opened them (APP-12)
//   - preferences: theme, four text sizes, animations, lock time, sort; pins ride with the item
//   - the back gesture closes what's on top, one level at a time, and never leaves HumID
//   - leaving HumID while a check is running locks it; the document never opens (PC-17)
//   - a deleted biometric key is explained, and setting up again starts from Welcome
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
import { hold, confirmCard, cardGroups, youScreen, backOut, tab, pickKind, addFile as addFileV3 } from "./_v3.mjs";

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
      if (el.matches(".link, .linklike") || el.closest(".field, .search, .tabbar")) return false; // inline text links; fields and the tab bar are taller than 44 by their containers (segmented controls are 44 themselves)
      return r.width < 43.5 || r.height < 43.5; // sub-pixel layout rounds 44 to 43.99
    })
    .map((el) => { const r = el.getBoundingClientRect(); return `${el.tagName.toLowerCase()}.${String(el.className).replace(/\s+/g, ".")} "${(el.innerText || el.getAttribute("aria-label") || "").trim().slice(0, 24)}" ${Math.round(r.width)}×${Math.round(r.height)}`; }));
  assert.deepEqual(small, [], `controls under 44 px on ${where}`);
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
  await page.getByText(/No password exists/).waitFor();
  await targets(page, "Welcome"); await shot(page, "small-welcome");
  // one h1 per page, and Welcome and Lock have theirs (the wordmark)
  assert.equal(await page.getByRole("heading", { level: 1, name: "HumID" }).count(), 1, "Welcome's h1 is the wordmark");
  step("welcome: the main button is on screen on a small phone, and the no-password promise is the first thing said");

  await page.getByRole("button", { name: "Create my HumID" }).click();
  await page.getByText("Your vault server").first().waitFor();
  assert.equal(await page.locator(".stepper").getAttribute("role"), "progressbar");
  assert.equal(await page.locator(".stepper").getAttribute("aria-valuemax"), "6"); // connect, access, mode, bind, card, in
  // the key is behind a disclosure: the host leads
  assert.equal(await page.getByText(/Compare it with the key/).count(), 0, "the key is folded away");
  await page.getByRole("button", { name: "Show its key" }).click();
  await page.getByText(/Compare it with the key/).waitFor();
  await onScreen(page, page.getByRole("button", { name: "Trust this server" }), "Trust this server");
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByRole("button", { name: "Use a demo access code" }).click();
  await page.getByText("Access pass ready").first().waitFor({ timeout: 30_000 });
  assert.equal(await page.locator(".toast").count(), 0, "no toast on top of the Access pass ready banner");
  await targets(page, "Access pass");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByText("If you lose every device").waitFor();
  await page.getByRole("button", { name: "Next: lock it to you" }).click(); // the recommended mode is already selected
  await page.getByText("Your body becomes the key").waitFor();
  await onScreen(page, page.getByRole("button", { name: /Use demo mode/ }), "the bind button on a 375×667 phone");
  await targets(page, "Bind"); await shot(page, "small-bind");
  step("server step shown (not pinned), key behind a disclosure; no duplicate toast; bind button on screen");

  // never a dead grey button (3.0): the statement is still required, and tapping Create points at it
  const bind = page.getByRole("button", { name: /Use demo mode/ });
  assert.equal(await bind.isDisabled(), false, "the bind button is live");
  await bind.click();
  await page.waitForFunction(() => document.activeElement?.getAttribute("role") === "checkbox" || document.activeElement?.closest("[role=checkbox]"), null, { timeout: 5000 }).catch(() => {});
  assert.equal(await page.locator(".interrupt").count(), 0, "no check without the statement");
  await page.getByRole("button", { name: "What does this mean?" }).click();
  await page.getByText(/HumID can't see whose faces/).waitFor();
  await page.getByRole("checkbox").first().click();
  await bind.click();
  await hold(page);
  await page.getByText("Shown once · write it down now").waitFor({ timeout: 30_000 });
  // until the card is checked, the button says so and takes you to the check instead of opening the vault
  const go = page.locator(".foot button.btn.primary");
  assert.equal((await go.innerText()).trim(), "Check your copy to continue");
  await go.click();
  await page.waitForFunction(() => document.activeElement?.id === "card-check");
  assert.ok(await page.getByText("Your recovery card").first().isVisible(), "still on the recovery card");
  await confirmCard(page, { wrong: true });
  await page.locator(".foot button.btn.primary", { hasText: "I've written it down" }).waitFor({ timeout: 5000 }); // changes on the next render
  await onScreen(page, go, "I've written it down");
  await targets(page, "Recovery card"); await shot(page, "small-recovery-card");
  await go.click();
  // then one line and the vault
  await page.getByRole("heading", { name: "You're in" }).waitFor();
  await onScreen(page, page.getByRole("button", { name: "Open my vault" }), "Open my vault");
  await targets(page, "You're in"); await shot(page, "small-youre-in");
  await page.getByRole("button", { name: "Open my vault" }).click();
  step("recovery card on its own screen, shown once: a wrong group is refused, the right one (written with O for 0, lower case) accepted; then You're in");

  // the vault: one way to add, and nothing to protect here (that's under You)
  await page.getByRole("button", { name: "Add to your vault" }).waitFor({ timeout: 15_000 });
  // Vault, Messages (the dev server runs a messaging relay, 4.1), Activity, You
  assert.deepEqual(await page.locator(".tabbar [role=tab]").allInnerTexts(), ["Vault", "Messages", "Activity", "You"], "four tabs, Messages second");
  assert.equal(await page.locator("nav.tabbar[role=tablist]").count(), 1, "the tab bar is the tablist");
  await targets(page, "Vault"); await shot(page, "small-vault-empty");

  // You: a hub of rows; Protection shows what's left, with a row for each
  await tab(page, "You");
  assert.equal(await page.locator(".tabbar [aria-selected=true]").innerText(), "You");
  const hub = page.locator("main .rows").first();
  await hub.locator(".row", { hasText: "Protection" }).getByText("1 of 3 done").waitFor({ timeout: 15_000 });
  await targets(page, "You"); await shot(page, "small-you-hub");
  await hub.locator(".row", { hasText: "Protection" }).click();
  const protect = page.locator(".pushed");
  await protect.getByText("Finish protecting your HumID").waitFor();
  await protect.getByText("1 of 3").waitFor();
  assert.equal(await protect.locator(".row", { hasText: "Recovery card" }).first().evaluate((el) => el.tagName), "DIV", "the recovery card is done: not a button");
  await protect.getByText("Optional: duress gesture").waitFor();
  // the plain-English security facts, first on this screen; the first point is the no-password one
  assert.match(await protect.locator(".rows").first().innerText(), /^A live check, every time/);
  await targets(page, "Protection"); await shot(page, "small-protection");
  await protect.locator(".row", { hasText: "A second device" }).click();
  await page.getByText("Enter the code from your new device").waitFor();
  await page.locator(".sheet button[aria-label=Close]").first().click();
  await page.locator(".sheet").waitFor({ state: "detached" });
  await page.locator(".pushed").getByRole("heading", { name: "Devices" }).waitFor();
  await backOut(page);
  await page.locator(".pushed").waitFor({ state: "detached" });
  await hub.locator(".row", { hasText: "Protection" }).click();
  await page.locator(".pushed .row", { hasText: "A second proof" }).click();
  await page.locator(".pushed").getByRole("heading", { name: "Recovery" }).waitFor();
  // a new recovery card opens its own sheet; only one sheet at a time
  await page.locator(".pushed button.row", { hasText: "Recovery card" }).click();
  await page.locator(".sheet").getByRole("button", { name: /Make a new card/ }).click();
  await hold(page);
  await page.getByText("Shown once · write it down now").waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".sheet").count(), 1, "one sheet: the recovery card");
  assert.equal(await page.getByText("Add a payment card").count(), 0, "the payment card sheet didn't open with it");
  const newGroups = await cardGroups(page);
  assert.equal(newGroups.length, 5);
  const keep = page.locator(".sheet .actions button.btn.primary");
  assert.equal((await keep.innerText()).trim(), "Check your copy to continue", "the sheet's button is live and says what's missing");
  // APP-03: until it's checked, Back, Escape or the close button asks before throwing it away
  const ask = page.getByText("Close without saving your new card?");
  for (const close of [
    () => page.evaluate(() => globalThis.__humidBack()),
    () => page.keyboard.press("Escape"),
    () => page.locator(".sheet button[aria-label=Close]").first().click(),
  ]) {
    await close();
    await ask.waitFor();
    await page.locator(".sheet").last().getByRole("button", { name: "Cancel" }).click();
    await ask.waitFor({ state: "detached" });
    assert.deepEqual(await cardGroups(page), newGroups, "Cancel keeps the card on screen");
  }
  // APP-02: a lock with the card on screen (the phone rang) keeps it in memory only, and the
  // next real unlock shows the same card again
  await page.waitForTimeout(700); // the check's busy flag clears 600 ms after it ends
  await page.evaluate(() => {
    const set = (h) => { Object.defineProperty(document, "hidden", { configurable: true, get: () => h }); document.dispatchEvent(new Event("visibilitychange")); };
    set(true); set(false);
  });
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.getByText("Shown once · write it down now").waitFor({ timeout: 15_000 });
  assert.deepEqual(await cardGroups(page), newGroups, "the same new card, after a real unlock");
  assert.equal(await page.getByText("Pick up where you left off?").count(), 0, "the card comes straight back, not as an offer");
  step("a new recovery card: Back, Escape and Close ask first; a lock keeps it, and the next unlock shows it again");
  await confirmCard(page);
  await keep.click();
  await page.locator(".sheet").waitFor({ state: "detached" });
  if (await page.locator(".pushed").count()) await backOut(page);
  // the diagnostics are under About; close & erase under its Advanced disclosure, behind a typed word
  await hub.locator(".row", { hasText: "About" }).click();
  await page.locator(".pushed").getByText("Pinned server key").waitFor();
  await page.locator(".pushed").getByText("Never accepted").waitFor();
  assert.equal(await page.getByRole("button", { name: /Close HumID/ }).count(), 0, "closing is folded under Advanced");
  await page.locator(".pushed").getByText("Advanced").click();
  await page.getByRole("button", { name: /Close HumID/ }).click();
  await page.locator(".sheet").getByText(/Type CLOSE/).waitFor();
  assert.ok(await page.locator(".sheet").getByRole("button", { name: /Close|Erase/ }).last().isDisabled(), "the erase needs the typed word");
  await page.locator(".sheet button[aria-label=Close]").first().click();
  await page.locator(".sheet").waitFor({ state: "detached" });
  await backOut(page);
  step("You: hub rows 1 of 3, each opens the right screen, the facts first on Protection, About holds the diagnostics, Close & erase behind Advanced and a typed word");

  // Android's back button / edge swipe (wired to the same handler): closes what's on top, never leaves HumID
  const back = () => page.evaluate(() => globalThis.__humidBack());
  assert.equal(await back(), "tab", "back from You goes to the Vault tab");
  assert.equal(await page.locator(".tabbar [aria-current=page]").innerText(), "Vault");
  assert.equal(await back(), "stay", "back at the Vault stays in HumID");
  // Add (3.0.1): what it is, first; no camera until a kind is picked; back closes it
  const addBtn = () => page.getByRole("button", { name: "Add to your vault" }).first().click();
  await addBtn();
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  assert.equal(await page.locator(".doccam").count(), 0, "Add starts no camera before a kind is picked");
  await targets(page, "What are you adding?"); await shot(page, "small-add-picker");
  assert.equal(await back(), "pushed");
  await page.locator(".pushed").waitFor({ state: "detached" });
  await tab(page, "You");
  await hub.locator(".row", { hasText: "Devices" }).click();
  await page.locator(".pushed").getByRole("button", { name: "Add" }).click();
  await page.locator(".sheet").waitFor();
  assert.match(await back(), /^sheet(-step)?$/, "back closes a sheet opened on a pushed screen (its own Close is the back control)");
  await page.locator(".sheet").waitFor({ state: "detached" });
  assert.equal(await back(), "pushed", "then the pushed screen");
  await page.locator(".pushed").waitFor({ state: "detached" });
  assert.equal(await back(), "tab");
  // inside Add: the picker, a kind (its camera opens at once); back steps back one level at a time
  await addBtn();
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  await pickKind(page, "Payment card");
  await page.locator(".doccam").waitFor();
  await shot(page, "small-add-card-camera");
  assert.equal(await back(), ".doccam");
  await page.locator(".doccam").waitFor({ state: "detached" });
  await page.locator(".pushed").getByText("What are you adding?").waitFor();
  assert.equal(await back(), "pushed", "back from the picker closes Add");
  await page.locator(".pushed").waitFor({ state: "detached" });
  assert.equal(await page.locator(".pushed").count(), 0);
  assert.equal(await page.locator(".tabbar").count(), 1, "still in the app");
  step("back gesture: camera, then each step of Add, then sheet, pushed screen, tab; at the Vault it stays put");

  // a document's tag is suggested from its name; the toast drops in at the top, over no control
  await tab(page, "Vault");
  const addFile = async (file) => {
    await addFileV3(page, file);
    await page.locator(".pushed").getByText("Review, then seal").waitFor();
  };
  await addFile({ name: "Apartment lease.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.4\n%lease\n") });
  await page.locator(".chips[aria-label=Tags] .chip[aria-pressed=true]", { hasText: "Home" }).waitFor();
  assert.match(await page.locator(".pushed .row", { hasText: "Kind" }).innerText(), /File/, "a PDF is a file");
  assert.equal(await page.locator(".place-stamp [role=switch]").getAttribute("aria-checked"), "false", "the location stamp is off unless turned on");
  await targets(page, "Review, then seal"); await shot(page, "small-add-file-review");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  const toast = page.locator(".toast").first();
  await toast.waitFor({ timeout: 30_000 });
  const tb = await toast.boundingBox();
  assert.ok(tb.y < page.viewportSize().height / 3, `the toast is at the top (y ${Math.round(tb.y)})`);
  const bar = await page.locator(".tabbar").boundingBox();
  assert.ok(tb.y + tb.height <= bar.y + 1, "and clear of the tab bar");
  await shot(page, "small-toast");
  step("a lease is tagged Home; the toast shows at the top, clear of the tab bar");

  // Settings (under You): how it looks and locks, kept on this device; pins sealed with the item
  await youScreen(page, "Settings");
  await targets(page, "Settings");
  const html = (k) => page.evaluate((key) => document.documentElement.dataset[key], k);
  assert.equal(await html("theme"), "dark", "night by default");
  await page.locator('[data-pref="theme:light"]').click();
  assert.equal(await html("theme"), "light");
  assert.deepEqual(await page.locator('[data-pref^="text:"]').allInnerTexts(), ["A", "A+", "A++", "A+++"], "four text sizes");
  await page.locator('[data-pref="text:large"]').click();
  assert.equal(await html("text"), "large");
  const base = await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize));
  await page.locator('[data-pref="text:largest"]').click();
  assert.equal(await html("text"), "largest");
  const big = await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize));
  assert.ok(big > base * 1.4, `the largest size really is larger (${base} → ${big})`);
  await page.locator('[data-pref="text:large"]').click();
  await page.getByRole("switch", { name: "Animations" }).click();
  assert.equal(await html("motion"), "reduced");
  await page.locator('[data-pref="idle:60000"]').click();
  await page.locator('[data-pref="sort:name"]').click();
  assert.equal(await page.locator('[data-pref="idle:600000"]').count(), 0, "no lock time longer than 5 minutes is offered");
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("humid.prefs.v1")));
  assert.deepEqual([saved.theme, saved.text, saved.motion, saved.idleMs, saved.sort], ["light", "large", false, 60000, "name"]);
  assert.equal("startTab" in saved, false, "no start-tab preference any more");
  await shot(page, "small-settings-day");
  await backOut(page);
  step("settings: day theme, four text sizes, animations off, 1-minute lock, sort by name");

  // a second document, so there's an order to change
  await tab(page, "Vault");
  await addFile({ name: "Zoo membership.pdf", mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.4\n%zoo\n") });
  assert.equal(await page.locator(".chips[aria-label=Tags] .chip[aria-pressed=true]").count(), 0, "nothing in the name says what it's about: no tag");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  const rows = page.locator(".rows .item");
  await page.waitForFunction(() => document.querySelectorAll(".rows .item").length === 2, null, { timeout: 30_000 });
  assert.deepEqual((await rows.locator(".name").allInnerTexts()).map((t) => t.trim()), ["Apartment lease", "Zoo membership"], "sorted by name");
  const last = 1, lastName = "Zoo membership";
  // the lease carries its tag; the tag row appears only now that something has a tag
  assert.match(await rows.first().innerText(), /Home/, "the tag shows on the row");
  await page.getByRole("button", { name: "More filters" }).click();
  await page.locator(".chips[aria-label='Filter by tag'] .chip", { hasText: "Home" }).click();
  await page.waitForFunction(() => document.querySelectorAll(".rows .item").length === 1);
  await page.locator(".chips[aria-label='Filter by tag'] .chip", { hasText: "Any tag" }).click();
  await page.waitForFunction(() => document.querySelectorAll(".rows .item").length === 2);
  // tapping a row pushes the item: preview first, the facts, and an overflow menu whose rows say what they do
  await rows.nth(last).click();
  await page.locator(".pushed").getByRole("button", { name: "Open", exact: true }).waitFor();
  assert.equal(await page.locator(".pushed").getByRole("button", { name: "Save a copy" }).count(), 0, "Save a copy is only in the opened viewer");
  await targets(page, "Item"); await shot(page, "small-item");
  await page.locator(".pushed").getByRole("button", { name: "More", exact: true }).click();
  assert.deepEqual((await page.locator(".sheet .row .title").allInnerTexts()).map((t) => t.trim()), ["Rename", "Pin to the top", "Export sealed", "Delete"], "the overflow menu (no decoy entry while duress is off)");
  await page.locator(".sheet .row", { hasText: "Pin to the top" }).click();
  await page.locator(".rows .item[data-pinned]").first().waitFor({ timeout: 10_000 });
  // Delete goes straight to the inline question; Keep it steps back
  await page.locator(".pushed").getByRole("button", { name: "More", exact: true }).click();
  await page.locator(".sheet .row", { hasText: "Delete" }).click();
  await page.getByText(`Delete ${lastName}?`).waitFor();
  assert.equal(await back(), "pushed", "back from the delete question keeps the item");
  await page.locator(".pushed").getByRole("button", { name: "Open", exact: true }).waitFor();
  assert.equal(await back(), "pushed", "back leaves the item");
  await page.locator(".pushed").waitFor({ state: "detached" });
  assert.equal((await rows.first().locator(".name").innerText()).trim(), lastName, "a pinned item goes to the top");
  await shot(page, "small-vault-pinned-day");
  step("a pinned item moves to the top of the vault");

  // APP-08: Back with the viewer's "Save an unsealed copy?" open closes that question, not the
  // viewer; and the question never carries over to the next document opened
  const openDoc = async (i) => {
    await rows.nth(i).click();
    await page.locator(".pushed").getByRole("button", { name: "Open", exact: true }).click();
    await hold(page);
    await page.locator(".viewer").waitFor();
  };
  const saveAsk = page.getByText("Save an unsealed copy?");
  await openDoc(1);
  await page.locator(".viewer header").getByRole("button", { name: "Save a copy" }).click();
  await saveAsk.waitFor();
  assert.equal(await back(), "sheet", "back closes the question first");
  await saveAsk.waitFor({ state: "detached" });
  assert.equal(await page.locator(".viewer").count(), 1, "the viewer is still open");
  // APP-12: the viewer is a modal layer: focus is inside it, the vault behind it is inert, and the
  // question it opens takes focus and gives it back
  const where = () => page.evaluate(() => ({ viewer: !!document.activeElement?.closest(".viewer"), sheet: !!document.activeElement?.closest(".sheet"), name: document.activeElement?.getAttribute("aria-label") || document.activeElement?.innerText?.trim() }));
  assert.ok((await where()).viewer, "focus is in the viewer");
  assert.equal(await page.evaluate(() => [...document.querySelectorAll(".tabbar, .pushed")].every((e) => e.closest("[inert]"))), true, "the tab bar and the item behind the viewer are inert");
  await page.locator(".viewer header").getByRole("button", { name: "Save a copy" }).focus();
  await page.keyboard.press("Enter");
  await saveAsk.waitFor();
  const inSheet = await where();
  assert.ok(inSheet.sheet, `the question takes focus (${inSheet.name})`);
  for (let i = 0; i < 6; i++) { await page.keyboard.press(i % 2 ? "Shift+Tab" : "Tab"); await page.keyboard.press("Tab"); assert.ok((await where()).sheet, "Tab and Shift+Tab stay inside the question"); }
  // closed from the keyboard (Escape works too, but misses about 1 time in 20 here, on the base as well)
  await page.locator(".sheet").getByRole("button", { name: "Cancel" }).focus();
  await page.keyboard.press("Enter");
  await saveAsk.waitFor({ state: "detached" });
  assert.equal((await where()).name, "Save a copy", "closing it gives focus back to what opened it");
  await page.locator(".viewer header").getByRole("button", { name: "Save a copy" }).click();
  await saveAsk.waitFor();
  assert.equal(await back(), "sheet");
  assert.equal(await back(), ".viewer", "then back closes the viewer");
  await page.locator(".viewer").waitFor({ state: "detached" });
  await backOut(page);
  await page.locator(".pushed").waitFor({ state: "detached" });
  await openDoc(0);
  await page.waitForTimeout(300);
  assert.equal(await saveAsk.count(), 0, "the next document opens without a stale question");
  await page.locator(".viewer [data-back]").first().click();
  await page.locator(".viewer").waitFor({ state: "detached" });
  await backOut(page);
  await page.locator(".pushed").waitFor({ state: "detached" });
  step("viewer: back closes its Save question first; the question never carries to the next document; focus stays in the top layer and comes back (APP-12)");

  // PC-17: HumID hidden while a check is running (here the demo hold, before the prompt)
  // locks at once; the document never opens behind the scenes, and isn't showing on return
  const setHidden = (h) => page.evaluate((hid) => {
    Object.defineProperty(document, "hidden", { configurable: true, get: () => hid });
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => (hid ? "hidden" : "visible") });
    document.dispatchEvent(new Event("visibilitychange"));
  }, h);
  await rows.first().click();
  await page.locator(".pushed").getByRole("button", { name: "Open", exact: true }).click();
  await page.locator(".interrupt button.hold").waitFor();
  await setHidden(true);
  await page.waitForTimeout(300);
  if (await page.locator(".interrupt button.hold").count()) { // finish the check while hidden, if it's still asking
    await page.locator(".interrupt button.hold").focus(); await page.keyboard.down(" "); await page.waitForTimeout(1500); await page.keyboard.up(" ");
  }
  await page.waitForTimeout(2500);
  await setHidden(false);
  await page.waitForTimeout(800);
  assert.equal(await page.locator(".viewer").count(), 0, "no document showing after HumID came back");
  assert.equal(await page.locator(".tabbar").count(), 0, "the vault is locked");
  await page.getByRole("button", { name: "Unlock", exact: true }).waitFor();
  step("PC-17: hidden mid-check locks at once; the document never opens");

  // APP-06: the duress unlock for keyboards and screen readers is named for what it does,
  // drawn when focused, and behind a disclosure, off the straight Tab path
  await page.evaluate(() => document.activeElement?.blur());
  const focused = () => page.evaluate(() => { const a = document.activeElement, r = a.getBoundingClientRect(); return { name: (a.innerText || a.getAttribute("aria-label") || "").trim(), w: r.width, h: r.height }; });
  const order = [];
  for (let i = 0; i < 4; i++) { await page.keyboard.press("Tab"); order.push(await focused()); }
  assert.ok(!order.some((f) => /duress|safe mode/i.test(f.name)), `no duress unlock on the straight Tab path: ${order.map((f) => f.name).join(" › ")}`);
  const more = order.find((f) => f.name === "More ways to unlock");
  assert.ok(more, "the disclosure is reachable");
  assert.ok(more.w > 40 && more.h >= 40, `and drawn while focused (${Math.round(more.w)}×${Math.round(more.h)})`);
  while ((await focused()).name !== "More ways to unlock") await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Enter");
  assert.equal((await focused()).name, "More ways to unlock", "opening it doesn't move focus onto the duress unlock");
  await page.keyboard.press("Tab");
  const d = await focused();
  assert.match(d.name, /^Unlock with your duress gesture \(shows only decoys, locks your vault\)$/);
  assert.ok(d.w > 40 && d.h >= 40, "drawn while focused");
  assert.equal(await page.getByText(/safe mode/i).count(), 0);
  assert.equal(await page.getByRole("heading", { level: 1, name: "HumID" }).count(), 1, "Lock's h1 is the wordmark");
  assert.equal(await page.locator("main").count(), 1, "Lock is one main landmark");
  step("Lock: the duress unlock is named, drawn when focused, behind More ways to unlock; an h1");

  await page.reload();
  await page.getByRole("button", { name: "Unlock", exact: true }).waitFor({ timeout: 15_000 });
  assert.equal(await html("theme"), "light", "the theme is there before unlocking");
  await page.getByText(/password/).first().waitFor();
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await hold(page);
  await page.getByRole("heading", { name: "Vault", level: 1 }).waitFor({ timeout: 15_000 });
  assert.equal(await page.locator(".tabbar [aria-current=page]").innerText(), "Vault", "always opens on the vault");
  await page.locator(".rows .item[data-pinned]").first().waitFor({ timeout: 10_000 });
  step("after a restart: same look, opens on the Vault, the pin came back from the vault");
  await youScreen(page, "Settings");
  await page.locator('[data-pref="theme:dark"]').click();
  await page.locator('[data-pref="text:standard"]').click();
  await backOut(page);

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
  assert.equal(await p2.page.locator(".stepper").getAttribute("aria-valuemax"), "5", "access, mode, bind, recovery card, in");
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
