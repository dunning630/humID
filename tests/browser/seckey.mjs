// A security key as a recovery proof (4.0, docs/SECURITY-KEY.md), in a real browser, on a
// phone-sized screen, against the dev server's simulated key (PIN 123456):
//   - You → Recovery lists four proofs, and the security key opens its own sheet
//   - a wrong PIN is answered in the form, with the tries left; the overlay never hides it
//   - one tap and one check add the key; it shows with its name, mint, in the proof meter
//   - on a second "phone": Prove it's me → recovery card + security key → the wait → the
//     vault opens with the same document, and the first phone's Activity shows the key
//   - every button is at least 44 px, and nothing scrolls sideways
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/seckey.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { hold, cardGroups, confirmCard, youScreen, tab } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5203);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const step = (s) => console.log(`· ${s}`);
const DELAY = 3000; // the dev server's base recovery wait for this run

const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), RECOVERY_DELAY_MS: String(DELAY) }, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
dev.stdout.on("data", (d) => { log += d; });
dev.stderr.on("data", (d) => { log += d; });
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${log}`)), 120_000);
  const check = setInterval(() => { if (/HumID dev:/.test(log)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
  dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${log}`)); });
});

const browser = await chromium.launch();
const errors = [];
async function phone() {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(m.text()); });
  await page.goto(BASE);
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: false }); };
async function noSideScroll(page, where) {
  const w = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  assert.ok(w <= 0, `${where}: the page scrolls sideways by ${w}px`);
}
async function bigEnough(page, scope, where) {
  const small = await page.locator(`${scope} button:visible, ${scope} [role=switch]:visible`).evaluateAll((els) => els
    .map((e) => { const r = e.getBoundingClientRect(); return { t: (e.innerText || e.getAttribute("aria-label") || "").trim().slice(0, 40), w: r.width, h: r.height }; })
    .filter((b) => b.w > 0 && (b.w < 44 || b.h < 44) && !/^(Remove|Cancel)$/.test(b.t)));
  assert.deepEqual(small, [], `${where}: buttons under 44 px`);
}

try {
  /* ---------- phone A: create a HumID, keep its card, add a document ---------- */
  const A = await phone();
  let card;
  {
    const p = A.page;
    await p.getByRole("button", { name: "Create my HumID" }).click();
    await p.getByRole("button", { name: "Trust this server" }).click({ timeout: 20_000 });
    await p.getByRole("button", { name: "Use a demo access code" }).click({ timeout: 20_000 });
    await p.getByText("Access pass ready").first().waitFor({ timeout: 30_000 });
    await p.getByRole("button", { name: "Continue" }).click();
    await p.getByText("If you lose every device").waitFor();
    await p.getByRole("button", { name: "Next: lock it to you" }).click(); // the recommended recovery mode is already selected
    await p.getByText("Your body becomes the key").waitFor();
    await p.getByRole("checkbox").first().click();
    await p.getByRole("button", { name: /Use demo mode/ }).click();
    await hold(p);
    await p.getByText("Your recovery card").first().waitFor({ timeout: 30_000 });
    card = "HUMID-" + (await cardGroups(p)).join("-");
    await confirmCard(p);
    await p.getByRole("button", { name: "I've written it down" }).click();
    await p.getByRole("button", { name: "Open my vault" }).click();
    await p.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 15_000 });
    step(`phone A: HumID created (card ${card.slice(0, 12)}…)`);
  }

  /* ---------- phone A: You → Recovery → Security key ---------- */
  {
    const p = A.page;
    await youScreen(p, "Recovery");
    const meter = p.locator(".pushed .proofmeter span");
    await meter.first().waitFor({ timeout: 15_000 });
    assert.equal(await meter.count(), 4, "four proofs in the meter");
    assert.deepEqual(await meter.allInnerTexts(), ["Witnesses", "ID chip", "Recovery card", "Security key"]);
    await p.locator(".pushed").getByText("If you lose every device, any").waitFor();
    await p.getByRole("button", { name: /^Security key/ }).click();
    const sheet = p.locator(".sheet");
    await sheet.getByRole("heading", { name: "Add a security key" }).waitFor();
    await shot(p, "01-key-sheet");
    await noSideScroll(p, "security key sheet");
    await bigEnough(p, ".sheet", "security key sheet");
    const go = sheet.getByRole("button", { name: /Hold the key to the phone, then confirm/ });
    await go.click();
    await sheet.getByText("Type your key's PIN first.").waitFor();
    assert.equal(await p.evaluate(() => document.activeElement?.id), "key-pin", "a tap with no PIN points at the PIN");
    assert.equal(await p.locator(".interrupt").count(), 0, "and starts nothing");
    await sheet.locator("#key-name").fill("Blue key on my keyring");

    // A wrong PIN first: the form says so, with the tries left.
    await sheet.locator("#key-pin").fill("000000");
    await go.click();
    await sheet.getByText(/Wrong PIN\. 7 tries left/).waitFor({ timeout: 20_000 });
    assert.equal(await p.locator(".interrupt").count(), 0, "the overlay steps aside for the PIN");
    assert.equal(await sheet.locator("#key-pin").inputValue(), "", "a wrong PIN is cleared");
    await shot(p, "02-wrong-pin");
    step("phone A: a wrong PIN is answered in the form, 7 tries left");

    // The right PIN: one tap, then the live check.
    await sheet.locator("#key-pin").fill("123456");
    await go.click();
    await hold(p);
    await p.getByText("Security key added").first().waitFor({ timeout: 20_000 });
    await sheet.locator(".row", { hasText: "Blue key on my keyring" }).waitFor({ timeout: 15_000 });
    await sheet.getByRole("heading", { name: "Your security key" }).waitFor();
    await sheet.getByText("Add a second key and keep it somewhere else").waitFor();
    await shot(p, "03-key-added");
    await p.keyboard.press("Escape");
    assert.equal(await p.locator('.pushed .proofmeter span[data-on="1"]', { hasText: "Security key" }).count(), 1, "the key lights up in the meter");
    assert.equal(await p.locator('.pushed .proofmeter span[data-on="1"]').count(), 2, "card + key: two proofs");
    step("phone A: security key added; card + key = two proofs");
  }

  /* ---------- phone B: Prove it's me with the card and the key ---------- */
  const B = await phone();
  {
    const p = B.page;
    await p.getByRole("button", { name: "I already have HumID" }).click();
    await p.getByRole("button", { name: "Trust this server" }).click({ timeout: 20_000 }).catch(() => {});
    await p.getByRole("button", { name: /Prove it's me/ }).click({ timeout: 20_000 });
    await p.getByRole("heading", { name: "Any two of these four" }).waitFor();
    for (const t of ["Witnesses", "ID chip", "Recovery card", "Security key"]) await p.locator(".row", { hasText: t }).first().waitFor();
    await shot(p, "04-prelude");
    await p.getByRole("button", { name: "I have two of these" }).click();
    await p.locator("#qcard").fill(card);
    await p.getByText("Card code looks right").waitFor();
    await p.getByRole("checkbox").first().click();
    await p.getByRole("button", { name: /Use demo mode/ }).click();
    await hold(p);
    await p.getByRole("heading", { name: "One proof in. Add a second" }).waitFor({ timeout: 20_000 });
    await p.getByRole("button", { name: /^Security key/ }).click();
    await p.locator("#join-key-pin").fill("123456");
    await shot(p, "05-recover-key");
    await noSideScroll(p, "recovery wait");
    await p.getByRole("button", { name: /Hold the key to the phone, then confirm/ }).click();
    await hold(p);
    await p.getByRole("heading", { name: /Your vault opens here in/ }).waitFor({ timeout: 20_000 });
    await p.getByText(/seal card \+ security key/).waitFor();
    await shot(p, "06-waiting");
    step("phone B: card + security key accepted; waiting (7/3 × base)");
  }

  /* ---------- phone A sees it; phone B gets in after the wait ---------- */
  {
    const p = A.page;
    await p.reload();
    await p.getByRole("button", { name: "Unlock", exact: true }).click();
    await hold(p);
    await tab(p, "You");
    await p.getByText(/Proofs so far: seal card \+ security key/).waitFor({ timeout: 20_000 });
    step("phone A: the recovery in progress names both proofs, with a cancel");
  }
  {
    const p = B.page;
    await p.locator(".interrupt button.hold").waitFor({ timeout: (DELAY * 7) / 3 + 60_000 });
    await hold(p);
    await p.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 30_000 });
    await shot(p, "07-recovered");
    step("phone B: recovered with the recovery card and the security key");
  }
  {
    const p = A.page;
    await tab(p, "Activity");
    await p.getByText("Security key added").first().waitFor({ timeout: 20_000 });
    await p.getByText(/Recovery proof added · security key/).first().waitFor({ timeout: 20_000 });
    await shot(p, "08-activity");
    step("phone A: Activity shows the key being added and used");
  }
  assert.deepEqual(errors, [], "no page errors");
  console.log("seckey: all checks passed");
} finally {
  await browser.close();
  dev.kill();
}
