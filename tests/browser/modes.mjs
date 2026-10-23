// Recovery modes in a real browser (docs/RECOVERY.md#two-recovery-modes):
//   - the default setup (tests/browser/_v3.mjs enroll) still works: hardened is preselected,
//     the card is shown and confirmed
//   - holder-only: needs "I understand", makes no card, asks for a second device at once
//   - the Recovery screen then shows the mode and no card/witness/ID/key rows, and Protection
//     asks for devices only, with a warning while there's one
//   - the ID chip screen (hardened) says plainly that the vault server can open the passport piece
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/modes.mjs
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { enroll, hold, youScreen } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5276), BASE = `http://localhost:${PORT}`;
const step = (s) => console.log(`· ${s}`);
const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
dev.stdout.on("data", (d) => { log += d; });
dev.stderr.on("data", (d) => { log += d; });
await new Promise((res, rej) => {
  const t = setInterval(() => { if (/HumID dev:/.test(log)) { clearInterval(t); res(); } }, 200);
  setTimeout(() => rej(new Error(`dev server didn't start:\n${log}`)), 120_000);
});
const browser = await chromium.launch();
const errors = [];
async function phone() {
  const ctx = await browser.newContext({ viewport: { width: 375, height: 667 }, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(BASE);
  return page;
}
try {
  const p1 = await phone();
  await enroll(p1);
  step("default setup (_v3 enroll): hardened preselected, card shown and confirmed");
  await youScreen(p1, "Recovery");
  await p1.getByText("A safe way back in").first().waitFor();
  await p1.locator(".pushed .row", { hasText: "ID chip" }).first().click();
  await p1.getByText("Your vault server can open this piece").waitFor();
  assert.match(await p1.getByText(/any ONE other of your proofs/).first().innerText(), /witnesses or a security key instead/);
  step("hardened: the ID chip screen says the server can open the passport piece, and what to use instead");

  const p = await phone();
  await p.getByRole("button", { name: "Create my HumID" }).click();
  await p.getByRole("button", { name: "Trust this server" }).click({ timeout: 20_000 });
  await p.getByRole("button", { name: "Use a demo access code" }).click({ timeout: 20_000 });
  await p.getByText("Access pass ready").first().waitFor({ timeout: 30_000 });
  await p.getByRole("button", { name: "Continue" }).click();
  await p.getByText("If you lose every device").waitFor();
  assert.equal(await p.locator('[data-mode="hardened"]').getAttribute("aria-checked"), "true", "recommended preselected");
  await p.locator('[data-mode="holder-only"]').click();
  await p.getByRole("button", { name: "Next: lock it to you" }).click();
  assert.equal(await p.getByText("Your body becomes the key").count(), 0, "can't go on without I understand");
  await p.getByRole("checkbox", { name: /I understand/ }).click();
  await p.getByRole("button", { name: "Next: lock it to you" }).click();
  await p.getByText("Your body becomes the key").waitFor();
  await p.getByRole("checkbox").first().click();
  await p.getByRole("button", { name: /Use demo mode/ }).click();
  await hold(p);
  await p.getByRole("heading", { name: "Add a second device" }).waitFor({ timeout: 30_000 });
  assert.equal(await p.getByText("Your recovery card").count(), 0, "no card in holder-only");
  step("holder-only: explicit I understand, no card, Add a second device next");
  await p.getByRole("button", { name: "Not now" }).click();
  await p.getByRole("button", { name: /I'll add it soon/ }).click();
  await p.getByRole("heading", { name: "You're in" }).waitFor();
  assert.match(await p.locator("main").first().innerText(), /a second device/);
  await p.getByRole("button", { name: "Open my vault" }).click();
  await p.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 15_000 });
  await youScreen(p, "Recovery");
  await p.getByText("Only my own devices").first().waitFor();
  // The mode card is filled by loadRecovery(): read the screen once it has said where it stands
  // (V74B-05: reading straight away raced the load on a busy machine).
  await p.locator(".pushed").getByText(/Your vault opens only on devices you've already set up/).waitFor({ timeout: 20_000 });
  const rtext = await p.locator(".pushed").innerText();
  assert.doesNotMatch(rtext, /Recovery card|Witnesses|Security key|ID chip/, "no recovery proofs to set up");
  assert.doesNotMatch(rtext, /doesn't check out/, "the server's record verifies");
  await p.locator(".pushed [data-back]").first().click();
  await youScreen(p, "Protection");
  // The checklist appears once recovery and devices have loaded (V74B-05).
  await p.locator(".pushed").getByText("A second device").first().waitFor({ timeout: 20_000 });
  await p.locator(".pushed").getByText("This is your only device").waitFor({ timeout: 20_000 });
  const ptext = await p.locator(".pushed").innerText();
  assert.match(ptext, /This is your only device/);
  assert.match(ptext, /A second device/);
  assert.doesNotMatch(ptext, /Recovery card/);
  step("holder-only: Recovery shows the mode and no proofs; Protection asks for devices and warns at one");
  assert.deepEqual(errors, [], "no page errors");
  console.log("ok — recovery mode checks pass");
} finally { await browser.close(); dev.kill(); }
