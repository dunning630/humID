// Person to person (4.0), in a real browser: two phones meet and talk, and nothing happens
// without a live check. Checks, on a common phone (390×844):
//   - Messages appears as a tab only because the server runs a relay
//   - invite → ask to connect → see who's asking → approve → chat, each step one check
//   - a message arrives marked live; the reader sees content only while their check is fresh
//   - when the check lapses, the thread seals itself and one check opens it again
//   - every control is at least 44 px; nothing on these screens throws
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/messages.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { hold, enroll, tab } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5199);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const step = (s) => console.log(`· ${s}`);
let n = 0;
const shot = async (page, name) => { await page.waitForTimeout(450); if (SHOTS) await page.screenshot({ path: join(SHOTS, `${String(++n).padStart(2, "0")}-${name}.png`), fullPage: false }); };

const data = mkdtempSync(join(tmpdir(), "humid-msg-"));
const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), HUMID_DEV_DATA: data }, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
dev.stdout.on("data", (d) => { log += d; });
dev.stderr.on("data", (d) => { log += d; });
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${log}`)), 180_000);
  const c = setInterval(() => { if (/HumID dev:/.test(log)) { clearTimeout(t); clearInterval(c); resolve(); } }, 200);
  dev.on("exit", (code) => { clearTimeout(t); clearInterval(c); reject(new Error(`dev server exited ${code}:\n${log}`)); });
});

const browser = await chromium.launch();
const errors = [];
async function phone(name) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${name}: ${e.message}`));
  await page.clock.install();
  await page.goto(BASE);
  return page;
}

async function targets(page, where) {
  const small = await page.evaluate(() => [...document.querySelectorAll("button, a[href], input:not([type=checkbox]):not([type=file]), [role=button]")]
    .filter((el) => {
      const r = el.getBoundingClientRect(), s = getComputedStyle(el);
      if (!r.width || !r.height || s.visibility === "hidden" || el.closest("[aria-hidden=true]")) return false;
      if (el.matches(".link, .linklike, .bubble") || el.closest(".field, .search, .tabbar, .seg")) return false;
      return r.width < 43.5 || r.height < 43.5;
    })
    .map((el) => { const r = el.getBoundingClientRect(); return `${el.tagName.toLowerCase()}.${String(el.className).replace(/\s+/g, ".")} "${(el.innerText || el.getAttribute("aria-label") || "").trim().slice(0, 24)}" ${Math.round(r.width)}×${Math.round(r.height)}`; }));
  assert.deepEqual(small, [], `controls under 44 px on ${where}`);
}

try {
  const alice = await phone("alice");
  const bob = await phone("bob");
  step("both create a HumID");
  await enroll(alice);
  await enroll(bob);

  step("Messages is a tab, because this server runs a relay");
  await alice.locator(".tabbar button", { hasText: "Messages" }).waitFor({ timeout: 15_000 });
  await tab(alice, "Messages");
  await alice.getByRole("heading", { name: "Messages", level: 1 }).waitFor();
  await alice.getByText("Talk only with people you've approved").waitFor({ timeout: 20_000 });
  await shot(alice, "alice-empty");
  await targets(alice, "Messages (empty)");

  step("Alice makes an invite: one check");
  await alice.getByRole("button", { name: "Invite someone" }).click();
  await alice.fill("#inv-label", "Bob");
  await shot(alice, "alice-invite-form");
  await alice.getByRole("button", { name: "Make an invite" }).click();
  await hold(alice);
  await alice.locator(".invite-code").waitFor({ timeout: 30_000 });
  const code = "HI-" + (await alice.locator(".invite-code span").allInnerTexts()).join("-");
  assert.match(code, /^HI-([0-9A-Z]{4}-){10}[0-9A-Z]{4}$/);
  await shot(alice, "alice-invite-made");
  await alice.getByRole("button", { name: "Done" }).click();

  step("Bob types the code, names her, asks to connect: one check");
  await tab(bob, "Messages");
  await bob.getByText("Talk only with people you've approved").waitFor({ timeout: 20_000 });
  await bob.getByRole("button", { name: "I have an invite code" }).click();
  await bob.fill("#inv-code", code.toLowerCase());
  await shot(bob, "bob-enter-code");
  await bob.getByRole("button", { name: "Find invite" }).click();
  await bob.getByText("Invite found").waitFor({ timeout: 20_000 });
  await bob.fill("#ct-label", "Alice");
  await bob.fill("#ct-intro", "Bob, from the workshop");
  await shot(bob, "bob-found");
  await bob.getByRole("button", { name: "Ask to connect" }).click();
  await hold(bob);
  await bob.getByText("Asked Alice to connect").waitFor({ timeout: 30_000 });
  await shot(bob, "bob-sent");
  await bob.getByRole("button", { name: "Done" }).click();
  await bob.getByText("Waiting for them to approve you").first().waitFor();

  step("Alice sees the request, opens it with a check, approves with another");
  await alice.getByText("Someone asked to connect").waitFor({ timeout: 40_000 });
  await shot(alice, "alice-request-listed");
  await alice.getByText("Someone asked to connect").click();
  await alice.getByRole("button", { name: "See who's asking" }).click();
  await hold(alice);
  await alice.getByText("Made with a live check").waitFor({ timeout: 30_000 });
  await alice.getByText("Bob, from the workshop").waitFor();
  await shot(alice, "alice-request-shown");
  await alice.getByRole("button", { name: "Approve" }).click();
  await hold(alice);
  await alice.locator(".composer textarea").waitFor({ timeout: 30_000 });
  await shot(alice, "alice-chat-new");
  assert.equal(await alice.locator(".live-state").getAttribute("data-live"), "true", "Bob's stamped request proves him live");

  step("Bob is connected once the acceptance arrives (stamped)");
  await bob.locator(".row", { hasText: "Alice" }).click();
  await bob.locator(".composer textarea").waitFor({ timeout: 40_000 });
  await bob.getByText("They approved you with a live check").waitFor({ timeout: 10_000 });
  await shot(bob, "bob-chat-connected");
  const st = await bob.locator(".live-state").evaluate((el) => ({ ...el.dataset, now: Date.now() }));
  console.log("  bob live state after the acceptance:", JSON.stringify(st));
  assert.equal(st.live, "true", "the stamped acceptance proves Alice live, and Bob's own ask proved him");

  step("Bob sends: one check; Alice receives it marked live");
  await bob.fill(".composer textarea", "Hi Alice, it's really me.");
  await bob.getByRole("button", { name: "Send with a live check" }).click();
  await hold(bob);
  await bob.locator(".bubble.out", { hasText: "it's really me" }).waitFor({ timeout: 30_000 });
  await shot(bob, "bob-sent-message");
  await alice.locator(".bubble.in", { hasText: "it's really me" }).waitFor({ timeout: 40_000 });
  assert.ok(await alice.locator(".bubble.in .lv").count() >= 1, "marked live");
  await shot(alice, "alice-received");
  await targets(alice, "a conversation");

  step("the reader's check lapses: the thread seals itself; one check opens it");
  // Six minutes of reading without a check (activity keeps the idle lock away meanwhile).
  for (let i = 0; i < 4; i++) { await alice.clock.fastForward("01:30"); await alice.keyboard.press("Shift"); }
  await alice.getByText("Sealed until you verify").waitFor({ timeout: 10_000 });
  assert.equal(await alice.locator(".bubble").count(), 0, "no content on screen once the check lapsed");
  await shot(alice, "alice-lapsed");
  await alice.getByRole("button", { name: "Verify it's you" }).click();
  await hold(alice);
  await alice.locator(".bubble.in", { hasText: "it's really me" }).waitFor({ timeout: 20_000 });
  await shot(alice, "alice-reopened");

  step("details: safety code, timer, duress alerts, delete");
  await alice.getByRole("button", { name: "Details" }).click();
  await alice.getByText("Safety code").first().waitFor();
  await shot(alice, "alice-details");

  assert.deepEqual(errors, [], "no page errors");
  console.log("\nmessages: all checks passed");
} finally {
  await browser.close();
  dev.kill();
  rmSync(data, { recursive: true, force: true });
}
