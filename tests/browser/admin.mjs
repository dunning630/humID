// Managing the server, in a real browser: the admin console (on a simulated Windows)
// and the HumID app side by side, as an administrator would use them.
//   1. the console's one-time sign-in link; read-only until a phone is added
//   2. Add a phone: the console shows a code and QR; the app (You › About › Manage this
//      server) looks it up, approves with a live check, and shows an admin match code; the
//      console shows the same one; They match
//   3. the app's About screen now shows This server
//   4. Restart on the console: a code; the app approves exactly that; the console runs it
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/admin.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { confirmCard, youScreen, backOut } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5199);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const step = (s) => console.log(`· ${s}`);
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };

const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), HUMID_DEV_ADMIN: "1", HUMID_REGISTRATION: "open" }, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
dev.stdout.on("data", (d) => { log += d; });
dev.stderr.on("data", (d) => { log += d; });
const stop = () => new Promise((r) => { dev.once("exit", r); dev.kill(); });

const browser = await chromium.launch();
try {
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${log}`)), 120_000);
    const check = setInterval(() => { if (/admin console: http/.test(log)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
    dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${log}`)); });
  });
  const link = /admin console: (http:\/\/127\.0\.0\.1:\d+\/#login=[A-Za-z0-9_-]+)/.exec(log)[1];

  /* ---- the console ---- */
  const desk = await (await browser.newContext({ viewport: { width: 1280, height: 860 }, colorScheme: "dark" })).newPage();
  desk.on("pageerror", (e) => { throw new Error(`console page error: ${e.message}`); });
  await desk.goto(link);
  await desk.locator(".verdict").waitFor();
  assert.ok(await desk.getByText("No administrator phone yet").first().isVisible());
  assert.ok(await desk.locator('button[data-req="restart-server"]').isDisabled(), "changes are off until a phone is added");
  step("console: signed in with the one-time link; read-only without an administrator phone");

  /* ---- the app: a new HumID in demo mode ---- */
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const app = await ctx.newPage();
  app.on("pageerror", (e) => { throw new Error(`app page error: ${e.message}`); });
  const hold = async () => {
    const b = app.locator(".interrupt .hold");
    await b.waitFor({ timeout: 20_000 });
    await b.focus(); await app.keyboard.down(" "); await app.waitForTimeout(1500); await app.keyboard.up(" ");
    await app.locator(".interrupt").waitFor({ state: "detached", timeout: 20_000 });
  };
  await app.goto(BASE);
  await app.getByRole("button", { name: "Create my HumID" }).click();
  await app.getByRole("button", { name: "Trust this server" }).click();
  await app.getByRole("button", { name: "Next: lock it to you" }).click({ timeout: 30_000 }); // recommended mode
  await app.getByText("Your body becomes the key").waitFor({ timeout: 30_000 });
  await app.getByRole("checkbox").first().click();
  await app.getByRole("button", { name: /Use demo mode/ }).click();
  await hold();
  await app.getByText("Your recovery card").first().waitFor({ timeout: 30_000 });
  await confirmCard(app);
  await app.getByRole("button", { name: "I've written it down" }).click();
  await app.getByRole("button", { name: "Open my vault" }).click();
  await app.getByRole("button", { name: "Add to your vault" }).first().waitFor({ timeout: 15_000 });
  await youScreen(app, "About");
  step("app: a new HumID, on About");

  /* ---- enrol ---- */
  await desk.getByRole("button", { name: "Add a phone" }).click();
  const code = (await desk.locator(".seal .code").innerText()).trim();
  const check = (await desk.locator(".seal .check b").innerText()).trim();
  assert.match(code, /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  assert.ok(await desk.locator(".seal .qr svg").isVisible(), "a QR code to scan");
  await shot(desk, "console-enrol-code");

  await app.locator(".pushed").getByText("Manage this server").click(); // a disclosure under About (3.0)
  await app.getByRole("button", { name: "Enter a console code" }).click();
  await app.fill("#admin-code", code);
  await app.getByRole("button", { name: "Look it up" }).click();
  await app.getByText("Become an administrator of this server?").waitFor();
  assert.ok(await app.getByText(`Match code ${check}`).isVisible(), "the app shows the same short match code as the console");
  await shot(app, "app-enrol-request");
  await app.getByRole("button", { name: "Become an administrator" }).click();
  await hold();
  await app.getByText("Compare this with the console").waitFor({ timeout: 20_000 });
  const appCheck = (await app.locator("[aria-label='Admin match code'] .code").first().innerText()).replace(/[^0-9A-Z]/g, "");
  await shot(app, "app-admin-check");

  await desk.getByText("Compare the admin check").waitFor({ timeout: 10_000 });
  const deskCheck = (await desk.locator(".compare").innerText()).replace(/[^0-9A-Z]/g, "");
  assert.ok(appCheck.includes(deskCheck), `the console's check ${deskCheck} matches the app's ${appCheck}`);
  await shot(desk, "console-compare");
  await desk.getByRole("button", { name: /They match/ }).click();
  await desk.getByText("Administrator added").waitFor();
  await desk.getByRole("button", { name: "OK" }).click();
  step(`enrolled: the app's admin check and the console's agree (${deskCheck})`);

  /* ---- the app now shows the server ---- */
  await app.locator(".sheet").getByRole("button", { name: "Done" }).click();
  await backOut(app);
  await app.locator(".tabbar button", { hasText: "Vault" }).click();
  await youScreen(app, "About");
  await app.getByRole("heading", { name: "This server" }).waitFor({ timeout: 10_000 });
  await app.getByRole("heading", { name: "This server" }).scrollIntoViewIfNeeded();
  await shot(app, "app-this-server");
  step("app: This server appears under About for its administrator");

  /* ---- a change ---- */
  await desk.locator('button[data-req="restart-server"]').click();
  const code2 = (await desk.locator(".seal .code").innerText()).trim();
  await shot(desk, "console-approve-code");
  await app.getByRole("button", { name: "Approve a change" }).click();
  await app.fill("#admin-code", code2);
  await app.getByRole("button", { name: "Look it up" }).click();
  await app.getByRole("heading", { name: "Restart the HumID server" }).waitFor();
  await app.getByRole("button", { name: "Approve this change" }).click();
  await hold();
  await app.getByText("Approved").first().waitFor({ timeout: 20_000 });
  await desk.getByText("Done.").waitFor({ timeout: 15_000 });
  await shot(desk, "console-done");
  step("restart: approved on the phone, checked and run by the console");
  console.log("ADMIN BROWSER OK");
} finally {
  await browser.close();
  await stop();
}
