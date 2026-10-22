// The phone's document scanner (Android ML Kit, apps 2.1.1) is no longer used to add anything
// (3.0.1): its screen draws a four-point outline around whatever it finds and isn't covered by
// HumID's screenshot protection, and the person now says what they're adding first, so each kind
// gets HumID's own camera with the outline made for it. The development build runs in Chromium
// with a stand-in for the scanner (globalThis.__humidFakeScanner, development builds only), as
// on an Android phone that has it. Checks that:
//   - every kind in "What are you adding?" opens HumID's own camera, never the scanner
//   - the outline made for that kind is the one shown (a template, not a free-form outline)
//
//   npm i --no-save playwright@1.56.0 && npx playwright install chromium
//   node tests/browser/docscan.mjs            (SHOTS=dir to keep screenshots)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { enroll, openAdd as openAddFlow, pickKind as pick } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixture = (n) => join(root, "tests/fixtures/id", n);
const PORT = Number(process.env.PORT || 5199);
const BASE = `http://tauri.localhost:${PORT}`;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "humid-docscan-"));
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: docscan timed out after 8 minutes"); process.exit(1); }, 8 * 60_000).unref();
const contexts = [];

const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "pipe", "pipe"] });
let devLog = "";
dev.stdout.on("data", (d) => { devLog += d; });
dev.stderr.on("data", (d) => { devLog += d; });
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${devLog}`)), 120_000);
  const check = setInterval(() => { if (/HumID dev:/.test(devLog)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
  dev.on("exit", (c) => { clearTimeout(t); clearInterval(check); reject(new Error(`dev server exited ${c}:\n${devLog}`)); });
});
step("dev server up");

// The stand-in scanner: each scan takes the next answer from a queue the test fills. While a
// scan is "on screen" HumID is hidden, as when the real scanner's activity covers it.
const STANDIN = () => {
  globalThis.__scanQueue = [];
  globalThis.__scans = 0;
  const hide = (on) => {
    Object.defineProperty(document, "hidden", { get: () => on, configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
  };
  globalThis.__humidFakeScanner = {
    async invoke(cmd, args) {
      if (cmd !== "scan") return { available: true };
      globalThis.__scans++;
      globalThis.__lastArgs = args;
      hide(true);
      await new Promise((r) => setTimeout(r, 400));
      for (let i = 0; i < 100 && !globalThis.__scanQueue.length; i++) await new Promise((r) => setTimeout(r, 100));
      const next = globalThis.__scanQueue.shift();
      if (next?.holdMs) await new Promise((r) => setTimeout(r, next.holdMs)); // the person left HumID from the scanner
      hide(false);
      if (!next) throw "cancelled";
      if (next.reject) throw next.reject;
      return { data: next.data, mime: "image/jpeg", width: next.width || 0, height: next.height || 0 };
    },
  };
};

async function launch() {
  const ctx = await chromium.launchPersistentContext(profile, {
    headless: true,
    viewport: { width: 412, height: 915 },
    deviceScaleFactor: 2,
    permissions: ["camera"],
    args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", `--use-file-for-fake-video-capture=${fixture("camera-empty.mjpeg")}`,
      "--host-resolver-rules=MAP tauri.localhost 127.0.0.1", `--unsafely-treat-insecure-origin-as-secure=${BASE}`],
  });
  contexts.push(ctx);
  await ctx.addInitScript(STANDIN);
  // count camera streams: the scanner path must never open the live camera
  await ctx.addInitScript(() => {
    globalThis.__streams = 0;
    const real = navigator.mediaDevices?.getUserMedia?.bind(navigator.mediaDevices);
    if (real) navigator.mediaDevices.getUserMedia = (c) => { globalThis.__streams++; return real(c); };
  });
  const page = ctx.pages()[0] || await ctx.newPage();
  page.on("pageerror", (e) => console.error("page error:", e.message));
  page.on("console", (m) => { if (m.type() === "error") console.error("console:", m.text()); });
  return { ctx, page };
}
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) }); };
const queue = (page, ...items) => page.evaluate((xs) => { globalThis.__scanQueue.push(...xs); }, items);

try {
  const { page } = await launch();
  await page.goto(BASE);
  await enroll(page);
  step("enrolled (demo)");
  const scans = () => page.evaluate(() => globalThis.__scans);
  const streams = () => page.evaluate(() => globalThis.__streams);

  const kinds = [["passport", "td3"], ["driver_license", "id1"], ["id_card", "id1"], ["residence_permit", "id1"], ["other", "id1"], ["card", "id1"], ["page", "page"], ["photo", "full"]];
  await openAddFlow(page);
  for (const [key, shape] of kinds) {
    const s0 = await streams();
    await pick(page, key);
    await page.locator(`.doccam:not([data-scanner])[data-shape="${shape}"] .dc-shutter:not([disabled])`).waitFor({ timeout: 20_000 });
    if (shape !== "full") assert.equal(await page.locator(".doccam[data-guided]").count(), 1, `${key}: the outline made for it`);
    assert.equal(await streams(), s0 + 1, `${key}: HumID's own camera opened`);
    await shot(page, `kind-${key}`);
    await page.getByRole("button", { name: "Close the camera" }).click();
    await page.locator(".doccam").waitFor({ state: "detached" });
    await page.locator(".pushed").getByText("What are you adding?").waitFor({ timeout: 10_000 });
  }
  assert.equal(await scans(), 0, "the phone's scanner was never opened");
  step(`every kind (${kinds.map(([k]) => k).join(", ")}) opens HumID's own camera with its outline; the phone's scanner never opens`);

  console.log("ok — adding never opens the phone's document scanner: every kind gets HumID's camera");
} catch (e) {
  console.error(e);
  console.error(devLog.split("\n").slice(-20).join("\n"));
  // where it stopped: the last page's screen and words, for whoever reads the failure
  const last = contexts.at(-1)?.pages().at(-1);
  if (last) {
    if (SHOTS) await last.screenshot({ path: join(SHOTS, "failed.png") }).catch(() => {});
    console.error("screen at failure:", (await last.locator("#app").innerText().catch(() => "")).replace(/\s+/g, " ").slice(0, 400));
  }
  process.exitCode = 1;
} finally {
  for (const c of contexts) await c.close().catch(() => {});
  dev.kill("SIGTERM");
  rmSync(profile, { recursive: true, force: true });
  process.exit(process.exitCode ?? 0);
}
