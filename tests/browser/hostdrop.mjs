// The vault's computer loses its connection while the phone keeps its own (a laptop on Wi-Fi behind
// Tailscale Funnel), then gets it back. A relay sits between the browser and the server, as Funnel's
// ingress does: while the server's side is gone it accepts connections and holds them silent, and the
// connections it held stay dead after the server is back (only new ones get through). Checks that the
// app notices, keeps trying, and is back in the same session by itself once the server is reachable.
//
//   node tests/browser/hostdrop.mjs            (SHOTS=dir to keep screenshots; H2=0 for plain HTTP/1.1)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import http2 from "node:http2";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { enroll, addFile, hold } from "./_v3.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.env.PORT || 5195), RELAY = PORT + 1000, FRONT = PORT + 2000;
// Like Funnel: TLS and HTTP/2 end at the server's computer (tailscaled), behind the relay. H2=0: plain
// HTTP/1.1 (slower to recover: each dead pooled socket has to time out on its own, about 2 minutes)
const H2 = process.env.H2 !== "0";
const BASE = `${H2 ? "https" : "http"}://localhost:${RELAY}`;
const UPSTREAM = H2 ? FRONT : PORT;
const SHOTS = process.env.SHOTS || "";
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const step = (s) => console.log(`· ${s}`);
setTimeout(() => { console.error("Error: hostdrop timed out"); process.exit(1); }, 8 * 60_000).unref();

/* the relay: pass | hold (the server's side is gone: accept, forward nothing, keep the sockets open) */
let mode = "pass";
const held = new Set();
const relay = net.createServer((c) => {
  if (mode === "hold") { held.add(c); c.on("error", () => {}); c.on("close", () => held.delete(c)); return; }
  const s = net.connect(UPSTREAM, "127.0.0.1");
  const pair = { c, s, dead: false };
  c.on("data", (d) => { if (!pair.dead) s.write(d); });
  s.on("data", (d) => { if (!pair.dead) c.write(d); });
  c.on("error", () => {}); s.on("error", () => {});
  c.on("close", () => { s.destroy(); conns.delete(pair); });
  s.on("close", () => { if (!pair.dead) c.destroy(); conns.delete(pair); });
  conns.add(pair);
});
const conns = new Set();
const drop = () => { mode = "hold"; for (const p of conns) { p.dead = true; p.s.destroy(); } }; // the server's side goes; the browser's sockets stay open, silent
const back = () => { mode = "pass"; }; // new connections get through; the held ones stay dead
await new Promise((r) => relay.listen(RELAY, "127.0.0.1", r));
if (H2) {
  const d = mkdtempSync(join(tmpdir(), "humid-hostdrop-tls-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(d, "k.pem"), "-out", join(d, "c.pem"), "-days", "2", "-subj", "/CN=localhost"], { stdio: "ignore" });
  const front = http2.createSecureServer({ key: readFileSync(join(d, "k.pem")), cert: readFileSync(join(d, "c.pem")), allowHTTP1: true }, async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const h = {}; for (const [k, v] of Object.entries(req.headers)) if (typeof k === "string" && !k.startsWith(":") && !["host", "connection", "te", "keep-alive", "transfer-encoding", "upgrade"].includes(k)) h[k] = String(v);
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}${req.url}`, { method: req.method, headers: h, body: chunks.length ? Buffer.concat(chunks) : undefined, redirect: "manual" });
      const out = {}; r.headers.forEach((v, k) => { if (!["connection", "transfer-encoding", "keep-alive", "content-encoding", "content-length"].includes(k)) out[k] = v; });
      res.writeHead(r.status, out); res.end(Buffer.from(await r.arrayBuffer()));
    } catch (e) { if (!globalThis.__frontErr) { globalThis.__frontErr = 1; console.error("front:", e.cause?.message || e.message); } res.writeHead(502); res.end(); }
  });
  await new Promise((r) => front.listen(FRONT, "127.0.0.1", r));
}

const data = mkdtempSync(join(tmpdir(), "humid-hostdrop-"));
const dev = spawn(process.execPath, [join(root, "tools/dev.mjs")], { cwd: root, env: { ...process.env, PORT: String(PORT), HUMID_DEV_DATA: data }, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
dev.stdout.on("data", (d) => { log += d; }); dev.stderr.on("data", (d) => { log += d; });
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`dev server didn't start:\n${log}`)), 120_000);
  const check = setInterval(() => { if (/HumID dev:/.test(log)) { clearTimeout(t); clearInterval(check); resolve(); } }, 200);
});
step("dev server up, behind the relay");

const profile = mkdtempSync(join(tmpdir(), "humid-hostdrop-p-"));
const ctx = await chromium.launchPersistentContext(profile, { headless: true, viewport: { width: 412, height: 915 }, ignoreHTTPSErrors: true });
const page = ctx.pages()[0] || await ctx.newPage();
page.on("pageerror", (e) => console.error("page error:", e.message));
page.on("console", (m) => { if (m.type() === "error") console.error("console:", m.text().slice(0, 200)); });
try {
  await page.goto(BASE);
  await enroll(page);
  await addFile(page, { name: "Lease.txt", mimeType: "text/plain", buffer: Buffer.from("Lease: kept for the test.\n") });
  await page.locator(".pushed").getByText("Review, then seal").waitFor();
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  await hold(page);
  await page.locator(".item", { hasText: "Lease" }).waitFor({ timeout: 30_000 });
  step("enrolled, one document sealed");

  const bar = page.locator(".linkbar");
  drop();
  await page.locator(".tabbar button", { hasText: "Activity" }).click(); // anything that asks the server notices
  await bar.getByText(/Can't reach your vault/).waitFor({ timeout: 70_000 });
  if (SHOTS) await page.screenshot({ path: join(SHOTS, "hostdrop-down.png") });
  step(`the server's computer drops off: the app says it can't reach the vault (${held.size} connections held silent)`);
  await page.waitForTimeout(20_000);
  back();
  const t0 = Date.now();
  await bar.waitFor({ state: "detached", timeout: 120_000 }).catch(async (e) => {
    if (SHOTS) await page.screenshot({ path: join(SHOTS, "hostdrop-stuck.png") });
    throw new Error(`still not reconnected 120 s after the server came back: "${await bar.innerText().catch(() => "")}"`, { cause: e });
  });
  const took = Math.round((Date.now() - t0) / 1000);
  if (H2) assert.ok(took <= 60, `took ${took} s to reconnect over HTTP/2`);
  step(`back by itself ${took} s after the server's computer reconnected${H2 ? " (HTTP/2 over TLS, as through Funnel)" : ""}`);
  await page.locator(".tabbar button", { hasText: "Vault" }).click();
  await page.locator(".item", { hasText: "Lease" }).click();
  await page.locator(".pushed").getByRole("button", { name: "Open", exact: true }).click();
  await hold(page);
  await page.getByText(/Lease: kept for the test/).waitFor({ timeout: 30_000 });
  step("and the document opens: the same session carried on");
  console.log("ok — the app reconnects by itself after the server's computer loses and regains its connection");
} catch (e) {
  console.error(e);
  console.error("screen:", (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ").slice(0, 300));
  if (SHOTS) await page.screenshot({ path: join(SHOTS, "hostdrop-failed.png") }).catch(() => {});
  console.error(log.split("\n").slice(-15).join("\n"));
  process.exitCode = 1;
} finally {
  await ctx.close().catch(() => {});
  dev.kill(); relay.close(); for (const c of held) c.destroy(); for (const p of conns) { p.c.destroy(); p.s.destroy(); }
  rmSync(profile, { recursive: true, force: true }); rmSync(data, { recursive: true, force: true });
  process.exit(process.exitCode ?? 0);
}
