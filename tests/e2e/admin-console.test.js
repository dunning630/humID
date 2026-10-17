// End to end: the HumID server for Windows (all services + edge in one process) with
// the admin console beside it, and a HumID app (the API client with real keys) as the
// administrator's phone. Checks that the console only acts on approvals it can verify
// itself, whatever the server hands it.
import { test, after, before } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import net from "node:net";
import http from "node:http";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, toHex, sha3_256, random, b64u } from "@humid/htp";
import { adminCheck } from "@humid/recovery";
import { createConsole } from "../../deploy/windows/admin/console.mjs";
import { fakeWindows } from "../support/admin-platform.js";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const program = join(repo, "deploy", "windows", "src", "server.mjs");
const root = mkdtempSync(join(tmpdir(), "humid-admin-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const host = (...args) => execFileSync(process.execPath, ["--no-warnings", program, ...args, "--root", root], { encoding: "utf8" });

let child, base, consolePort, con, fake, cookie;
const S = suite();
const GATE = "linux-fprintd-keyring";
const interrupt = { method: GATE, assurance: "os" };

/** A HumID holder: an account and one device, signed in to the server. */
async function holder(platform) {
  const seed = random(64), keys = S.deriveKeys(seed), pub = S.publicOf(keys), dev = S.deriveKeys(random(64));
  const api = new HumidApi({ baseUrl: base });
  await api.server();
  const commit = toHex(S.identityCommit(pub, sha3_256(random(16))));
  const s = await api.register({
    pub, commit, device: { dsaPk: dev.dsaPk, platform, gateMethod: GATE, assurance: "os" },
    sign: async (m) => ({ registerSig: ml_dsa87.sign(m.register, keys.dsaSk), sigAccount: ml_dsa87.sign(m.device, keys.dsaSk), sigDevice: ml_dsa87.sign(m.device, dev.dsaSk) }),
  });
  return { api, dev, id: s.id, stepUp: async ({ message }) => ({ sig: ml_dsa87.sign(message, dev.dsaSk), interrupt }) };
}

async function web(path, { method, body, headers = {} } = {}) {
  method ||= body !== undefined ? "POST" : "GET";
  const res = await fetch(`http://127.0.0.1:${consolePort}${path}`, {
    method, headers: { ...(body !== undefined ? { "content-type": "application/json", "x-humid-console": "1" } : {}), ...(cookie ? { cookie } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const out = await res.json().catch(() => ({}));
  return { status: res.status, body: out, res };
}

before(async () => {
  const port = await freePort();
  consolePort = await freePort();
  host("init", "--set", `HUMID_PORT=${port}`, "--set", "HUMID_DEVICE_POLICY=biometric", "--set", "HUMID_REGISTRATION=open", "--set", `HUMID_ADMIN_PORT=${consolePort}`);
  child = spawn(process.execPath, ["--no-warnings", program, "run", "--service", "--root", root], { stdio: "ignore" });
  for (let i = 0; i < 150 && !existsSync(join(root, "server-status.json")); i++) await sleep(100);
  base = `http://127.0.0.1:${port}`;
  fake = fakeWindows(root);
  con = createConsole({ root, installDir: root, port: consolePort, platform: fake.platform, timers: false, version: "test", log: () => {} });
  await con.start();
  await con.probeWindows();
});
after(async () => { await con?.stop(); child?.kill(); rmSync(root, { recursive: true, force: true }); });

test("the server writes its health for the console: every service, the edge, the process", async () => {
  const st = JSON.parse(readFileSync(join(root, "server-status.json"), "utf8"));
  assert.deepEqual(st.services.map((s) => s.name).sort(), ["access", "gateway", "identity", "keyshare", "ledger", "recovery", "vault"]);
  assert.ok(st.services.every((s) => s.ok), "all services healthy");
  assert.equal(st.edge.ok, true);
  assert.ok(st.process.rssMB > 0 && st.kid && st.fingerprint);
  await con.tick();
  assert.equal(con.state().server.up, true);
});

test("the console answers only to this computer's name and its own page", async () => {
  const wrongHost = await new Promise((resolve, reject) => http.get({ host: "127.0.0.1", port: consolePort, path: "/api/state", headers: { host: `evil.example:${consolePort}` } }, (r) => { r.resume(); resolve(r.statusCode); }).on("error", reject));
  assert.equal(wrongHost, 421, "DNS-rebinding style requests are refused");
  assert.equal((await web("/api/state")).status, 401, "signed out without a link");
  const page = await fetch(`http://127.0.0.1:${consolePort}/`);
  const csp = page.headers.get("content-security-policy");
  const html = await page.text();
  const nonce = /script-src 'nonce-([^']+)'/.exec(csp)[1];
  assert.ok(html.includes(`<script nonce="${nonce}">`), "inline script runs only with this response's nonce");
  assert.match(csp, /frame-ancestors 'none'/);
});

test("sign-in links work once, and changes need the console's header", async () => {
  const token = b64u(random(32));
  writeFileSync(join(root, "admin", "logins", `${createHash("sha256").update(token).digest("hex")}.json`), JSON.stringify({ exp: Date.now() + 120_000 }));
  const noHeader = await fetch(`http://127.0.0.1:${consolePort}/api/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
  assert.equal(noHeader.status, 403);
  const bad = await web("/api/login", { body: { token }, headers: { origin: "https://evil.example" } });
  assert.equal(bad.status, 403, "another site's origin is refused");
  const ok = await web("/api/login", { body: { token } });
  assert.equal(ok.status, 200);
  cookie = ok.res.headers.get("set-cookie").split(";")[0];
  assert.match(ok.res.headers.get("set-cookie"), /HttpOnly; SameSite=Strict/);
  assert.equal((await web("/api/login", { body: { token } })).status, 401, "a link works once");
  assert.equal((await web("/api/state")).status, 200);
});

let admin;

test("nothing can change before an administrator phone is enrolled", async () => {
  const r = await web("/api/requests", { body: { type: "restart-server" } });
  assert.equal(r.status, 409);
  assert.equal(r.body.error, "no_admin");
});

test("enrolment: a live check on the phone, then the person compares the admin check", async () => {
  admin = await holder("Pixel 9 (test)");
  const r = await web("/api/enrol", { body: {} });
  assert.equal(r.status, 200);
  assert.match(r.body.qr, /<svg/);
  const req = await admin.api.adminRequest(r.body.code);
  assert.equal(req.kind, "enrol");
  assert.equal(req.check, r.body.check, "the phone sees the same short check as the console");
  await admin.api.approveAdmin(r.body.code, req.digest, admin.stepUp);
  con.takeApprovals();
  let st = con.state().requests.find((x) => x.code === r.body.code);
  assert.equal(st.state, "matching");
  assert.equal(st.candidate.check, adminCheck(admin.dev.dsaPk), "the console's check is computed from the phone's own key");
  const c = await web(`/api/enrol/${r.body.code}/confirm`, { body: { match: true } });
  assert.equal(c.body.state, "done");
  assert.equal(con.state().admins.length, 1);
  // the phone's own ledger records the approval
  const l = await admin.api.ledger();
  assert.ok(l.entries.some((e) => e.type === "admin.approved"));
});

test("a change waits for the phone, and runs only after its signature checks out", async () => {
  const r = await web("/api/requests", { body: { type: "restart-server" } });
  assert.equal(r.status, 200);
  assert.equal(r.body.state, "waiting");
  assert.equal(fake.ran.length, 0, "nothing runs before approval");
  const req = await admin.api.adminRequest(r.body.code);
  assert.equal(req.title, "Restart the HumID server");
  await admin.api.approveAdmin(r.body.code, req.digest, admin.stepUp);
  con.takeApprovals();
  await sleep(50);
  const st = con.state();
  const shown = st.requests.find((x) => x.code === r.body.code);
  assert.equal(shown.state, "running");
  assert.equal(fake.ran.at(-1).type, "restart-server");
  assert.equal(st.jobs[0].state, "done");
  assert.ok(st.audit.some((a) => a.type === "approval.verified" && a.code === r.body.code));
  assert.equal(st.console.audit.broken, null, "audit chain intact");
});

test("someone who isn't an administrator can't see or approve a change", async () => {
  const other = await holder("Somebody else");
  const r = await web("/api/requests", { body: { type: "backup" } });
  await assert.rejects(other.api.adminRequest(r.body.code), (e) => e.code === "not_admin");
  await assert.rejects(other.api.adminSummary(), (e) => e.code === "not_admin");
  const sum = await admin.api.adminSummary();
  assert.ok(["ok", "warn", "bad"].includes(sum.health));
  assert.equal(sum.approvers, undefined, "the phone doesn't learn who else administers the server");
  await web(`/api/requests/${r.body.code}/cancel`, { body: {} });
});

test("an approval for a different digest is refused by the server", async () => {
  const r = await web("/api/requests", { body: { type: "defender-update" } });
  const wrong = "0".repeat(64);
  await assert.rejects(admin.api.approveAdmin(r.body.code, wrong, admin.stepUp), (e) => e.code === "admin_request_changed");
  await web(`/api/requests/${r.body.code}/cancel`, { body: {} });
});

test("a forged approval written by a compromised server process is rejected", async () => {
  const ranBefore = fake.ran.length;
  const r = await web("/api/requests", { body: { type: "reboot" } });
  // An attacker controlling the server can write the approvals folder, and can make a valid
  // step-up with their own key, but can't sign with the administrator's pinned device key.
  const attacker = await holder("Attacker");
  const forged = { ...JSON.parse(JSON.stringify({})) };
  const req = JSON.parse(readFileSync(join(root, "data", "admin", "requests", `${r.body.code}.json`), "utf8"));
  // impersonate the admin: their account and device ids, the attacker's signature
  const admins = JSON.parse(readFileSync(join(root, "admin", "admins.json"), "utf8"));
  const enc = new TextEncoder();
  Object.assign(forged, {
    code: r.body.code, account: admins[0].account, device: admins[0].device, method: "POST", path: `/admin/requests/${r.body.code}/approve`,
    body: b64u(enc.encode(JSON.stringify({ digest: req.digest }))), th: b64u(random(32)), seq: 3, at: Date.now(), exp: Date.now() + 60_000,
    nonce: b64u(random(16)), sig: b64u(ml_dsa87.sign(random(32), attacker.dev.dsaSk)), deviceDsaPk: b64u(attacker.dev.dsaPk),
  });
  writeFileSync(join(root, "data", "admin", "approvals", `${r.body.code}.json`), JSON.stringify(forged));
  con.takeApprovals();
  const st = con.state();
  assert.equal(st.requests.find((x) => x.code === r.body.code).state, "rejected");
  assert.equal(fake.ran.length, ranBefore, "nothing ran");
  assert.ok(st.audit.some((a) => a.type === "approval.rejected" && a.reason === "bad_signature"));
});

test("break-glass: a restart without the phone only while the server is down", async () => {
  const r = await web("/api/breakglass/restart", { body: {} });
  assert.equal(r.status, 409, "refused while the server answers");
  child.kill();
  await sleep(300);
  con.S.edge.downSince = Date.now() - 60_000; // as if it had been down for a minute
  await con.tick();
  con.S.edge.downSince = Date.now() - 60_000;
  assert.equal(con.state().breakGlass, true);
  const ok = await web("/api/breakglass/restart", { body: {} });
  assert.equal(ok.status, 200);
  assert.ok(con.state().audit.some((a) => a.type === "breakglass.restart"));
  assert.ok(con.state().alerts.some((a) => /isn't answering/.test(a.title)) || readdirSync(join(root, "admin", "jobs")).length > 0);
});
