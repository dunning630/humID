// End to end: the Windows server program (all five services + the local edge
// in one process), started the way its background task starts it, then the
// deployment smoke test against it. Runs on any OS; CI also installs the real
// package on Windows.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const program = join(repo, "deploy", "windows", "src", "server.mjs");
const root = mkdtempSync(join(tmpdir(), "humid-winhost-"));
const children = [];
after(() => { for (const c of children) c.kill(); rmSync(root, { recursive: true, force: true }); });

const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const host = (...args) => execFileSync(process.execPath, ["--no-warnings", program, ...args, "--root", root], { encoding: "utf8" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function start() {
  const child = spawn(process.execPath, ["--no-warnings", program, "run", "--service", "--root", root], { stdio: "ignore" });
  children.push(child);
  for (let i = 0; i < 100; i++) {
    const info = existsSync(join(root, "server.json")) && JSON.parse(readFileSync(join(root, "server.json"), "utf8"));
    if (info?.pid === child.pid) return { child, info };
    await sleep(100);
  }
  throw new Error("the server didn't start");
}
const stop = (c) => new Promise((r) => { c.once("exit", r); c.kill(); });
const smoke = (url) => execFileSync(process.execPath, [join(repo, "tests", "smoke.mjs"), url], { encoding: "utf8", env: { ...process.env, NODE_NO_WARNINGS: "1" } });

let port;

test("init writes settings with a fresh internal key pair; set validates", async () => {
  port = await freePort();
  host("init", "--set", `HUMID_PORT=${port}`);
  const env = readFileSync(join(root, "humid.env"), "utf8");
  assert.match(env, /^HUMID_INTERNAL_SK=\S{40,}/m);
  assert.match(env, /^HUMID_DEVICE_POLICY=attested/m);
  assert.throws(() => host("set", "HUMID_DEVICE_POLICY=pin"), /attested, biometric, demo/);
  assert.doesNotMatch(host("show"), /SK=[^(]/, "show hides the secret key");
});

test("default policy: the server refuses a device that can't prove a live check", async () => {
  const { child, info } = await start();
  assert.equal(info.localUrl, `http://127.0.0.1:${port}`);
  assert.equal(info.devicePolicy, "attested");
  assert.match(smoke(info.localUrl), /device_not_proven/);
  await stop(child);
});

test("biometric policy: the whole flow works, and the server keeps its identity across restarts", async () => {
  const before = JSON.parse(readFileSync(join(root, "server.json"), "utf8"));
  host("set", "HUMID_DEVICE_POLICY=biometric");
  const { child, info } = await start();
  assert.equal(info.kid, before.kid, "same server key after a restart");
  assert.match(smoke(info.localUrl), /SMOKE OK$/m);
  const log = readFileSync(join(root, "logs", "humid-server.log"), "utf8");
  assert.match(log, /"msg":"ready"/);
  assert.match(log, /"service":"gateway","msg":"listening".*"host":"127.0.0.1"/, "services bind to localhost only");
  await stop(child);
});
