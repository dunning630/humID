// End to end, server 3.0 on the Windows host program (any OS; CI also runs it on real Windows
// with DPAPI): secrets sealed at rest, encrypted backups that restore elsewhere, and the roles
// split across two "machines" (two data roots) talking mutual TLS, with the deployment smoke
// test passing through all of it.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, readdirSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import net from "node:net";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const program = join(repo, "deploy", "windows", "src", "server.mjs");
const work = mkdtempSync(join(tmpdir(), "humid-s3win-"));
const children = [];
after(async () => {
  for (const c of children) c.kill();
  await new Promise((r) => setTimeout(r, 500)); // Windows: files stay locked until the processes have gone
  try { rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* left in the temp folder */ }
});

const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** One "machine": a data root and its own seal key file (on Windows: DPAPI). */
function machine(name) {
  const root = join(work, name);
  const keyFile = join(work, `${name}.seal`);
  writeFileSync(keyFile, randomBytes(32).toString("hex"));
  const env = { ...process.env, HUMID_SEAL: "file", HUMID_SEAL_KEY_FILE: keyFile, HUMID_BACKUP_KEY_FILE: "" };
  delete env.HUMID_BACKUP_KEY_FILE;
  const run = (...args) => execFileSync(process.execPath, ["--no-warnings", program, ...args, "--root", root], { encoding: "utf8", env });
  return { name, root, keyFile, env, run };
}
async function start(m) {
  const child = spawn(process.execPath, ["--no-warnings", program, "run", "--service", "--root", m.root], { stdio: "ignore", env: m.env });
  children.push(child);
  for (let i = 0; i < 150; i++) {
    const info = existsSync(join(m.root, "server.json")) && JSON.parse(readFileSync(join(m.root, "server.json"), "utf8"));
    if (info?.pid === child.pid) return { child, info };
    if (child.exitCode !== null) break;
    await sleep(100);
  }
  const log = existsSync(join(m.root, "logs", "humid-server.log")) ? readFileSync(join(m.root, "logs", "humid-server.log"), "utf8").split("\n").filter((l) => /"error"/.test(l)).slice(-3).join("\n") : "";
  throw new Error(`${m.name} didn't start\n${log}`);
}
const stop = (c) => new Promise((r) => { if (c.exitCode !== null) return r(); c.once("exit", r); c.kill(); });
const smoke = (url, code = "") => execFileSync(process.execPath, [join(repo, "tests", "smoke.mjs"), url, code], { encoding: "utf8", env: { ...process.env, NODE_NO_WARNINGS: "1" } });
const json = (s) => JSON.parse(s.trim().split("\n").pop());

const A = machine("a");
let kidA;

test("a fresh 3.0 install seals every secret, and the full flow runs", async () => {
  const port = await freePort();
  A.run("init", "--set", `HUMID_PORT=${port}`, "--set", `HUMID_ADMIN_PORT=${port + 1 === 65536 ? port - 1 : port + 1}`, "--set", "HUMID_DEVICE_POLICY=biometric");
  assert.match(readFileSync(join(A.root, "humid.env"), "utf8"), /^HUMID_INTERNAL_SK=sealed:v1:/m, "the internal key is sealed in humid.env");
  const { child, info } = await start(A);
  kidA = info.kid;
  assert.deepEqual(info.roles, ["front", "core", "keys"]);
  assert.equal(info.sealed, "file");
  const st = json(A.run("seal-status"));
  assert.deepEqual(st.plain, [], "no secret left in plain");
  assert.equal(st.sealed.length, 4);
  assert.equal(st.internalKey, "sealed");
  // nothing secret readable in the data folder
  assert.match(readFileSync(join(A.root, "data", "gateway", "htp-keys.json"), "utf8"), /^\{"humid-sealed":1/);
  const [code] = A.run("mint", "1", "s3").trim().split("\n");
  const out = smoke(info.localUrl, code);
  assert.match(out, /blind-signed pass/);
  await stop(child);
});

test("an older install's plain secrets are sealed in place on first start; the server's kid stays", async () => {
  const B = machine("legacy");
  const port = await freePort();
  // a 2.x install: no sealing
  B.run("init", "--set", `HUMID_PORT=${port}`, "--set", `HUMID_ADMIN_PORT=${port + 1}`, "--set", "HUMID_SEAL=off");
  const envOff = { ...B.env, HUMID_SEAL: "off" };
  let child = spawn(process.execPath, ["--no-warnings", program, "run", "--service", "--root", B.root], { stdio: "ignore", env: envOff });
  children.push(child);
  for (let i = 0; i < 150 && !existsSync(join(B.root, "server.json")); i++) await sleep(100);
  const before = JSON.parse(readFileSync(join(B.root, "server.json"), "utf8")).kid;
  assert.doesNotMatch(readFileSync(join(B.root, "data", "gateway", "htp-keys.json"), "utf8"), /humid-sealed/);
  await stop(child);
  // upgrade: sealing on (the default on Windows)
  B.run("set", "HUMID_SEAL=file");
  B.run("init"); // the installer runs init again on an update: it seals the internal key
  const r = await start(B);
  assert.equal(r.info.kid, before, "same server identity: phones pinned to it keep working");
  assert.deepEqual(json(B.run("seal-status")).plain, []);
  await stop(r.child);
});

test("encrypted backups: two files, restore elsewhere with the backup key, wrong key and tampering refused", async () => {
  const dir = join(work, "backups");
  const main = json(A.run("backup", "--out", join(dir, "b-main.humidbak"), "--part", "main"));
  const keys = json(A.run("backup", "--out", join(dir, "b-keys.humidbak"), "--part", "keys"));
  assert.ok(main.files > 5 && keys.files >= 2, `main ${main.files} files, keys ${keys.files}`);
  const raw = readFileSync(join(dir, "b-main.humidbak"));
  assert.ok(!raw.includes(Buffer.from("HUMID_INTERNAL_PK")), "nothing readable inside");
  const hbk = A.run("backup-key").trim();
  assert.match(hbk, /^HBK-[A-Z2-9-]+$/);
  // on another machine: its own (different) backup key; the typed one opens the backup
  const C = machine("c");
  const to = join(C.root);
  assert.throws(() => C.run("restore", "--in", `${join(dir, "b-main.humidbak")},${join(dir, "b-keys.humidbak")}`, "--to", to), /another server's backup key|no backup key/);
  assert.throws(() => C.run("restore", "--in", join(dir, "b-main.humidbak"), "--to", to, "--backup-key", "HBK-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA"), /typo|doesn't open/);
  const r = json(C.run("restore", "--in", `${join(dir, "b-main.humidbak")},${join(dir, "b-keys.humidbak")}`, "--to", to, "--backup-key", hbk));
  assert.equal(r.files, main.files + keys.files);
  assert.ok(r.sealKey, "the seal key travelled inside the backup");
  // the restored server opens the sealed secrets (here with A's seal key file; on Windows it is re-sealed under the new machine's DPAPI)
  const port = await freePort();
  C.run("set", `HUMID_PORT=${port}`, `HUMID_ADMIN_PORT=${port + 1}`);
  const restored = await start({ ...C, env: { ...C.env, HUMID_SEAL_KEY_FILE: A.keyFile } });
  assert.equal(restored.info.kid, kidA, "the restored server is the same server");
  await stop(restored.child);
  // a changed byte: refused, nothing written
  const bad = Buffer.from(raw); bad[bad.length - 40] ^= 1;
  writeFileSync(join(dir, "bad.humidbak"), bad);
  assert.throws(() => A.run("restore", "--in", join(dir, "bad.humidbak"), "--to", join(work, "nope")), /damaged|changed/);
  assert.ok(!existsSync(join(work, "nope")) || readdirSync(join(work, "nope")).length === 0);
  // a cut file: refused
  writeFileSync(join(dir, "cut.humidbak"), raw.subarray(0, raw.length - 100));
  assert.throws(() => A.run("restore", "--in", join(dir, "cut.humidbak"), "--to", join(work, "nope2")), /cut short|damaged|incomplete/);
});

test("split roles: front+core on one machine, keys on another, mutual TLS between them; the full flow passes", async () => {
  // machine K runs only keys; machine A (front, core) reaches it by name, over mutual TLS
  const K = machine("k");
  const kport = await freePort(), base = 20000 + Math.floor(Math.random() * 30000);
  K.run("init", "--set", `HUMID_PORT=${kport}`, "--set", `HUMID_ADMIN_PORT=${kport + 1}`);
  A.run("pki", "init");
  const bundle = join(work, "keys-bundle");
  A.run("pki", "issue", "keys", "--out", bundle);
  assert.ok(existsSync(join(bundle, "keys.key")));
  K.run("pki", "import", "--from", bundle);
  assert.match(readFileSync(join(K.root, "humid.env"), "utf8"), /^HUMID_INTERNAL_SK=$/m, "the keys machine holds no private gateway key");
  assert.match(readFileSync(join(K.root, "pki", "keys.key"), "utf8"), /^\{"humid-sealed":1/, "its TLS key is sealed");
  rmSync(bundle, { recursive: true, force: true });
  K.run("set", "HUMID_ROLES=keys", "HUMID_INTERNAL_BIND=127.0.0.1", `HUMID_INTERNAL_PORT_BASE=${base}`);
  const k = await start(K);
  assert.deepEqual(k.info.roles, ["keys"]);
  assert.equal(k.info.kid, null, "no front here");
  assert.equal(k.info.internal.keyshare, `127.0.0.1:${base + 6}`);
  const health = await fetch(`http://127.0.0.1:${kport}/healthz`);
  assert.equal(health.status, 200);
  // plain HTTP to the keys role: refused at the door
  await assert.rejects(fetch(`http://127.0.0.1:${base + 6}/healthz`));
  A.run("set", "HUMID_ROLES=front,core", "HUMID_KEYS_HOST=127.0.0.1", `HUMID_INTERNAL_PORT_BASE=${base}`);
  const a = await start(A);
  assert.equal(a.info.kid, kidA, "the front keeps its identity when keys moves away");
  assert.deepEqual(a.info.roles, ["front", "core"]);
  const [code] = A.run("mint", "1", "split").trim().split("\n");
  const out = smoke(a.info.localUrl, code);
  assert.match(out, /blind-signed pass/);
  // the key-share data is on the keys machine, not this one
  assert.ok(existsSync(join(K.root, "data", "keyshare", "keyshare.db")));
  await stop(a.child);
  await stop(k.child);
  // and the keys role refuses to start without its certificate
  rmSync(join(K.root, "pki", "keys.crt"));
  await assert.rejects(start(K), /didn't start/);
});
