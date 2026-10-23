// End to end, server 3.x on the Windows host program (any OS; CI also runs it on real Windows
// with DPAPI): secrets sealed at rest, encrypted backups (server 3.1: to a backup key kept off
// the server, keyshare's half apart) that restore elsewhere, and the roles
// split across two "machines" (two data roots) talking mutual TLS, with the deployment smoke
// test passing through all of it.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import net from "node:net";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const program = join(repo, "deploy", "windows", "src", "server.mjs");
const adminProgram = join(repo, "deploy", "windows", "admin", "admin.mjs");
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
  const env = { ...process.env, HUMID_SEAL: "file", HUMID_SEAL_KEY_FILE: keyFile };
  const run = (...args) => execFileSync(process.execPath, ["--no-warnings", program, ...args, "--root", root], { encoding: "utf8", env });
  const admin = (...args) => execFileSync(process.execPath, ["--no-warnings", adminProgram, ...args, "--root", root], { encoding: "utf8", env, stdio: ["ignore", "pipe", "pipe"] });
  return { name, root, keyFile, env, run, admin };
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

test("encrypted backups: to a key kept off the server, keyshare apart; restore elsewhere with the key file; the server can't open its own", async () => {
  const dir = join(work, "backups"), usb = join(work, "usb");
  // no backup key yet: nothing is written
  assert.throws(() => A.admin("backup", "--out", join(dir, "early.humidbak"), "--keyshare-out", join(dir, "early-ks.humidbak")), (e) => /No backup key is set/.test(e.stdout));
  assert.ok(!existsSync(join(dir, "early.humidbak")));
  mkdirSync(usb, { recursive: true });
  const made = A.admin("backup-key-new", "--out", join(usb, "humid-backup.key"));
  assert.match(made, /Backup key [0-9A-F-]{19} is set/);
  const keyText = readFileSync(join(usb, "humid-backup.key"), "utf8");
  // the server keeps only the public half
  for (const f of [join(A.root, "humid.env"), join(A.root, "admin", "admin.env")]) assert.ok(!readFileSync(f, "utf8").includes(JSON.parse(keyText).seed));
  const main = join(dir, "HumID-backup-x.humidbak"), ks = join(dir, "HumID-keyshare-x.humidbak");
  A.admin("backup", "--out", main, "--keyshare-out", ks);
  const raw = readFileSync(main);
  assert.ok(!raw.includes(Buffer.from("HUMID_INTERNAL_PK")), "nothing readable inside");
  for (const f of [main, ks]) assert.ok(!readFileSync(f).includes(Buffer.from(readFileSync(A.keyFile, "utf8").trim(), "hex")), "no seal key in the clear");
  // the server itself can't open it: restoring needs the key file
  assert.throws(() => A.admin("restore", "--into", join(work, "self"), "--in", main, "--keyshare", ks), (e) => /needs that key file/.test(e.stdout));
  assert.ok(!existsSync(join(work, "self")));
  // and keyshare's half: refused without it
  writeFileSync(join(usb, "k.key"), keyText);
  assert.throws(() => A.admin("restore", "--into", join(work, "noks"), "--in", main, "--key", join(usb, "k.key")), (e) => /also needs keyshare's half/.test(e.stdout));
  // on another machine, with the key file: the same server comes back, its sealed secrets open
  const C = machine("c");
  const to = join(work, "c-restored");
  const out = C.admin("restore", "--into", to, "--in", main, "--keyshare", ks, "--key", join(usb, "k.key"));
  const r = JSON.parse(out.trim().split("\n").pop());
  assert.equal(r.kind, "data");
  assert.ok(r.sealKey, "the seal key travelled inside the encrypted backup");
  assert.ok(existsSync(join(to, "data", "keyshare", "share-key.bin")));
  rmSync(C.root, { recursive: true, force: true });
  cpSync(to, C.root, { recursive: true });
  const port = await freePort();
  C.run("set", `HUMID_PORT=${port}`, `HUMID_ADMIN_PORT=${port + 1}`);
  // (here the seal key is A's key file, which the restore can't move; on Windows it is sealed again under the new machine's DPAPI)
  const restored = await start({ ...C, env: { ...C.env, HUMID_SEAL_KEY_FILE: A.keyFile } });
  assert.equal(restored.info.kid, kidA, "the restored server is the same server");
  await stop(restored.child);
  // a changed byte: refused, nothing written
  const bad = Buffer.from(raw); bad[bad.length - 40] ^= 1;
  writeFileSync(join(dir, "bad.humidbak"), bad);
  assert.throws(() => A.admin("restore", "--into", join(work, "nope"), "--in", join(dir, "bad.humidbak"), "--keyshare", ks, "--key", join(usb, "k.key")), (e) => /damaged|changed/.test(e.stdout));
  assert.ok(!existsSync(join(work, "nope")));
  // a cut file: refused
  writeFileSync(join(dir, "cut.humidbak"), raw.subarray(0, raw.length - 100));
  assert.throws(() => A.admin("restore", "--into", join(work, "nope2"), "--in", join(dir, "cut.humidbak"), "--keyshare", ks, "--key", join(usb, "k.key")), (e) => /cut short|damaged/.test(e.stdout));
  assert.ok(!existsSync(join(work, "nope2")));
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
  // SRV-30: it holds its own statement key (sealed) and core's public one, never core's private one
  const kenv = readFileSync(join(K.root, "humid.env"), "utf8");
  assert.match(kenv, /^HUMID_KEYS_STATEMENT_SK=sealed:v1:/m);
  assert.match(kenv, /^HUMID_CORE_STATEMENT_SK=$/m);
  assert.match(kenv, /^HUMID_CORE_STATEMENT_PK=\S+/m);
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
