// HumID Server for Windows: settings file, the local edge (proxy, static app,
// limits, client address), without Windows. The full program is exercised
// end to end in tests/e2e/windows-server.test.js and on a real Windows runner in CI.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readEnvFile, updateEnvFile, initialEnvText, validate } from "../deploy/windows/src/config.mjs";
import { createEdge, clientIp } from "../deploy/windows/src/edge.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "humid-win-"));

test("settings: a new file holds the key pair and every default; edits keep comments and order", () => {
  const dir = tmp();
  const f = join(dir, "humid.env");
  writeFileSync(f, initialEnvText({ sk: "SECRET", pk: "PUBLIC" }));
  const cfg = readEnvFile(f);
  assert.equal(cfg.HUMID_INTERNAL_SK, "SECRET");
  assert.equal(cfg.HUMID_DEVICE_POLICY, "attested");
  assert.equal(cfg.HUMID_BIND_HOST, "127.0.0.1");
  assert.equal(cfg.HUMID_PORT, "8480");
  updateEnvFile(f, { HUMID_DEVICE_POLICY: "biometric", NEW_SETTING: "x" });
  const text = readFileSync(f, "utf8");
  assert.ok(text.includes("# attested = phones whose secure chip"), "comments survive");
  assert.ok(text.indexOf("HUMID_DEVICE_POLICY=biometric") < text.indexOf("NEW_SETTING=x"), "existing keys stay in place, new ones go last");
  assert.equal(readEnvFile(f).HUMID_DEVICE_POLICY, "biometric");
  assert.ok(text.includes("\r\n"), "Windows line endings");
  rmSync(dir, { recursive: true, force: true });
});

test("settings: validation explains what's wrong", () => {
  const ok = { HUMID_INTERNAL_SK: "a", HUMID_INTERNAL_PK: "b" };
  validate({ ...ok, HUMID_DEVICE_POLICY: "attested", HUMID_IOS_APP_ID: "ABCDE12345.app.humid.vault", HUMID_PUBLIC_URL: "https://dell.tail1234.ts.net" });
  assert.throws(() => validate({ ...ok, HUMID_DEVICE_POLICY: "pin" }), /attested, biometric, demo/);
  assert.throws(() => validate({ ...ok, HUMID_IOS_APP_ID: "app.humid.vault" }), /Team ID/);
  assert.throws(() => validate({ ...ok, HUMID_PUBLIC_URL: "http://x.example" }), /https/);
  assert.throws(() => validate({ ...ok, HUMID_PORT: "99999" }), /port/);
  assert.throws(() => validate({}), /init/);
});

test("client address: trust the tunnel's last hop, never the visitor's own claims", () => {
  const req = (peer, headers = {}) => ({ socket: { remoteAddress: peer }, headers });
  assert.equal(clientIp(req("127.0.0.1", { "x-forwarded-for": "6.6.6.6, 203.0.113.9" })), "203.0.113.9");
  assert.equal(clientIp(req("::1", { "cf-connecting-ip": "198.51.100.4", "x-forwarded-for": "6.6.6.6" })), "198.51.100.4");
  assert.equal(clientIp(req("192.168.1.20", { "x-forwarded-for": "6.6.6.6" })), "192.168.1.20", "headers count only from the local tunnel");
  assert.equal(clientIp(req("127.0.0.1")), "127.0.0.1");
});

test("edge: proxies /htp with a clean X-Forwarded-For, serves the app, caps bodies, blocks traversal", async () => {
  const dir = tmp();
  const app = join(dir, "app");
  mkdirSync(join(app, "assets"), { recursive: true });
  writeFileSync(join(app, "index.html"), "<!doctype html><title>HumID</title>");
  writeFileSync(join(app, "assets", "app.js"), "console.log(1)");
  writeFileSync(join(dir, "secret.txt"), "do not serve");

  const seen = [];
  const gw = http.createServer((req, res) => {
    let n = 0;
    req.on("data", (c) => { n += c.length; });
    req.on("end", () => {
      seen.push({ url: req.url, xff: req.headers["x-forwarded-for"], cf: req.headers["cf-connecting-ip"], n });
      res.writeHead(req.url === "/healthz" ? 200 : 201, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise((r) => gw.listen(0, "127.0.0.1", r));
  const edge = createEdge({ port: 0, appDir: app, gatewayUrl: `http://127.0.0.1:${gw.address().port}`, maxBodyBytes: 1000, log: { error() {} } });
  await edge.start();
  const base = `http://127.0.0.1:${edge.server.address().port}`;
  try {
    const p = await fetch(`${base}/htp/v1/call`, { method: "POST", body: new Uint8Array(500), headers: { "x-forwarded-for": "6.6.6.6, 203.0.113.9" } });
    assert.equal(p.status, 201);
    assert.equal(p.headers.get("x-frame-options"), "DENY");
    assert.equal(seen.at(-1).xff, "203.0.113.9");
    assert.equal(seen.at(-1).n, 500);

    assert.equal((await fetch(`${base}/htp/v1/call`, { method: "POST", body: new Uint8Array(5000) })).status, 413);

    const h = await fetch(`${base}/healthz`);
    assert.equal(h.status, 200);
    assert.equal(await h.text(), "ok");

    const index = await fetch(`${base}/`);
    assert.match(index.headers.get("content-security-policy"), /frame-ancestors 'none'/);
    assert.equal(index.headers.get("cache-control"), "no-cache");
    const js = await fetch(`${base}/assets/app.js`);
    assert.equal(js.headers.get("content-type"), "text/javascript; charset=utf-8");
    assert.match(js.headers.get("cache-control"), /immutable/);
    assert.match(await (await fetch(`${base}/vault/anything`)).text(), /<title>HumID/, "app routes fall back to index.html");

    for (const path of ["/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt", "/..%5csecret.txt"]) {
      const r = await fetch(base + path);
      assert.doesNotMatch(await r.text(), /do not serve/, path);
    }
    assert.equal((await fetch(`${base}/`, { method: "DELETE" })).status, 405);
  } finally {
    await edge.stop();
    await new Promise((r) => gw.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("edge: a gateway that's down gives 502 / 503, not a crash", async () => {
  const dir = tmp();
  mkdirSync(join(dir, "app"));
  writeFileSync(join(dir, "app", "index.html"), "x");
  const edge = createEdge({ port: 0, appDir: join(dir, "app"), gatewayUrl: "http://127.0.0.1:1", log: { error() {} } });
  await edge.start();
  const base = `http://127.0.0.1:${edge.server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/htp/v1/keys`)).status, 502);
    assert.equal((await fetch(`${base}/healthz`)).status, 503);
  } finally {
    await edge.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the installer lets the server's account write exactly the data folders the services use", () => {
  // humid.ps1 Set-DataAcl grants LOCAL SERVICE modify on data\<service> only (PC-09); a new
  // service needs its folder added there, or it can't create its database.
  const ps1 = readFileSync(new URL("../deploy/windows/scripts/humid.ps1", import.meta.url), "utf8");
  const listed = /^\$ServerDataDirs = @\(([^)]*)\)/m.exec(ps1)[1].match(/'([a-z]+)'/g).map((x) => x.slice(1, -1)).sort();
  const server = readFileSync(new URL("../deploy/windows/src/server.mjs", import.meta.url), "utf8");
  // server 3.0: data("gateway"), and opts("identity", role, port) for the services a role runs
  const used = [...new Set([...server.matchAll(/(?:data|opts)\("([a-z]+)"/g)].map((m) => m[1]))].sort();
  assert.ok(used.length >= 7);
  assert.deepEqual(listed, used);
});
