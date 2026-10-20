// Server 3.0 (docs/DEPLOY-VMS.md): internal requests bound to one use (SEC-S-01), mutual TLS
// between roles on separate machines, and server secrets sealed at rest.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  createService, json, newInternalKeys, signAssertion, signRequest, verifyAssertion, internalRequest, roleAgent,
  makeCa, issueRoleCert, serverTls, clientTls, sealer, secretFile, isSealedFile, parseKeyText,
} from "@humid/svc";

const keys = newInternalKeys();
const dirs = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), "humid-s3-")); dirs.push(d); return d; };
// Windows keeps a database file locked while this process has it open (the ledgers below stay open until exit):
// what can't be removed now is left in the temp folder rather than failing the run
test.after(() => { for (const d of dirs) { try { rmSync(d, { recursive: true, force: true, maxRetries: 3 }); } catch { /* Windows: still open */ } } });

/** A tiny service with the real framework: GET /objects, DELETE /objects, POST /echo. */
async function service(opts = {}) {
  const hits = [];
  const svc = createService({
    name: "vault", port: 0, ...opts,
    verify: (t) => verifyAssertion(keys.pk, t, "vault"),
    routes: [
      ["GET", "/objects", ({ claims }) => { hits.push(["GET", claims.sub]); return json(200, { ok: true }); }],
      ["DELETE", "/objects", ({ claims }) => { hits.push(["DELETE", claims.sub]); return json(200, { erased: true }); }],
      ["POST", "/echo", ({ body }) => json(200, { n: body.length })],
    ],
  });
  await svc.start();
  const proto = opts.tls ? "https" : "http";
  return { svc, hits, url: `${proto}://127.0.0.1:${svc.server.address().port}` };
}
const call = (url, method, path, { assertion, body, agent } = {}) =>
  internalRequest(`${url}${path}`, { method, body, agent, headers: assertion ? { "x-humid-assertion": assertion } : {} });

/* ---------------- SEC-S-01 ---------------- */

test("an assertion works once, for the request it names", async () => {
  const { svc, url, hits } = await service();
  const a = signRequest(keys.sk, { aud: "vault", method: "GET", path: "/objects", claims: { sub: "hid_alice" } });
  assert.equal((await call(url, "GET", "/objects", { assertion: a })).status, 200);
  // the same assertion again: refused
  assert.equal((await call(url, "GET", "/objects", { assertion: a })).status, 401, "a replay is refused");
  assert.deepEqual(hits, [["GET", "hid_alice"]]);
  await svc.stop();
});

test("a captured download assertion can't erase the vault (the SEC-S-01 attack)", async () => {
  const { svc, url, hits } = await service();
  const download = signRequest(keys.sk, { aud: "vault", method: "GET", path: "/objects", claims: { sub: "hid_alice" } });
  const r = await call(url, "DELETE", "/objects", { assertion: download });
  assert.equal(r.status, 401);
  assert.match(Buffer.from(r.body).toString(), /another method/);
  assert.deepEqual(hits, [], "nothing erased");
  await svc.stop();
});

test("path, query and body are bound: a different one is refused", async () => {
  const { svc, url } = await service();
  const body = Buffer.from('{"a":1}');
  const a = () => signRequest(keys.sk, { aud: "vault", method: "POST", path: "/echo", body, claims: { sub: "hid_alice" } });
  assert.equal((await call(url, "POST", "/echo", { assertion: a(), body })).status, 200);
  assert.equal((await call(url, "POST", "/echo", { assertion: a(), body: Buffer.from('{"a":2}') })).status, 401, "another body");
  assert.equal((await call(url, "POST", "/echo?x=1", { assertion: a(), body })).status, 401, "another query");
  const g = signRequest(keys.sk, { aud: "vault", method: "GET", path: "/objects?limit=5", claims: { sub: "hid_alice" } });
  assert.equal((await call(url, "GET", "/objects?limit=500", { assertion: g })).status, 401, "a widened query");
  await svc.stop();
});

test("an assertion for another service, an old unbound one, and one older than the service are refused", async () => {
  const { svc, url } = await service();
  const other = signRequest(keys.sk, { aud: "keyshare", method: "GET", path: "/objects", claims: { sub: "hid_alice" } });
  assert.equal((await call(url, "GET", "/objects", { assertion: other })).status, 401);
  const v1 = signAssertion(keys.sk, { iss: "gateway", aud: "vault", rid: "0123456789abcdef0123", sub: "hid_alice" });
  assert.equal((await call(url, "GET", "/objects", { assertion: v1 })).status, 401, "an assertion bound to nothing");
  await svc.stop();
  // made before a (re)started service: refused, so a restart doesn't reopen what its memory covered
  const early = signRequest(keys.sk, { aud: "vault", method: "GET", path: "/objects", claims: { sub: "hid_alice" } });
  await new Promise((r) => setTimeout(r, 2100));
  const again = await service();
  assert.equal((await call(again.url, "GET", "/objects", { assertion: early })).status, 401);
  await again.svc.stop();
});

/* ---------------- mutual TLS ---------------- */

test("a role on another machine takes calls only from the server's own humid-front", async () => {
  const ca = makeCa();
  const keysCert = issueRoleCert(ca, "keys"), front = issueRoleCert(ca, "front"), core = issueRoleCert(ca, "core");
  const { svc, url } = await service({ tls: serverTls({ ca: ca.certPem, cert: keysCert.certPem, key: keysCert.keyPem }) });
  const a = () => signRequest(keys.sk, { aud: "vault", method: "GET", path: "/objects", claims: { sub: "hid_alice" } });
  const agent = roleAgent(clientTls({ ca: ca.certPem, cert: front.certPem, key: front.keyPem, expect: "keys" }));
  assert.equal((await call(url, "GET", "/objects", { assertion: a(), agent })).status, 200, "front to keys");
  // a core certificate (or any role but front) can't call
  const asCore = roleAgent(clientTls({ ca: ca.certPem, cert: core.certPem, key: core.keyPem, expect: "keys" }));
  await assert.rejects(call(url, "GET", "/objects", { assertion: a(), agent: asCore }));
  // a certificate from another CA can't either
  const other = makeCa(), stranger = issueRoleCert(other, "front");
  await assert.rejects(call(url, "GET", "/objects", { assertion: a(), agent: roleAgent(clientTls({ ca: ca.certPem, cert: stranger.certPem, key: stranger.keyPem, expect: "keys" })) }));
  // and the gateway refuses a server that isn't the role it meant to reach
  await assert.rejects(call(url, "GET", "/objects", { assertion: a(), agent: roleAgent(clientTls({ ca: ca.certPem, cert: front.certPem, key: front.keyPem, expect: "core" })) }), /expected humid-core/);
  // plain HTTP to a TLS role: nothing
  await assert.rejects(internalRequest(url.replace("https:", "http:") + "/objects", { headers: { "x-humid-assertion": a() } }));
  agent.destroy(); asCore.destroy();
  await svc.stop();
});

/* ---------------- sealed secrets ---------------- */

test("a secret file is sealed, opens only with its key and its own name, and a plain one is sealed in place", () => {
  const d = tmp();
  const key = new Uint8Array(randomBytes(32));
  const s = sealer(key);
  const f = join(d, "share-key.bin");
  const v = secretFile(f, { seal: s, name: "keyshare/share-key", make: () => randomBytes(32) });
  assert.equal(v.length, 32);
  assert.ok(isSealedFile(f), "written sealed");
  assert.ok(!readFileSync(f).includes(v), "the secret isn't in the file");
  assert.deepEqual(secretFile(f, { seal: s, name: "keyshare/share-key", make: () => { throw new Error("not again"); } }), v, "reads back the same");
  // another machine's key, or no key: refused, never a new secret
  assert.throws(() => secretFile(f, { seal: sealer(new Uint8Array(randomBytes(32))), name: "keyshare/share-key", make: () => randomBytes(32) }), /doesn't open/);
  assert.throws(() => secretFile(f, { seal: sealer(null), name: "keyshare/share-key", make: () => randomBytes(32) }), /no seal key/);
  // a sealed file moved under another secret's name doesn't open
  assert.throws(() => s.open("recovery/anchor-secret", readFileSync(f)), /doesn't open/);
  // an install from before 3.0: plain file, sealed in place, same bytes
  const g = join(d, "anchor-secret.bin"), plain = randomBytes(32);
  writeFileSync(g, plain);
  assert.deepEqual(secretFile(g, { seal: s, name: "recovery/anchor-secret", make: () => randomBytes(32) }), plain);
  assert.ok(isSealedFile(g));
  assert.ok(!readFileSync(g).includes(plain));
  assert.ok(!existsSync(join(d, `.anchor-secret.bin.${process.pid}.tmp`)), "no temporary file left");
});

test("text secrets (in a database) seal the same way; key files read as raw, hex or base64", () => {
  const key = new Uint8Array(randomBytes(32));
  const s = sealer(key);
  const t = s.sealText("access/issuer/k1", "-----BEGIN PRIVATE KEY-----x");
  assert.match(t, /^sealed:v1:/);
  assert.equal(s.openText("access/issuer/k1", t), "-----BEGIN PRIVATE KEY-----x");
  assert.equal(sealer(null).openText("x", "plain"), "plain");
  assert.deepEqual(parseKeyText(Buffer.from(key)), key);
  assert.deepEqual(parseKeyText(Buffer.from(Buffer.from(key).toString("hex") + "\n")), key);
  assert.deepEqual(parseKeyText(Buffer.from(Buffer.from(key).toString("base64"))), key);
  assert.throws(() => parseKeyText(Buffer.from("short")));
});

test("the services keep their keys across a restart, sealed: same server key id, same log key", async () => {
  const { createGateway } = await import("../services/gateway/src/server.js");
  const { createLedger } = await import("../services/ledger/src/server.js");
  const d = tmp();
  const s = sealer(new Uint8Array(randomBytes(32)));
  const gw = (seal) => createGateway({ port: 0, dataDir: join(d, "gateway"), internalSk: keys.sk, seal, internalTls: null, upstreams: { identity: "http://127.0.0.1:1", vault: "http://127.0.0.1:1", ledger: "http://127.0.0.1:1", recovery: "http://127.0.0.1:1", access: "http://127.0.0.1:1", keyshare: "http://127.0.0.1:1" } });
  // a pre-3.0 gateway (no seal key) writes a plain key file; 3.0 with a seal key seals it in place
  const before = gw(null).htp.kid;
  assert.ok(!isSealedFile(join(d, "gateway", "htp-keys.json")));
  const after = gw(s).htp.kid;
  assert.equal(after, before, "the kid every phone pinned is unchanged");
  assert.ok(isSealedFile(join(d, "gateway", "htp-keys.json")));
  assert.equal(gw(s).htp.kid, before);
  assert.throws(() => gw(null), /sealed, and this server has no seal key/, "a sealed key without the seal key: refused, never replaced");
  const l1 = createLedger({ port: 0, dataDir: join(d, "ledger"), internalPk: keys.pk, seal: s, tls: null });
  const l2 = createLedger({ port: 0, dataDir: join(d, "ledger"), internalPk: keys.pk, seal: s, tls: null });
  assert.ok(isSealedFile(join(d, "ledger", "ledger-key.json")));
  l1.db?.close?.(); l2.db?.close?.();
});
