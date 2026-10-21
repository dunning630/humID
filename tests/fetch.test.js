// CRD-02: the server-side fetcher for status lists and trust lists refuses
// anything that could reach inside the network, follows no redirects, and
// caps time and size. A real TLS server on loopback stands in for the
// internet; the test resolves its name and allows its address explicitly,
// which production callers can't do.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:https";
import { BlockList } from "node:net";
import { safeFetch, statusListFetcher, publicAddress, checkUrl } from "@humid/creds/server";
import { ecKeys, certificate, extension, pem } from "./support/pki.js";

const code = (c) => (e) => { assert.equal(e.code, c, `${e.code}: ${e.message}`); return true; };

/** A self-signed TLS certificate for status.example. */
function tls() {
  const k = ecKeys("P-256");
  const host = Buffer.from("status.example");
  const san = Buffer.concat([Buffer.from([0x30, host.length + 2, 0x82, host.length]), host]);
  const der = certificate({ subject: "status.example", issuer: "status.example", publicKey: k.publicKey, signingKey: k.privateKey, ca: true, extensions: [extension("2.5.29.17", san)] });
  return { cert: pem(der), key: k.privateKey.export({ type: "pkcs8", format: "pem" }) };
}

async function server(handler) {
  const t = tls();
  const s = createServer({ cert: t.cert, key: t.key }, handler);
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const allowLoopback = new BlockList(); // nothing blocked: only this test may do this
  const opts = { ca: t.cert, resolve: async () => ["127.0.0.1"], blockList: allowLoopback, connectPort: s.address().port };
  return { s, opts, close: () => new Promise((r) => s.close(r)) };
}

test("addresses: private, loopback, link-local, CGNAT, reserved and IPv4-in-IPv6 are refused", () => {
  for (const a of ["127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2001:db8::1"]) {
    assert.equal(publicAddress(a), false, a);
  }
  for (const a of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) assert.equal(publicAddress(a), true, a);
  assert.equal(publicAddress("not an ip"), false);
});

test("URLs: https on 443 only, no credentials, no private literals or local names, optional host list", () => {
  assert.throws(() => checkUrl("http://status.example/x"), code("bad_url"));
  assert.throws(() => checkUrl("https://status.example:8443/x"), code("bad_url"));
  assert.throws(() => checkUrl("https://user:pw@status.example/x"), code("bad_url"));
  assert.throws(() => checkUrl("https://127.0.0.1/x"), code("blocked_address"));
  assert.throws(() => checkUrl("https://2130706433/x"), code("blocked_address"), "decimal 127.0.0.1");
  assert.throws(() => checkUrl("https://0x7f.1/x"), code("blocked_address"), "hex 127.0.0.1");
  assert.throws(() => checkUrl("https://[::ffff:a9fe:a9fe]/x"), code("blocked_address"), "metadata address in IPv6");
  assert.throws(() => checkUrl("https://metadata.internal/x"), code("blocked_address"));
  assert.throws(() => checkUrl("https://printer.local/x"), code("blocked_address"));
  assert.throws(() => checkUrl("https://localhost/x"), code("blocked_address"));
  assert.throws(() => checkUrl("not a url"), code("bad_url"));
  assert.throws(() => checkUrl("https://evil.example/x", { allowHosts: ["status.example", ".dmv.gov"] }), code("blocked_host"));
  assert.equal(checkUrl("https://lists.il.dmv.gov/x", { allowHosts: ["status.example", ".dmv.gov"] }).hostname, "lists.il.dmv.gov");
  assert.equal(checkUrl("https://status.example:443/x").hostname, "status.example");
});

test("DNS: a name resolving to any private address is refused before connecting", async () => {
  let connected = false;
  const { opts, close } = await server((_q, r) => { connected = true; r.end("x"); });
  try {
    await assert.rejects(safeFetch("https://status.example/l", { ...opts, blockList: undefined }), code("blocked_address"), "loopback, with the real block list");
    await assert.rejects(safeFetch("https://status.example/l", { ...opts, blockList: undefined, resolve: async () => ["8.8.8.8", "10.0.0.1"] }), code("blocked_address"), "one private answer among public ones");
    await assert.rejects(safeFetch("https://status.example/l", { ...opts, resolve: async () => { throw new Error("NXDOMAIN"); } }), code("dns_failed"));
    assert.equal(connected, false);
  } finally { await close(); }
});

test("fetch: reads a status list; refuses redirects, errors, oversize and slow answers", async () => {
  const { opts, close } = await server((q, r) => {
    if (q.url === "/jwt") { r.writeHead(200, { "content-type": "application/statuslist+jwt" }); return r.end("eyJ.a.b\n"); }
    if (q.url === "/cwt") { r.writeHead(200, { "content-type": "application/statuslist+cwt" }); return r.end(Buffer.from([0xd2, 0x84])); }
    if (q.url === "/html") { r.writeHead(200, { "content-type": "text/html" }); return r.end("<html>"); }
    if (q.url === "/redirect") { r.writeHead(302, { location: "https://169.254.169.254/latest/meta-data/" }); return r.end(); }
    if (q.url === "/big") { r.writeHead(200, { "content-type": "application/statuslist+jwt" }); r.write(Buffer.alloc(3000)); return r.end(Buffer.alloc(3000)); }
    if (q.url === "/declared") { r.writeHead(200, { "content-length": "999999999" }); return r.end(); }
    if (q.url === "/slow") return setTimeout(() => r.end("late"), 1500);
    if (q.url === "/cookie") { assert.equal(q.headers.cookie, undefined); assert.equal(q.headers.authorization, undefined); r.writeHead(200, { "content-type": "application/statuslist+jwt" }); return r.end("ok"); }
    r.writeHead(404); r.end();
  });
  try {
    const fetchList = statusListFetcher(opts);
    assert.equal(await fetchList("https://status.example/jwt"), "eyJ.a.b");
    assert.deepEqual([...(await fetchList("https://status.example/cwt"))], [0xd2, 0x84]);
    assert.equal(await fetchList("https://status.example/cookie"), "ok");
    await assert.rejects(fetchList("https://status.example/html"), code("bad_status_list"));
    await assert.rejects(fetchList("https://status.example/redirect"), code("redirect_refused"));
    await assert.rejects(fetchList("https://status.example/missing"), code("http_error"));
    await assert.rejects(safeFetch("https://status.example/big", { ...opts, maxBytes: 4000 }), code("too_large"));
    await assert.rejects(safeFetch("https://status.example/declared", { ...opts, maxBytes: 4000 }), code("too_large"));
    await assert.rejects(safeFetch("https://status.example/slow", { ...opts, timeoutMs: 200 }), code("timeout"));
    await assert.rejects(fetchList("http://status.example/jwt"), code("bad_url"));
  } finally { await close(); }
});

test("fetch: TLS is verified (a certificate for another name or from another CA fails)", async () => {
  const { opts, close } = await server((_q, r) => { r.writeHead(200, { "content-type": "application/statuslist+jwt" }); r.end("x"); });
  try {
    await assert.rejects(safeFetch("https://other.example/l", opts), code("network"), "wrong name");
    await assert.rejects(safeFetch("https://status.example/l", { ...opts, ca: tls().cert }), code("network"), "untrusted CA");
  } finally { await close(); }
});

test("status lists are cached and concurrent requests share one fetch", async () => {
  let hits = 0;
  const { opts, close } = await server((_q, r) => { hits++; setTimeout(() => { r.writeHead(200, { "content-type": "application/statuslist+jwt" }); r.end(`v${hits}`); }, 50); });
  try {
    const fetchList = statusListFetcher(opts);
    const [a, b] = await Promise.all([fetchList("https://status.example/l"), fetchList("https://status.example/l")]);
    assert.equal(a, b);
    assert.equal(await fetchList("https://status.example/l"), a);
    assert.equal(hits, 1);
    const noCache = statusListFetcher({ ...opts, cacheMs: 0 });
    await noCache("https://status.example/l"); await noCache("https://status.example/l");
    assert.equal(hits, 3);
  } finally { await close(); }
});
