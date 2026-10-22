// @humid/svc hardening: a bad request never takes the process down, body caps are enforced
// before anything is buffered, and a JSON body that is not an object is a 400.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { createService, json, parseObject, HttpError } from "../packages/svc/src/index.js";

let svc, port;
before(async () => {
  const routes = [
    ["POST", "/small", ({ body }) => json(200, { n: body.length }), { public: true, bodyLimit: 1024 }],
    ["POST", "/obj", ({ body }) => json(200, parseObject(body)), { public: true }],
    ["GET", "/boom", () => { throw new TypeError("boom"); }, { public: true }],
    ["GET", "/item/:id", ({ params }) => json(200, params), { public: true }],
    ["POST", "/adaptive", ({ body }) => json(200, { n: body.length }), { public: true, readLimit: { max: 100_000, peek: 4, decide: (p) => { if (p[0] === 0x78) throw new HttpError(401, "nope", "no"); return p[0] === 0x73 ? 10 : 100_000; } } }],
  ];
  svc = createService({ name: "t", port: 0, routes, extraHeaders: (req) => { if (req.headers["x-throw"]) throw new Error("header boom"); return {}; } });
  await svc.start();
  port = svc.server.address().port;
});
after(async () => { await svc?.stop(); });

const raw = (payload, { wait = 400, end = false } = {}) => new Promise((resolve) => {
  const s = net.connect(port, "127.0.0.1"); let out = "";
  s.on("data", (d) => (out += d)); s.on("error", () => {}); s.on("close", () => resolve(out));
  s.write(payload); if (end) s.end();
  setTimeout(() => { s.destroy(); resolve(out); }, wait);
});
const status = (r) => Number((r.split("\r\n")[0] || "").split(" ")[1]) || 0;
const alive = async () => (await fetch(`http://127.0.0.1:${port}/healthz`)).status === 200;

test("malformed request targets are 400 and the process survives (SRV-03 / F-01)", async () => {
  for (const t of ["//", "http://[", "//[", "///", "//evil.example/item/1", "*", "http://x/item/1"]) {
    const r = await raw(`GET ${t} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
    assert.equal(status(r), 400, `GET ${t}`);
  }
  assert.equal(status(await raw("GET /item/%E0%A4%A HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")), 400);
  assert.ok(await alive());
});

test("an unexpected error in a handler or in the reply path is a 500 for that request only", async () => {
  assert.equal(status(await raw("GET /boom HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")), 500);
  assert.equal(status(await raw("GET /item/1 HTTP/1.1\r\nHost: x\r\nx-throw: 1\r\nConnection: close\r\n\r\n")), 500);
  assert.equal(status(await raw("GARBAGE\r\n\r\n")), 400);
  assert.ok(await alive());
  assert.equal((await fetch(`http://127.0.0.1:${port}/item/ok`)).status, 200);
});

test("a declared Content-Length over the route cap is refused without reading the body (SRV-06 / F-03)", async () => {
  // headers only, body never sent: the 413 must still arrive
  const r = await raw("POST /small HTTP/1.1\r\nHost: x\r\nContent-Length: 104857600\r\n\r\n");
  assert.equal(status(r), 413);
  assert.match(r, /too_large/);
  assert.ok(await alive());
});

test("a streamed (chunked) body is cut off at the cap and the connection is closed", async () => {
  const chunk = "x".repeat(600);
  const msg = "POST /small HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + `${chunk.length.toString(16)}\r\n${chunk}\r\n`.repeat(4);
  const r = await raw(msg, { wait: 1000 });
  assert.equal(status(r), 413);
  assert.match(r.toLowerCase(), /connection: close/);
  // a body within the cap still works
  const ok = await fetch(`http://127.0.0.1:${port}/small`, { method: "POST", body: "y".repeat(1000) });
  assert.deepEqual(await ok.json(), { n: 1000 });
});

test("a route can choose its cap from the first bytes of the body, or refuse it at once", async () => {
  const post = (b) => fetch(`http://127.0.0.1:${port}/adaptive`, { method: "POST", body: b });
  assert.equal((await post("s" + "a".repeat(50))).status, 413);        // 's' → cap 10
  assert.equal((await post("s" + "a".repeat(5))).status, 200);
  assert.equal((await post("b" + "a".repeat(50_000))).status, 200);     // otherwise the large cap
  assert.equal((await post("x" + "a".repeat(50))).status, 401);         // refused from the prefix
  assert.equal((await post("x")).status, 401);                          // shorter than the peek: decided at the end
});

test("JSON null, arrays and scalars are a 400 where an object is required (F-05)", async () => {
  for (const b of ["null", "[]", "5", '"x"', "true", ""]) {
    const res = await fetch(`http://127.0.0.1:${port}/obj`, { method: "POST", body: b });
    assert.equal(res.status, 400, b);
    assert.equal((await res.json()).error, "bad_json");
  }
  assert.equal((await fetch(`http://127.0.0.1:${port}/obj`, { method: "POST", body: '{"a":1}' })).status, 200);
});

/* PC-08: an internal assertion is good for one request only. The audit's proof of concept:
   one assertion the gateway made for reading one object was accepted for listing the vault
   and deleting a different object. */
test("PC-08: an internal assertion can't be replayed or turned into another request", async () => {
  const { signRequest, verifyAssertion, newInternalKeys } = await import("../packages/svc/src/index.js");
  const reply = json;
  const k = newInternalKeys();
  const seen = [];
  const svc = createService({
    name: "vault-test", port: 0, verify: (t) => verifyAssertion(k.pk, t, "vault"),
    routes: [
      ["GET", "/objects/:id", ({ params }) => { seen.push(`get ${params.id}`); return reply(200, { ok: true }); }],
      ["GET", "/objects", () => { seen.push("list"); return reply(200, { ok: true }); }],
      ["DELETE", "/objects/:id", ({ params }) => { seen.push(`delete ${params.id}`); return reply(200, { ok: true }); }],
    ],
  });
  await svc.start();
  try {
    const base = `http://127.0.0.1:${svc.server.address().port}`;
    const mint = (method, path, body) => signRequest(k.sk, { aud: "vault", method, path, body, claims: { sub: "hid_" + "a".repeat(40), stepUp: { at: Date.now() } } });
    const call = (method, path, a, body) => fetch(base + path, { method, headers: { "x-humid-assertion": a }, body });
    const read = mint("GET", "/objects/aaaa");
    assert.equal((await call("GET", "/objects/aaaa", read)).status, 200);
    assert.equal((await call("GET", "/objects/aaaa", read)).status, 401, "used once");
    const read2 = mint("GET", "/objects/aaaa");
    assert.equal((await call("GET", "/objects", read2)).status, 401, "not for another path");
    assert.equal((await call("DELETE", "/objects/bbbb", read2)).status, 401, "not for another method or object");
    const del = mint("DELETE", "/objects/bbbb", Buffer.from("x"));
    assert.equal((await call("DELETE", "/objects/bbbb", del, "y")).status, 401, "not with another body");
    assert.deepEqual(seen, ["get aaaa"]);
  } finally { await svc.stop(); }
});
