// Penetration regression: the gateway's edges. Device policy, malformed handshakes,
// oversize bodies and the per-IP handshake limiter, all at production values.
// The handshake flood runs last: it empties this process's hello bucket.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { clientHello, unb64u } from "@humid/htp";
import { createGateway } from "../../services/gateway/src/server.js";
import { startStack } from "../e2e/stack.js";
import { makeHolder } from "../e2e/holder.js";
import { HumidApi } from "@humid/api";
import { hello, send, registered, assertNoLeak } from "./_lib.js";

let stack;
before(async () => { stack = await startStack(); }); // devicePolicy "attested", like production
after(async () => { await stack?.stop(); });

test("demo gate under the attested policy: 403 device_not_proven, no account created", async () => {
  await assert.rejects(registered(stack, "limits-demo", { kind: "demo" }), (e) => e.code === "device_not_proven" && e.status === 403);
  // a desktop biometric gate without hardware proof is refused the same way
  await assert.rejects(registered(stack, "limits-desktop", { kind: "desktop" }), (e) => e.code === "device_not_proven" && e.status === 403);
});

test("malformed hello bodies: bad_json or handshake_rejected, never a stack trace", async () => {
  const cases = [
    ["not json", "{not json", "bad_json"],
    ["empty", "", "handshake_rejected"],
    ["null", "null", "handshake_rejected"],
    ["wrong types", JSON.stringify({ v: 1, suite: "x", kid: 123, nC: {}, ts: "abc", ekC: [], xC: null, ctS: false }), "handshake_rejected"],
    ["unknown kid", JSON.stringify({ v: 1, suite: "HTP1-MLKEM1024+X25519-HKDF-SHA3-256-AES256GCM", kid: "00".repeat(32), nC: "AAAA", ts: Date.now(), ekC: "AAAA", xC: "AAAA", ctS: "AAAA" }), "handshake_rejected"],
  ];
  for (const [name, body, code] of cases) {
    const r = await hello(stack.baseUrl, body);
    assert.equal(r.status, 400, name);
    assert.equal(r.error, code, name);
    assertNoLeak(assert, r.text);
  }
});

test("oversize hello body: 413 too_large before anything is parsed", async () => {
  const r = await hello(stack.baseUrl, "x".repeat(17 * 1024));
  assert.equal(r.status, 413);
  assert.equal(r.error, "too_large");
  assertNoLeak(assert, r.text);
});

test("oversize call body: 413 too_large at the gateway's frame limit", async () => {
  // The same gateway code on the same upstreams, with a small frame cap, so the test
  // doesn't have to push 64 MB through loopback to reach the production limit.
  const gw = createGateway({ port: 0, dataDir: `${stack.root}/gateway-small`, internalSk: stack.internalSk, upstreams: stack.upstreams, allowedOrigins: [], trustProxy: false, devicePolicy: "attested", registration: "open", maxCallBytes: 4096 });
  await gw.start();
  try {
    const base = `http://127.0.0.1:${gw.server.address().port}`;
    const r = await send(base, new Uint8Array(8192));
    assert.equal(r.status, 413);
    assert.equal(r.error, "too_large");
    assertNoLeak(assert, r.text);
    // and a body under the cap gets the ordinary frame refusal, so the cap is what refused the big one
    assert.equal((await send(base, new Uint8Array(1024))).error, "bad_frame");
  } finally { await gw.stop(); }
});

test("SRV-24: unknown account, unknown device and wrong key get one answer, in similar time", async () => {
  const { api, holder } = await registered(stack, "limits-victim");
  await api.logout();
  const mallory = makeHolder("limits-mallory");
  const { ml_dsa87 } = await import("@humid/htp");
  const wrongKey = async (m) => ({ sig: ml_dsa87.sign(m, mallory.dkeys.dsaSk), interrupt: holder.interrupt, live: holder.liveKey.sign(m) });
  const attempt = async (id, device) => {
    const t0 = performance.now();
    const out = await new HumidApi({ baseUrl: stack.baseUrl }).login({ id, device, sign: wrongKey }).then(() => "ok", (e) => `${e.status}/${e.code}/${e.message}`);
    return { out, ms: performance.now() - t0 };
  };
  const cases = { unknown: [`hid_${"0".repeat(40)}`, `dev_${"0".repeat(24)}`], unknownDevice: [holder.id, `dev_${"0".repeat(24)}`], wrongKey: [holder.id, holder.deviceId] };
  const times = { unknown: [], unknownDevice: [], wrongKey: [] };
  const answers = new Set();
  for (let round = 0; round < 5; round++) {
    for (const [k, [id, dev]] of Object.entries(cases)) { const r = await attempt(id, dev); answers.add(r.out); times[k].push(r.ms); }
  }
  assert.deepEqual([...answers], ["401/bad_proof/Sign-in proof was rejected."], "one answer, whatever was wrong");
  // Same work on every path (the signature is always checked, the ledger note comes after the
  // reply). A loose bound: this box is shared, so it only catches a large, systematic gap.
  const med = (a) => [...a].sort((x, y) => x - y)[2];
  const m = Object.values(times).map(med);
  // before the fix an unknown account skipped every signature check (two ML-DSA verifies and a
  // ledger write): a gap of the order of the whole sign-in. Allow scheduling noise, not that.
  assert.ok(Math.max(...m) < 2 * Math.min(...m) + 25, `medians differ too much: ${m.map((x) => x.toFixed(1)).join(" / ")} ms`);
});

test("a replayed hello: 409 replay, and the gateway does none of the handshake work again (CRYPTO-04)", async () => {
  const j = await (await fetch(`${stack.baseUrl}/htp/v1/keys`)).json();
  const { wire } = clientHello({ kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) });
  const body = JSON.stringify(wire);
  assert.equal((await hello(stack.baseUrl, body)).status, 200);
  const sessions = stack.gateway.htp.sessions.size;
  const again = await hello(stack.baseUrl, body);
  assert.equal(again.status, 409);
  assert.equal(again.error, "replay");
  assertNoLeak(assert, again.text);
  assert.equal(stack.gateway.htp.sessions.size, sessions, "no second session");
});

test("handshake flood from one IP: at most 30 succeed per minute, the rest are 429 rate_limited", async () => {
  const j = await (await fetch(`${stack.baseUrl}/htp/v1/keys`)).json();
  const server = { kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) };
  let ok = 0, limited = 0, other = 0, lastText = "";
  for (let i = 0; i < 50; i++) {
    const { wire } = clientHello(server);
    const r = await hello(stack.baseUrl, JSON.stringify(wire));
    if (r.status === 200) ok++;
    else if (r.status === 429 && r.error === "rate_limited") { limited++; lastText = r.text; }
    else other++;
  }
  assert.equal(other, 0, "only success or rate_limited");
  assert.ok(ok <= 30, `${ok} handshakes got through (limit 30/min/IP)`);
  assert.ok(limited >= 20, `${limited} refused`);
  assertNoLeak(assert, lastText);
  // the limit holds: one more is still refused
  const { wire } = clientHello(server);
  assert.equal((await hello(stack.baseUrl, JSON.stringify(wire))).error, "rate_limited");
});
