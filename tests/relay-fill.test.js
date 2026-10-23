// The relay can't be filled, or locked, by a few networks (precert PC-27, security review MSG-05).
// Against services/relay with scaled-down caps (the same code paths as the defaults).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelay } from "@humid/relay-service";
import { newInternalKeys, signRequest, internalRequest } from "@humid/svc";

const ik = newInternalKeys();
const root = mkdtempSync(join(tmpdir(), "humid-relay-fill-"));
after(() => rmSync(root, { recursive: true, force: true }));

async function call(relay, path, body, rk, headers = {}) {
  const url = `http://127.0.0.1:${relay.server.address().port}${path}`;
  const assertion = signRequest(ik.sk, { aud: "relay", method: "POST", path, body, claims: { iss: "gateway", rk } });
  const res = await internalRequest(url, { method: "POST", headers: { "x-humid-assertion": assertion, ...headers }, body });
  return res.status;
}
const box = (i) => i.toString(16).padStart(32, "0");
const wire = (n) => { const w = new Uint8Array(n); w[0] = 1; return w; };
const K = 262144;

test("MSG-05: a few addresses in one /24 can't fill the relay; an honest network still deposits", async () => {
  // total 8 units, 2 per address, 3 per /24: the PoC filled it from four addresses in one /24
  const relay = createRelay({ port: 0, dataDir: join(root, "a"), internalPk: ik.pk, maxTotalBytes: 8 * K, maxNetBytesPerDay: 2 * K, maxBlockBytesPerDay: 3 * K, maxPerBox: 500, maxBoxBytes: 64 * 1024 * 1024 });
  await relay.start();
  try {
    let n = 0, ok = 0, quota = 0;
    for (let net = 0; net < 4; net++) for (let k = 0; k < 2; k++) {
      const s = await call(relay, "/internal/put", wire(K), `v4:203.0.113.${net}`, { "x-humid-box": box(n++) });
      if (s === 201) ok++; else if (s === 429) quota++;
    }
    assert.equal(ok, 3, "the /24 as a whole stops at its quota");
    assert.equal(quota, 5);
    assert.equal(await call(relay, "/internal/put", wire(8192), "v4:198.51.100.7", { "x-humid-box": box(999) }), 201, "an ordinary message from elsewhere goes in");
    // IPv6: /48s inside one /32 count together too
    for (let i = 0; i < 4; i++) await call(relay, "/internal/put", wire(K), `v6:2001:db8:${i.toString(16)}:1::/64`, { "x-humid-box": box(500 + i) });
    assert.equal(await call(relay, "/internal/put", wire(K), "v6:2001:db8:ff:1::/64", { "x-humid-box": box(600) }), 429);
  } finally { await relay.stop(); relay.close(); }
});

test("MSG-05: near full, only networks over a fair share are refused", async () => {
  const relay = createRelay({ port: 0, dataDir: join(root, "b"), internalPk: ik.pk, maxTotalBytes: 8 * K, maxNetBytesPerDay: 8 * K, maxBlockBytesPerDay: 8 * K, fairAboveFraction: 0.5, maxPerBox: 500, maxBoxBytes: 64 * 1024 * 1024 });
  await relay.start();
  try {
    // one heavy network takes half the relay
    for (let i = 0; i < 4; i++) assert.equal(await call(relay, "/internal/put", wire(K), "v4:203.0.113.1", { "x-humid-box": box(i) }), 201);
    // two others deposit a little
    assert.equal(await call(relay, "/internal/put", wire(8192), "v4:198.51.100.7", { "x-humid-box": box(100) }), 201);
    assert.equal(await call(relay, "/internal/put", wire(8192), "v4:192.0.2.7", { "x-humid-box": box(101) }), 201);
    // past half full: the heavy one is over its share (8 / 3 blocks) and refused; the light ones aren't
    assert.equal(await call(relay, "/internal/put", wire(K), "v4:203.0.113.1", { "x-humid-box": box(4) }), 429);
    assert.equal(await call(relay, "/internal/put", wire(8192), "v4:198.51.100.7", { "x-humid-box": box(102) }), 201);
  } finally { await relay.stop(); relay.close(); }
});

test("MSG-13: the relay writes no log line per deposit or fetch", async () => {
  const relay = createRelay({ port: 0, dataDir: join(root, "d"), internalPk: ik.pk });
  await relay.start();
  const lines = [];
  const write = process.stdout.write;
  process.stdout.write = (chunk, ...rest) => { lines.push(String(chunk)); return write.call(process.stdout, chunk, ...rest); };
  try {
    assert.equal(await call(relay, "/internal/put", wire(4096), "v4:198.51.100.7", { "x-humid-box": box(7) }), 201);
    assert.equal(await call(relay, "/internal/take", new TextEncoder().encode(JSON.stringify({ boxes: [box(7)] })), "v4:198.51.100.7", { "content-type": "application/json" }), 200);
  } finally { process.stdout.write = write; await relay.stop(); relay.close(); }
  assert.ok(!lines.some((l) => l.includes('"service":"relay"') && l.includes('"msg":"req"')), "no per-request timestamps to line up with the issuer's");
});

test("MSG-05: the per-minute limits never lock out a new network, however many keys are live", async () => {
  const relay = createRelay({ port: 0, dataDir: join(root, "c"), internalPk: ik.pk, maxRateKeys: 2000 });
  await relay.start();
  try {
    const take = (rk) => call(relay, "/internal/take", new TextEncoder().encode(JSON.stringify({ boxes: [box(1)] })), rk, { "content-type": "application/json" });
    for (let i = 0; i < 2100; i++) await take(`v6:2001:db8:${(i >> 16).toString(16)}:${(i & 0xffff).toString(16)}::/64`);
    assert.equal(await take("v4:198.51.100.9"), 200, "an honest new network can still fetch its messages");
  } finally { await relay.stop(); relay.close(); }
});
