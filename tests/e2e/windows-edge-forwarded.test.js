// SRV-31: behind Tailscale Funnel nothing overwrites CF-Connecting-IP, so a visitor who
// sends a fresh one each time used to reset every per-address limit (hello 30/min, failed
// sign-ins, in-flight uploads, the relay's per-network quota). With the default
// HUMID_TRUST_FORWARDED=off the header is ignored and the limit holds.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clientHello, unb64u } from "@humid/htp";
import { startStack } from "./stack.js";
import { createGateway } from "../../services/gateway/src/server.js";
import { createEdge } from "../../deploy/windows/src/edge.mjs";

let stack, gw;
const edges = [];
before(async () => {
  stack = await startStack({ messaging: false });
  // a server-wide ceiling for unknown addresses of 40 (V76-03), so the test can reach it
  gw = createGateway({ port: 0, dataDir: `${stack.root}/gw-win`, internalSk: stack.internalSk, upstreams: stack.upstreams, allowedOrigins: [], trustProxy: true, devicePolicy: "attested", registration: "open", sharedHelloPerMin: 40 });
  await gw.start();
});
after(async () => { for (const e of edges) await e.stop(); await gw?.stop(); await stack?.stop(); });

async function edgeWith(trustForwarded) {
  const e = createEdge({ port: 0, host: "127.0.0.1", appDir: mkdtempSync(join(tmpdir(), "app-")), gatewayUrl: `http://127.0.0.1:${gw.server.address().port}`, trustForwarded, log: { error() {} } });
  await e.start();
  edges.push(e);
  return `http://127.0.0.1:${e.server.address().port}`;
}
async function hellos(base, n, header) {
  const j = await (await fetch(`${base}/htp/v1/keys`)).json();
  const body = JSON.stringify(clientHello({ kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) }).wire);
  let ok = 0;
  for (let i = 0; i < n; i++) {
    const r = await fetch(`${base}/htp/v1/hello`, { method: "POST", headers: { "content-type": "application/json", ...header(i) }, body });
    if (r.status === 200) ok++;
  }
  return ok;
}

test("default edge: a client-chosen CF-Connecting-IP doesn't buy a fresh per-address bucket", async () => {
  // every visitor draws on the one server-wide ceiling for unknown addresses, whatever the headers say
  const ok = await hellos(await edgeWith(undefined), 60, (i) => ({ "cf-connecting-ip": `198.51.100.${i}`, "x-forwarded-for": `203.0.113.${i}` }));
  assert.equal(ok, 40);
});

test("cloudflare edge: CF-Connecting-IP is used (Cloudflare overwrites it), X-Forwarded-For isn't", async () => {
  const base = await edgeWith("cloudflare");
  assert.equal(await hellos(base, 3, (i) => ({ "cf-connecting-ip": `192.0.2.${i}` })), 3);
  // one visitor rotating X-Forwarded-For while Cloudflare says the same address: one bucket
  assert.equal(await hellos(base, 35, (i) => ({ "cf-connecting-ip": "192.0.2.200", "x-forwarded-for": `203.0.113.${i}` })), 30);
});
