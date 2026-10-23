// V76-04: behind a proxy (TRUST_PROXY=1) the gateway takes the visitor's address from the LAST
// X-Forwarded-For entry, the one the proxy wrote. Entries to its left come from the visitor and
// could be anything; taking the first let a visitor behind an appending proxy pick a fresh
// address, and so a fresh rate-limit bucket, every time.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { clientHello, unb64u } from "@humid/htp";
import { startStack } from "./stack.js";
import { createGateway } from "../../services/gateway/src/server.js";

let stack, gw, base;
before(async () => {
  stack = await startStack({ messaging: false });
  gw = createGateway({ port: 0, dataDir: `${stack.root}/gw-proxy`, internalSk: stack.internalSk, upstreams: stack.upstreams, allowedOrigins: [], trustProxy: true, devicePolicy: "attested", registration: "open" });
  await gw.start();
  base = `http://127.0.0.1:${gw.server.address().port}`;
});
after(async () => { await gw?.stop(); await stack?.stop(); });

test("a rotating first X-Forwarded-For entry doesn't buy a fresh bucket; the proxy's entry decides", async () => {
  const j = await (await fetch(`${base}/htp/v1/keys`)).json();
  // a fresh hello each time: the gateway refuses a replayed one before any work (CRYPTO-04)
  const fresh = () => JSON.stringify(clientHello({ kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) }).wire);
  const hello = (xff) => fetch(`${base}/htp/v1/hello`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": xff }, body: fresh() }).then((r) => r.status);
  let ok = 0;
  for (let i = 0; i < 40; i++) if ((await hello(`198.51.100.${i}, 203.0.113.9`)) === 200) ok++;
  assert.equal(ok, 30, "one visitor (203.0.113.9, as the proxy saw it), one bucket of 30");
  assert.equal(await hello("203.0.113.10"), 200, "another visitor has their own");
});
