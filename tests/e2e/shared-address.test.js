// V76-03: behind a tunnel that can't say who the visitor is (Tailscale Funnel with the Windows
// edge's HUMID_TRUST_FORWARDED=off) every visitor reaches the gateway from the same loopback
// address. One visitor's 30 handshakes a minute used to lock every holder out of opening a
// session, and with Check-in armed a holder who can't sign in misses the deadline and loses
// the vault. Now: an unknown address shares a much larger server-wide ceiling, and a holder
// who has signed in before carries a one-use hello pass past every handshake limit.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clientHello, unb64u } from "@humid/htp";
import { HumidApi } from "@humid/api";
import { startStack } from "./stack.js";
import { makeHolder } from "./holder.js";
import { createGateway } from "../../services/gateway/src/server.js";
import { createEdge } from "../../deploy/windows/src/edge.mjs";

const H = 3_600_000, MIN = 60_000;
let stack, gw, edge, base, mono = 0;
let alice, aliceApi, bobPass;
before(async () => {
  stack = await startStack({ messaging: false, checkin: "on", checkinSweepMs: 0, keyshareClock: { mono: () => mono, tickMs: 0 } });
  // a small server-wide ceiling, so the test can reach it quickly
  gw = createGateway({ port: 0, dataDir: `${stack.root}/gw-win`, internalSk: stack.internalSk, upstreams: stack.upstreams, allowedOrigins: [], trustProxy: true, devicePolicy: "attested", registration: "open", checkin: "on", checkinSweepMs: 0, sharedHelloPerMin: 40 });
  await gw.start();
  edge = createEdge({ port: 0, host: "127.0.0.1", appDir: mkdtempSync(join(tmpdir(), "app-")), gatewayUrl: `http://127.0.0.1:${gw.server.address().port}`, log: { error() {} } }); // trustForwarded: off
  await edge.start();
  base = `http://127.0.0.1:${edge.server.address().port}`;
  // Two holders who set up HumID before any of this, signed in through the tunnel as their
  // phones would (registered on the stack directly, so the tunnel's budget isn't spent on it).
  alice = makeHolder("alice-shared");
  await new HumidApi({ baseUrl: stack.baseUrl }).register({ pub: alice.pub, commit: alice.commit, device: alice.device, sign: alice.registerSign });
  aliceApi = new HumidApi({ baseUrl: base, pinnedKid: gw.htp.kid });
  await aliceApi.login({ id: alice.id, device: alice.deviceId, sign: alice.unlockSign(0) });
  await aliceApi.armCheckin({ windowMs: 2 * H, maxWindowMs: 8 * H, graceMs: 15 * MIN }, alice.stepUp);
  aliceApi.htp.close(); // the app was locked; its next unlock needs a new handshake
  const bob = makeHolder("bob-shared");
  await new HumidApi({ baseUrl: stack.baseUrl }).register({ pub: bob.pub, commit: bob.commit, device: bob.device, sign: bob.registerSign });
  const b = new HumidApi({ baseUrl: base, pinnedKid: gw.htp.kid });
  await b.login({ id: bob.id, device: bob.deviceId, sign: bob.sign });
  bobPass = b.session.helloPass;
});
after(async () => { await edge?.stop(); await gw?.stop(); await stack?.stop(); });

async function flood(n) {
  const j = await (await fetch(`${base}/htp/v1/keys`)).json();
  const body = JSON.stringify(clientHello({ kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) }).wire);
  let ok = 0;
  for (let i = 0; i < n; i++) if ((await fetch(`${base}/htp/v1/hello`, { method: "POST", headers: { "content-type": "application/json" }, body })).status === 200) ok++;
  return ok;
}

test("an unknown address gets the server-wide ceiling, not 30 for everyone", async () => {
  const ok = await flood(45);
  assert.ok(ok > 30 && ok <= 40, `past 30, up to the server-wide 40 (setup used two): ${ok}`);
});

test("a returning holder signs in and checks in while strangers exhaust the shared ceiling", async () => {
  await flood(80); // a stranger keeps the shared ceiling empty
  const stranger = new HumidApi({ baseUrl: base, pinnedKid: gw.htp.kid });
  await assert.rejects(stranger.htp.connect(), (e) => e.code === "rate_limited", "the ceiling is spent");
  // Alice's phone presents its one-use pass: it gets through, signs in and checks in
  await aliceApi.login({ id: alice.id, device: alice.deviceId, sign: alice.unlockSign(0) });
  const st = await aliceApi.checkIn({}, alice.stepUp);
  assert.equal(st.state, "armed");
  // the pass was used up, and a new one came with the new session
  assert.match(String(aliceApi.session.helloPass), /^[A-Za-z0-9_-]{43}$/);
});

test("a hello pass works once, and a made-up one is just an ordinary hello", async () => {
  const j = await (await fetch(`${base}/htp/v1/keys`)).json();
  const body = JSON.stringify(clientHello({ kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) }).wire);
  await flood(80);
  const hello = (pass) => fetch(`${base}/htp/v1/hello`, { method: "POST", headers: { "content-type": "application/json", ...(pass ? { "x-humid-hello-pass": pass } : {}) }, body }).then((r) => r.status);
  assert.equal(await hello("A".repeat(43)), 429, "an unknown pass doesn't skip the limit");
  assert.equal(await hello(bobPass), 200);
  assert.equal(await hello(bobPass), 429, "spent");
});
