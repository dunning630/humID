// SRV-32 (the SRV-25 residue): a signed-in session's frame may be as large as a vault upload,
// because the frame cap is chosen before the route is known. Every other route now has its own
// small cap, checked as soon as the frame is open and before anything parses the body, so one
// large JSON body can't stall the gateway's one event loop. Only POST /vault/objects keeps the
// large cap. Uses a gateway with a 4 MiB frame cap on the same upstreams, so the test needn't
// push 64 MiB through loopback.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { createGateway } from "../../services/gateway/src/server.js";
import { startStack } from "../e2e/stack.js";
import { makeHolder, sealFor } from "../e2e/holder.js";
import { HumidApi } from "@humid/api";

let stack, gw, api, holder;
const FRAME_CAP = 4 * 1024 * 1024;
before(async () => {
  stack = await startStack({ messaging: false });
  gw = createGateway({ port: 0, dataDir: `${stack.root}/gateway-caps`, internalSk: stack.internalSk, upstreams: stack.upstreams, allowedOrigins: [], trustProxy: false, devicePolicy: "attested", registration: "open", maxCallBytes: FRAME_CAP });
  await gw.start();
  holder = makeHolder("caps");
  api = new HumidApi({ baseUrl: `http://127.0.0.1:${gw.server.address().port}`, pinnedKid: gw.htp.kid });
  await api.register({ pub: holder.pub, commit: holder.commit, device: holder.device, sign: holder.registerSign });
});
after(async () => { await gw?.stop(); await stack?.stop(); });

/** A JSON object that is expensive to parse: a long array of small numbers. */
function bigJson(n) {
  const body = Buffer.alloc(n, 0x20);
  const head = Buffer.from('{"m":"GET","p":"/identity/me","x":[');
  head.copy(body, 0);
  let i = head.length;
  while (i < n - 4) { body[i] = 0x31; body[i + 1] = 0x2c; i += 2; }
  body[i - 1] = 0x31; body[i] = 0x5d; body[i + 1] = 0x7d;
  return new Uint8Array(body);
}

test("a 3 MiB JSON body to a control route is refused 413 before it is parsed", async () => {
  const body = bigJson(3 * 1024 * 1024);
  const h = monitorEventLoopDelay({ resolution: 5 }); h.enable();
  for (const [m, p] of [["POST", "/auth/step-up"], ["POST", "/auth/login"], ["POST", "/checkin/arm"], ["PUT", "/recovery/settings"], ["POST", "/recovery/requests"]]) {
    const r = await api.htp.call(m, p, { body, headers: { "content-type": "application/json" } });
    assert.equal(r.status, 413, `${m} ${p}`);
    assert.equal(r.json().error, "too_large");
  }
  h.disable();
  assert.ok(h.max / 1e6 < 400, `no long parse on the event loop (max stall ${Math.round(h.max / 1e6)} ms)`);
});

test("a body just under a control route's cap still gets through to its handler", async () => {
  const r = await api.htp.call("POST", "/auth/step-up", { body: { m: "GET", p: "/identity/me", pad: "x".repeat(32 * 1024) } });
  assert.equal(r.status, 200);
});

test("the vault upload keeps the large cap", async () => {
  const s = await sealFor(holder, "big.bin", "x".repeat(1024 * 1024)); // ~1 MiB envelope: over every control cap
  const out = await api.upload(s.envelope, s.index);
  assert.ok(out.id);
});

test("an oversized frame meta is refused when the frame is opened", async () => {
  const { sealFrame, DIR, MEDIA_TYPE } = await import("@humid/htp");
  const s = api.htp.session;
  const seq = ++api.htp.seq;
  const meta = { m: "GET", p: "/identity/me", h: { "x-pad": "y".repeat(200 * 1024) } };
  const frame = await sealFrame(s.c2s, DIR.request, s.sid, seq, meta, new Uint8Array(0));
  const res = await fetch(`http://127.0.0.1:${gw.server.address().port}/htp/v1/call`, { method: "POST", headers: { "content-type": MEDIA_TYPE }, body: frame });
  const j = await res.json();
  assert.equal(res.status, 400);
  assert.equal(j.error, "bad_frame");
});
