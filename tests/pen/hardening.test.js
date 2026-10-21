// Penetration regression: pre-authentication limits on the gateway and the recovery service
// (SRV-06 / F-03, F-05). Production defaults: 512 KiB for a session that has not signed in.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { signRequestAssertion } from "@humid/svc";
import { randomUUID } from "node:crypto";
import { startStack } from "../e2e/stack.js";
import { rawSession, frame, send } from "./_lib.js";

let stack;
before(async () => { stack = await startStack(); });
after(async () => { await stack?.stop(); });

test("a frame for an unknown session is refused from its header: session_unknown, however large it claims to be", async () => {
  const s = await rawSession(stack.baseUrl);
  const f = await frame(s, 1);
  const body = new Uint8Array(5 * 1024 * 1024);
  body.set(f);
  body[8] ^= 0x01; // a flipped sid byte: well-formed header, no such session
  const r = await send(stack.baseUrl, body);
  assert.equal(r.status, 401);
  assert.equal(r.error, "session_unknown");
});

test("a session that has not signed in cannot send more than the anonymous cap", async () => {
  const s = await rawSession(stack.baseUrl);
  const big = await send(stack.baseUrl, await frame(s, 1, { m: "POST", p: "/recovery/requests", h: {} }, new Uint8Array(700 * 1024)));
  assert.equal(big.status, 413);
  assert.equal(big.error, "too_large");
  // under the cap the same session is answered inside the channel
  const small = await send(stack.baseUrl, await frame(s, 2, { m: "GET", p: "/identity/me", h: {} }));
  assert.equal(small.cipher, true);
});

test("a huge declared Content-Length from an anonymous session is refused before the body is sent", async () => {
  const s = await rawSession(stack.baseUrl);
  const head = await frame(s, 1, { m: "GET", p: "/identity/me", h: {} });
  const port = new URL(stack.baseUrl).port;
  const out = await new Promise((resolve) => {
    const c = net.connect(port, "127.0.0.1"); let t = "";
    c.on("data", (d) => (t += d)); c.on("error", () => {}); c.on("close", () => resolve(t));
    c.write(`POST /htp/v1/call HTTP/1.1\r\nHost: x\r\nContent-Length: ${60 * 1024 * 1024}\r\n\r\n`); c.write(head);
    setTimeout(() => { c.destroy(); resolve(t); }, 600);
  });
  assert.match(out.split("\r\n")[0], /413/);
});

test("recovery routes answer a JSON null / array / scalar body with 400, not 500 (F-05)", async () => {
  const hdr = (aud, method, path, body) => ({ "x-humid-assertion": signRequestAssertion(stack.internalSk, { iss: "gateway", aud, rid: randomUUID(), sub: "hid_" + "a".repeat(40) }, { method, path, body: Buffer.from(body) }), "content-type": "application/json" });
  for (const [m, path] of [["POST", "/links"], ["POST", "/offers"], ["POST", "/requests"]]) {
    for (const body of ["null", "[]", "5", '"x"']) {
      const res = await fetch(`${stack.upstreams.recovery}${path}`, { method: m, headers: hdr("recovery", m, path, body), body });
      assert.equal(res.status, 400, `${m} ${path} ${body}`);
    }
  }
});
