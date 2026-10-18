// Penetration regression: session fixation and mixing. A frame is bound to the
// session whose keys sealed it; a dead or never-issued session id opens nothing.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { sealFrame, DIR } from "@humid/htp";
import { startStack } from "../e2e/stack.js";
import { rawSession, frame, send, registered, assertNoLeak } from "./_lib.js";

let stack, A, B;
before(async () => { stack = await startStack(); A = await rawSession(stack.baseUrl); B = await rawSession(stack.baseUrl); });
after(async () => { await stack?.stop(); });

const ME = { m: "GET", p: "/identity/me", h: {} };

test("control: B's sid with B's keys is accepted", async () => {
  const r = await send(stack.baseUrl, await frame(B, 1));
  assert.equal(r.status, 200);
  assert.equal(r.cipher, true);
});

test("A's sid sealed with B's keys: bad_frame (the sid is bound into the AEAD)", async () => {
  const r = await send(stack.baseUrl, await sealFrame(B.c2s, DIR.request, A.sid, 1, ME, undefined));
  assert.equal(r.status, 400);
  assert.equal(r.error, "bad_frame");
  assertNoLeak(assert, r.text);
  // and A's own seq 1 was not consumed by the attempt
  assert.equal((await send(stack.baseUrl, await frame(A, 1))).status, 200);
});

test("a sid after logout: session_unknown, and the keys open nothing", async () => {
  const { api } = await registered(stack, "sessions-logout");
  const { sid, c2s } = api.htp.session;
  await api.logout();
  const r = await send(stack.baseUrl, await sealFrame(c2s, DIR.request, sid, 999, ME, undefined));
  assert.equal(r.status, 401);
  assert.equal(r.error, "session_unknown");
  assertNoLeak(assert, r.text);
});

test("a call before any hello (a sid the server never issued): session_unknown", async () => {
  const fake = new Uint8Array(16);
  fake.set([1, 2, 3, 4]);
  const r = await send(stack.baseUrl, await sealFrame(A.c2s, DIR.request, fake, 1, ME, undefined));
  assert.equal(r.status, 401);
  assert.equal(r.error, "session_unknown");
});

test("a session that never signed in gets sign_in_required on an account route, inside the encrypted channel", async () => {
  const { HtpClient } = await import("@humid/htp/client");
  const c = new HtpClient({ baseUrl: stack.baseUrl });
  const r = await c.call("GET", "/vault/objects");
  assert.equal(r.status, 401);
  assert.equal(r.json().error, "sign_in_required");
  c.close();
});

test("a signed-in session's keys cannot be reused by a second handshake (each hello is a new session)", async () => {
  const { api, holder } = await registered(stack, "sessions-two");
  const first = api.htp.session.sidText;
  await api.htp.connect(); // a new handshake: new keys, the old session is dropped client-side
  assert.notEqual(api.htp.session.sidText, first);
  const r = await api.htp.call("GET", "/identity/me");
  assert.equal(r.status, 401, "the new session is not signed in until the holder signs again");
  assert.equal(r.json().error, "sign_in_required");
  const s = await api.login({ id: holder.id, device: holder.deviceId, sign: holder.sign });
  assert.equal(s.id, holder.id);
});
