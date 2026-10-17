// Penetration regression: replayed, stale, tampered and malformed HTP/1 frames.
// Every refusal is the exact code docs/PROTOCOL.md documents, with no internals in the body.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { HEADER_LEN, WINDOW, FRAME_SKEW_MS } from "@humid/htp";
import { startStack } from "../e2e/stack.js";
import { rawSession, frame, send, flip, assertNoLeak } from "./_lib.js";

let stack, s;
before(async () => { stack = await startStack(); s = await rawSession(stack.baseUrl); });
after(async () => { await stack?.stop(); });

test("a well-formed frame is accepted (baseline for everything below)", async () => {
  const r = await send(stack.baseUrl, await frame(s, 1));
  assert.equal(r.status, 200);
  assert.equal(r.cipher, true, "the answer is an encrypted frame, not a JSON refusal");
});

test("replay: the same frame again is refused with 409 replay", async () => {
  const f = await frame(s, 2);
  assert.equal((await send(stack.baseUrl, f)).status, 200);
  const r = await send(stack.baseUrl, f);
  assert.equal(r.status, 409);
  assert.equal(r.error, "replay");
  assertNoLeak(assert, r.text);
});

test("replay: a decremented sequence number (seq 0) is refused with 409 replay", async () => {
  const r = await send(stack.baseUrl, await frame(s, 0));
  assert.equal(r.status, 409);
  assert.equal(r.error, "replay");
});

test("replay: a jump ahead is accepted, then an old seq behind the window is refused", async () => {
  const ahead = await send(stack.baseUrl, await frame(s, 1000));
  assert.equal(ahead.status, 200, "a fresh, higher seq moves the window");
  const old = await send(stack.baseUrl, await frame(s, 1000 - WINDOW - 1));
  assert.equal(old.status, 409);
  assert.equal(old.error, "replay");
  // and a seq inside the new window that was never used is still fine
  assert.equal((await send(stack.baseUrl, await frame(s, 999))).status, 200);
});

test("stale frames: a timestamp 3 minutes ahead or behind is refused with stale_frame", async () => {
  assert.ok(3 * 60_000 > FRAME_SKEW_MS, "the probe is outside the documented window");
  for (const skew of [3 * 60_000, -3 * 60_000]) {
    const r = await send(stack.baseUrl, await frame(s, 1001 + (skew > 0 ? 0 : 1), undefined, undefined, Date.now() + skew));
    assert.equal(r.status, 400, `skew ${skew}`);
    assert.equal(r.error, "stale_frame");
    assertNoLeak(assert, r.text);
  }
});

test("tampered header (session id byte): session_unknown, nothing decrypted", async () => {
  const r = await send(stack.baseUrl, flip(await frame(s, 1010), 6)); // offset 6 is inside the 16-byte sid
  assert.equal(r.status, 401);
  assert.equal(r.error, "session_unknown");
  assertNoLeak(assert, r.text);
});

test("tampered ciphertext: bad_frame, and the untouched seq is still usable", async () => {
  const f = await frame(s, 1011);
  const r = await send(stack.baseUrl, flip(f, HEADER_LEN + 5));
  assert.equal(r.status, 400);
  assert.equal(r.error, "bad_frame");
  assertNoLeak(assert, r.text);
  // the replay window only moves after authentication, so the genuine frame still goes through
  assert.equal((await send(stack.baseUrl, f)).status, 200);
});

test("tampered authentication tag: bad_frame", async () => {
  const f = await frame(s, 1012);
  const r = await send(stack.baseUrl, flip(f, f.length - 1));
  assert.equal(r.status, 400);
  assert.equal(r.error, "bad_frame");
  assertNoLeak(assert, r.text);
});

test("empty and garbage bodies are refused as bad_frame without a stack trace", async () => {
  for (const body of [new Uint8Array(0), new TextEncoder().encode("garbage-not-a-frame"), new Uint8Array(HEADER_LEN + 16).fill(0x41)]) {
    const r = await send(stack.baseUrl, body);
    assert.equal(r.status, 400, `body of ${body.length} bytes`);
    assert.equal(r.error, "bad_frame");
    assertNoLeak(assert, r.text);
  }
  // a frame whose header says "response" is not a request either
  const f = await frame(s, 1013);
  f[4] = 0x02;
  const r = await send(stack.baseUrl, f);
  assert.equal(r.status, 400);
  assert.equal(r.error, "bad_frame");
});

test("the content-type header is not trusted: a valid frame sent as text/plain is still processed", async () => {
  const r = await send(stack.baseUrl, await frame(s, 1014), "text/plain");
  assert.equal(r.status, 200);
  assert.equal(r.cipher, true);
});

test("GET on /htp/v1/call and /htp/v1/hello is not a route", async () => {
  for (const p of ["/htp/v1/call", "/htp/v1/hello"]) {
    const res = await fetch(`${stack.baseUrl}${p}`);
    assert.equal(res.status, 404);
    const j = await res.json();
    assert.equal(j.error, "not_found");
  }
});
