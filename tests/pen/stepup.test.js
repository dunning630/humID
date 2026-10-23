// Penetration regression: step-up proofs on a sensitive call (downloading a document).
// Each crafted proof must fail with the documented code; a good one works once.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { ml_dsa87, stepUpMessage } from "@humid/htp";
import { startStack } from "../e2e/stack.js";
import { makeHolder, sealFor } from "../e2e/holder.js";
import { registered } from "./_lib.js";

let stack, api, holder, id, htp;
before(async () => {
  stack = await startStack();
  ({ api, holder } = await registered(stack, "stepup-holder"));
  const { envelope, index } = await sealFor(holder, "secret.txt", "TOPSECRET");
  id = (await api.upload(envelope, index)).id;
  htp = api.htp;
});
after(async () => { await stack?.stop(); });

const path = () => `/vault/objects/${id}`;
const goodSign = (message, t) => ({ sig: ml_dsa87.sign(message, holder.dkeys.dsaSk), interrupt: holder.interrupt, live: holder.liveKey.sign(t.live) });
const call = (t, sign) => htp.call("GET", path(), { stepUp: { ticket: t, sign } });
const expectRefusal = async (t, sign, status, code) => {
  const r = await call(t, sign);
  assert.equal(r.status, status, `expected ${status} ${code}, got ${r.status} ${JSON.stringify(r.json())}`);
  assert.equal(r.json()?.error, code);
};

test("no proof at all: 403 step_up_required", async () => {
  await assert.rejects(api.download(id), (e) => e.code === "step_up_required" && e.status === 403);
});

test("proof over the wrong body hash: 401 bad_proof", async () => {
  const t = await htp.ticket("GET", path());
  const sign = () => {
    const bogus = stepUpMessage(htp.session.th, t.seq, "GET", path(), new TextEncoder().encode("x"), t.at, t.actionBytes);
    return goodSign(bogus, t);
  };
  await expectRefusal(t, sign, 401, "bad_proof");
});

test("proof signed by another device's key: 401 bad_proof", async () => {
  const mallory = makeHolder("stepup-mallory");
  const t = await htp.ticket("GET", path());
  const sign = (message) => ({ sig: ml_dsa87.sign(message, mallory.dkeys.dsaSk), interrupt: holder.interrupt, live: holder.liveKey.sign(t.live) });
  await expectRefusal(t, sign, 401, "bad_proof");
});

test("proof with a stale `at` (2 minutes old, consistently signed): 403 step_up_stale", async () => {
  const t = await htp.ticket("GET", path());
  t.at = Date.now() - 120_000;
  const sign = () => goodSign(stepUpMessage(htp.session.th, t.seq, "GET", path(), new Uint8Array(0), t.at, t.actionBytes), t);
  await expectRefusal(t, sign, 403, "step_up_stale");
});

test("a good proof works once; the same ticket (nonce and seq) again is 409 replay", async () => {
  const t = await htp.ticket("GET", path());
  const frames = [];
  const fetch = htp.fetch;
  htp.fetch = (url, init) => { if (init?.body instanceof Uint8Array) frames.push(init.body); return fetch(url, init); };
  let r1;
  try { r1 = await call(t, (m) => goodSign(m, t)); } finally { htp.fetch = fetch; }
  assert.equal(r1.status, 200);
  assert.ok(r1.body.length > 0, "ciphertext released");
  // The client won't send a second frame under that seq (CRYPTO-06: it would reuse the GCM nonce)…
  await assert.rejects(call(t, (m) => goodSign(m, t)), (e) => e.code === "ticket_used");
  // …and the captured frame, sent again by someone on the path, is refused by the server.
  const again = await fetch(`${htp.base}/htp/v1/call`, { method: "POST", headers: { "content-type": "application/vnd.humid.htp" }, body: frames.at(-1) });
  assert.equal(again.status, 409);
  assert.equal((await again.json()).error, "replay");
});

test("a nonce issued for one action used for another: 403 step_up_mismatch", async () => {
  const t = await htp.ticket("GET", path());
  const forged = { ...t, method: "DELETE" };
  const r = await htp.call("DELETE", path(), { stepUp: { ticket: forged, sign: (m) => goodSign(m, t) } });
  assert.equal(r.status, 403);
  assert.equal(r.json()?.error, "step_up_mismatch");
  // the document is still there
  assert.equal((await api.list()).items.length, 1);
});

test("a proof whose nonce was never issued: 403 step_up_unknown", async () => {
  const t = await htp.ticket("GET", path());
  const forged = { ...t, action: { ...t.action, nonce: new Uint8Array(32) } };
  const r = await htp.call("GET", path(), { stepUp: { ticket: forged, sign: (m) => goodSign(m, t) } });
  assert.equal(r.status, 403);
  assert.equal(r.json()?.error, "step_up_unknown");
});

test("every rejected proof is in the ledger as access.denied", async () => {
  const l = await api.ledger();
  assert.equal(l.ok, true, l.reason);
  const denied = l.entries.filter((e) => e.type === "access.denied").map((e) => e.detail.reason);
  // the two proofs that reached signature checking (wrong body, wrong key); stale and unknown nonces are refused before it
  assert.equal(denied.filter((r) => r === "bad_step_up").length, 2, `bad_step_up logged: ${JSON.stringify(denied)}`);
  assert.ok(denied.includes("step_up_required"));
});
