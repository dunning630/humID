// HTP/1 protocol properties. Client and server run in-process; the "network"
// is a fetch function that routes to the server core, so tests can tamper
// with traffic exactly as an attacker in the middle could.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HtpClient } from "@humid/htp/client";
import { HtpServer, createStatics } from "@humid/htp/server";
import {
  ml_dsa87, stepUpMessage, actionBytes, loginMessage, verify, ReplayWindow, MEDIA_TYPE,
} from "@humid/htp";

const ISSUED = { nonce: new Uint8Array(16).fill(5), exp: Date.now() + 60_000, device: "dev_test" };
function wire(server, { tamper } = {}) {
  const log = [];
  const fetch = async (url, init = {}) => {
    const path = new URL(url, "http://x").pathname;
    const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
    try {
      if (path === "/htp/v1/keys") return json(200, server.publicKeys());
      if (path === "/htp/v1/hello") return json(200, server.hello(JSON.parse(init.body)));
      if (path === "/htp/v1/call") {
        let frame = new Uint8Array(init.body);
        log.push(frame);
        if (tamper) frame = tamper(frame);
        const { session, seq, meta, body } = await server.open(frame);
        // a step-up approval, as the gateway issues it
        const reply = meta.p === "/auth/step-up"
          ? { nonce: Buffer.from(ISSUED.nonce).toString("base64url"), exp: ISSUED.exp, device: ISSUED.device }
          : { echo: meta, bodyLen: body.length, proof: meta.proof || null, th: Buffer.from(session.th).toString("hex") };
        return new Response(await server.seal(session, seq, 200, { "content-type": "application/json" }, new TextEncoder().encode(JSON.stringify(reply))), { headers: { "content-type": MEDIA_TYPE } });
      }
      return json(404, { error: "not_found" });
    } catch (e) {
      return json(e.status || 500, { error: e.code || "error", message: e.message });
    }
  };
  return { fetch, log };
}

test("handshake + encrypted call round trip", async () => {
  const server = new HtpServer(createStatics());
  const { fetch } = wire(server);
  const client = new HtpClient({ fetch, pinnedKid: server.kid });
  const res = await client.call("POST", "/vault/objects", { body: new Uint8Array([1, 2, 3]) });
  assert.equal(res.status, 200);
  const j = res.json();
  assert.equal(j.echo.m, "POST");
  assert.equal(j.echo.p, "/vault/objects");
  assert.equal(j.bodyLen, 3);
  // Both sides derived the same transcript hash.
  assert.equal(j.th, Buffer.from(client.transcript).toString("hex"));
});

test("a different server is refused when the key id is pinned", async () => {
  const real = new HtpServer(createStatics());
  const impostor = new HtpServer(createStatics());
  const client = new HtpClient({ fetch: wire(impostor).fetch, pinnedKid: real.kid });
  await assert.rejects(client.call("GET", "/x"), /does not match/);
});

test("a server that substitutes its own keys mid-handshake fails key confirmation", async () => {
  const real = new HtpServer(createStatics());
  const mitm = new HtpServer(createStatics());
  // MITM serves the real public keys but answers the hello with its own static keys.
  const fetch = async (url, init) => {
    const p = new URL(url, "http://x").pathname;
    if (p === "/htp/v1/keys") return Response.json(real.publicKeys());
    if (p === "/htp/v1/hello") {
      const hello = JSON.parse(init.body);
      hello.kid = mitm.kid; // cannot decapsulate the real ctS, so must fake
      try { return Response.json(mitm.hello(hello)); } catch (e) { return Response.json({ error: e.code }, { status: 400 }); }
    }
  };
  const client = new HtpClient({ fetch, pinnedKid: real.kid });
  await assert.rejects(client.connect(), /key confirmation/);
});

test("tampered frames are rejected before anything is processed", async () => {
  const server = new HtpServer(createStatics());
  const { fetch } = wire(server, { tamper: (f) => { const c = f.slice(); c[c.length - 5] ^= 1; return c; } });
  const client = new HtpClient({ fetch });
  await assert.rejects(client.call("GET", "/vault/objects"), /authentication/);
});

test("header tampering (e.g. altered sequence number) fails authentication", async () => {
  const server = new HtpServer(createStatics());
  const { fetch } = wire(server, { tamper: (f) => { const c = f.slice(); c[28] ^= 1; return c; } });
  const client = new HtpClient({ fetch });
  await assert.rejects(client.call("GET", "/vault/objects"), /authentication/);
});

test("replayed frames are rejected", async () => {
  const server = new HtpServer(createStatics());
  const { fetch, log } = wire(server);
  const client = new HtpClient({ fetch });
  await client.call("DELETE", "/vault/objects/abc");
  await assert.rejects(server.open(log[0]), /already used/);
});

test("replay window tolerates reordering but never a repeat", () => {
  const w = new ReplayWindow();
  assert.ok(w.accept(5));
  assert.ok(w.accept(3));
  assert.ok(!w.accept(3));
  assert.ok(w.accept(400));
  assert.ok(!w.accept(100)); // now outside the window
  assert.ok(!w.accept(0));
});

test("expired and unknown sessions force a new handshake", async () => {
  const server = new HtpServer(createStatics(), { idleMs: 1 });
  const { fetch } = wire(server);
  const client = new HtpClient({ fetch });
  await client.connect();
  await new Promise((r) => setTimeout(r, 5));
  let lost = null;
  client.onSessionLost = (why) => (lost = why);
  await assert.rejects(client.call("GET", "/x"), /expired/);
  assert.equal(lost, "session_expired");
  assert.equal(client.connected, false);
});

test("step-up proofs are bound to session, request and body", async () => {
  const server = new HtpServer(createStatics());
  const { fetch } = wire(server);
  const client = new HtpClient({ fetch });
  const holder = ml_dsa87.keygen();
  const body = new Uint8Array([9, 9, 9]);
  const res = await client.call("GET", "/vault/objects/42", {
    body,
    stepUp: async ({ message }) => ({ sig: ml_dsa87.sign(message, holder.secretKey), interrupt: { method: "test", assurance: "hardware" } }),
  });
  const { proof, th } = res.json();
  const sig = Buffer.from(proof.sig, "base64url");
  const thB = Buffer.from(th, "hex");
  const action = (over = {}) => actionBytes({ method: "GET", path: "/vault/objects/42", device: ISSUED.device, nonce: ISSUED.nonce, exp: ISSUED.exp, ...over });
  // slot 1 went to fetching the approval; the request itself is slot 2
  assert.ok(verify(sig, stepUpMessage(thB, 2, "GET", "/vault/objects/42", body, proof.at, action()), holder.publicKey));
  assert.equal(proof.nonce, Buffer.from(ISSUED.nonce).toString("base64url"));
  assert.equal(proof.exp, ISSUED.exp);
  // Same signature does not verify for another request, body, session, device, nonce or expiry.
  assert.ok(!verify(sig, stepUpMessage(thB, 3, "GET", "/vault/objects/42", body, proof.at, action()), holder.publicKey));
  assert.ok(!verify(sig, stepUpMessage(thB, 2, "GET", "/vault/objects/43", body, proof.at, action()), holder.publicKey));
  assert.ok(!verify(sig, stepUpMessage(thB, 2, "GET", "/vault/objects/42", new Uint8Array([1]), proof.at, action()), holder.publicKey));
  assert.ok(!verify(sig, stepUpMessage(new Uint8Array(32), 2, "GET", "/vault/objects/42", body, proof.at, action()), holder.publicKey));
  assert.ok(!verify(sig, stepUpMessage(thB, 2, "GET", "/vault/objects/42", body, proof.at, action({ device: "dev_other" })), holder.publicKey));
  assert.ok(!verify(sig, stepUpMessage(thB, 2, "GET", "/vault/objects/42", body, proof.at, action({ nonce: new Uint8Array(16) })), holder.publicKey));
  assert.ok(!verify(sig, stepUpMessage(thB, 2, "GET", "/vault/objects/42", body, proof.at, action({ exp: ISSUED.exp + 1 })), holder.publicKey));
});

test("login proofs from one session do not verify in another", () => {
  const holder = ml_dsa87.keygen();
  const ch = new Uint8Array(32).fill(7);
  const a = new Uint8Array(32).fill(1), b = new Uint8Array(32).fill(2);
  const sig = ml_dsa87.sign(loginMessage(a, "hid_x", ch), holder.secretKey);
  assert.ok(verify(sig, loginMessage(a, "hid_x", ch), holder.publicKey));
  assert.ok(!verify(sig, loginMessage(b, "hid_x", ch), holder.publicKey));
});

test("a rotated server key surfaces as 'server identity changed', even with stale cached keys", async () => {
  const before = new HtpServer(createStatics());
  const after = new HtpServer(createStatics());
  // Keys endpoint still serves the OLD bundle (stale cache); hello reaches the NEW server.
  const fetch = async (url, init) => {
    const p = new URL(url, "http://x").pathname;
    if (p === "/htp/v1/keys") return Response.json(before.publicKeys());
    try { return Response.json(after.hello(JSON.parse(init.body))); }
    catch (e) { return Response.json({ error: e.code, message: e.message }, { status: e.status }); }
  };
  const client = new HtpClient({ fetch, pinnedKid: before.kid });
  await assert.rejects(client.connect(), (e) => e.code === "server_identity_changed");
});
