// End to end: the server accepts only live biometric checks it can prove.
// Phones carry a hardware liveness key (attested like Android key attestation
// and Apple App Attest); every sign-in, step-up and seal must be signed by it.
// Here are the things a bot would try instead, and the policies that decide
// which devices may join.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, actionBytes, liveMessage } from "@humid/htp";
import { createGateway } from "../../services/gateway/src/server.js";
import { newInternalKeys } from "@humid/svc";
import { makeHolder, register, sealFor, ROOTS } from "./holder.js";
import { androidChain } from "../support/pki.js";

let stack;
before(async () => { stack = await startStack(); }); // policy: attested
after(async () => { await stack?.stop(); });

const code = (c) => (e) => { assert.equal(e.code, c, `expected ${c}, got ${e.code}: ${e.message}`); return true; };

/* ---------------- who may join ---------------- */

test("the server tells apps it accepts only hardware-proven devices", async () => {
  const s = await new HumidApi({ baseUrl: stack.baseUrl }).server();
  assert.equal(s.policy.devicePolicy, "attested");
});

test("an Android phone with an attested biometric-only key joins; its proof is recorded", async () => {
  const p = makeHolder("pixel");
  const api = await register(p, stack.baseUrl);
  assert.equal(api.session.proof, "android-tee");
  assert.equal(api.session.assurance, "hardware");
  const me = await api.me();
  assert.equal(me.devices[0].proof, "android-tee");
});

test("an iPhone attested by App Attest joins", async () => {
  const api = await register(makeHolder("iphone", { kind: "apple" }), stack.baseUrl);
  assert.equal(api.session.proof, "apple-secure-enclave");
});

test("a desktop, a demo device, and a phone key that also takes a PIN are all refused", async () => {
  await assert.rejects(register(makeHolder("desk", { kind: "desktop" }), stack.baseUrl), code("device_not_proven"));
  await assert.rejects(register(makeHolder("demo", { kind: "demo" }), stack.baseUrl), code("device_not_proven"));
  await assert.rejects(register(makeHolder("rooted", { kind: "rooted" }), stack.baseUrl), code("pin_allowed"));
});

test("a bot that claims to be a phone but can't attest its key is refused", async () => {
  const bot = makeHolder("bot");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  // live key present, attestation stripped
  const sign = async (m) => { const r = await bot.registerSign(m); return { ...r, live: { pub: r.live.pub, sig: r.live.sig } }; };
  await assert.rejects(api.register({ pub: bot.pub, commit: bot.commit, device: bot.device, sign }), code("device_not_proven"));
});

test("an attestation made for another session can't be replayed", async () => {
  const bot = makeHolder("replayer");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const old = androidChain({ root: ROOTS.android, challenge: randomBytes(32), liveKey: bot.liveKey }).chain;
  const sign = async (m) => { const r = await bot.registerSign(m); return { ...r, live: { ...r.live, attestation: { kind: "android-key", chain: old } } }; };
  await assert.rejects(api.register({ pub: bot.pub, commit: bot.commit, device: bot.device, sign }), code("wrong_challenge"));
});

test("an attestation is good for a few minutes only: an old session can't enrol", async () => {
  const p = makeHolder("slowpoke");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const real = api.htp.connect.bind(api.htp);
  api.htp.connect = async () => { const s = await real(); stack.gateway.htp.sessions.get(s.sidText).createdAt -= 6 * 60_000; return s; };
  await assert.rejects(api.register({ pub: p.pub, commit: p.commit, device: p.device, sign: p.registerSign }), code("attestation_stale"));
});

test("one attestation challenge enrols one device: a second device in the same session is refused", async () => {
  const first = makeHolder("first");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await api.register({ pub: first.pub, commit: first.commit, device: first.device, sign: first.registerSign });
  // keep the same session (and so the same challenge) for a second, different device
  const same = api.htp.session;
  api.htp.connect = async () => same;
  const second = makeHolder("second");
  await assert.rejects(api.register({ pub: second.pub, commit: second.commit, device: second.device, sign: second.registerSign }), code("challenge_used"));
});

test("a phone whose attestation certificate Google revoked is refused", async () => {
  const p = makeHolder("revoked-phone");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const { X509Certificate } = await import("node:crypto");
  const { serialKey } = await import("@humid/attest");
  const sign = async (m) => {
    const r = await p.registerSign(m);
    for (const c of r.live.attestation.chain.slice(1, -1)) stack.revoked.add(serialKey(new X509Certificate(Buffer.from(c)).serialNumber));
    return r;
  };
  try { await assert.rejects(api.register({ pub: p.pub, commit: p.commit, device: p.device, sign }), code("revoked")); }
  finally { stack.revoked.clear(); }
});

test("an enrolment the liveness key didn't sign is refused", async () => {
  const bot = makeHolder("unsigned");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const sign = async (m) => { const r = await bot.registerSign(m); return { ...r, live: { ...r.live, sig: bot.liveKey.sign(randomBytes(16)) } }; };
  await assert.rejects(api.register({ pub: bot.pub, commit: bot.commit, device: bot.device, sign }), code("bad_live_proof"));
});

/* ---------------- every sign-in and step-up ---------------- */

let alice, aliceApi, docId;

test("setup: Alice's phone seals a document under a live check", async () => {
  alice = makeHolder("alice");
  aliceApi = await register(alice, stack.baseUrl);
  const { envelope, index } = await sealFor(alice, "will.txt", "Last will");
  docId = (await aliceApi.upload(envelope, index)).id;
});

test("signing in without the liveness signature is refused, and logged", async () => {
  await aliceApi.logout();
  const noLive = async (m) => { const r = await alice.sign(m); return { sig: r.sig, interrupt: r.interrupt }; };
  await assert.rejects(new HumidApi({ baseUrl: stack.baseUrl }).login({ id: alice.id, device: alice.deviceId, sign: noLive }), code("bad_live_proof"));
  // the device key alone (a bot that stole the seeds) is not enough either
  await aliceApi.login({ id: alice.id, device: alice.deviceId, sign: alice.sign });
  const l = await aliceApi.ledger();
  assert.ok(l.entries.some((e) => e.type === "access.denied" && e.detail.reason === "no_live_biometric"));
});

test("opening a document needs the liveness key's signature over that exact request", async () => {
  const noLive = async ({ message }) => ({ sig: ml_dsa87.sign(message, alice.dkeys.dsaSk), interrupt: alice.interrupt });
  await assert.rejects(aliceApi.download(docId, noLive), code("bad_live_proof"));

  // a liveness signature captured for one request can't approve another
  const t1 = await aliceApi.ticket("download", docId);
  const stolen = alice.liveKey.sign(t1.live);
  const t2 = await aliceApi.ticket("download", docId);
  await assert.rejects(aliceApi.download(docId, { ticket: t2, sign: async (m) => ({ sig: ml_dsa87.sign(m, alice.dkeys.dsaSk), interrupt: alice.interrupt, live: stolen }) }), code("bad_live_proof"));

  // the real thing: ticket first, one check signs it, then the request goes
  const t = await aliceApi.ticket("download", docId);
  const env = await aliceApi.download(docId, { ticket: t, sign: async (m) => ({ sig: ml_dsa87.sign(m, alice.dkeys.dsaSk), interrupt: alice.interrupt, live: alice.liveKey.sign(t.live) }) });
  const { bytes } = await suite().open(env, alice.keys);
  assert.equal(new TextDecoder().decode(bytes), "Last will");
});

/* ---------------- sign the action, not just a nonce ---------------- */

// Rebuild a ticket around a different server approval (what a tampering client would try).
const withAction = (t, action) => {
  const bytes = actionBytes(action);
  return { ...t, action, actionBytes: bytes, live: liveMessage(aliceApi.htp.session.th, t.seq, t.method, t.path, t.at, bytes) };
};
const approve = (t) => ({ ticket: t, sign: async (m) => ({ sig: ml_dsa87.sign(m, alice.dkeys.dsaSk), interrupt: alice.interrupt, live: alice.liveKey.sign(t.live) }) });

test("an approval is used once: after it opens a document, it can't open it again", async () => {
  const t1 = await aliceApi.ticket("download", docId);
  await aliceApi.download(docId, approve(t1));
  const t2 = await aliceApi.ticket("download", docId); // a new request slot…
  await assert.rejects(aliceApi.download(docId, approve(withAction(t2, t1.action))), code("step_up_unknown")); // …with the spent approval
});

test("an approval for one action can't approve another, even signed properly", async () => {
  const forOpen = await aliceApi.ticket("download", docId);
  const forDelete = await aliceApi.ticket("remove", docId);
  // a delete, signed by the device and the secure chip, but carrying the approval issued for opening
  await assert.rejects(aliceApi.remove(docId, approve(withAction(forDelete, { ...forDelete.action, nonce: forOpen.action.nonce, exp: forOpen.action.exp }))), code("step_up_mismatch"));
  // and the approval it carried was burnt by that attempt: one try per approval
  const again = await aliceApi.ticket("download", docId); // a fresh request slot, the burnt approval
  await assert.rejects(aliceApi.download(docId, approve(withAction(again, forOpen.action))), code("step_up_unknown"));
});

test("an approval names its device and expiry: changing either breaks the signatures", async () => {
  const t = await aliceApi.ticket("download", docId);
  await assert.rejects(aliceApi.download(docId, approve(withAction(t, { ...t.action, device: "dev_" + "0".repeat(24) }))), code("bad_proof"));
  const t2 = await aliceApi.ticket("download", docId);
  await assert.rejects(aliceApi.download(docId, approve(withAction(t2, { ...t2.action, exp: t2.action.exp + 60_000 }))), code("step_up_stale"));
});

test("an approval left unused for over a minute has expired", async () => {
  const t = await aliceApi.ticket("download", docId);
  const s = [...stack.gateway.htp.sessions.values()].find((x) => x.stepUps?.has(Buffer.from(t.action.nonce).toString("base64url")));
  s.stepUps.get(Buffer.from(t.action.nonce).toString("base64url")).exp = Date.now() - 1;
  await assert.rejects(aliceApi.download(docId, approve(t)), code("step_up_stale"));
});

test("a ticket is bound to its request: it can't approve a different one", async () => {
  const t = await aliceApi.ticket("download", docId);
  await assert.rejects(aliceApi.remove(docId, { ticket: t, sign: async (m) => ({ sig: ml_dsa87.sign(m, alice.dkeys.dsaSk), interrupt: alice.interrupt, live: alice.liveKey.sign(t.live) }) }), code("ticket_mismatch"));
});

test("a document sealed without a live check on this phone is refused", async () => {
  const S = alice.S;
  const p = await S.prepareSeal({ bytes: new TextEncoder().encode("forged"), name: "x.txt", type: "text/plain" }, alice.pub);
  const { envelope } = S.finishSeal(p, alice.keys, { identityCommit: alice.commit, interrupt: alice.interrupt }); // no live signature
  const index = await S.sealIndex(alice.indexKey, { name: "x.txt" });
  await assert.rejects(aliceApi.upload(envelope, index), code("no_live_seal"));
});

/* ---------------- policies ---------------- */

test("'biometric' policy: biometric-only desktops join; unproven phones and demo devices still don't", async () => {
  const s = await startStack({ devicePolicy: "biometric" });
  try {
    const desk = await register(makeHolder("desk2", { kind: "desktop" }), s.baseUrl);
    assert.equal(desk.session.proof, "none");
    assert.equal(desk.session.assurance, "os");
    await assert.rejects(register(makeHolder("demo2", { kind: "demo" }), s.baseUrl), code("device_not_proven"));
    const bot = makeHolder("bot2");
    const sign = async (m) => { const r = await bot.registerSign(m); return { ...r, live: undefined }; };
    await assert.rejects(new HumidApi({ baseUrl: s.baseUrl }).register({ pub: bot.pub, commit: bot.commit, device: bot.device, sign }), code("device_not_proven"));
    assert.equal((await register(makeHolder("pixel2"), s.baseUrl)).session.proof, "android-tee");
  } finally { await s.stop(); }
});

test("'demo' policy (local development) accepts a device with no sensor", async () => {
  const s = await startStack({ devicePolicy: "demo" });
  try {
    const d = await register(makeHolder("demo3", { kind: "demo" }), s.baseUrl);
    assert.equal(d.session.assurance, "none");
  } finally { await s.stop(); }
});

test("tightening the policy later locks out devices that no longer qualify", async () => {
  const s = await startStack({ devicePolicy: "biometric" });
  try {
    const desk = makeHolder("desk3", { kind: "desktop" });
    await register(desk, s.baseUrl);
    // the operator switches to attested: same identity service, new gateway
    const ik = newInternalKeys(); // fresh gateway keys are fine; identity trusts the stack's internal key
    const strict = createGateway({
      port: 0, dataDir: `${s.root}/gateway-strict`, internalSk: s.internalSk ?? ik.sk,
      upstreams: s.upstreams, allowedOrigins: [], trustProxy: false, devicePolicy: "attested",
    });
    await strict.start();
    try {
      const url = `http://127.0.0.1:${strict.server.address().port}`;
      await assert.rejects(new HumidApi({ baseUrl: url }).login({ id: desk.id, device: desk.deviceId, sign: desk.sign }), code("device_not_proven"));
    } finally { await strict.stop(); }
  } finally { await s.stop(); }
});
