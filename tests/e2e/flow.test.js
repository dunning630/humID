// End to end: a phone (simulated) against the real service stack over HTP/1.
// Exercises the full POC journey and the attacks the design must stop.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, toHex, sha3_256, random } from "@humid/htp";

let stack;
before(async () => { stack = await startStack(); });
after(async () => { await stack?.stop(); });

/** A simulated phone: identity seed + the biometric gate as a callback. */
function makeHolder(label) {
  const S = suite();
  const seed = random(64);
  const keys = S.deriveKeys(seed);
  const pub = S.publicOf(keys);
  const commit = toHex(S.identityCommit(pub, sha3_256(new TextEncoder().encode(label))));
  const interrupt = { method: "test-gate", assurance: "hardware" };
  const signRaw = (m) => ml_dsa87.sign(m, keys.dsaSk);
  return {
    label, S, keys, pub, commit, interrupt,
    sign: async (m) => ({ sig: signRaw(m), interrupt }),
    stepUp: async ({ message }) => ({ sig: signRaw(message), interrupt }),
    indexKey: S.indexKey(seed),
    device: { platform: "test", gateMethod: "test-gate", assurance: "hardware" },
  };
}

async function sealFor(h, name, text) {
  const bytes = new TextEncoder().encode(text);
  const { envelope } = await h.S.seal({ bytes, name, type: "text/plain" }, h.keys, h.pub, { identityCommit: h.commit, interrupt: { ...h.interrupt, purpose: "seal", at: new Date().toISOString() } });
  const index = await h.S.sealIndex(h.indexKey, { name, type: "text/plain", size: bytes.length, category: "personal" });
  return { envelope, index };
}

let alice, aliceApi, aliceId, docId;

test("server presents a stable identity the app can pin", async () => {
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const s = await api.server();
  assert.match(s.kid, /^[0-9a-f]{64}$/);
  assert.match(s.fingerprint, /^[0-9A-F]{4}(-[0-9A-F]{4}){7}$/);
  assert.equal(s.kid, stack.gateway.htp.kid);
});

test("enrol: register proves key possession and opens a session", async () => {
  alice = makeHolder("alice-device");
  aliceApi = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  const session = await aliceApi.register({ pub: alice.pub, commit: alice.commit, device: alice.device, sign: (m) => ml_dsa87.sign(m, alice.keys.dsaSk) });
  assert.equal(session.created, true);
  assert.match(session.id, /^hid_[0-9a-f]{40}$/);
  aliceId = session.id;
  const me = await aliceApi.me();
  assert.equal(me.id, aliceId);
  assert.equal(me.devices[0].assurance, "hardware");
});

test("registering with someone else's public key fails proof of possession", async () => {
  const mallory = makeHolder("mallory");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await assert.rejects(api.register({ pub: alice.pub, commit: alice.commit, device: {}, sign: (m) => ml_dsa87.sign(m, mallory.keys.dsaSk) }), /Proof of possession/);
});

test("sign out, then sign back in with a biometric-signed challenge", async () => {
  await aliceApi.logout();
  assert.equal(aliceApi.signedIn, false);
  const s = await aliceApi.login({ id: aliceId, device: alice.device, sign: alice.sign });
  assert.equal(s.id, aliceId);
  assert.equal(s.assurance, "hardware");
});

test("a login signed by the wrong key is refused", async () => {
  const mallory = makeHolder("mallory");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await assert.rejects(api.login({ id: aliceId, device: {}, sign: mallory.sign }), /rejected/);
});

test("seal on device, upload, list without the server learning the name", async () => {
  const { envelope, index } = await sealFor(alice, "passport.txt", "P<USADUNNING<<PARKER");
  const item = await aliceApi.upload(envelope, index);
  docId = item.id;
  const { items, usage } = await aliceApi.list();
  assert.equal(items.length, 1);
  assert.equal(usage.count, 1);
  const meta = await alice.S.openIndex(alice.indexKey, new Uint8Array(Buffer.from(items[0].index, "base64url")));
  assert.equal(meta.name, "passport.txt");
  // What the server stored contains no plaintext and no file name.
  const { readdirSync, readFileSync } = await import("node:fs");
  const blobs = readdirSync(`${stack.root}/vault/blobs`, { recursive: true, withFileTypes: true }).filter((d) => d.isFile());
  const raw = Buffer.concat(blobs.map((d) => readFileSync(`${d.parentPath}/${d.name}`))).toString("latin1");
  assert.ok(!raw.includes("DUNNING") && !raw.includes("passport"));
});

test("an envelope sealed to someone else is refused by the vault", async () => {
  const bob = makeHolder("bob");
  const { envelope, index } = await sealFor(bob, "bob.txt", "not alice's");
  await assert.rejects(aliceApi.upload(envelope, index), /not signed by your identity|not sealed to your identity/);
});

test("downloading without a fresh biometric proof is denied (and logged)", async () => {
  await assert.rejects(aliceApi.download(docId), (e) => e.code === "step_up_required");
});

test("download with a step-up proof returns ciphertext that only the holder can open", async () => {
  const envelope = await aliceApi.download(docId, alice.stepUp);
  const { bytes, meta } = await alice.S.open(envelope, alice.keys);
  assert.equal(new TextDecoder().decode(bytes), "P<USADUNNING<<PARKER");
  assert.equal(meta.name, "passport.txt");
});

test("a step-up proof signed by another key is rejected", async () => {
  const mallory = makeHolder("mallory");
  await assert.rejects(aliceApi.download(docId, mallory.stepUp), (e) => e.code === "bad_proof");
});

test("another identity cannot see or fetch Alice's items", async () => {
  const bob = makeHolder("bob2");
  const bobApi = new HumidApi({ baseUrl: stack.baseUrl });
  await bobApi.register({ pub: bob.pub, commit: bob.commit, device: bob.device, sign: (m) => ml_dsa87.sign(m, bob.keys.dsaSk) });
  assert.equal((await bobApi.list()).items.length, 0);
  await assert.rejects(bobApi.download(docId, bob.stepUp), (e) => e.status === 404);
});

test("the access ledger verifies on the device and records every access", async () => {
  const l = await aliceApi.ledger();
  assert.equal(l.ok, true, l.reason);
  const types = l.entries.map((e) => e.type);
  for (const t of ["identity.created", "session.opened", "session.closed", "object.sealed", "access.denied", "object.opened"]) {
    assert.ok(types.includes(t), `ledger has ${t}`);
  }
  const opened = l.entries.find((e) => e.type === "object.opened");
  assert.equal(opened.detail.id, docId);
  assert.match(opened.detail.proof, /^[0-9a-f]{32}$/);
});

test("a tampered ledger page fails verification on the device", async () => {
  const { verifyLedger } = await import("@humid/audit");
  const res = await aliceApi.htp.call("GET", "/ledger/events");
  const page = res.json();
  const forged = structuredClone(page);
  forged.entries[1].body = forged.entries[1].body.replace("session.opened", "session.closed");
  assert.equal(verifyLedger(page).ok, true);
  assert.equal(verifyLedger(forged).ok, false);
  const dropped = structuredClone(page);
  dropped.entries.splice(2, 1);
  assert.equal(verifyLedger(dropped).ok, false);
});

test("rename replaces only the encrypted index", async () => {
  const idx = await alice.S.sealIndex(alice.indexKey, { name: "Passport (scan).txt", type: "text/plain", size: 20, category: "identity" });
  await aliceApi.rename(docId, idx);
  const { items } = await aliceApi.list();
  const meta = await alice.S.openIndex(alice.indexKey, new Uint8Array(Buffer.from(items[0].index, "base64url")));
  assert.equal(meta.name, "Passport (scan).txt");
});

test("delete needs a step-up and removes the item", async () => {
  await assert.rejects(aliceApi.remove(docId), (e) => e.code === "step_up_required");
  await aliceApi.remove(docId, alice.stepUp);
  assert.equal((await aliceApi.list()).items.length, 0);
});

test("if the ledger is down, documents are not released (fail closed)", async () => {
  const { envelope, index } = await sealFor(alice, "x.txt", "secret");
  const item = await aliceApi.upload(envelope, index);
  const port = stack.ledger.server.address().port;
  await stack.ledger.stop();
  await assert.rejects(aliceApi.download(item.id, alice.stepUp), (e) => e.code === "audit_unavailable");
  await new Promise((r) => stack.ledger.server.listen(port, r));
  const envelope2 = await aliceApi.download(item.id, alice.stepUp); // back up: released again
  assert.ok(envelope2.length > 0);
});

test("closing the identity erases the vault and ends the session", async () => {
  const r = await aliceApi.closeIdentity(alice.stepUp);
  assert.equal(r.closed, true);
  assert.equal(aliceApi.signedIn, false);
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await assert.rejects(api.login({ id: aliceId, device: {}, sign: alice.sign }), /not registered|rejected/);
});
