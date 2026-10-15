// The simulation build's in-app server: a phone with a secure chip (simulated,
// attested like a Pixel) registers, signs in, seals, opens and deletes over the
// real HTP/1 protocol, and every rule a real server enforces still holds.
import "fake-indexeddb/auto";
import { test } from "node:test";
import assert from "node:assert/strict";
import { HumidApi } from "@humid/api";
import { createSimServer } from "../apps/mobile/src/sim/server.js";
import { makeHolder, sealFor } from "./e2e/holder.js";

const reports = [];
const sim = await createSimServer({ onCheck: (r) => reports.push(r) });
const api = () => new HumidApi({ baseUrl: "sim://this-phone", fetch: sim.fetch });
const last = (kind) => reports.filter((r) => r.kind === kind).at(-1);

const alice = makeHolder("alice-sim");
let phone, docId;

test("an access code becomes a blind pass; no pass, no account; a pass spends once", async () => {
  const bob = makeHolder("bob-sim");
  await assert.rejects(api().register({ pub: bob.pub, commit: bob.commit, device: bob.device, sign: bob.registerSign }), (e) => e.code === "pass_required");
  const code = sim.demoAccessCode();
  const pass = await api().getPass(code);
  assert.ok(last("pass").checks.every((c) => c.ok));
  await assert.rejects(api().getPass(code), (e) => e.code === "code_used");
  assert.equal((await api().register({ pub: bob.pub, commit: bob.commit, device: bob.device, sign: bob.registerSign, pass })).created, true);
  const carol = makeHolder("carol-sim");
  await assert.rejects(api().register({ pub: carol.pub, commit: carol.commit, device: carol.device, sign: carol.registerSign, pass }), (e) => e.code === "pass_spent");
});

test("register: account key, device key and the secure chip are all checked; the attestation is read", async () => {
  phone = api();
  const pass = await api().getPass(sim.demoAccessCode());
  const s = await phone.register({ pub: alice.pub, commit: alice.commit, device: alice.device, sign: alice.registerSign, soleBiometric: true, pass });
  assert.equal(s.created, true);
  assert.equal(s.assurance, "hardware");
  const labels = last("enrol").checks.map((c) => `${c.ok} ${c.label}`);
  for (const want of ["true Access pass is genuine and unspent", "true Account key proved possession", "true Secure chip signed during a live biometric match", "true Biometric only: no PIN or password can use it", "true Needs a live check for every single use", "true Attestation made for this connection"]) {
    assert.ok(labels.some((l) => l.startsWith(want)), `${want}\n${labels.join("\n")}`);
  }
  assert.ok(labels.some((l) => l.startsWith("null Certificate chain")), "says honestly it can't check the chain");
});

test("sign-in needs the device key AND a live secure-chip signature over the server's challenge", async () => {
  const again = api();
  await again.login({ id: alice.id, device: alice.deviceId, sign: alice.sign });
  assert.equal(last("login").checks.length, 3);
  const noChip = api();
  await assert.rejects(noChip.login({ id: alice.id, device: alice.deviceId, sign: async (m) => ({ ...(await alice.sign(m)), live: undefined }) }), (e) => e.code === "bad_live_proof");
  const bot = makeHolder("bot");
  await assert.rejects(api().login({ id: alice.id, device: alice.deviceId, sign: bot.sign }), (e) => e.code === "bad_proof");
});

test("seal, open and delete: envelope signature, live seal, and step-ups over the exact request", async () => {
  const { envelope, index } = await sealFor(alice, "will.txt", "Alice's will");
  docId = (await phone.upload(envelope, index)).id;
  assert.ok(last("seal").checks.some((c) => /live biometric/.test(c.label)));
  await assert.rejects(phone.download(docId), (e) => e.code === "step_up_required");
  const got = await phone.download(docId, alice.stepUp);
  assert.equal(new TextDecoder().decode((await alice.S.open(got, alice.keys)).bytes), "Alice's will");
  await assert.rejects(phone.remove(docId, async (x) => ({ ...(await alice.stepUp(x)), live: undefined })), (e) => e.code === "bad_live_proof");
  await phone.remove(docId, alice.stepUp);
  assert.equal((await phone.list()).items.length, 0);
});

test("split keys: the account keys alone open nothing; the key comes only with a step-up", async () => {
  const { sealSplitFor } = await import("./e2e/holder.js");
  const { splitUnwrap, isSplit } = await import("@humid/crypto");
  assert.equal((await phone.server()).policy.splitKeys, true);
  const s = await sealSplitFor(alice, "deed.txt", "the deed");
  const id = (await phone.upload(s.envelope, s.index, s.share)).id;
  assert.ok(last("seal").checks.some((c) => /second key/.test(c.label)));
  await assert.rejects(phone.downloadWithShare(id), (e) => e.code === "step_up_required");
  const got = await phone.downloadWithShare(id, alice.stepUp);
  const outer = await alice.S.open(got.envelope, alice.keys);
  assert.ok(isSplit(outer.meta));
  assert.equal(new TextDecoder().decode((await splitUnwrap(outer.bytes, got.share)).bytes), "the deed");
  await phone.remove(id, alice.stepUp);
});

test("history and the public log verify on the phone; duress locks sensitive changes", async () => {
  const l = await phone.ledger();
  assert.equal(l.ok, true, l.reason);
  const c = await phone.continuity();
  assert.equal(c.ok, true, c.reason);
  await phone.presence(true);
  assert.deepEqual(await phone.duressStatus(), { lockdown: false }, "the coerced session sees a calm account");
  await assert.rejects(phone.setSettings({ duressAlert: true }, alice.stepUp), (e) => e.code === "busy");
});

test("a phone whose key accepts a PIN is refused, like a real server would, and its pass isn't used up", async () => {
  const rooted = makeHolder("rooted-sim", { kind: "rooted" });
  const pass = await api().getPass(sim.demoAccessCode());
  await assert.rejects(api().register({ pub: rooted.pub, commit: rooted.commit, device: rooted.device, sign: rooted.registerSign, pass }), (e) => e.code === "pin_allowed");
  const dave = makeHolder("dave-sim");
  assert.equal((await api().register({ pub: dave.pub, commit: dave.commit, device: dave.device, sign: dave.registerSign, pass })).created, true);
});
