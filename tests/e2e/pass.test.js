// End to end: anonymous payment. Access code → blind-signed pass → registration,
// against the real services, plus the property that matters: nothing the server
// stores links a payment to an account.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { spentId } from "@humid/pass";
import { makeHolder, anotherDevice } from "./holder.js";

let stack, codes;
before(async () => {
  stack = await startStack({ registration: "pass", passBuyUrl: "https://humidsecure.com/access" });
  codes = stack.access.mint(8, "e2e");
});
after(async () => { await stack?.stop(); });

const newApi = () => new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
const registerWith = (h, pass, api = newApi()) => api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign, pass });

test("the server tells the app that registration needs a pass, and where to buy one", async () => {
  const s = await newApi().server();
  assert.equal(s.policy.registration, "pass");
  assert.equal(s.policy.passBuyUrl, "https://humidsecure.com/access");
});

test("no pass, no account", async () => {
  await assert.rejects(registerWith(makeHolder("nopass"), undefined), (e) => e.code === "pass_required" && e.status === 402);
});

test("bad, unknown and mistyped access codes are refused before anything is signed", async () => {
  const api = newApi();
  await assert.rejects(api.getPass("HA-1234-5678"), (e) => e.code === "code_invalid");
  const typo = codes[0].slice(0, 5) + (codes[0][5] === "0" ? "1" : "0") + codes[0].slice(6);
  await assert.rejects(api.getPass(typo), (e) => e.code === "code_invalid");
  const { newAccessCode } = await import("@humid/pass");
  await assert.rejects(api.getPass(newAccessCode()), (e) => e.code === "code_unknown");
});

let alicePass, aliceId;
test("access code → pass → account", async () => {
  alicePass = await newApi().getPass(codes[0]);
  const alice = makeHolder("alice");
  const s = await registerWith(alice, alicePass);
  assert.equal(s.created, true);
  aliceId = s.id;
});

test("a pass spends once; an access code buys one pass", async () => {
  await assert.rejects(registerWith(makeHolder("copycat"), alicePass), (e) => e.code === "pass_spent");
  await assert.rejects(newApi().getPass(codes[0]), (e) => e.code === "code_used");
});

test("a forged or altered pass is refused", async () => {
  const p = await newApi().getPass(codes[1]);
  const sig = Buffer.from(p.sig, "base64url"); sig[5] ^= 1;
  await assert.rejects(registerWith(makeHolder("forger"), { ...p, sig: sig.toString("base64url") }), (e) => e.code === "pass_invalid");
  await assert.rejects(registerWith(makeHolder("forger2"), { ...p, kid: "0".repeat(64) }), (e) => e.code === "pass_expired");
  // the genuine pass is still good
  assert.equal((await registerWith(makeHolder("honest"), p)).created, true);
});

test("if the app dies mid-payment, resending the saved request recovers the same pass", async () => {
  let saved = null;
  const first = await newApi().getPass(codes[2], { saveDraft: async (d) => { saved = structuredClone(d); } });
  assert.ok(saved, "draft persisted before the code was sent");
  const again = await newApi().getPass(codes[2], { draft: saved });
  assert.deepEqual(again, first);
  // a different request with the same code is still refused
  await assert.rejects(newApi().getPass(codes[2]), (e) => e.code === "code_used");
});

test("a registration that fails gives the pass back", async () => {
  const p = await newApi().getPass(codes[3]);
  const alice = makeHolder("alice-again");
  const mallory = makeHolder("mallory");
  // mallory's device can't prove possession of these account keys: refused, pass refunded
  await assert.rejects(newApi().register({ pub: alice.pub, commit: alice.commit, device: mallory.device, sign: mallory.registerSign, pass: p }), /Proof of possession/);
  assert.equal((await registerWith(makeHolder("retry"), p)).created, true);
});

test("REC-01: registering with an existing account's keys is refused and gives the pass back", async () => {
  const owner = makeHolder("owner-rec01");
  await registerWith(owner, await newApi().getPass(codes[7]));
  // A thief with a copy of owner's seed and a phone of their own: no device is added, and the pass isn't spent.
  const thief = anotherDevice(owner);
  const p = await newApi().getPass(codes[6]);
  await assert.rejects(registerWith(thief, p), (e) => e.code === "identity_exists" && e.status === 409);
  assert.equal((await registerWith(makeHolder("rec01-retry"), p)).created, true, "the refused registration left the pass unspent");
});

test("pass requests can't ride on a signed-in session", async () => {
  const bob = makeHolder("bob");
  const api = newApi();
  await registerWith(bob, await newApi().getPass(codes[4]), api);
  const res = await api.htp.call("POST", "/pass/issue", { body: { code: codes[5], kid: "x", blinded: "x" } });
  assert.equal(res.status, 400);
  assert.equal(res.json().error, "signed_in");
});

test("nothing stored links a payment to an account", () => {
  const access = new DatabaseSync(join(stack.root, "access", "access.db"), { readOnly: true });
  const identity = new DatabaseSync(join(stack.root, "identity", "identity.db"), { readOnly: true });
  const ledger = new DatabaseSync(join(stack.root, "ledger", "ledger.db"), { readOnly: true });
  try {
    const dump = (db) => JSON.stringify(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()
      .map(({ name }) => db.prepare(`SELECT * FROM "${name}"`).all()), (k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v));
    const accessText = dump(access);
    // the access service never sees an account, a device or a key of one
    assert.ok(!accessText.includes(aliceId) && !/hid_[0-9a-f]{40}|dev_[0-9a-f]{24}/.test(accessText));
    // it keeps days, never times
    for (const r of access.prepare("SELECT minted_day, used_day FROM codes").all()) {
      assert.match(r.minted_day, /^\d{4}-\d{2}-\d{2}$/);
      if (r.used_day) assert.match(r.used_day, /^\d{4}-\d{2}-\d{2}$/);
    }
    for (const r of access.prepare("SELECT day FROM spent").all()) assert.match(r.day, /^\d{4}-\d{2}-\d{2}$/);
    // what it saw at issue time shares nothing with what it saw at spend time
    const spent = access.prepare("SELECT id FROM spent").all().map((r) => r.id);
    assert.ok(spent.includes(spentId(alicePass)));
    const blindedSeen = access.prepare("SELECT blinded_sha FROM codes WHERE blinded_sha IS NOT NULL").all().map((r) => r.blinded_sha);
    assert.equal(blindedSeen.filter((b) => spent.includes(b)).length, 0);
    // and identity and the ledger never see a pass or a code
    for (const text of [dump(identity), dump(ledger)]) {
      assert.ok(!spent.some((s) => text.includes(s)));
      assert.ok(!text.includes(alicePass.sig) && !text.includes(alicePass.input));
      assert.ok(!/HA-|access_code|"pass"/.test(text));
    }
  } finally { access.close(); identity.close(); ledger.close(); }
});
