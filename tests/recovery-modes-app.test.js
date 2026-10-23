// The app's side of the recovery modes (apps/mobile/src/core/enroll.js, recmode.js, join.js):
// setup in holder-only never calls an escrow API and sends no card; hardened (the default)
// makes the card under the same check; the mode is signed by the new account key; a mode
// the server shows that the account key never signed isn't trusted; and a holder-only
// HumID's join screen offers only the device link. Real services, the real app modules.
import "fake-indexeddb/auto";
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { HumidApi } from "@humid/api";
import { openStore } from "@humid/store";
import { ml_dsa87, random, b64u } from "@humid/htp";
import { recoveryModeMessage } from "@humid/recovery";
import { startStack } from "./e2e/stack.js";
import { liveKey, androidChain } from "./support/pki.js";
import { ROOTS } from "./e2e/holder.js";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { enroll, startEnroll } from "../apps/mobile/src/core/enroll.js";
import { verifiedMode, signMode, loadRecoveryMode, deviceRisk, DEFAULT_MODE } from "../apps/mobile/src/core/recmode.js";
import { joinRoutes, setJoinMode, beginJoin } from "../apps/mobile/src/core/join.js";
import { protectionItems } from "../apps/mobile/src/core/recmode.js";

let stack;
const ESCROW = ["setCard", "setContacts", "setAnchor", "addKey", "keyChallenge", "offerContact"];

/** A phone's gate as the native plugin presents it: a secret behind a live check, and an attested liveness key. */
function fakeHardwareGate() {
  const lk = liveKey();
  const secret = random(32);
  const rec = (purpose) => ({ method: "android-keystore-biometric", assurance: "hardware", purpose, at: new Date().toISOString() });
  return {
    id: "native", needsHold: false,
    async enroll({ challenge, attest }) {
      return { handle: { id: "h1" }, bindingId: b64u(random(16)).replace(/-/g, "+").replace(/_/g, "/"), secret: secret.slice(), interrupt: rec("enroll"),
        live: { pub: lk.pub, sig: lk.sign(challenge), attestation: { kind: "android-key", chain: androidChain({ root: ROOTS.android, challenge: attest, liveKey: lk }).chain } } };
    },
    async release(_h, { purpose, challenge }) { return { secret: secret.slice(), interrupt: rec(purpose), live: { sig: lk.sign(challenge) } }; },
    async forget() {},
  };
}

/** The app's API client, with every call recorded. */
function spiedApi(baseUrl) {
  const api = new HumidApi({ baseUrl });
  const calls = [];
  const proxy = new Proxy(api, {
    get(t, k) {
      const v = Reflect.get(t, k, t);
      if (typeof v !== "function") return v;
      return (...args) => { calls.push({ name: String(k), args }); return v.apply(t, args); };
    },
  });
  return { api: proxy, calls };
}

async function setupPhone() {
  const { api, calls } = spiedApi(stack.baseUrl);
  R.api = api;
  R.store = await openStore();
  await R.store.clearIdentity?.();
  S.server.value = { ...(await api.server()) };
  S.hwGate.value = { adapter: fakeHardwareGate(), probe: { available: true, proof: true, method: "android-keystore-biometric", assurance: "hardware", label: "fingerprint" } };
  return calls;
}

before(async () => { stack = await startStack(); });
after(async () => { await stack?.stop(); });

test("setup starts with the recommended mode selected", () => {
  S.setupMode.value = "holder-only";
  startEnroll();
  assert.equal(S.setupMode.value, "hardened");
  assert.equal(DEFAULT_MODE, "hardened");
  assert.equal(S.enrollStep.value, "connect", "an unpinned build asks about the server first, then the mode");
});

test("holder-only setup: no recovery card, no escrow call, and the mode signed by the new account key", async () => {
  const calls = await setupPhone();
  assert.equal(await enroll(false, { soleBiometric: true, recoveryMode: "holder-only" }), true);
  const reg = calls.find((c) => c.name === "register").args[0];
  assert.equal(reg.card, undefined, "no recovery card is made or sent");
  assert.equal(reg.recoveryMode.mode, "holder-only");
  assert.ok(ml_dsa87.verify(reg.recoveryMode.sig, recoveryModeMessage(S.identity.value.server.id, "holder-only", 1, 1), reg.pub.dsaPk), "signed by the account key");
  assert.deepEqual(calls.filter((c) => ESCROW.includes(c.name)), [], "no escrow API is ever called");
  assert.equal(S.cardCode.value, null, "no card to show");
  assert.equal(S.recoveryMode.value.mode, "holder-only");
  // The server agrees, and this phone checks that against its own account key.
  const m = await loadRecoveryMode();
  assert.deepEqual([m.mode, m.trusted, m.escrow], ["holder-only", true, []]);
});

test("hardened setup (the default): the recovery card is made under the same check, and the mode is signed too", async () => {
  const calls = await setupPhone();
  S.setupMode.value = "hardened";
  assert.equal(await enroll(false, { soleBiometric: true }), true);
  const reg = calls.find((c) => c.name === "register").args[0];
  assert.ok(reg.card?.tag, "a card is made");
  assert.equal(reg.recoveryMode.mode, "hardened");
  assert.ok(S.cardCode.value?.startsWith("HUMID-"), "and shown once");
  const m = await loadRecoveryMode();
  assert.deepEqual([m.mode, m.trusted, m.escrow], ["hardened", true, ["card"]]);
});

test("a mode the server shows that the account key never signed isn't trusted", () => {
  const k = ml_dsa87.keygen(), other = ml_dsa87.keygen();
  const acct = "hid_" + "ab".repeat(20);
  const good = signMode(acct, k.secretKey, "holder-only", 3, 2);
  assert.equal(verifiedMode(acct, k.publicKey, good), "holder-only");
  assert.equal(verifiedMode(acct, k.publicKey, { ...good, mode: "hardened" }), null, "the server flipped the mode");
  assert.equal(verifiedMode(acct, k.publicKey, { ...good, version: 4 }), null);
  assert.equal(verifiedMode(acct, k.publicKey, signMode(acct, other.secretKey, "hardened", 4, 2)), null, "signed by another key");
  assert.equal(verifiedMode(acct, k.publicKey, { mode: "hardened", version: 0, epoch: 1, sig: null }), "hardened", "an account from before modes");
  assert.equal(verifiedMode(acct, k.publicKey, { mode: "holder-only", version: 0, sig: null }), null, "unsigned holder-only is not a thing");
  assert.equal(verifiedMode(acct, k.publicKey, { ...good, broken: true }), null);
});

test("joining a holder-only HumID: only the device link is offered, and the other routes are refused before anything is bound", async () => {
  setJoinMode(null);
  assert.deepEqual(joinRoutes(), ["link", "quorum", "card", "contacts"]);
  setJoinMode("holder-only");
  assert.deepEqual(joinRoutes(), ["link"]);
  S.interrupt.value = null;
  const before = S.identity.value;
  await beginJoin("quorum");
  await beginJoin("card", { cardInput: "HUMID-00000-00000-00000-00000-00000" });
  assert.equal(S.identity.value, before, "nothing was bound or started");
  assert.equal(S.interrupt.value, null, "no check was even asked for");
  setJoinMode(null);
});

test("holder-only Protection: the second device is the checklist, and one device is flagged", () => {
  const rec = { proofs: {} };
  const one = [{ id: "a" }], two = [{ id: "a" }, { id: "b" }];
  assert.deepEqual(protectionItems(rec, one, "holder-only").map((i) => [i.label, i.done]), [["A second device", false], ["A third device, kept somewhere else", false]]);
  assert.equal(protectionItems(rec, two, "holder-only")[0].done, true);
  assert.ok(protectionItems(rec, one, "hardened").some((i) => i.label === "Recovery card"), "hardened still asks for proofs");
  assert.equal(deviceRisk("holder-only", one), "alone");
  assert.equal(deviceRisk("holder-only", two), null);
  assert.equal(deviceRisk("hardened", one), null);
});
