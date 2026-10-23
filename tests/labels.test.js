// What the app says about how a check was proven (apps/mobile/src/ui/labels.js).
// APP-09: Activity once described every past proof by the viewing device's own assurance, so
// an open from a software-protected computer showed on the phone as "proved by this phone's
// chip". And Welcome promised "proven by your phone's secure chip" on every platform.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as S from "../apps/mobile/src/core/state.js";
import { eventProof, checkPromise, deviceProof, proofLabel } from "../apps/mobile/src/ui/labels.js";

const HERE = "dev_phone";
S.session.value = { device: HERE, assurance: "hardware" };

test("a proof is described by what the server recorded with it, never by this device", () => {
  const fromComputer = { type: "object.opened", detail: { proof: "ab", assurance: "os", by: "dev_mac" } };
  assert.equal(eventProof(fromComputer).short, "software-protected check");
  assert.equal(eventProof(fromComputer).strong, false);
  const fromOtherPhone = { type: "object.opened", detail: { proof: "ab", assurance: "hardware", by: "dev_other" } };
  assert.equal(eventProof(fromOtherPhone).short, "proved by a phone's secure chip");
  assert.doesNotMatch(eventProof(fromOtherPhone).long, /This phone/);
  const fromHere = { type: "object.opened", detail: { proof: "ab", assurance: "hardware", by: HERE } };
  assert.equal(eventProof(fromHere).short, "proved by this phone's chip");
  assert.equal(eventProof(fromHere).long, "This phone's secure chip");
});

test("an older entry with no recorded assurance claims no chip at all", () => {
  for (const e of [{ type: "object.deleted", detail: { proof: "ab" } }, { type: "recovery.card_set", detail: { proof: "ab" } }, {}]) {
    assert.equal(eventProof(e).short, "signed by one of your devices");
    assert.equal(eventProof(e).strong, false);
  }
});

test("`device` names the actor only on events where it is one (a removed device isn't the remover)", () => {
  const removed = { type: "device.removed", detail: { device: HERE, proof: "ab", assurance: "hardware", by: "dev_other" } };
  assert.equal(eventProof(removed).short, "proved by a phone's secure chip");
  const unlocked = { type: "session.opened", detail: { device: HERE, proof: "ab", assurance: "hardware" } };
  assert.equal(eventProof(unlocked).short, "proved by this phone's chip");
});

test("the promise about a check is only as strong as this device can keep it", () => {
  S.identity.value = null; S.hwGate.value = null;
  assert.equal(deviceProof(), null);
  assert.match(checkPromise(), /In the HumID app for iPhone and Android/);
  S.identity.value = { assurance: "os" };
  assert.doesNotMatch(checkPromise(), /its secure chip signs/);
  assert.match(checkPromise(), /no secure chip signs it/);
  S.identity.value = { assurance: "hardware" };
  assert.match(checkPromise(), /on this phone, and its secure chip signs each one/);
  // before setup, from the probe of this device's gate
  S.identity.value = null; S.hwGate.value = { probe: { available: true, assurance: "os" } };
  assert.equal(deviceProof(), "os");
  for (const p of ["hardware", "os", null]) assert.doesNotMatch(checkPromise(p), /only your face|living you|proven by your phone/i);
  S.hwGate.value = null;
});

test("a device list names each device's own chip", () => {
  assert.equal(proofLabel("android-tee", "hardware"), "Each check is proven by its secure chip");
  assert.equal(proofLabel(null, "os"), "Checks are software-protected, not chip-proven");
});
