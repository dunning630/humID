// LIVE-06: when Android or iOS destroys a device's biometric keys (fingerprints or face
// changed, or HumID reinstalled), the server learns it: the holder's Activity shows it and
// the device is marked as needing setup again, until a live sign-in from it proves its keys
// are back. The report needs no sign-in (nothing is left to sign with), so it is built to
// tell a stranger nothing and cost little.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { makeHolder, register } from "./holder.js";

let stack, alice, phone;
before(async () => {
  stack = await startStack();
  alice = makeHolder("alice-keys-gone");
  phone = await register(alice, stack.baseUrl);
});
after(async () => { await stack?.stop(); });

const gone = (h) => (h.devices || []).find((d) => d.id === alice.deviceId);

test("a device's 'keys gone' report shows in Activity and marks it as needing setup", async () => {
  const before = await phone.me();
  assert.equal(gone(before).needsSetup, undefined);
  const stranger = new HumidApi({ baseUrl: stack.baseUrl }); // a fresh session: the phone can't sign in any more
  assert.deepEqual(await stranger.reportKeysGone({ id: alice.id, device: alice.deviceId }), { ok: true });
  const me = await phone.me();
  assert.equal(gone(me).needsSetup, true);
  assert.ok(gone(me).keysGoneAt);
  const events = (await phone.ledger()).entries.filter((e) => e.type === "device.keys_invalidated");
  assert.equal(events.length, 1);
  assert.equal(events[0].detail.device, alice.deviceId);

  // once a day per device: a repeated or replayed report adds nothing to the log
  await stranger.reportKeysGone({ id: alice.id, device: alice.deviceId });
  assert.equal((await phone.ledger()).entries.filter((e) => e.type === "device.keys_invalidated").length, 1);
});

test("the device's next live sign-in clears the mark (its keys were there after all)", async () => {
  const again = new HumidApi({ baseUrl: stack.baseUrl });
  await again.login({ id: alice.id, device: alice.deviceId, sign: alice.sign });
  assert.equal(gone(await again.me()).needsSetup, undefined);
});

test("the answer is the same for accounts and devices that don't exist, and nothing is written", async () => {
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const other = makeHolder("not-registered");
  assert.deepEqual(await api.reportKeysGone({ id: other.id, device: other.deviceId }), { ok: true });
  assert.deepEqual(await api.reportKeysGone({ id: alice.id, device: other.deviceId }), { ok: true }, "a device that isn't Alice's");
  await assert.rejects(api.reportKeysGone({ id: "hid_x", device: "dev_y" }), (e) => e.code === "bad_identity");
  assert.equal((await phone.ledger()).entries.filter((e) => e.type === "device.keys_invalidated").length, 1);
});

test("a signed-in session can't report another account's device", async () => {
  const carol = makeHolder("carol-keys-gone");
  const carolApi = await register(carol, stack.baseUrl);
  const bobApi = await register(makeHolder("bob-keys-gone"), stack.baseUrl);
  await bobApi.reportKeysGone({ id: carol.id, device: carol.deviceId });
  const mine = (await carolApi.me()).devices.find((d) => d.id === carol.deviceId);
  assert.equal(mine.needsSetup, undefined, "Bob's session speaks only for Bob");
  assert.equal((await carolApi.ledger()).entries.filter((e) => e.type === "device.keys_invalidated").length, 0);
  // and Carol's own device, signed out, still can (its once-a-day slot wasn't spent by Bob)
  await new HumidApi({ baseUrl: stack.baseUrl }).reportKeysGone({ id: carol.id, device: carol.deviceId });
  assert.equal((await carolApi.me()).devices.find((d) => d.id === carol.deviceId).needsSetup, true);
});
