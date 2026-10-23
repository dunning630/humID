// SRV-01 (review 2026-10-23): /auth/register must not enrol a new device on an existing account.
// A copied account seed alone used to add a thief's attested phone, with no approval, wait or alert,
// and that phone then opened every document, split ones included. A new device joins only through
// an existing device's approval or a completed recovery.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { makeHolder, anotherDevice, register } from "./holder.js";

let stack, alice, phone;
before(async () => { stack = await startStack(); alice = makeHolder("alice"); phone = await register(alice, stack.baseUrl); });
after(async () => { await stack?.stop(); });

test("a new device can't join an existing account through registration", async () => {
  const thief = anotherDevice(alice);
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await assert.rejects(
    api.register({ pub: alice.pub, commit: alice.commit, device: thief.device, sign: thief.registerSign }),
    (e) => e.code === "identity_exists" && e.status === 409,
  );
  const me = await phone.me();
  assert.equal(me.devices.length, 1, "the account still has only its own device");
});

test("the enrolled device may repeat its own registration (a retry whose answer was lost)", async () => {
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const s = await api.register({ pub: alice.pub, commit: alice.commit, device: alice.device, sign: alice.registerSign });
  assert.equal(s.created, false);
  assert.equal(s.device, alice.deviceId);
});
