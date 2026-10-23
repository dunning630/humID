// SRV-01 (review 2026-10-23): /auth/register must not enrol a new device on an existing account.
// A copied account seed alone used to add a thief's attested phone, with no approval, wait or alert,
// and that phone then opened every document, split ones included. A new device joins only through
// an existing device's approval or a completed recovery.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { makeHolder, anotherDevice, register } from "./holder.js";
import { ml_dsa87 } from "@humid/htp";
import { cardTag, newCard, sealCard, recoveryModeMessage, recoveryModeHash, RECMODE_GENESIS } from "@humid/recovery";

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

// Follow-up found by the independent check: sign-up used to push the recovery mode it carried to
// the recovery service BEFORE identity refused the device. A seed-only attacker could sign a newer
// statement and retire every recovery piece, with no live check and nothing in the ledger.
test("a refused sign-up can't change the recovery mode or retire recovery pieces", async () => {
  const sm = (mode, version, epoch, prev) => ({ mode, version, epoch, prev, sig: ml_dsa87.sign(recoveryModeMessage(alice.id, mode, version, epoch, prev), alice.keys.dsaSk) });
  const c = newCard();
  await phone.setCard({ tag: cardTag(c.secret), blob: await sealCard(c.secret, alice.seed, alice.id) }, alice.stepUp);
  const before = await phone.card();
  assert.ok(before, "the card is on file");
  const v1 = recoveryModeHash(alice.id, { mode: "hardened", version: 1, epoch: 1, prev: RECMODE_GENESIS });
  const thief = anotherDevice(alice);
  for (const st of [sm("hardened", 1, 2, RECMODE_GENESIS), sm("hardened", 2, 2, v1)]) {
    const api = new HumidApi({ baseUrl: stack.baseUrl });
    await assert.rejects(api.register({ pub: alice.pub, commit: alice.commit, device: thief.device, sign: thief.registerSign, recoveryMode: st }));
  }
  assert.deepEqual(await phone.card(), before, "the card is untouched");
});
