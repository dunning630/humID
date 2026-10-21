// PC-02 (pre-certification audit, October 2026): holding the account seed is not enough to
// add a device. A seed copied once off a phone used to let anyone enrol an attested phone of
// their own, silently, with no wait and no alert, and open every document. Now a device joins
// only through a link one of the account's devices approved for that exact device key, or a
// released recovery (its proofs in, its wait over, not cancelled). Its own stack, so these
// handshakes don't eat into the other suites' rate limits.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { random } from "@humid/htp";
import { cardTag, newCard, sealCard } from "@humid/recovery";
import { makeHolder, anotherDevice, register, sealBytes } from "./holder.js";

const DELAY = 800;
const S = suite();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const receiveKeys = () => S.deriveKeys(random(64));

let stack, alice, phone;
before(async () => {
  stack = await startStack({ recoveryDelayMs: DELAY });
  alice = makeHolder("alice-enrol");
  phone = await register(alice, stack.baseUrl);
});
after(async () => { await stack?.stop(); });

test("PC-02: the account seed alone doesn't let a device in: no approved link, no join", async () => {
  // An attacker copied Alice's seed once (a compromised phone) and has an attested phone of their own.
  // (One session for every attempt: a refused enrolment leaves it signed out.)
  const thief = anotherDevice(alice);
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const lk = receiveKeys();
  const { code } = await api.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, devicePk: thief.device.dsaPk, platform: "x" });
  const attempt = (via, extra = {}) => api.enrollDevice({ account: alice.id, device: thief.device, via, sign: thief.enrollSign, ...extra });
  await assert.rejects(attempt("link"), (e) => e.code === "not_approved");
  await assert.rejects(attempt("register"), (e) => e.code === "bad_via");
  await assert.rejects(attempt("card"), (e) => e.code === "not_released");
  // A link someone made and nobody approved doesn't count either.
  await assert.rejects(attempt("link", { linkCode: code }), (e) => e.code === "not_approved");
  assert.ok(!(await phone.me()).devices.some((d) => d.id === thief.deviceId), "the thief's phone never joined");
  assert.ok((await phone.ledger()).entries.some((e) => e.type === "access.denied" && e.detail.reason === "enrol_without_evidence"));
});

test("PC-02: an approved link lets in only the device it names, and only once", async () => {
  const lk = receiveKeys();
  const mine = anotherDevice(alice), thief = anotherDevice(alice), other = anotherDevice(alice);
  const fresh = new HumidApi({ baseUrl: stack.baseUrl });
  const { code } = await fresh.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, devicePk: mine.device.dsaPk, platform: "Alice's laptop" });
  const req = await phone.getLink(code);
  await phone.approveLink(code, await sealBytes(alice, alice.seed, req), alice.stepUp);
  // Someone who saw the code and holds the seed races the real device: refused, the link stays good.
  const intruder = new HumidApi({ baseUrl: stack.baseUrl });
  await assert.rejects(intruder.enrollDevice({ account: alice.id, device: thief.device, via: "link", linkCode: code, sign: thief.enrollSign }), (e) => e.code === "not_approved");
  const joined = await fresh.enrollDevice({ account: alice.id, device: mine.device, via: "link", linkCode: code, sign: mine.enrollSign });
  assert.equal(joined.id, alice.id);
  // Spent: a second device with the same code is refused; the same device finishing again is fine.
  await assert.rejects(intruder.enrollDevice({ account: alice.id, device: other.device, via: "link", linkCode: code, sign: other.enrollSign }), (e) => e.code === "not_approved");
  assert.equal((await intruder.enrollDevice({ account: alice.id, device: mine.device, via: "link", linkCode: code, sign: mine.enrollSign })).id, alice.id);
  await phone.removeDevice(mine.deviceId, alice.stepUp);
});

test("PC-02: a cancelled recovery lets no device in, even after its wait and even holding the seed", async () => {
  const card = newCard();
  await phone.setCard({ tag: cardTag(card.secret), blob: await sealCard(card.secret, alice.seed, alice.id) }, alice.stepUp);
  const fresh = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await fresh.startRecovery({ method: "card", tag: cardTag(card.secret), platform: "Stolen phone" });
  await phone.cancelAlert((await phone.alerts())[0].ref, alice.stepUp);
  await sleep(DELAY + 100);
  const thief = anotherDevice(alice);
  await assert.rejects(fresh.enrollDevice({ account: alice.id, device: thief.device, via: "card", recoveryId: req.id, sign: thief.enrollSign }), (e) => e.code === "not_released");
  // ...nor under another route than the one it was started with
  await assert.rejects(fresh.enrollDevice({ account: alice.id, device: thief.device, via: "quorum", recoveryId: req.id, sign: thief.enrollSign }), (e) => e.code === "not_released");
  assert.equal((await phone.me()).devices.length, 1);
});
