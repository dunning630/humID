// End to end: getting the account seed to a new device — by a device you still
// have, by a recovery card, by recovery contacts — and the attacks each path
// must stop. Real services, real crypto; the release delay is 1.5 s here.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { identityId, random, toHex, sha3_256 } from "@humid/htp";
import {
  keyCode, LINK_LABEL, OFFER_LABEL, REQUEST_LABEL, newCard, parseCard, cardTag, sealCard, openCard,
  split, combine, thresholdFor, encodeShare, decodeShare,
} from "@humid/recovery";
import { makeHolder, anotherDevice, register, sealFor, sealBytes } from "./holder.js";

const DELAY = 1500;
const S = suite();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let stack, alice, phone, docId;
before(async () => {
  stack = await startStack({ recoveryDelayMs: DELAY });
  alice = makeHolder("alice-phone");
  phone = await register(alice, stack.baseUrl);
  const { envelope, index } = await sealFor(alice, "birth-certificate.txt", "Alice, born 1990");
  docId = (await phone.upload(envelope, index)).id;
});
after(async () => { await stack?.stop(); });

/** Ephemeral KEM + X25519 keys a new device makes to receive something. */
const receiveKeys = () => S.deriveKeys(random(64));

/** What a new device does once it holds the seed: check it, then join with its own device key. */
async function joinWith(seed, account, via, extra = {}) {
  const keys = S.deriveKeys(seed);
  assert.equal(identityId(keys.dsaPk), account, "seed derives the expected account");
  const me = anotherDevice({ ...alice, keys, pub: S.publicOf(keys), seed });
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const session = await api.enrollDevice({ account, device: me.device, via, sign: me.enrollSign, ...extra });
  return { api, me, session };
}

async function canOpenAlicesDocument(api, me) {
  const envelope = await api.download(docId, me.stepUp);
  const { bytes } = await S.open(envelope, me.keys);
  return new TextDecoder().decode(bytes);
}

/* ---------------- 1. another device you still have ---------------- */

let tablet;

test("link: a new device shows a code; the phone approves; the tablet joins and opens the vault", async () => {
  const lk = receiveKeys();
  const fresh = new HumidApi({ baseUrl: stack.baseUrl });
  const { code } = await fresh.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: "iPad" });
  assert.equal(code, keyCode(LINK_LABEL, lk.kemPk, lk.xPk));
  assert.equal((await fresh.linkResult(code)).status, "waiting");

  // On the phone: look up the code (verified against the keys), approve with a biometric.
  const req = await phone.getLink(code.toLowerCase().replace(/(.{4})/g, "$1-"));
  assert.equal(req.platform, "iPad");
  const envelope = await sealBytes(alice, alice.seed, { kemPk: req.kemPk, xPk: req.xPk });
  await assert.rejects(phone.approveLink(code, envelope), (e) => e.code === "step_up_required");
  await phone.approveLink(code, envelope, alice.stepUp);

  // On the tablet: open the seed, check who sealed it, join.
  const r = await fresh.linkResult(code);
  assert.equal(r.status, "approved");
  assert.equal(r.account, alice.id);
  const opened = await S.open(r.envelope, lk);
  assert.equal(toHex(sha3_256(Buffer.from(opened.manifest.signer.mldsa87Pk, "base64"))), toHex(sha3_256(alice.pub.dsaPk)), "sealed by the account key");
  tablet = await joinWith(opened.bytes, r.account, "link");
  assert.equal(tablet.session.id, alice.id);
  assert.notEqual(tablet.session.device, alice.deviceId);
  assert.equal(await canOpenAlicesDocument(tablet.api, tablet.me), "Alice, born 1990");
  assert.equal((await phone.me()).devices.length, 2);
});

test("link: a code can only be used once", async () => {
  const lk = receiveKeys();
  const { code } = await new HumidApi({ baseUrl: stack.baseUrl }).startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: "x" });
  const req = await phone.getLink(code);
  await phone.approveLink(code, await sealBytes(alice, alice.seed, req), alice.stepUp);
  await assert.rejects(phone.getLink(code), (e) => e.code === "already_used");
});

test("link: a server that swaps in its own keys is caught by the code, before anything is sealed", async () => {
  const lk = receiveKeys();
  const { code } = await new HumidApi({ baseUrl: stack.baseUrl }).startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: "x" });
  const evil = receiveKeys();
  const db = new DatabaseSync(`${stack.root}/recovery/recovery.db`);
  db.prepare("UPDATE links SET kem_pk = ?, x_pk = ? WHERE code = ?").run(evil.kemPk, evil.xPk, code);
  db.close();
  await assert.rejects(phone.getLink(code), (e) => e.code === "code_mismatch");
});

test("link: the seed must be sealed to the waiting device's keys", async () => {
  const lk = receiveKeys();
  const { code } = await new HumidApi({ baseUrl: stack.baseUrl }).startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: "x" });
  const wrong = await sealBytes(alice, alice.seed, receiveKeys());
  await assert.rejects(phone.approveLink(code, wrong, alice.stepUp), (e) => e.code === "wrong_recipient");
});

test("a device joins only with the account key's signature", async () => {
  const mallory = makeHolder("mallory");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  // Mallory knows Alice's account id but not her seed: signs with his own "account" key.
  await assert.rejects(api.enrollDevice({ account: alice.id, device: mallory.device, via: "link", sign: mallory.enrollSign }), /not authorised/);
});

/* ---------------- losing a device ---------------- */

test("remove a lost device: its sessions end and it can't sign in again", async () => {
  await assert.rejects(phone.removeDevice(tablet.session.device), (e) => e.code === "step_up_required");
  await assert.rejects(phone.removeDevice(alice.deviceId, alice.stepUp), (e) => e.code === "current_device");
  await phone.removeDevice(tablet.session.device, alice.stepUp);
  await assert.rejects(tablet.api.list(), (e) => ["session_unknown", "session_expired", "sign_in_required"].includes(e.code));
  const again = new HumidApi({ baseUrl: stack.baseUrl });
  await assert.rejects(again.login({ id: alice.id, device: tablet.session.device, sign: tablet.me.sign }), (e) => e.code === "device_removed");
  const types = (await phone.ledger()).entries.map((e) => e.type);
  assert.ok(types.includes("device.removed"));
  assert.ok(types.includes("access.denied"));
  assert.equal((await phone.me()).devices.length, 1); // only the phone is left
});

/* ---------------- 2. recovery card ---------------- */

let card;

test("card: set up a recovery card (needs a biometric check)", async () => {
  card = newCard();
  assert.match(card.code, /^HUMID(-[0-9A-HJKMNP-TV-Z]{5}){5}$/);
  const blob = await sealCard(card.secret, alice.seed, alice.id);
  await assert.rejects(phone.setCard({ tag: cardTag(card.secret), blob }), (e) => e.code === "step_up_required");
  await phone.setCard({ tag: cardTag(card.secret), blob }, alice.stepUp);
  assert.equal((await phone.card()).exists, true);
});

test("card: a card made during registration is saved under that same live check", async () => {
  const bob = makeHolder("bob-card");
  const c = newCard();
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const sess = await api.register({ pub: bob.pub, commit: bob.commit, device: bob.device, sign: bob.registerSign, card: { tag: cardTag(c.secret), blob: await sealCard(c.secret, bob.seed, bob.id) } });
  assert.equal(sess.cardSet, true);
  assert.equal((await api.card()).exists, true);
  const req = await new HumidApi({ baseUrl: stack.baseUrl }).startRecovery({ method: "card", tag: cardTag(c.secret) });
  assert.equal(req.account, bob.id);
  await api.cancelAlert((await api.alerts())[0].ref, bob.stepUp);
});

test("card: recovery waits, alerts the owner's devices, then releases to the new device", async () => {
  const secret = parseCard(card.code.toLowerCase());
  const fresh = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await fresh.startRecovery({ method: "card", tag: cardTag(secret), platform: "Pixel 9" });
  assert.equal(req.account, alice.id);
  assert.ok(req.releaseAt - Date.now() > DELAY - 500);

  const early = await fresh.recoveryStatus(req.id);
  assert.equal(early.status, "waiting");
  assert.equal(early.blob, undefined, "nothing released before the wait ends");

  const alerts = await phone.alerts();
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].method, "card");
  assert.equal(alerts[0].platform, "Pixel 9");

  await sleep(DELAY + 100);
  const done = await fresh.recoveryStatus(req.id);
  assert.equal(done.status, "released");
  const seed = await openCard(secret, done.blob, alice.id);
  const pixel = await joinWith(seed, done.account, "card", { recoveryId: req.id });
  assert.equal(await canOpenAlicesDocument(pixel.api, pixel.me), "Alice, born 1990");
  assert.equal((await phone.alerts()).length, 0);
  const types = (await phone.ledger()).entries.map((e) => e.type);
  for (const t of ["recovery.card_set", "recovery.requested", "recovery.completed"]) assert.ok(types.includes(t), `ledger has ${t}`);
});

test("card: the owner can cancel a recovery they didn't start", async () => {
  const fresh = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await fresh.startRecovery({ method: "card", tag: cardTag(card.secret), platform: "Stolen phone" });
  const [alert] = await phone.alerts();
  await assert.rejects(phone.cancelAlert(alert.ref), (e) => e.code === "step_up_required");
  await phone.cancelAlert(alert.ref, alice.stepUp);
  await sleep(DELAY + 100);
  const r = await fresh.recoveryStatus(req.id);
  assert.equal(r.status, "cancelled");
  assert.equal(r.blob, undefined);
});

test("card: an unknown card is refused, and a card cannot open someone else's vault", async () => {
  await assert.rejects(new HumidApi({ baseUrl: stack.baseUrl }).startRecovery({ method: "card", tag: cardTag(newCard().secret) }), (e) => e.code === "unknown_card");
  const blob = await sealCard(card.secret, alice.seed, alice.id);
  await assert.rejects(openCard(card.secret, blob, "hid_" + "0".repeat(40)), /does not open/);
  await assert.rejects(openCard(newCard().secret, blob, alice.id), /does not open/);
});

test("card: a request can't be marked complete before its release time", async () => {
  // The seed is what lets a device join, and the card blob is only released after the wait.
  // A device that already had the seed some other way still can't close out an unreleased request.
  const fresh = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await fresh.startRecovery({ method: "card", tag: cardTag(card.secret) });
  const pending = await joinWith(alice.seed, alice.id, "card", { recoveryId: req.id });
  const completed = (await phone.ledger()).entries.filter((e) => e.type === "recovery.completed");
  assert.equal(completed.length, 1, "only the released recovery completed");
  assert.equal((await fresh.recoveryStatus(req.id)).status, "waiting");
  await phone.cancelAlert((await phone.alerts())[0].ref, alice.stepUp);
  await phone.removeDevice(pending.session.device, alice.stepUp);
});

/* ---------------- 3. recovery contacts ---------------- */

test("contacts: any 2 of 3 contacts recover the vault after the wait; one alone can't", async () => {
  const people = ["bob", "carol", "dave"].map((n) => makeHolder(n));
  const apis = await Promise.all(people.map((p) => register(p, stack.baseUrl)));

  // Each contact shows a contact code; Alice types it (verified against their keys).
  const offers = [];
  for (let i = 0; i < people.length; i++) offers.push((await apis[i].offerContact(people[i].pub)).code);
  const t = thresholdFor(people.length);
  assert.equal(t, 2);
  const shares = split(alice.seed, people.length, t);
  const guardians = [];
  for (let i = 0; i < people.length; i++) {
    const o = await phone.getOffer(offers[i]);
    assert.equal(o.account, people[i].id);
    const share = encodeShare({ owner: alice.id, label: "Alice", ...shares[i], t, n: people.length });
    guardians.push({ contact: o.account, offer: offers[i], envelope: await sealBytes(alice, share, o), label: new TextEncoder().encode("Bob/Carol/Dave") });
  }
  await assert.rejects(phone.setContacts({ threshold: t, guardians }), (e) => e.code === "step_up_required");
  await phone.setContacts({ threshold: t, guardians }, alice.stepUp);
  assert.equal((await phone.contacts()).n, 3);

  // Alice loses everything. A new phone asks for help and shows a code.
  const rk = receiveKeys();
  const fresh = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await fresh.startRecovery({ method: "contacts", kemPk: rk.kemPk, xPk: rk.xPk, platform: "New iPhone" });

  // Mallory isn't a contact.
  const mallory = makeHolder("mallory2");
  const mapi = await register(mallory, stack.baseUrl);
  await mapi.getHelp(req.code);
  await assert.rejects(mapi.help(req.code, { owner: alice.id, envelope: await sealBytes(mallory, random(64), rk) }, mallory.stepUp), (e) => e.code === "not_a_contact");

  // Each contact: verify the code, open the piece they hold for Alice, re-seal it to the new phone.
  async function help(i) {
    const h = await apis[i].getHelp(req.code);
    const held = (await apis[i].protecting()).find((s) => s.owner === alice.id);
    const { bytes } = await S.open(held.envelope, people[i].keys);
    assert.equal(decodeShare(bytes).owner, alice.id);
    return apis[i].help(req.code, { owner: alice.id, envelope: await sealBytes(people[i], bytes, h) }, people[i].stepUp);
  }
  const first = await help(0);
  assert.equal(first.approvals, 1);
  assert.equal(first.releaseAt, null);
  assert.equal((await fresh.recoveryStatus(req.id)).status, "collecting");
  assert.equal((await phone.alerts())[0].method, "contacts");

  const second = await help(2);
  assert.equal(second.approvals, 2);
  assert.ok(second.releaseAt > Date.now());
  assert.equal((await fresh.recoveryStatus(req.id)).shares, undefined, "nothing released before the wait ends");

  await sleep(DELAY + 100);
  const done = await fresh.recoveryStatus(req.id);
  assert.equal(done.status, "released");
  assert.equal(done.shares.length, 2);
  const pieces = [];
  for (const env of done.shares) pieces.push(decodeShare((await S.open(env, rk)).bytes));
  const seed = combine(pieces);
  const restored = await joinWith(seed, alice.id, "contacts", { recoveryId: req.id });
  assert.equal(await canOpenAlicesDocument(restored.api, restored.me), "Alice, born 1990");

  const contactLedger = (await apis[0].ledger()).entries.map((e) => e.type);
  assert.ok(contactLedger.includes("recovery.helped"), "the contact's own ledger records the help");
});

test("contacts: one share alone reveals nothing about the seed", () => {
  const seed = random(64);
  const [a] = split(seed, 3, 2);
  assert.notDeepEqual(a.y, seed);
  // Any two rebuild it; a forged second share gives a different seed (caught by the account-id check).
  const [, b, c] = split(seed, 3, 2);
  assert.deepEqual(combine([b, c]), seed);
  assert.notDeepEqual(combine([a, { x: 9, y: random(64) }]), seed);
});

test("contacts: a contact code returning someone else's keys is caught", async () => {
  const eve = makeHolder("eve");
  const eapi = await register(eve, stack.baseUrl);
  const { code } = await eapi.offerContact(eve.pub);
  const other = receiveKeys();
  const db = new DatabaseSync(`${stack.root}/recovery/recovery.db`);
  db.prepare("UPDATE offers SET kem_pk = ? WHERE code = ?").run(other.kemPk, code);
  db.close();
  await assert.rejects(phone.getOffer(code), (e) => e.code === "code_mismatch");
});

/* ---------------- the device that shows a code checks it too ---------------- */

/** A server that answers with a code for keys of its own (here: by rewriting the reply). */
function lyingServer(api, label, ...keys) {
  const real = api.htp.call.bind(api.htp);
  api.htp.call = async (...a) => {
    const res = await real(...a);
    const j = res.json();
    if (!j?.code) return res;
    const forged = { ...j, code: keyCode(label, ...keys) };
    return { ...res, ok: res.ok, status: res.status, json: () => forged };
  };
  return api;
}

test("a server that hands back a code for its own keys is caught before the code is shown", async () => {
  const mine = receiveKeys(), theirs = receiveKeys();
  // adding a device
  const a = lyingServer(new HumidApi({ baseUrl: stack.baseUrl }), LINK_LABEL, theirs.kemPk, theirs.xPk);
  await assert.rejects(a.startLink({ kemPk: mine.kemPk, xPk: mine.xPk, platform: "x" }), (e) => e.code === "code_mismatch");
  // asking for recovery help
  const b = lyingServer(new HumidApi({ baseUrl: stack.baseUrl }), REQUEST_LABEL, theirs.kemPk, theirs.xPk);
  await assert.rejects(b.startRecovery({ method: "contacts", kemPk: mine.kemPk, xPk: mine.xPk, platform: "x" }), (e) => e.code === "code_mismatch");
  // offering to be a witness
  const eve = makeHolder("eve-offer");
  const c = lyingServer(await register(eve, stack.baseUrl), OFFER_LABEL, theirs.kemPk, theirs.xPk, eve.pub.dsaPk);
  await assert.rejects(c.offerContact(eve.pub), (e) => e.code === "code_mismatch");
  // an honest server's codes pass
  const honest = receiveKeys();
  const ok = await new HumidApi({ baseUrl: stack.baseUrl }).startLink({ kemPk: honest.kemPk, xPk: honest.xPk, platform: "x" });
  assert.equal(ok.code, keyCode(LINK_LABEL, honest.kemPk, honest.xPk));
});

test("a new device's name for itself is shown plainly: no control or direction-override characters", async () => {
  const lk = receiveKeys();
  const { code } = await new HumidApi({ baseUrl: stack.baseUrl }).startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: "\u202eenohPi\u202c\u200b Alice's\n phone" + "x".repeat(80) });
  const req = await phone.getLink(code);
  assert.doesNotMatch(req.platform, /[\u0000-\u001f\u200b-\u200f\u202a-\u202e]/);
  assert.ok(req.platform.length <= 40);
  assert.match(req.platform, /^enohPi Alice's phone/);
  const bk = receiveKeys();
  const blank = await new HumidApi({ baseUrl: stack.baseUrl }).startLink({ kemPk: bk.kemPk, xPk: bk.xPk, platform: "\u200b\u2066 " });
  assert.equal((await phone.getLink(blank.code)).platform, "a new device");
});
