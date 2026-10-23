// End to end: proving it's the same person after every device is gone.
// Two-proof recovery (witnesses, ID chip, seal card), waits set by the strength
// of the evidence, verification stations, the duress gesture, and the public
// transparency log. Real services, real crypto; the base wait is 1.5 s here.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { identityId, random, ml_dsa87, b64u } from "@humid/htp";
import { cosignMessage } from "@humid/audit";
import {
  newCard, cardTag, sealCardPart, openCardPart, split, combine, encodeShare, decodeShare,
  quorumParts, decodeQuorumPart, combineQuorum, QUORUM, anchorPartKey, sealAnchorPart, openAnchorPart,
} from "@humid/recovery";
import { makeHolder, anotherDevice, register, sealFor, sealBytes } from "./holder.js";
import { testCsca, testPassport } from "../support/passport.js";

const DELAY = 2500;   // generous margins: CI runners are slow
const S = suite();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const csca = testCsca("HumID Test Country");
const cosigner = ml_dsa87.keygen();

let stack, alice, phone, docId, card, passport, witnesses, witnessApis;
const station = makeHolder("station-operator");
let stationApi;

before(async () => {
  stack = await startStack({ recoveryDelayMs: DELAY, cscas: [csca.pem], stations: [station.id], cosigners: new Map([["test-cosigner", cosigner.publicKey]]), duressCoolOffMs: 5000 }); // long enough that a slow machine still checks "too soon" inside it
  alice = makeHolder("alice-quorum");
  phone = await register(alice, stack.baseUrl);
  const { envelope, index } = await sealFor(alice, "will.txt", "Alice's will");
  docId = (await phone.upload(envelope, index)).id;
  stationApi = await register(station, stack.baseUrl);

  // Alice sets up all three proofs, as the app does: one 2-of-3 split of her seed.
  const parts = quorumParts(alice.seed);
  card = newCard();
  await phone.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, alice.id) }, alice.stepUp);

  witnesses = ["wendy", "xavier", "yolanda"].map((n) => makeHolder(n));
  witnessApis = await Promise.all(witnesses.map((w) => register(w, stack.baseUrl)));
  const pieces = split(parts.witness.y, 3, 2);
  const guardians = [];
  for (let i = 0; i < 3; i++) {
    const code = (await witnessApis[i].offerContact(witnesses[i].pub)).code;
    const o = await phone.getOffer(code);
    const share = encodeShare({ owner: alice.id, label: "Alice", ...pieces[i], t: 2, n: 3 });
    guardians.push({ contact: o.account, offer: code, envelope: await sealBytes(alice, share, o) });
  }
  await phone.setContacts({ threshold: 2, guardians, scheme: "quorum" }, alice.stepUp);

  passport = testPassport({ csca, mrz: { surname: "LIDDELL", given: "ALICE" } });
  await linkChip(alice, phone, passport, parts.anchor);
});

/** As the app links an ID chip: the live chip answers a challenge; the part is sealed to that chip. */
async function linkChip(h, api, chip, part) {
  const nonce = await api.anchorChallenge();
  return api.setAnchor({ chip, sealedPart: await sealAnchorPart(anchorPartKey(chip.dg15), part, h.id), signature: chip.answer(nonce) }, h.stepUp);
}
after(async () => { await stack?.stop(); });

/* ---------------- helpers: a new device, and Alice's people ---------------- */

const receiveKeys = () => S.deriveKeys(random(64));

async function newDevice(extra = {}) {
  const rk = receiveKeys();
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await api.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, platform: "New phone", ...extra });
  return { rk, api, req };
}

async function witness(i, code) {
  const h = await witnessApis[i].getHelp(code);
  const held = (await witnessApis[i].protecting()).find((s) => s.owner === alice.id);
  const { bytes } = await S.open(held.envelope, witnesses[i].keys);
  return witnessApis[i].help(code, { owner: alice.id, envelope: await sealBytes(witnesses[i], bytes, h) }, witnesses[i].stepUp);
}

async function liveChip(api, id, chip = passport) {
  const nonce = await api.recoveryChallenge(id);
  return api.recoveryAddAnchor(id, { chip, signature: chip.answer(nonce) });
}

/** What the new device does when released: open whichever parts arrived, rebuild, check, join. */
async function finish(dev, released) {
  const parts = [];
  if (released.blob) parts.push(await openCardPart(card.secret, released.blob, released.account));
  if (released.shares) {
    const pieces = [];
    for (const env of released.shares) pieces.push(decodeShare((await S.open(env, dev.rk)).bytes));
    parts.push({ x: QUORUM.witness, y: combine(pieces) });
  }
  if (released.anchorPart) parts.push(decodeQuorumPart(released.anchorPart));
  // The anchor part as Alice's phone sealed it: the recovering device opens it with the chip it read
  // (after a station, the station hands it the chip's key, sealed to this device's recovery keys).
  if (released.anchorSealed) {
    const dg15 = released.anchorKey ? (await S.open(released.anchorKey, dev.rk)).bytes : passport.dg15;
    parts.push(await openAnchorPart(anchorPartKey(dg15), released.anchorSealed, released.account));
  }
  const seed = combineQuorum(parts);
  const keys = S.deriveKeys(seed);
  assert.equal(identityId(keys.dsaPk), alice.id, "two proofs rebuild Alice's seed");
  const me = anotherDevice({ ...alice, keys, pub: S.publicOf(keys), seed });
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await api.enrollDevice({ account: alice.id, device: me.device, via: "quorum", recoveryId: dev.req.id, sign: me.enrollSign, soleBiometric: true });
  const envelope = await api.download(docId, me.stepUp);
  assert.equal(new TextDecoder().decode((await S.open(envelope, me.keys)).bytes), "Alice's will");
  return { api, me };
}

const waitFor = async (api, id, ms) => { await sleep(ms); return api.recoveryStatus(id); };
const cancelAll = async () => { for (const a of await phone.alerts()) await phone.cancelAlert(a.ref, alice.stepUp); };

/* ---------------- the parts ---------------- */

test("parts: any two of witness, anchor and card rebuild the seed; one alone doesn't, and the split is the same every time", () => {
  const p = quorumParts(alice.seed);
  for (const [a, b] of [["witness", "anchor"], ["witness", "card"], ["anchor", "card"]]) assert.deepEqual(combineQuorum([p[a], p[b]]), alice.seed);
  assert.throws(() => combineQuorum([p.card, p.card]), /two different kinds/);
  assert.deepEqual(quorumParts(alice.seed).anchor.y, p.anchor.y, "deterministic: any device makes the same parts");
  assert.notDeepEqual(quorumParts(alice.seed, 2).anchor.y, p.anchor.y, "a new epoch makes new parts");
});

test("setup: the server knows which proofs exist, and stores nothing that opens them", async () => {
  assert.equal((await phone.card()).scheme, "quorum");
  assert.equal((await phone.contacts()).scheme, "quorum");
  const a = await phone.anchor();
  assert.equal(a.exists, true);
  assert.equal(a.document, "passport");
  const db = new DatabaseSync(`${stack.root}/recovery/recovery.db`);
  const row = db.prepare("SELECT * FROM anchors WHERE account = ?").get(alice.id);
  db.close();
  assert.ok(!JSON.stringify(row).includes("LIDDELL"), "no names on file");
  assert.equal(row.blob.length, 12 + (12 + 65 + 16) + 16, "the anchor part is stored sealed by the phone, and wrapped again");
  assert.equal(row.version, 2);
  // Someone else can't anchor their HumID to Alice's passport, even holding it.
  const mallory = makeHolder("mallory-anchor");
  const mapi = await register(mallory, stack.baseUrl);
  await assert.rejects(linkChip(mallory, mapi, passport, quorumParts(mallory.seed).anchor), (e) => e.code === "anchor_taken");
  // An untrusted country's passport is refused.
  const fake = testPassport({ csca: testCsca("Nowhere") });
  await assert.rejects(linkChip(mallory, mapi, fake, quorumParts(mallory.seed).anchor), (e) => e.code === "untrusted_country");
});

/* ---------------- one proof is never enough ---------------- */

test("one proof alone never opens: a card waits for a second proof, and the old single-card route refuses it", async () => {
  const dev = await newDevice({ tag: cardTag(card.secret) });
  assert.equal(dev.req.account, alice.id);
  assert.deepEqual(dev.req.kinds, ["card"]);
  assert.equal(dev.req.releaseAt, null);
  await sleep(DELAY * 3);
  const st = await dev.api.recoveryStatus(dev.req.id);
  assert.equal(st.status, "collecting");
  assert.equal(st.blob, undefined);
  await assert.rejects(new HumidApi({ baseUrl: stack.baseUrl }).startRecovery({ method: "card", tag: cardTag(card.secret) }), (e) => e.code === "needs_second_proof");
  await cancelAll();
});

/* ---------------- the tiers ---------------- */

test("witnesses + seal card: 72-hour tier, alerts, then the device joins carrying its evidence", async () => {
  const dev = await newDevice();
  const first = await witness(0, dev.req.code);
  assert.equal(first.releaseAt, null);
  await dev.api.recoveryAddCard(dev.req.id, cardTag(card.secret));
  const second = await witness(2, dev.req.code);
  assert.ok(second.releaseAt - Date.now() > DELAY - 1000 && second.releaseAt - Date.now() <= DELAY, "witnesses + card wait the base delay");
  const [alert] = await phone.alerts();
  assert.deepEqual(alert.kinds.sort(), ["card", "witness"]);
  assert.match(alert.evidence, /witnesses \+ seal card/);
  assert.equal((await dev.api.recoveryStatus(dev.req.id)).blob, undefined, "nothing before the wait");

  const released = await waitFor(dev.api, dev.req.id, DELAY + 150);
  assert.equal(released.status, "released");
  const joined = await finish(dev, released);
  const added = (await phone.ledger()).entries.filter((e) => e.type === "device.added").pop();
  assert.equal(added.detail.via, "quorum");
  assert.deepEqual(added.detail.kinds.sort(), ["card", "witness"]);
  assert.equal(added.detail.soleBiometric, true);
  await phone.removeDevice(joined.api.session.device, alice.stepUp);
});

test("seal card + live ID chip (no people): the 7-day tier, and only a chip that answers counts", async () => {
  const dev = await newDevice({ tag: cardTag(card.secret) });
  // A copied chip: right data, but it can't answer the challenge.
  const nonce = await dev.api.recoveryChallenge(dev.req.id);
  const clone = testPassport({ csca, mrz: { surname: "LIDDELL", given: "ALICE" } });
  await assert.rejects(dev.api.recoveryAddAnchor(dev.req.id, { chip: passport, signature: clone.answer(nonce) }), (e) => e.code === "chip_not_present");
  // An answer to a challenge already used doesn't work twice.
  await assert.rejects(dev.api.recoveryAddAnchor(dev.req.id, { chip: passport, signature: passport.answer(nonce) }), (e) => e.code === "challenge_expired");
  const r = await liveChip(dev.api, dev.req.id);
  assert.equal(r.anchorMode, "remote");
  const wait = r.releaseAt - Date.now();
  assert.ok(wait > (DELAY * 7) / 3 - 1000 && wait <= (DELAY * 7) / 3, `card + chip waits 7/3 × base (${wait})`);
  const released = await waitFor(dev.api, dev.req.id, wait + 150);
  assert.ok(released.anchorSealed && !released.anchorPart && released.blob && !released.shares, "the anchor part arrives as the phone sealed it");
  const joined = await finish(dev, released);
  await phone.removeDevice(joined.api.session.device, alice.stepUp);
});

test("station: the 24-hour tier; only stations can vouch, only after their checks, and they don't learn who", async () => {
  const dev = await newDevice();
  await witness(1, dev.req.code);
  await witness(2, dev.req.code);
  assert.equal((await dev.api.recoveryStatus(dev.req.id)).releaseAt, null, "witnesses alone are one kind of proof");
  await dev.api.recoveryAddCard(dev.req.id, cardTag(card.secret));
  const before = (await dev.api.recoveryStatus(dev.req.id)).releaseAt;
  assert.ok(before, "witnesses + card start the base wait");

  const view = await stationApi.stationRequest(dev.req.code);
  assert.equal(view.platform, "New phone");
  assert.equal(view.account, undefined);
  await assert.rejects(witnessApis[0].stationVerify(dev.req.code, { chip: passport, checks: { document: true, face: true, present: true } }, witnesses[0].stepUp), (e) => e.code === "not_a_station");
  await assert.rejects(stationApi.stationVerify(dev.req.code, { chip: passport, checks: { document: true, face: false, present: true } }, station.stepUp), (e) => e.code === "checks_incomplete");
  await assert.rejects(stationApi.stationVerify(dev.req.code, { chip: passport, checks: { document: true, face: true, present: true } }), (e) => e.code === "step_up_required");
  // A chip that can prove it's present must, at the station too: copied chip data isn't enough.
  const all = { document: true, face: true, present: true };
  await assert.rejects(stationApi.stationVerify(dev.req.code, { chip: passport, checks: all }, station.stepUp), (e) => e.code === "challenge_expired");
  let nonce = await stationApi.stationChallenge(dev.req.code);
  await assert.rejects(stationApi.stationVerify(dev.req.code, { chip: passport, checks: all, signature: passport.answer(new Uint8Array(8)) }, station.stepUp), (e) => e.code === "chip_not_present");
  await assert.rejects(stationApi.stationVerify(dev.req.code, { chip: passport, checks: all, signature: passport.answer(nonce) }, station.stepUp), (e) => e.code === "challenge_expired", "a challenge is answered once");
  nonce = await stationApi.stationChallenge(dev.req.code);
  const { dg15: _drop, ...noKey } = passport;
  await assert.rejects(stationApi.stationVerify(dev.req.code, { chip: noKey, checks: all, signature: passport.answer(nonce) }, station.stepUp), (e) => e.code === "no_chip_proof", "leaving DG15 out doesn't dodge the challenge");
  await assert.rejects(witnessApis[0].stationChallenge(dev.req.code), (e) => e.code === "not_a_station");
  nonce = await stationApi.stationChallenge(dev.req.code);
  // The station must hand the chip's key to the recovering phone (Alice's part opens only with it).
  await assert.rejects(stationApi.stationVerify(dev.req.code, { chip: passport, checks: all, signature: passport.answer(nonce) }, station.stepUp), (e) => e.code === "update_required");
  nonce = await stationApi.stationChallenge(dev.req.code);
  // ...sealed to the keys the recovery code commits to (the API checks them against the code).
  const req = await stationApi.stationRequest(dev.req.code);
  const chipKey = await sealBytes(station, passport.dg15, { kemPk: req.kemPk, xPk: req.xPk });
  const v = await stationApi.stationVerify(dev.req.code, { chip: passport, checks: all, signature: passport.answer(nonce), chipKey }, station.stepUp);
  assert.equal(v.verified, true);
  assert.equal(v.chipProof, true);
  assert.equal(v.account, undefined, "the operator doesn't learn whose HumID it is");
  assert.ok(v.releaseAt < before, "a station shortens the wait");
  assert.ok(v.releaseAt - Date.now() <= DELAY / 3);

  const released = await waitFor(dev.api, dev.req.id, v.releaseAt - Date.now() + 150);
  assert.ok(released.anchorSealed && released.anchorKey && released.shares, "with the chip key the station sealed to this device");
  const joined = await finish(dev, released);
  const types = (await phone.ledger()).entries.map((e) => e.type);
  assert.ok(types.includes("recovery.station_verified"));
  assert.ok((await stationApi.ledger()).entries.some((e) => e.type === "station.verified"), "the station's own ledger records it");
  await phone.removeDevice(joined.api.session.device, alice.stepUp);
});

test("proofs from two different people are refused", async () => {
  const bob = makeHolder("bob-quorum");
  const bapi = await register(bob, stack.baseUrl);
  const bobCard = newCard();
  await bapi.setCard({ tag: cardTag(bobCard.secret), blob: await sealCardPart(bobCard.secret, quorumParts(bob.seed).card, bob.id) }, bob.stepUp);
  const dev = await newDevice({ tag: cardTag(bobCard.secret) });
  await assert.rejects(liveChip(dev.api, dev.req.id), (e) => e.code === "different_person");
  await bapi.cancelAlert((await bapi.alerts())[0].ref, bob.stepUp);
});

test("veto: any surviving device cancels, and the requesting device gets nothing", async () => {
  const dev = await newDevice({ tag: cardTag(card.secret) });
  await witness(0, dev.req.code);
  await witness(1, dev.req.code);
  await cancelAll();
  const st = await waitFor(dev.api, dev.req.id, DELAY + 150);
  assert.equal(st.status, "cancelled");
  assert.equal(st.blob ?? st.shares ?? st.anchorPart ?? st.anchorSealed, undefined);
});

/* ---------------- duress ---------------- */

test("duress: a decoy session works for reading, sensitive changes fail like a busy server, waits double, witnesses who were asked see it", async () => {
  // Alice chose to let her witnesses know.
  await phone.setSettings({ duressAlert: true }, alice.stepUp);

  // (a second device of hers, joined the proper way, to show lockdown reaches every session)
  const coerced = anotherDevice(alice);
  const lk0 = receiveKeys();
  const joiner = new HumidApi({ baseUrl: stack.baseUrl });
  const link0 = await joiner.startLink({ kemPk: lk0.kemPk, xPk: lk0.xPk, devicePk: coerced.device.dsaPk, platform: "Alice's tablet" });
  await phone.approveLink(link0.code, await sealBytes(alice, alice.seed, await phone.getLink(link0.code)), alice.stepUp);
  await joiner.enrollDevice({ account: alice.id, device: coerced.device, via: "link", linkCode: link0.code, sign: coerced.enrollSign });
  await joiner.logout();

  // She's forced to unlock: she uses her duress gesture. The flag is signed into the sign-in.
  const calmApi = new HumidApi({ baseUrl: stack.baseUrl });
  const normalShape = await calmApi.login({ id: alice.id, device: coerced.deviceId, sign: coerced.unlockSign(0) });
  await calmApi.logout();
  const forcedApi = new HumidApi({ baseUrl: stack.baseUrl });
  const duressShape = await forcedApi.login({ id: alice.id, device: coerced.deviceId, sign: coerced.unlockSign(1) });
  assert.deepEqual(Object.keys(normalShape), Object.keys(duressShape), "the reply is the same either way");
  await sleep(150);
  // A link someone starts during the lockdown, for the approval check below.
  const lk = receiveKeys();
  const linker = new HumidApi({ baseUrl: stack.baseUrl });
  const { code } = await linker.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, devicePk: lk.dsaPk, platform: "Attacker's phone" });

  // Reading still works, so nothing looks wrong.
  assert.ok((await forcedApi.list()).items.length >= 1);
  await forcedApi.download(docId, coerced.stepUp);
  // The decoy session sees a calm account.
  assert.deepEqual(await forcedApi.duressStatus(), { lockdown: false });
  // Sensitive changes fail like a busy server, on this session and on Alice's own phone.
  const req = await forcedApi.getLink(code);
  await assert.rejects(forcedApi.approveLink(code, await sealBytes(alice, alice.seed, req), coerced.stepUp), (e) => e.code === "busy" && e.status === 503);
  await assert.rejects(phone.removeDevice(coerced.deviceId, alice.stepUp), (e) => e.code === "busy");
  await assert.rejects(phone.setCard({ tag: cardTag(newCard().secret), blob: random(93) }, alice.stepUp), (e) => e.code === "busy");
  const status = await phone.duressStatus();
  assert.equal(status.lockdown, true);

  // Recoveries now wait twice as long.
  const dev = await newDevice({ tag: cardTag(card.secret) });
  await witness(0, dev.req.code);
  const w = await witness(1, dev.req.code);
  assert.ok(w.releaseAt - Date.now() > 2 * DELAY - 1000, "doubled wait");
  const [alert] = await phone.alerts();
  assert.equal(alert.duress, true);

  // A witness who was asked to be told sees the signal.
  const seen = await witnessApis[2].protectingAlerts();
  assert.ok(seen.some((a) => a.kind === "duress" && a.owner === alice.id));
  assert.ok(seen.some((a) => a.kind === "recovery" && a.owner === alice.id));

  // Lifting lockdown: only from a calm session, only after a quiet period.
  await assert.rejects(forcedApi.clearDuress(coerced.stepUp), (e) => e.code === "busy");
  await assert.rejects(phone.clearDuress(alice.stepUp), (e) => e.code === "too_soon");
  const { clearableAt } = await phone.duressStatus();
  await sleep(Math.max(0, Number(clearableAt) - Date.now()) + 100); // until it has been calm long enough
  assert.equal((await phone.clearDuress(alice.stepUp)).cleared, true);
  await phone.removeDevice(coerced.deviceId, alice.stepUp);
  await cancelAll();
  const types = (await phone.ledger()).entries.map((e) => e.type);
  for (const t of ["duress.signaled", "duress.cleared"]) assert.ok(types.includes(t), `ledger has ${t}`);
  assert.ok((await phone.ledger()).entries.some((e) => e.type === "access.denied" && e.detail.reason === "lockdown"));
});

/* ---------------- the public log ---------------- */

let firstCheck;

test("transparency: Alice's latest entry is in the public log, and the log only grows", async () => {
  firstCheck = await phone.continuity();
  assert.equal(firstCheck.ok, true, firstCheck.reason);
  await phone.list();
  await sealFor(alice, "x", "y").then(({ envelope, index }) => phone.upload(envelope, index));
  const second = await phone.continuity({ previous: firstCheck });
  assert.equal(second.ok, true, second.reason);
  assert.ok(second.size > firstCheck.size);
});

test("transparency: the page the phone verified and the public log are the same history (CRYPTO-01)", async () => {
  const l = await phone.ledger();
  assert.equal(l.ok, true, l.reason);
  const c = await phone.continuity({ previous: firstCheck, head: l.head });
  assert.equal(c.ok, true, c.reason);
  assert.deepEqual([c.seq, c.hash], [l.head.seq, l.head.hash]);
  // A short page that starts after the head seen earlier links back to it through the range route.
  const seen = { seq: l.head.seq, hash: l.head.hash };
  for (const n of ["a", "b"]) await sealFor(alice, n, n).then(({ envelope, index }) => phone.upload(envelope, index)); // two more entries
  const later = await phone.ledger({ limit: 1, previousHead: seen });
  assert.equal(later.ok, true, later.reason);
  assert.equal(later.previousHeadOnPage, false);
  // The server rewrites the entry this phone saw: refused.
  const db = new DatabaseSync(`${stack.root}/ledger/ledger.db`);
  const owner = db.prepare("SELECT owner FROM entries WHERE seq = ? AND hash = ?").get(seen.seq, seen.hash).owner;
  db.prepare("UPDATE entries SET body = replace(body, '\"type\"', '\"type\" ') WHERE owner = ? AND seq = ?").run(owner, seen.seq);
  db.close();
  const bad = await phone.ledger({ limit: 1, previousHead: seen });
  assert.equal(bad.ok, false);
});

test("transparency: anyone can fetch checkpoints; a configured cosigner vouches; a rewritten past is caught", async () => {
  const cp = await (await fetch(`${stack.baseUrl}/tlog/v1/checkpoint`)).json();
  assert.ok(cp.checkpoint.size > 0);
  const { size, root, at } = cp.checkpoint;
  const sig = ml_dsa87.sign(cosignMessage("test-cosigner", size, Buffer.from(root, "hex"), at), cosigner.secretKey);
  const post = (body) => fetch(`${stack.baseUrl}/tlog/v1/cosign`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  assert.equal((await post({ name: "test-cosigner", size, sig: b64u(sig) })).status, 200);
  assert.equal((await post({ name: "test-cosigner", size, sig: b64u(random(sig.length)) })).status, 401);
  assert.equal((await post({ name: "stranger", size, sig: b64u(sig) })).status, 403);
  // Only cosigners built into the app count (PC-04): without that list, the server's word means nothing.
  assert.deepEqual((await phone.continuity({ previous: firstCheck })).cosigned, []);
  const withCosig = await phone.continuity({ previous: firstCheck, cosigners: new Map([["test-cosigner", cosigner.publicKey]]) });
  assert.deepEqual(withCosig.cosigned, ["test-cosigner"]);

  // The server rewrites the first entries of the log.
  const db = new DatabaseSync(`${stack.root}/ledger/ledger.db`);
  db.prepare("UPDATE tlog_nodes SET hash = randomblob(32) WHERE idx = 0").run();
  db.close();
  await phone.list();
  const after = await phone.continuity({ previous: { size: withCosig.size, root: withCosig.root } });
  assert.equal(after.ok, false);
  assert.match(after.reason, /doesn't extend|isn't in the public log/);
});
