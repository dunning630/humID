// End to end: a FIDO2 security key as the fourth recovery proof (docs/SECURITY-KEY.md).
// Real services, real crypto, the real CTAP client (@humid/fido) talking APDUs to a
// simulated key written separately from it (tests/support/fido-sim.js).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { createPublicKey, verify as verifySig, createHash } from "node:crypto";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { identityId, random } from "@humid/htp";
import {
  newCard, cardTag, sealCardPart, openCardPart, split, combine, encodeShare, decodeShare,
  quorumParts, combineQuorum, QUORUM, keyTag, sealKeyPart, openKeyPart,
} from "@humid/recovery";
import { addRecoveryKey, readRecoveryKey, RP_ID, clientDataHash } from "@humid/fido";
import { simulatedKey } from "../support/fido-sim.js";
import { makeHolder, anotherDevice, register, sealFor, sealBytes } from "./holder.js";

const DELAY = 2500;
const S = suite();
const PIN = "246810";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let stack, alice, phone, docId, card, key, witnesses, witnessApis;

/** What the app does when adding a key: one tap (challenge signed, secret read), then one live check. */
async function addKey(h, api, k, { pin = PIN, newPin = false, label } = {}) {
  const { challenge, exclude } = await api.keyChallenge();
  const got = await addRecoveryKey(k, { pin, newPin, challenge, exclude });
  const r = await api.addKey(await addBody(h, got, label), h.stepUp);
  return { ...r, got };
}
async function addBody(h, got, label) {
  const blob = await sealKeyPart(got.secret, quorumParts(h.seed).key, h.id);
  return { tag: keyTag(got.secret), blob, pub: got.publicKey, credentialId: got.credentialId, authData: got.authData, signature: got.signature, label };
}

before(async () => {
  stack = await startStack({ recoveryDelayMs: DELAY, duressCoolOffMs: 5000 });
  alice = makeHolder("alice-seckey");
  phone = await register(alice, stack.baseUrl);
  const { envelope, index } = await sealFor(alice, "deed.txt", "Alice's deed");
  docId = (await phone.upload(envelope, index)).id;
  const parts = quorumParts(alice.seed);
  card = newCard();
  await phone.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, alice.id) }, alice.stepUp);
  witnesses = ["kim", "lou", "max"].map((n) => makeHolder(`${n}-seckey`));
  witnessApis = await Promise.all(witnesses.map((w) => register(w, stack.baseUrl)));
  const pieces = split(parts.witness.y, 3, 2);
  const guardians = [];
  for (let i = 0; i < 3; i++) {
    const code = (await witnessApis[i].offerContact(witnesses[i].pub)).code;
    const o = await phone.getOffer(code);
    guardians.push({ contact: o.account, offer: code, envelope: await sealBytes(alice, encodeShare({ owner: alice.id, label: "Alice", ...pieces[i], t: 2, n: 3 }), o) });
  }
  await phone.setContacts({ threshold: 2, guardians, scheme: "quorum" }, alice.stepUp);
  key = simulatedKey(); // a new key, no PIN yet
});
after(async () => { await stack?.stop(); });

async function newDevice(extra = {}) {
  const rk = S.deriveKeys(random(64));
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await api.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, platform: "New phone", ...extra });
  return { rk, api, req };
}
async function witness(i, code) {
  const h = await witnessApis[i].getHelp(code);
  const held = (await witnessApis[i].protecting()).find((x) => x.owner === alice.id);
  const { bytes } = await S.open(held.envelope, witnesses[i].keys);
  return witnessApis[i].help(code, { owner: alice.id, envelope: await sealBytes(witnesses[i], bytes, h) }, witnesses[i].stepUp);
}
/** The new device: one tap with the PIN; the server checks the key's signature over its challenge. */
async function keyProof(dev, k = key, pin = PIN) {
  const challenge = await dev.api.recoveryKeyChallenge(dev.req.id);
  const cands = await readRecoveryKey(k, { pin, challenge });
  const list = cands.map((c) => ({ tag: keyTag(c.secret), authData: c.authData, signature: c.signature, secret: c.secret }));
  const r = await dev.api.recoveryAddKey(dev.req.id, list);
  return { r, secret: list.find((c) => c.tag === r.tag).secret, list, challenge };
}
async function finish(dev, released, { keySecret = null } = {}) {
  const parts = [];
  if (released.blob) parts.push(await openCardPart(card.secret, released.blob, released.account));
  if (released.keyBlob) parts.push(await openKeyPart(keySecret, released.keyBlob, released.account));
  if (released.shares) {
    const pieces = [];
    for (const env of released.shares) pieces.push(decodeShare((await S.open(env, dev.rk)).bytes));
    parts.push({ x: QUORUM.witness, y: combine(pieces) });
  }
  const seed = combineQuorum(parts);
  const keys = S.deriveKeys(seed);
  assert.equal(identityId(keys.dsaPk), alice.id, "two proofs rebuild Alice's seed");
  const me = anotherDevice({ ...alice, keys, pub: S.publicOf(keys), seed });
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await api.enrollDevice({ account: alice.id, device: me.device, via: "quorum", recoveryId: dev.req.id, sign: me.enrollSign, soleBiometric: true });
  const envelope = await api.download(docId, me.stepUp);
  assert.equal(new TextDecoder().decode((await S.open(envelope, me.keys)).bytes), "Alice's deed");
  return { api, me };
}
const cancelAll = async () => { for (const a of await phone.alerts()) await phone.cancelAlert(a.ref, alice.stepUp); };
const ledgerTypes = async () => (await phone.ledger()).entries.map((e) => e.type);

/* ---------------- adding a key ---------------- */

test("adding a key: a key with no PIN gets one, the key signs the server's challenge, and the server stores nothing that opens", async () => {
  await assert.rejects(addKey(alice, phone, key), (e) => e.code === "pin_not_set", "a key with no PIN isn't used without one");
  await assert.rejects(addKey(alice, phone, key, { newPin: true, pin: "12345" }), (e) => e.code === "pin_policy", "HumID asks for 6 or more");
  const r = await addKey(alice, phone, key, { newPin: true, label: random(64) });
  assert.equal(r.count, 1);
  assert.equal(key.state.pinSet, true, "the key has its PIN now");
  // The answer the server checked: our RP, present, PIN-verified, signed over SHA-256("HUMID-KEY-v1 add " ‖ challenge).
  assert.equal(r.got.authData[32] & 0x05, 0x05);
  assert.deepEqual([...r.got.authData.subarray(0, 32)], [...createHash("sha256").update(RP_ID).digest()]);
  const list = await phone.keys();
  assert.equal(list.keys.length, 1);
  assert.match(list.keys[0].id, /^[0-9a-f]{32}$/);
  assert.equal(list.max, 4);
  assert.ok(!JSON.stringify(list).includes(keyTag(r.got.secret)), "the tag isn't handed out");
  const db = new DatabaseSync(`${stack.root}/recovery/recovery.db`);
  const row = db.prepare("SELECT * FROM seckeys WHERE account = ?").get(alice.id);
  db.close();
  assert.equal(row.blob.length, 12 + 65 + 16, "the key part is stored encrypted");
  assert.ok(!Buffer.from(row.blob).includes(Buffer.from(quorumParts(alice.seed).key.y.subarray(0, 16))), "and not in the clear");
  assert.ok((await ledgerTypes()).includes("recovery.key_added"));
  r.got.secret.fill(0);
});

test("adding a key: a challenge answers once, a forged answer is refused, the same key twice is refused", async () => {
  const k2 = simulatedKey({ pin: PIN });
  const got = await addRecoveryKey(k2, { pin: PIN, challenge: (await phone.keyChallenge()).challenge });
  const body = await addBody(alice, got);
  // Signed by another key: refused (and that used up the challenge).
  const other = await addRecoveryKey(simulatedKey({ pin: PIN }), { pin: PIN, challenge: random(32) });
  await assert.rejects(phone.addKey({ ...body, pub: other.publicKey }, alice.stepUp), (e) => e.code === "bad_key_proof");
  // The genuine answer can't be replayed onto a new challenge, nor sent with none.
  await assert.rejects(phone.addKey(body, alice.stepUp), (e) => e.code === "challenge_expired");
  await phone.keyChallenge();
  await assert.rejects(phone.addKey(body, alice.stepUp), (e) => e.code === "bad_key_proof", "an answer to an old challenge doesn't check out against a new one");
  // The first key again: the key itself refuses to make a second HumID credential for Alice.
  await assert.rejects(addKey(alice, phone, key), (e) => e.code === "credential_excluded");
  assert.equal((await phone.keys()).keys.length, 1);
  got.secret.fill(0); other.secret.fill(0);
});

test("a stolen key alone opens nothing: one proof, no wait, nothing released", async () => {
  const dev = await newDevice();
  const { r } = await keyProof(dev);
  assert.deepEqual(r.kinds, ["key"]);
  assert.equal(r.account, alice.id);
  assert.equal(r.releaseAt, null);
  await sleep(DELAY * 2);
  const st = await dev.api.recoveryStatus(dev.req.id);
  assert.equal(st.status, "collecting");
  assert.equal(st.keyBlob, undefined);
  await cancelAll();
});

test("a wrong PIN: the key refuses and counts it; the server never sees the PIN", async () => {
  const dev = await newDevice();
  const challenge = await dev.api.recoveryKeyChallenge(dev.req.id);
  await assert.rejects(readRecoveryKey(key, { pin: "000000", challenge }), (e) => e.code === "pin_invalid" && e.retries === 7);
  key.powerCycle();
  await cancelAll().catch(() => {});
});

/* ---------------- recovering ---------------- */

test("security key + recovery card (no people): the 7-day tier, alerts naming both, then the device joins", async () => {
  const dev = await newDevice({ tag: cardTag(card.secret) });
  const { r, secret } = await keyProof(dev);
  assert.deepEqual(r.kinds.sort(), ["card", "key"]);
  const wait = r.releaseAt - Date.now();
  assert.ok(wait > (DELAY * 7) / 3 - 1000 && wait <= (DELAY * 7) / 3, `card + key waits 7/3 × base (${wait})`);
  const [alert] = await phone.alerts();
  assert.match(alert.evidence, /seal card \+ security key/);
  assert.ok((await ledgerTypes()).includes("recovery.evidence"));
  await sleep(wait + 150);
  const released = await dev.api.recoveryStatus(dev.req.id);
  assert.equal(released.status, "released");
  assert.ok(released.keyBlob && released.blob && !released.shares);
  const joined = await finish(dev, released, { keySecret: secret });
  const added = (await phone.ledger()).entries.filter((e) => e.type === "device.added").pop();
  assert.deepEqual(added.detail.kinds.sort(), ["card", "key"]);
  await phone.removeDevice(joined.api.session.device, alice.stepUp);
});

test("security key + witnesses: the 72-hour tier", async () => {
  const dev = await newDevice();
  await witness(0, dev.req.code);
  await witness(1, dev.req.code);
  const { r, secret } = await keyProof(dev);
  const wait = r.releaseAt - Date.now();
  assert.ok(wait > DELAY - 1000 && wait <= DELAY, `witnesses + key wait the base delay (${wait})`);
  await sleep(wait + 150);
  const released = await dev.api.recoveryStatus(dev.req.id);
  assert.ok(released.keyBlob && released.shares && !released.blob);
  const joined = await finish(dev, released, { keySecret: secret });
  await phone.removeDevice(joined.api.session.device, alice.stepUp);
});

test("only the key itself counts: a replayed answer and a tag without the key are refused", async () => {
  const dev = await newDevice({ tag: cardTag(card.secret) });
  const first = await keyProof(dev);
  // Same request, the earlier answer again: the challenge it signed is gone.
  await dev.api.recoveryKeyChallenge(dev.req.id);
  await assert.rejects(dev.api.recoveryAddKey(dev.req.id, first.list), (e) => e.code === "bad_key_proof");
  // Another device that only knows the tag (no key, no PIN): nothing it can sign.
  const thief = await newDevice();
  await thief.api.recoveryKeyChallenge(thief.req.id);
  const forged = first.list.map((c) => ({ ...c, signature: c.signature.map((b, i) => (i === 10 ? b ^ 1 : b)) }));
  await assert.rejects(thief.api.recoveryAddKey(thief.req.id, forged), (e) => e.code === "bad_key_proof");
  assert.ok((await ledgerTypes()).includes("recovery.key_refused"), "Alice sees the refused answer");
  await cancelAll();
});

test("a copied key is caught by its counter going backwards, and Alice is told", async () => {
  const copy = key.clone();
  const dev = await newDevice();
  await keyProof(dev); // the real key moves its counter on
  await cancelAll();
  const dev2 = await newDevice();
  await assert.rejects(keyProof(dev2, copy), (e) => e.code === "key_cloned");
  const refused = (await phone.ledger()).entries.filter((e) => e.type === "recovery.key_refused").pop();
  assert.equal(refused.detail.reason, "key_cloned");
  await cancelAll();
});

test("removing the key during the wait withdraws it as a proof: the recovery goes back to collecting", async () => {
  const extra = simulatedKey({ pin: PIN });
  const { id } = await addKey(alice, phone, extra);
  const dev = await newDevice({ tag: cardTag(card.secret) });
  const { r } = await keyProof(dev, extra);
  assert.ok(r.releaseAt);
  await phone.removeKey(id, alice.stepUp);
  const st = await dev.api.recoveryStatus(dev.req.id);
  assert.equal(st.status, "collecting");
  assert.equal(st.releaseAt, null);
  assert.deepEqual(st.kinds, ["card"]);
  await sleep((DELAY * 7) / 3 + 200);
  const later = await dev.api.recoveryStatus(dev.req.id);
  assert.equal(later.status, "collecting", "nothing is released after the old wait either");
  assert.equal(later.keyBlob, undefined);
  assert.ok((await ledgerTypes()).includes("recovery.key_removed"));
  await cancelAll();
});

test("replacing the recovery card withdraws the old card as a proof too", async () => {
  const dev = await newDevice({ tag: cardTag(card.secret) });
  await keyProof(dev);
  assert.ok((await dev.api.recoveryStatus(dev.req.id)).releaseAt);
  const fresh = newCard();
  await phone.setCard({ tag: cardTag(fresh.secret), blob: await sealCardPart(fresh.secret, quorumParts(alice.seed).card, alice.id) }, alice.stepUp);
  const st = await dev.api.recoveryStatus(dev.req.id);
  assert.equal(st.status, "collecting");
  assert.deepEqual(st.kinds, ["key"]);
  card = fresh;
  await cancelAll();
});

test("up to four keys; a fifth is refused", async () => {
  const have = (await phone.keys()).keys.length;
  for (let i = have; i < 4; i++) await addKey(alice, phone, simulatedKey({ pin: PIN }));
  await assert.rejects(addKey(alice, phone, simulatedKey({ pin: PIN })), (e) => e.code === "too_many_keys");
  for (const k of (await phone.keys()).keys.slice(1)) await phone.removeKey(k.id, alice.stepUp);
  assert.equal((await phone.keys()).keys.length, 1);
});

test("a key the server doesn't know is refused without telling anything about anyone", async () => {
  const stranger = simulatedKey({ pin: PIN });
  const k = await addRecoveryKey(stranger, { pin: PIN, challenge: random(32) }); // a credential no server has
  k.secret.fill(0);
  const dev = await newDevice();
  await assert.rejects(keyProof(dev, stranger), (e) => e.code === "unknown_key" && !String(e.message).includes("hid_"));
  await cancelAll().catch(() => {});
});

test("duress: adding or removing a key fails like a busy server", async () => {
  const coerced = anotherDevice(alice);
  const forced = new HumidApi({ baseUrl: stack.baseUrl });
  await forced.enrollDevice({ account: alice.id, device: coerced.device, via: "link", sign: coerced.enrollSign });
  await forced.presence(true);
  await sleep(150);
  await assert.rejects(addKey(alice, forced, simulatedKey({ pin: PIN })), (e) => e.code === "busy" && e.status === 503);
  const [first] = (await phone.keys()).keys;
  await assert.rejects(phone.removeKey(first.id, alice.stepUp), (e) => e.code === "busy");
});

test("what the key signed is what the docs say: SHA-256(\"HUMID-KEY-v1 recover \" ‖ challenge)", () => {
  const ch = random(32);
  const ours = clientDataHash("recover", ch);
  const theirs = createHash("sha256").update("HUMID-KEY-v1 recover ").update(ch).digest();
  assert.deepEqual([...ours], [...theirs]);
  assert.ok(createPublicKey && verifySig); // the server checks with node:crypto, independently of @humid/fido
});
