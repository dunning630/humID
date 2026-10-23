// End to end: the two recovery modes (docs/RECOVERY.md#two-recovery-modes).
// Holder-only: no recovery material is ever stored, the recovery service refuses every
// escrow write and every recovery, and the choice is a statement signed by the account key
// that a server can't change on its own. Hardened: today's two proofs + wait + veto.
// Real services, real crypto.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, random } from "@humid/htp";
import {
  newCard, cardTag, sealCardPart, split, encodeShare, quorumParts, anchorPartKey, sealAnchorPart,
  recoveryModeMessage, recoveryModeHash, RECMODE_GENESIS, RECOVERY_MODES,
} from "@humid/recovery";
import { addRecoveryKey } from "@humid/fido";
import { signRequest } from "@humid/svc";
import { keyTag, sealKeyPart } from "@humid/recovery";
import { simulatedKey } from "../support/fido-sim.js";
import { makeHolder, anotherDevice, register, sealFor, sealBytes } from "./holder.js";
import { testCsca, testPassport } from "../support/passport.js";

const DELAY = 1500;
const S = suite();
const csca = testCsca("HumID Test Country");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let stack;

before(async () => { stack = await startStack({ recoveryDelayMs: DELAY, cscas: [csca.pem] }); });
after(async () => { await stack?.stop(); });

/** The account key's statement of a recovery mode, as the app signs it: chained to the one this holder signed at version - 1. */
const signed = new Map();
const statement = (h, mode, version = 1, epoch = 1) => {
  const after = signed.get(`${h.id}/${version - 1}`);
  const prev = version > 1 && after ? recoveryModeHash(h.id, after) : RECMODE_GENESIS;
  const st = { mode, version, epoch, prev, sig: ml_dsa87.sign(recoveryModeMessage(h.id, mode, version, epoch, prev), h.keys.dsaSk) };
  signed.set(`${h.id}/${version}`, st);
  return st;
};

async function registerAs(h, mode, extra = {}) {
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const sess = await api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign, recoveryMode: statement(h, mode), ...extra });
  return { api, sess };
}
const recoveryDb = () => new DatabaseSync(`${stack.root}/recovery/recovery.db`);
const escrowRows = (account) => {
  const db = recoveryDb();
  try {
    return {
      cards: db.prepare("SELECT COUNT(*) AS n FROM cards WHERE account = ?").get(account).n,
      guardians: db.prepare("SELECT COUNT(*) AS n FROM guardians WHERE owner = ?").get(account).n,
      sets: db.prepare("SELECT COUNT(*) AS n FROM guardian_sets WHERE owner = ?").get(account).n,
      anchors: db.prepare("SELECT COUNT(*) AS n FROM anchors WHERE account = ?").get(account).n,
      keys: db.prepare("SELECT COUNT(*) AS n FROM seckeys WHERE account = ?").get(account).n,
    };
  } finally { db.close(); }
};
const NONE = { cards: 0, guardians: 0, sets: 0, anchors: 0, keys: 0 };

/** Witnesses for `h`, set up as the app does. */
async function witnessesFor(h, api, parts) {
  const ws = [0, 1].map((i) => makeHolder(`${h.label}-w${i}`));
  const wapis = await Promise.all(ws.map((w) => register(w, stack.baseUrl)));
  const pieces = split(parts.witness.y, 2, 2);
  const guardians = [];
  for (let i = 0; i < 2; i++) {
    const code = (await wapis[i].offerContact(ws[i].pub)).code;
    const o = await api.getOffer(code);
    guardians.push({ contact: o.account, offer: code, envelope: await sealBytes(h, encodeShare({ owner: h.id, label: h.label, ...pieces[i], t: 2, n: 2 }), o) });
  }
  return { threshold: 2, guardians, scheme: "quorum" };
}

/* ---------------- holder-only ---------------- */

test("holder-only: setup stores no recovery card, and the server refuses every kind of escrow", async () => {
  const h = makeHolder("holder-only-setup");
  const parts = quorumParts(h.seed);
  const card = newCard();
  // Even if an app sent a card with the registration, it isn't stored.
  const { api, sess } = await registerAs(h, RECOVERY_MODES.holderOnly, { card: { tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, h.id) } });
  assert.equal(sess.cardSet, false);
  const mode = await api.recoveryMode();
  assert.equal(mode.mode, "holder-only");
  assert.deepEqual(mode.escrow, []);
  assert.ok(ml_dsa87.verify(mode.sig, recoveryModeMessage(h.id, mode.mode, mode.version, mode.epoch), h.pub.dsaPk), "the device can check the mode against its own account key");

  const refused = (e) => e.status === 409 && e.code === "holder_only";
  await assert.rejects(api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, h.id) }, h.stepUp), refused);
  await assert.rejects(api.setContacts(await witnessesFor(h, api, parts), h.stepUp), refused);
  const chip = testPassport({ csca, mrz: { surname: "HOLDER", given: "ONLY" } });
  await assert.rejects(api.anchorChallenge(), refused);
  await assert.rejects(api.setAnchor({ chip, sealedPart: await sealAnchorPart(anchorPartKey(chip.dg15), parts.anchor, h.id), signature: new Uint8Array(8) }, h.stepUp), refused);
  await assert.rejects(api.keyChallenge(), refused);
  assert.deepEqual(escrowRows(h.id), NONE);

  // The ledger says which mode was chosen, signed into the public log like everything else.
  const set = (await api.ledger()).entries.find((e) => e.type === "recovery.mode_set");
  assert.equal(set.detail.mode, "holder-only");
  assert.equal(set.detail.at, "setup");
  // Identity keeps the same signed statement, for every device to see.
  assert.equal((await api.me()).recoveryMode.mode, "holder-only");
});

test("holder-only: adding a device from another of your own devices still works", async () => {
  const h = makeHolder("holder-only-link");
  const { api } = await registerAs(h, RECOVERY_MODES.holderOnly);
  const second = anotherDevice(h);
  const lk = S.deriveKeys(random(64));
  const joiner = new HumidApi({ baseUrl: stack.baseUrl });
  const { code } = await joiner.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, devicePk: second.device.dsaPk, platform: "Tablet" });
  await api.approveLink(code, await sealBytes(h, h.seed, await api.getLink(code)), h.stepUp);
  const joined = await joiner.enrollDevice({ account: h.id, device: second.device, via: "link", linkCode: code, sign: second.enrollSign });
  assert.equal(joined.id, h.id);
  assert.equal((await api.me()).devices.length, 2);
});

test("holder-only: lose every device and nothing brings the vault back, not even escrow a server plants itself", async () => {
  const h = makeHolder("holder-only-lost");
  const { api } = await registerAs(h, RECOVERY_MODES.holderOnly);
  const { envelope, index } = await sealFor(h, "diary.txt", "private");
  await api.upload(envelope, index);
  await api.logout(); // the only device is gone

  // A server operator writes a recovery card for the account straight into its own database,
  // as if the holder had made one, hoping to open a recovery with it.
  const parts = quorumParts(h.seed);
  const card = newCard();
  const db = recoveryDb();
  db.prepare("INSERT INTO cards (account, tag, blob, created_at, scheme) VALUES (?, ?, ?, ?, 'quorum')").run(h.id, cardTag(card.secret), await sealCardPart(card.secret, parts.card, h.id), new Date().toISOString());
  db.prepare("INSERT INTO cards (account, tag, blob, created_at, scheme) VALUES (?, ?, ?, ?, 'full')").run(`${h.id.slice(0, -1)}0`, cardTag(newCard().secret), random(92), new Date().toISOString());
  db.close();

  const fresh = () => new HumidApi({ baseUrl: stack.baseUrl });
  const holderOnly = (e) => e.code === "holder_only";
  // Two proofs: the card names the account, and the service refuses to bind a recovery to it.
  const rk = S.deriveKeys(random(64));
  await assert.rejects(fresh().startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, tag: cardTag(card.secret) }), holderOnly);
  const dev = fresh();
  const req = await dev.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk });
  await assert.rejects(dev.recoveryAddCard(req.id, cardTag(card.secret)), holderOnly);
  // The older single-card route: refused too.
  const db2 = recoveryDb();
  db2.prepare("UPDATE cards SET scheme = 'full' WHERE account = ?").run(h.id);
  db2.close();
  await assert.rejects(fresh().startRecovery({ method: "card", tag: cardTag(card.secret) }), holderOnly);
  // No route lets a device join without an existing device's approval.
  const me = anotherDevice(h);
  for (const via of ["quorum", "card", "contacts"]) {
    await assert.rejects(fresh().enrollDevice({ account: h.id, device: me.device, via, recoveryId: req.id, sign: me.enrollSign }), (e) => e.code === "not_released");
  }
  await assert.rejects(fresh().enrollDevice({ account: h.id, device: me.device, via: "link", linkCode: "ABCDEFGHJKMN", sign: me.enrollSign }), (e) => e.code === "not_approved");
  assert.equal((await fresh().recoveryStatus(req.id)).account, null, "no recovery ever bound to the account");
});

test("holder-only: a mode the server changes on its own doesn't verify, and fails closed", async () => {
  const h = makeHolder("holder-only-forged");
  const { api } = await registerAs(h, RECOVERY_MODES.holderOnly);
  // The operator flips the stored mode to hardened, keeping the holder's signature (it can't make a new one).
  const db = recoveryDb();
  db.prepare("UPDATE modes SET mode = 'hardened' WHERE account = ?").run(h.id);
  db.close();
  const card = newCard();
  await assert.rejects(api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, quorumParts(h.seed).card, h.id) }, h.stepUp), (e) => e.code === "holder_only", "a statement that doesn't verify counts as holder-only");
  // The gateway then brings the recovery service back to identity's genuine statement (V74-01).
  const m = await api.recoveryMode();
  assert.equal(m.mode, "holder-only");
  assert.ok(ml_dsa87.verify(m.sig, recoveryModeMessage(h.id, m.mode, m.version, m.epoch, m.prev), h.pub.dsaPk), "healed from identity, and genuine");
  // Flipped in the recovery service without the gateway noticing (read straight from the service), it reads as broken.
  const db2 = recoveryDb();
  db2.prepare("UPDATE modes SET mode = 'hardened' WHERE account = ?").run(h.id);
  db2.close();
  const direct = await fetch(`${stack.upstreams.recovery}/internal/recovery-mode/${h.id}`, { headers: { "x-humid-assertion": signRequest(stack.internalSk, { aud: "recovery", method: "GET", path: `/internal/recovery-mode/${h.id}` }) } }).then((r) => r.json());
  assert.deepEqual([direct.mode, direct.broken], ["holder-only", true], "a statement that doesn't verify counts as holder-only");
  // The same flip in identity: the statement the devices fetch no longer verifies against the account key.
  const idb = new DatabaseSync(`${stack.root}/identity/identity.db`);
  idb.prepare("UPDATE identities SET recovery_mode = 'hardened' WHERE id = ?").run(h.id);
  idb.close();
  const shown = (await api.me()).recoveryMode;
  assert.equal(shown.mode, "hardened");
  assert.equal(ml_dsa87.verify(new Uint8Array(Buffer.from(shown.sig, "base64url")), recoveryModeMessage(h.id, shown.mode, shown.version, shown.epoch, shown.prev), h.pub.dsaPk), false, "a device that checks sees the flip");

  // A statement signed by any other key is refused outright.
  const mallory = makeHolder("mallory-modes");
  const prev = recoveryModeHash(h.id, signed.get(`${h.id}/1`));
  const forged = { mode: "hardened", version: 2, epoch: 1, prev, sig: ml_dsa87.sign(recoveryModeMessage(h.id, "hardened", 2, 1, prev), mallory.keys.dsaSk) };
  await assert.rejects(api.setRecoveryMode(forged, h.stepUp), (e) => e.status === 401 && e.code === "bad_proof");
});

/* ---------------- switching ---------------- */

test("holder-only → hardened: needs a fresh live check, is in the ledger, and then escrow is allowed", async () => {
  const h = makeHolder("upgrade");
  const { api } = await registerAs(h, RECOVERY_MODES.holderOnly);
  await assert.rejects(api.setRecoveryMode(statement(h, "hardened", 2)), (e) => e.code === "step_up_required");
  assert.equal((await api.recoveryMode()).mode, "holder-only");
  const r = await api.setRecoveryMode(statement(h, "hardened", 2), h.stepUp);
  assert.equal(r.mode, "hardened");
  const entry = (await api.ledger()).entries.filter((e) => e.type === "recovery.mode_set").pop();
  assert.deepEqual([entry.detail.mode, entry.detail.from, !!entry.detail.proof], ["hardened", "holder-only", true]);
  assert.equal((await api.me()).recoveryMode.mode, "hardened");
  // The holder's own older statement can't be played back over the newer one.
  await assert.rejects(api.setRecoveryMode(statement(h, "holder-only", 1), h.stepUp), (e) => e.code === "stale_recovery_mode");
  const card = newCard();
  await api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, quorumParts(h.seed).card, h.id) }, h.stepUp);
  assert.deepEqual((await api.recoveryMode()).escrow, ["card"]);
});

test("hardened → holder-only: refused while any escrow is left; each piece is deleted under its own check; then no rows remain", async () => {
  const h = makeHolder("downgrade");
  const { api } = await registerAs(h, RECOVERY_MODES.hardened);
  const parts = quorumParts(h.seed);
  const card = newCard();
  await api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, h.id) }, h.stepUp);
  await api.setContacts(await witnessesFor(h, api, parts), h.stepUp);
  const chip = testPassport({ csca, mrz: { surname: "DOWN", given: "GRADE" } });
  const nonce = await api.anchorChallenge();
  await api.setAnchor({ chip, sealedPart: await sealAnchorPart(anchorPartKey(chip.dg15), parts.anchor, h.id), signature: chip.answer(nonce) }, h.stepUp);
  const k = simulatedKey();
  const { challenge, exclude } = await api.keyChallenge();
  const got = await addRecoveryKey(k, { pin: "246810", newPin: true, challenge, exclude });
  await api.addKey({ tag: keyTag(got.secret), blob: await sealKeyPart(got.secret, parts.key, h.id), pub: got.publicKey, credentialId: got.credentialId, authData: got.authData, signature: got.signature }, h.stepUp);
  assert.deepEqual((await api.recoveryMode()).escrow.sort(), ["anchor", "card", "contacts", "key"]);
  // A recovery already under way, to show the switch ends it.
  const rk = S.deriveKeys(random(64));
  const dev = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await dev.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, tag: cardTag(card.secret) });

  const before = (await api.ledger()).entries.length;
  await assert.rejects(api.setRecoveryMode(statement(h, "holder-only", 2), h.stepUp), (e) => e.code === "escrow_remains");
  assert.equal((await api.recoveryMode()).mode, "hardened", "nothing changed");
  assert.equal((await api.ledger()).entries.filter((e) => e.type === "recovery.mode_set").length, 1, "and nothing was recorded but setup");
  assert.ok((await api.ledger()).entries.length >= before);

  // Each deletion is its own step-up; none goes through without one.
  await assert.rejects(api.removeCard(), (e) => e.code === "step_up_required");
  await assert.rejects(api.removeAllKeys(), (e) => e.code === "step_up_required");
  await api.removeCard(h.stepUp);
  await api.removeContacts(h.stepUp);
  await api.removeAnchor(h.stepUp);
  await api.removeAllKeys(h.stepUp);
  assert.deepEqual(escrowRows(h.id), NONE, "no escrow rows left in the recovery database");

  await api.setRecoveryMode(statement(h, "holder-only", 2), h.stepUp);
  assert.equal((await api.recoveryMode()).mode, "holder-only");
  assert.equal((await api.me()).recoveryMode.mode, "holder-only");
  const st = await dev.recoveryStatus(req.id);
  assert.equal(st.status, "cancelled", "a recovery under way is cancelled by the switch");
  const types = (await api.ledger()).entries.map((e) => e.type);
  for (const t of ["recovery.card_removed", "recovery.contacts_removed", "recovery.anchor_removed", "recovery.key_removed", "recovery.mode_set"]) assert.ok(types.includes(t), `ledger has ${t}`);
  // From now on, nothing can be stored again until the holder switches back with a live check.
  await assert.rejects(api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, h.id) }, h.stepUp), (e) => e.code === "holder_only");
  assert.deepEqual(escrowRows(h.id), NONE);
});

test("hardened accounts from before modes keep working: no statement on file means hardened", async () => {
  const h = makeHolder("legacy-hardened");
  const api = await register(h, stack.baseUrl); // an older app: no recoveryMode sent
  assert.equal((await api.recoveryMode()).mode, "hardened");
  const card = newCard();
  await api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, quorumParts(h.seed).card, h.id) }, h.stepUp);
  await sleep(10);
  assert.deepEqual((await api.recoveryMode()).escrow, ["card"]);
});
