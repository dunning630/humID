// CRYPTO-02: recovery pieces rotate. Before, every part was a point on one fixed line through
// the account seed (epoch 1 forever), so two REMOVED witnesses plus a new card (or the anchor
// part) rebuilt the seed, and "their pieces no longer work" was a server rule only. Now a
// holder can start a new set of pieces (a new epoch, signed by the account key): old pieces
// no longer fit with new ones, combineQuorum refuses a mix, and the server deletes what it held
// from older sets, cancels recoveries under way and refuses pieces made for an older set.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { startStack } from "./stack.js";
import { ml_dsa87 } from "@humid/htp";
import { suite } from "@humid/crypto";
import { random } from "@humid/htp";
import { HumidApi } from "@humid/api";
import {
  quorumParts, split, combine, combineQuorum, newCard, cardTag, sealCardPart, openCardPart, QUORUM,
  encodeShare, recoveryModeMessage,
} from "@humid/recovery";
import { makeHolder, register, sealBytes } from "./holder.js";

const S = suite();
let stack;
before(async () => { stack = await startStack({ recoveryDelayMs: 100_000 }); });
after(async () => { await stack?.stop(); });

const statement = (h, mode, version, epoch) => ({ mode, version, epoch, sig: ml_dsa87.sign(recoveryModeMessage(h.id, mode, version, epoch), h.keys.dsaSk) });

test("the PoC: removed witnesses + a new card, or + the anchor part, no longer rebuild the seed once the pieces are new", async () => {
  const seed = crypto.getRandomValues(new Uint8Array(64));
  const account = "hid_" + "cd".repeat(20);
  const old = quorumParts(seed, 1);
  const oldShares = split(old.witness.y, 3, 2);
  // The holder removes those witnesses and makes new pieces (epoch 2), then a new card.
  const now = quorumParts(seed, 2);
  assert.notDeepEqual(now.witness.y, old.witness.y, "the witness part changed");
  assert.notDeepEqual(now.card.y, old.card.y, "the card part changed");
  const card2 = newCard();
  const cardPart = await openCardPart(card2.secret, await sealCardPart(card2.secret, now.card, account), account, 2);
  const removed = { x: QUORUM.witness, y: combine([oldShares[0], oldShares[2]]), epoch: 1 };
  assert.throws(() => combineQuorum([removed, cardPart]), /different sets/, "refused outright");
  assert.throws(() => combineQuorum([removed, now.anchor]), /different sets/);
  // Even with the epoch label stripped, the bytes don't fit: the line moved.
  assert.notDeepEqual(combine([{ x: removed.x, y: removed.y }, { x: cardPart.x, y: cardPart.y }]), seed);
  assert.notDeepEqual(combine([{ x: removed.x, y: removed.y }, { x: now.anchor.x, y: now.anchor.y }]), seed);
  // Within one set, everything still fits.
  assert.deepEqual(combineQuorum([{ ...now.witness }, cardPart]), seed);
  // And a card sealed for epoch 2 doesn't open as an epoch-1 card (it's bound in the AAD).
  await assert.rejects(openCardPart(card2.secret, await sealCardPart(card2.secret, now.card, account), account, 1));
});

test("the server: a new set retires every stored piece, cancels recoveries, and refuses pieces for the old set", async () => {
  const h = makeHolder("epochs");
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  await api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign, recoveryMode: statement(h, "hardened", 1, 1) });
  const p1 = quorumParts(h.seed, 1);
  const card1 = newCard();
  await api.setCard({ tag: cardTag(card1.secret), blob: await sealCardPart(card1.secret, p1.card, h.id), epoch: 1 }, h.stepUp);
  const w = makeHolder("epochs-w");
  const wapi = await register(w, stack.baseUrl);
  const code = (await wapi.offerContact(w.pub)).code;
  const o = await api.getOffer(code);
  const share = encodeShare({ owner: h.id, label: "H", ...split(p1.witness.y, 2, 2)[0], t: 2, n: 2 });
  const w2 = makeHolder("epochs-w2");
  const w2api = await register(w2, stack.baseUrl);
  const code2 = (await w2api.offerContact(w2.pub)).code;
  const o2 = await api.getOffer(code2);
  await api.setContacts({ threshold: 2, scheme: "quorum", epoch: 1, guardians: [
    { contact: o.account, offer: code, envelope: await sealBytes(h, share, o) },
    { contact: o2.account, offer: code2, envelope: await sealBytes(h, share, o2) },
  ] }, h.stepUp);
  // A recovery under way with the old card.
  const rk = S.deriveKeys(random(64));
  const dev = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await dev.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, tag: cardTag(card1.secret) });

  // New pieces: one signed statement.
  await api.setRecoveryMode(statement(h, "hardened", 2, 2), h.stepUp);
  const m = await api.recoveryMode();
  assert.deepEqual([m.mode, m.epoch, m.escrow], ["hardened", 2, []], "everything from the old set is gone from the server");
  const db = new DatabaseSync(`${stack.root}/recovery/recovery.db`);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM cards WHERE account = ?").get(h.id).n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM guardians WHERE owner = ?").get(h.id).n, 0);
  db.close();
  assert.equal((await dev.recoveryStatus(req.id)).status, "cancelled", "a recovery collecting old pieces is cancelled");
  const rk2 = S.deriveKeys(random(64));
  await assert.rejects(new HumidApi({ baseUrl: stack.baseUrl }).startRecovery({ method: "quorum", kemPk: rk2.kemPk, xPk: rk2.xPk, tag: cardTag(card1.secret) }), (e) => { assert.equal(e.code, "unknown_card"); return true; }, "the old card names nothing now");
  // The witnesses no longer hold anything for this person.
  assert.equal((await wapi.protecting()).some((x) => x.owner === h.id), false);

  // Pieces made for the old set are refused; an app that doesn't say which set is told to update.
  const stale = newCard();
  await assert.rejects(api.setCard({ tag: cardTag(stale.secret), blob: await sealCardPart(stale.secret, p1.card, h.id), epoch: 1 }, h.stepUp), (e) => e.code === "stale_epoch");
  await assert.rejects(api.setCard({ tag: cardTag(stale.secret), blob: await sealCardPart(stale.secret, p1.card, h.id) }, h.stepUp), (e) => e.code === "update_required");
  // Pieces for the new set are fine, and they don't open as old ones.
  const p2 = quorumParts(h.seed, 2);
  const card2 = newCard();
  await api.setCard({ tag: cardTag(card2.secret), blob: await sealCardPart(card2.secret, p2.card, h.id), epoch: 2 }, h.stepUp);
  assert.deepEqual((await api.recoveryMode()).escrow, ["card"]);
  // An epoch can't go backwards, even signed.
  await assert.rejects(api.setRecoveryMode(statement(h, "hardened", 3, 1), h.stepUp), (e) => e.code === "stale_recovery_mode");
  // The ledger says the pieces were renewed.
  const entry = (await api.ledger()).entries.filter((e) => e.type === "recovery.mode_set").pop();
  assert.equal(entry.detail.newPieces, true);
});
