// Regressions for the ID-chip anchor (VAULT-01, CREDS-01, CREDS-02, CREDS-03): what a passport
// link lets the SERVER OPERATOR, and other people's passports, do.
//
// Before: the anchor part reached the recovery service in plaintext, was stored under
// HKDF(anchor-secret.bin, identity fields), and was found by a hash of name/birth date/sex/
// nationality. So the operator rebuilt it offline from its own files plus the holder's name
// and birth date (+ one stolen card = the whole seed, no wait, no veto); an old passport or a
// namesake's passport opened it; and a copy of someone's chip files squatted their identity.
//
// Now: the phone seals the part under a key from the chip's DG15 (the server doesn't store it);
// the anchor is that one chip's key fingerprint; and linking needs the live chip. That closes
// CREDS-01/02 and the at-rest half of VAULT-01/CREDS-03. It does NOT stop an operator who
// records DG15 in transit (V74-03): the last test here documents that limit as it stands, and
// that the app and the docs say so.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { hkdfSync, createDecipheriv } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { identityId, random } from "@humid/htp";
import {
  newCard, cardTag, sealCardPart, openCardPart, quorumParts, decodeQuorumPart, combineQuorum,
  anchorPartKey, sealAnchorPart, openAnchorPart, ANCHOR_PART_BLOB_BYTES,
} from "@humid/recovery";
import { stableIdentity, readDg1 } from "@humid/anchor";
import { makeHolder, register } from "./holder.js";
import { testCsca, testPassport } from "../support/passport.js";

const S = suite();
const csca = testCsca("HumID Test Country");
let stack;
before(async () => { stack = await startStack({ recoveryDelayMs: 100_000, cscas: [csca.pem] }); });
after(async () => { await stack?.stop(); });

/** How the app links an ID chip: a fresh challenge, the live chip's answer, the part sealed to the chip. */
async function linkChip(h, api, chip, { answer = chip.answer, part = quorumParts(h.seed).anchor } = {}) {
  const nonce = await api.anchorChallenge();
  const sealedPart = await sealAnchorPart(anchorPartKey(chip.dg15), part, h.id);
  return api.setAnchor({ chip, sealedPart, signature: answer(nonce) }, h.stepUp);
}
/** A stranger's new device starts a two-proof recovery and presents a chip live. */
async function recoverWith(chip) {
  const rk = S.deriveKeys(random(64));
  const api = new HumidApi({ baseUrl: stack.baseUrl });
  const req = await api.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, platform: "attacker phone" });
  const nonce = await api.recoveryChallenge(req.id);
  return api.recoveryAddAnchor(req.id, { chip, signature: chip.answer(nonce) });
}
const PERSON = { surname: "SMITH", given: "JOHN", birth: "800101", sex: "M", issuer: "UTO", nationality: "UTO" };
const dir = () => join(stack.root, "recovery");
const anchorRow = (account) => { const db = new DatabaseSync(join(dir(), "recovery.db")); try { return db.prepare("SELECT * FROM anchors WHERE account = ?").get(account); } finally { db.close(); } };

test("VAULT-01 (at rest): the server's stored files, its secret and the holder's details don't open the anchor part", async () => {
  const alice = makeHolder("alice-anchor");
  const phone = await register(alice, stack.baseUrl);
  const parts = quorumParts(alice.seed);
  const card = newCard();
  await phone.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, alice.id) }, alice.stepUp);
  const passport = testPassport({ csca, mrz: { surname: "LIDDELL", given: "ALICE", issuer: "UTO", nationality: "UTO", birth: "801120", sex: "F", expiry: "330101" } });
  await linkChip(alice, phone, passport);

  // Everything the operator holds: its secret, its database, the MRZ fields that passed through.
  const anchorSecret = readFileSync(join(dir(), "anchor-secret.bin"));
  const row = anchorRow(alice.id);
  const mrz = readDg1(passport.dg1);
  assert.equal(row.version, 2);
  assert.ok(!JSON.stringify(row).includes(Buffer.from(passport.dg15).toString("base64")), "DG15 itself isn't stored");
  // The old derivation no longer opens anything: HKDF(secret, account, identity fields).
  const old = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.from(alice.id), `HUMID-ANCHOR-WRAP-v1|${stableIdentity(mrz)}`, 32));
  const b = Buffer.from(row.blob);
  assert.throws(() => { const d = createDecipheriv("aes-256-gcm", old, b.subarray(0, 12)).setAAD(Buffer.from(alice.id)); d.setAuthTag(b.subarray(b.length - 16)); d.update(b.subarray(12, b.length - 16)); d.final(); }, "the identity-field key opens nothing");
  // The operator's own wrap (its secret, "chip v2") does come off, but what's inside is the phone's
  // seal under a key from DG15, which it never kept.
  const k2 = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.from(alice.id), "HUMID-ANCHOR-WRAP-v1|chip v2", 32));
  const d = createDecipheriv("aes-256-gcm", k2, b.subarray(0, 12)).setAAD(Buffer.from(alice.id)); d.setAuthTag(b.subarray(b.length - 16));
  const inner = new Uint8Array(Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]));
  assert.equal(inner.length, ANCHOR_PART_BLOB_BYTES);
  assert.throws(() => decodeQuorumPart(inner), "it isn't a recovery part");
  // A guess at the chip key from what the operator knows (the MRZ, the account) doesn't open it.
  for (const guess of [new TextEncoder().encode(stableIdentity(mrz)), new Uint8Array(passport.dg1), new Uint8Array(passport.sod)]) {
    await assert.rejects(openAnchorPart(anchorPartKey(guess), inner, alice.id));
  }
  // From what's stored alone, a stolen card gives one part, not two.
  const cardRow = (() => { const db = new DatabaseSync(join(dir(), "recovery.db")); try { return db.prepare("SELECT blob FROM cards WHERE account = ?").get(alice.id); } finally { db.close(); } })();
  const cardPart = await openCardPart(card.secret, new Uint8Array(cardRow.blob), alice.id);
  assert.throws(() => combineQuorum([cardPart, cardPart]), /two different kinds/);
  // The chip's DG15 opens it: what a recovering holder's phone reads from the chip, and also
  // what the server sees in transit (next test).
  const real = await openAnchorPart(anchorPartKey(passport.dg15), inner, alice.id);
  assert.equal(identityId(S.deriveKeys(combineQuorum([real, cardPart])).dsaPk), alice.id, "the holder, with the chip, still recovers");
});

test("CREDS-03: a plain anchor part is refused: it must be sealed to the chip on the phone", async () => {
  const h = makeHolder("plain-part");
  const api = await register(h, stack.baseUrl);
  const passport = testPassport({ csca, mrz: { ...PERSON, given: "PLAIN" } });
  // What an older app sent: { part } in the clear.
  const raw = await api.anchorChallenge();
  await assert.rejects(api.setAnchor({ chip: passport, sealedPart: new Uint8Array(65), signature: passport.answer(raw) }, h.stepUp), (e) => e.code === "bad_part");
});

test("CREDS-02: linking needs the live chip: a copy of someone's chip files can't squat their identity", async () => {
  const victim = testPassport({ csca, mrz: { ...PERSON, given: "MARY", sex: "F", birth: "900303", number: "VIC123456" } });
  const copy = { dg1: victim.dg1, sod: victim.sod, dg15: victim.dg15 }; // what a hotel or KYC vendor keeps
  const squatter = makeHolder("squatter");
  const sapi = await register(squatter, stack.baseUrl);
  const forged = () => new Uint8Array(128).fill(7);
  await assert.rejects(linkChip(squatter, sapi, copy, { answer: forged }), (e) => e.code === "chip_not_present");
  // No answer at all, or a challenge never asked for: refused too.
  await assert.rejects(sapi.setAnchor({ chip: copy, sealedPart: await sealAnchorPart(anchorPartKey(copy.dg15), quorumParts(squatter.seed).anchor, squatter.id), signature: new Uint8Array(0) }, squatter.stepUp), (e) => e.code === "challenge_expired");
  // A chip with no Active Authentication key can't hold a remote part at all.
  const noAa = testPassport({ csca, mrz: { ...PERSON, given: "NOAA" }, aaKind: null });
  await sapi.anchorChallenge();
  await assert.rejects(sapi.setAnchor({ chip: noAa, sealedPart: new Uint8Array(ANCHOR_PART_BLOB_BYTES), signature: new Uint8Array(8) }, squatter.stepUp), (e) => e.code === "no_chip_proof");
  // The real holder, with the real chip, links it.
  const mary = makeHolder("real-mary");
  const mapi = await register(mary, stack.baseUrl);
  assert.equal((await linkChip(mary, mapi, victim)).version, 2);
});

test("CREDS-01: an old passport (still in date) doesn't open the anchor after the holder links the new one", async () => {
  const victim = makeHolder("victim-renewal");
  const vapi = await register(victim, stack.baseUrl);
  const oldPassport = testPassport({ csca, mrz: { ...PERSON, number: "OLD000001", expiry: "311231" } });
  const newPassport = testPassport({ csca, mrz: { ...PERSON, number: "NEW000002", expiry: "361231" } });
  await linkChip(victim, vapi, newPassport);
  await assert.rejects(recoverWith(oldPassport), (e) => e.code === "unknown_anchor", "the thief's old booklet names no one");
  const ok = await recoverWith(newPassport);
  assert.equal(ok.account, victim.id, "the linked passport still works");
  assert.equal(ok.anchorSealed, true);
  for (const a of await vapi.alerts()) await vapi.cancelAlert(a.ref, victim.stepUp);
});

test("CREDS-01: a namesake's own passport doesn't open someone else's anchor, and they can link their own", async () => {
  const victim = makeHolder("victim-namesake");
  const vapi = await register(victim, stack.baseUrl);
  const P2 = { ...PERSON, given: "JAMES", birth: "750505" };
  await linkChip(victim, vapi, testPassport({ csca, mrz: { ...P2, number: "AAA111111" } }));
  const namesake = testPassport({ csca, mrz: { ...P2, number: "ZZZ999999" } });
  await assert.rejects(recoverWith(namesake), (e) => e.code === "unknown_anchor");
  const them = makeHolder("the-namesake");
  const tapi = await register(them, stack.baseUrl);
  assert.equal((await linkChip(them, tapi, namesake)).version, 2, "no anchor_taken: it's a different chip");
});

test("migration: an anchor linked the old way still recovers, and re-linking on the next chip read replaces it", async () => {
  const h = makeHolder("legacy-anchor");
  const api = await register(h, stack.baseUrl);
  const passport = testPassport({ csca, mrz: { ...PERSON, given: "LEGACY", birth: "700707" } });
  // Write a v1 row the way the old service did: identity-field hash, server-only wrap of the plain part.
  const { anchorOf } = await import("@humid/anchor");
  const secret = readFileSync(join(dir(), "anchor-secret.bin"));
  const hmacKey = Buffer.from(hkdfSync("sha3-256", secret, Buffer.alloc(0), "HUMID-ANCHOR-v1 hmac", 32));
  const mrz = readDg1(passport.dg1);
  const key = Buffer.from(hkdfSync("sha3-256", secret, Buffer.from(h.id), `HUMID-ANCHOR-WRAP-v1|${stableIdentity(mrz)}`, 32));
  const { createCipheriv, randomBytes } = await import("node:crypto");
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce).setAAD(Buffer.from(h.id));
  const plain = Buffer.from([2, ...quorumParts(h.seed).anchor.y]);
  const blob = Buffer.concat([nonce, c.update(plain), c.final(), c.getAuthTag()]);
  const db = new DatabaseSync(join(dir(), "recovery.db"));
  db.prepare("INSERT INTO anchors (account, anchor, blob, document, country, created_at) VALUES (?, ?, ?, 'passport', 'UTO', ?)").run(h.id, anchorOf(mrz, hmacKey), blob, new Date().toISOString());
  db.close();
  assert.equal((await api.anchor()).version, 1, "the app sees it needs re-linking");
  const r = await recoverWith(passport);
  assert.equal(r.account, h.id);
  assert.equal(r.anchorSealed, false, "v1: the part itself, as before");
  for (const a of await api.alerts()) await api.cancelAlert(a.ref, h.stepUp);
  // The next live chip read re-links it as v2, and the v1 row is gone.
  await linkChip(h, api, passport);
  const row = anchorRow(h.id);
  assert.equal(row.version, 2);
  assert.equal((await api.anchor()).version, 2);
});

test("V74-03 (the limit, documented): an operator that records DG15 in transit opens the anchor part; the app and docs say so", async () => {
  // DG15 is public chip data and the server must see it to check the chip, so a passport link
  // gives a hostile operator the passport piece. This test pins that behaviour as it is, so a
  // future change (the cosigner split wrap, docs/CONTINUITY.md) has to update it on purpose.
  const alice = makeHolder("alice-dg15-limit");
  const phone = await register(alice, stack.baseUrl);
  const parts = quorumParts(alice.seed);
  const card = newCard();
  await phone.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, alice.id) }, alice.stepUp);
  const passport = testPassport({ csca, mrz: { surname: "LIMIT", given: "ALICE", birth: "811111" } });
  await linkChip(alice, phone, passport);
  // What the operator sees on its own internal hop: the chip data in the link request.
  const seenDg15 = new Uint8Array(passport.dg15);
  const anchorSecret = readFileSync(join(dir(), "anchor-secret.bin"));
  const b = Buffer.from(anchorRow(alice.id).blob);
  const k2 = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.from(alice.id), "HUMID-ANCHOR-WRAP-v1|chip v2", 32));
  const d = createDecipheriv("aes-256-gcm", k2, b.subarray(0, 12)).setAAD(Buffer.from(alice.id)); d.setAuthTag(b.subarray(b.length - 16));
  const inner = new Uint8Array(Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]));
  const anchorPart = await openAnchorPart(anchorPartKey(seenDg15), inner, alice.id);
  const cardRow = (() => { const db = new DatabaseSync(join(dir(), "recovery.db")); try { return db.prepare("SELECT blob FROM cards WHERE account = ?").get(alice.id); } finally { db.close(); } })();
  const cardPart = await openCardPart(card.secret, new Uint8Array(cardRow.blob), alice.id);
  assert.equal(identityId(S.deriveKeys(combineQuorum([anchorPart, cardPart])).dsaPk), alice.id, "passport piece (via DG15 in transit) + ONE stolen card = the account key");

  // So the holder must be told, plainly, before linking, and the docs must not claim otherwise.
  const root = new URL("../../", import.meta.url);
  const screen = readFileSync(new URL("apps/mobile/src/screens/you/recovery.jsx", root), "utf8");
  assert.match(screen, /Your vault server can open this piece/);
  assert.match(screen, /any ONE other of your proofs/);
  assert.match(screen, /use witnesses or a security key instead, or choose Only my own devices/);
  const recovery = readFileSync(new URL("docs/RECOVERY.md", root), "utf8");
  assert.match(recovery, /With a passport link: yes\./);
  assert.doesNotMatch(recovery, /\*\*still no\.\*\* It holds no part it can open/);
  const continuity = readFileSync(new URL("docs/CONTINUITY.md", root), "utf8");
  assert.match(continuity, /### The anchor and the operator/);
  assert.match(continuity, /2-of-2 split wrap with an\s+independent cosigner/);
  assert.doesNotMatch(continuity, /never reaches the\s+server in a form it can open/);
});
