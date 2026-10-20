// Proving it's you (HumID 4.0, provisional): the "Is this really you?"
// challenge, stamped media and the sealed evidence locker.
// Each test names the property it proves.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { newIssuerKey, blindSign } from "@humid/pass/issuer";
import * as M from "@humid/msg";

const rnd = (n) => new Uint8Array(randomBytes(n));
const T0 = Date.UTC(2026, 9, 20, 16, 0, 0);
const MIN = 60_000, DAY = 86_400_000;

const issuer = newIssuerKey(2048);
const stampKeys = M.importStampKeys([{ ...issuer.publicView, issuing: true }]);
const stamper = M.makeStamper(stampKeys, async (blinded) => blindSign(issuer, blinded));
const otherIssuer = newIssuerKey(2048);
const otherKeys = M.importStampKeys([{ ...otherIssuer.publicView, issuing: true }]);
const foreignStamper = M.makeStamper(otherKeys, async (blinded) => blindSign(otherIssuer, blinded));

const contains = (hay, needle) => Buffer.from(hay).indexOf(Buffer.from(needle)) >= 0;
const code = async (p, c) => { try { await p; } catch (e) { assert.ok(e instanceof M.MsgError, `expected MsgError, got ${e?.name}: ${e?.message}`); assert.equal(e.code, c); return; } assert.fail(`expected ${c}`); };

/** Two connected contacts: `son` (verifier) invited `dad` (claimant). */
async function meet(now = T0) {
  const relay = M.memoryRelay({ now: () => now });
  const seedSon = rnd(64), seedDad = rnd(64);
  const inv = await M.createInvite(seedSon, { now });
  relay.put(inv.box, inv.wire);
  const [bundle] = relay.take(M.inviteBoxOf(M.parseInviteCode(inv.code).secret), { keep: true });
  const opened = await M.openInvite(inv.code, bundle, { now });
  const req = await M.requestContact(seedDad, opened, { stamper, now });
  relay.put(req.box, req.wire);
  const [reqWire] = relay.take(inv.state.replyBox);
  const personaSon = M.personaFromSalt(seedSon, inv.state.personaSalt);
  const shown = await M.readRequest(inv.state, personaSon, reqWire, { now, stampKeys });
  const son = M.acceptRequest(inv.state, personaSon, shown, { now });
  const acc = await son.encrypt("accept", "", { now });
  const dad = req.session;
  await dad.decrypt(acc.wire, { now, stampKeys });
  return { son, dad, seedDad };
}

/** Son asks; dad's phone reads the question. */
async function ask(son, dad, opts = {}) {
  const now = opts.now ?? T0;
  const sent = await M.sendChallenge(son, { purpose: "call", note: "the call about the wire transfer", now, ...opts });
  const got = await dad.decrypt(sent.wire, { now, stampKeys });
  return { sent, pending: sent.pending, question: M.readChallenge(got, { now }) };
}

/* ---------------- "Is this really you?" ---------------- */

test("challenge: a stamped yes is confirmed, and both phones show the same spoken code", async () => {
  const { son, dad } = await meet();
  const { pending, question } = await ask(son, dad);
  assert.equal(question.question, M.QUESTIONS.call);
  assert.equal(question.note, "the call about the wire transfer");
  assert.equal(question.expired, false);
  const reply = await M.replyToChallenge(dad, question, { answer: "yes", stamper, now: T0 + MIN });
  assert.match(reply.code, /^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  const msg = await son.decrypt(reply.wire, { now: T0 + MIN, stampKeys });
  assert.equal(M.replyId(msg), pending.id);
  const r = M.checkReply(son, pending, msg, { now: T0 + MIN });
  assert.equal(r.verdict, "confirmed");
  assert.equal(r.code, reply.code, "the person on the call must read this exact code");
  assert.equal(r.live, true);
  assert.equal(r.pending.outcome, "confirmed");
});

test("challenge: a second answer to the same question is flagged, not confirmed again", async () => {
  const { son, dad } = await meet();
  const { pending, question } = await ask(son, dad);
  const first = await M.replyToChallenge(dad, question, { answer: "yes", stamper, now: T0 });
  const r1 = M.checkReply(son, pending, await son.decrypt(first.wire, { now: T0, stampKeys }), { now: T0 });
  const second = await M.replyToChallenge(dad, question, { answer: "yes", stamper, now: T0 });
  const r2 = M.checkReply(son, r1.pending, await son.decrypt(second.wire, { now: T0, stampKeys }), { now: T0 });
  assert.equal(r2.verdict, "already_answered");
  assert.equal(r2.code, null);
  assert.equal(r2.pending.outcome, "confirmed", "the first answer stands");
});

test("challenge: 'no' means denied, stamped or not; there is no spoken code", async () => {
  const { son, dad } = await meet();
  const { pending, question } = await ask(son, dad);
  const reply = await M.replyToChallenge(dad, question, { answer: "no", stamper, now: T0 });
  assert.equal(reply.code, null);
  const r = M.checkReply(son, pending, await son.decrypt(reply.wire, { now: T0, stampKeys }), { now: T0 });
  assert.equal(r.verdict, "denied");
  assert.equal(r.code, null);

  const q2 = await ask(son, dad);
  const body = new TextEncoder().encode(JSON.stringify({ v: 1, re: Buffer.from(q2.question.id, "hex").toString("base64url"), a: "no", r: Buffer.from(rnd(16)).toString("base64url") }));
  const unstamped = await dad.encrypt("challenge-reply", body, { now: T0 });
  const r2 = M.checkReply(son, q2.pending, await son.decrypt(unstamped.wire, { now: T0, stampKeys }), { now: T0 });
  assert.equal(r2.verdict, "denied");
  assert.equal(r2.live, false);
});

test("challenge: a yes without a valid live stamp is never confirmed", async () => {
  const { son, dad } = await meet();
  // 1. no stamp at all (built by hand: replyToChallenge refuses to do this)
  const q1 = await ask(son, dad);
  const body = new TextEncoder().encode(JSON.stringify({ v: 1, re: Buffer.from(q1.question.id, "hex").toString("base64url"), a: "yes", r: Buffer.from(rnd(16)).toString("base64url") }));
  const bare = await dad.encrypt("challenge-reply", body, { now: T0 });
  const r1 = M.checkReply(son, q1.pending, await son.decrypt(bare.wire, { now: T0, stampKeys }), { now: T0 });
  assert.equal(r1.verdict, "unverified");
  assert.equal(r1.code, null);
  // 2. a stamp from a key the app doesn't trust
  const q2 = await ask(son, dad);
  const foreign = await M.replyToChallenge(dad, q2.question, { answer: "yes", stamper: foreignStamper, now: T0 });
  assert.equal(M.checkReply(son, q2.pending, await son.decrypt(foreign.wire, { now: T0, stampKeys }), { now: T0 }).verdict, "unverified");
  // 3. the verifier has no stamp keys to check with
  const q3 = await ask(son, dad);
  const ok = await M.replyToChallenge(dad, q3.question, { answer: "yes", stamper, now: T0 });
  assert.equal(M.checkReply(son, q3.pending, await son.decrypt(ok.wire, { now: T0 }), { now: T0 }).verdict, "unverified");
});

test("challenge: answering takes a live check (no stamper, no reply)", async () => {
  const { son, dad } = await meet();
  const { question } = await ask(son, dad);
  await code(M.replyToChallenge(dad, question, { answer: "yes", now: T0 }), "stamp_required");
  await code(M.replyToChallenge(dad, question, { answer: "maybe", stamper, now: T0 }), "bad_answer");
});

test("challenge: a yes from a duress unlock comes back unverified, flagged duress", async () => {
  const { son, dad } = await meet();
  const { pending, question } = await ask(son, dad);
  const reply = await M.replyToChallenge(dad, question, { answer: "yes", stamper, duress: true, now: T0 });
  const r = M.checkReply(son, pending, await son.decrypt(reply.wire, { now: T0, stampKeys }), { now: T0 });
  assert.equal(r.verdict, "unverified");
  assert.equal(r.duress, true);
  assert.equal(r.code, null, "never show a code that would make a coerced call look genuine");
});

test("challenge: expiry on both sides", async () => {
  const { son, dad } = await meet();
  const { pending, question } = await ask(son, dad, { ttl: 2 * MIN });
  // the claimant's app refuses to answer a question well past its time
  await code(M.replyToChallenge(dad, question, { answer: "yes", stamper, now: T0 + 2 * MIN + M.CLOCK_SKEW + 1 }), "challenge_expired");
  // within the skew it answers, but the verifier judges by its own clock
  const late = await M.replyToChallenge(dad, question, { answer: "yes", stamper, now: T0 + 3 * MIN });
  const r = M.checkReply(son, pending, await son.decrypt(late.wire, { now: T0 + 3 * MIN, stampKeys }), { now: T0 + 3 * MIN });
  assert.equal(r.verdict, "expired");
  assert.throws(() => M.makeChallenge({ ttl: 31 * MIN }), (e) => e.code === "bad_challenge");
  assert.throws(() => M.makeChallenge({ purpose: "wire" }), (e) => e.code === "bad_challenge");
});

test("challenge: a reply to one question can't confirm another; codes differ per question", async () => {
  const { son, dad } = await meet();
  const a = await ask(son, dad), b = await ask(son, dad);
  const ra = await M.replyToChallenge(dad, a.question, { answer: "yes", stamper, now: T0 });
  const rb = await M.replyToChallenge(dad, b.question, { answer: "yes", stamper, now: T0 });
  assert.notEqual(ra.code, rb.code);
  const ma = await son.decrypt(ra.wire, { now: T0, stampKeys });
  const r = M.checkReply(son, b.pending, ma, { now: T0 });
  assert.equal(r.verdict, "not_this_challenge");
  assert.equal(r.pending.outcome, null, "the other question is still open");
});

test("challenge: the note is one short line; control and direction-override characters are removed", () => {
  const { pending } = M.makeChallenge({ note: "pay‮me\nnow", now: T0 });
  assert.equal(pending.note, "pay me now");
  assert.ok(!/[‮\n]/.test(pending.note));
  assert.throws(() => M.makeChallenge({ note: "x".repeat(141) }), (e) => e.code === "bad_challenge");
});

test("relay view: a challenge, a reply and a media message look exactly like a text", async () => {
  const { son, dad } = await meet();
  const text = await son.encrypt("text", "hi", { now: T0 });
  await dad.decrypt(text.wire, { now: T0 });
  const { sent, question } = await ask(son, dad);
  const reply = await M.replyToChallenge(dad, question, { answer: "yes", stamper, now: T0 });
  const media = await dad.encrypt("media", M.encodeMedia({ bytes: rnd(500), kind: "voice", mime: "audio/mp4", capturedAt: T0 }), { now: T0, stamper });
  for (const w of [sent.wire, reply.wire, media.wire]) assert.equal(w.length, text.wire.length);
});

/* ---------------- stamped media ---------------- */

test("media in a conversation: stamped is verified, unstamped is not", async () => {
  const { son, dad } = await meet();
  const clip = rnd(4000);
  const body = M.encodeMedia({ bytes: clip, kind: "voice", mime: "audio/mp4", capturedAt: T0 });
  const m1 = await dad.encrypt("media", body, { now: T0, stamper });
  const d1 = M.decodeMedia(await son.decrypt(m1.wire, { now: T0, stampKeys }));
  assert.equal(d1.verified, true);
  assert.deepEqual(d1.bytes, clip);
  assert.equal(d1.mime, "audio/mp4");
  const m2 = await dad.encrypt("media", body, { now: T0 });
  assert.equal(M.decodeMedia(await son.decrypt(m2.wire, { now: T0, stampKeys })).verified, false);
  assert.throws(() => M.encodeMedia({ bytes: rnd(10), kind: "voice", mime: "not a type", capturedAt: T0 }), (e) => e.code === "bad_media");
});

test("media credential: checks out for the right bytes and the published persona, and nothing else", async () => {
  const seed = rnd(64);
  const pub = M.newPersona(seed); // the PUBLIC persona, whose ID the person publishes
  const photo = rnd(20_000);
  const cred = await M.makeMediaCredential({ persona: pub, bytes: photo, kind: "photo", mime: "image/heic", capturedAt: T0, stamper });
  const ok = M.verifyMediaCredential(cred, photo, { stampKeys, expectSigner: pub.id });
  assert.equal(ok.ok, true);
  assert.equal(ok.signer, pub.id);
  assert.equal(ok.live, true);

  const changed = photo.slice(); changed[1234] ^= 1;
  assert.equal(M.verifyMediaCredential(cred, changed, { stampKeys }).reason, "bytes_changed");
  assert.equal(M.verifyMediaCredential(cred, photo, { stampKeys, expectSigner: M.newPersona(rnd(64)).id }).reason, "not_expected_signer");
  assert.equal(M.verifyMediaCredential({ ...cred, capturedAt: T0 - DAY }, photo, { stampKeys }).reason, "bad_signature", "can't backdate a signed capture time");
  assert.equal(M.verifyMediaCredential({ ...cred, kind: "video" }, photo, { stampKeys }).reason, "bad_signature");
  assert.equal(M.verifyMediaCredential(cred, photo).reason, "no_stamp_keys");
  assert.equal(M.verifyMediaCredential(cred, photo, { stampKeys: otherKeys }).reason, "not_live");
  await assert.rejects(M.makeMediaCredential({ persona: pub, bytes: photo, kind: "photo", mime: "image/heic", capturedAt: T0 }), (e) => e.code === "stamp_required");
});

test("media credential: a stamp or signer from another credential can't be swapped in", async () => {
  const p1 = M.newPersona(rnd(64)), p2 = M.newPersona(rnd(64));
  const a = rnd(3000), b = rnd(3000);
  const ca = await M.makeMediaCredential({ persona: p1, bytes: a, kind: "voice", mime: "audio/mp4", capturedAt: T0, stamper });
  const cb = await M.makeMediaCredential({ persona: p2, bytes: b, kind: "voice", mime: "audio/mp4", capturedAt: T0, stamper });
  assert.equal(M.verifyMediaCredential({ ...ca, stamp: cb.stamp }, a, { stampKeys }).ok, false);
  assert.equal(M.verifyMediaCredential({ ...ca, signer: cb.signer }, a, { stampKeys }).ok, false);
  assert.equal(M.verifyMediaCredential({ ...ca, sig: cb.sig }, a, { stampKeys }).ok, false);
  assert.equal(M.verifyMediaCredential({ ...ca, signer: { ...ca.signer, id: p2.id } }, a, { stampKeys }).reason, "signer_mismatch");
});

/* ---------------- evidence locker ---------------- */

test("locker: sealed items reveal nothing; open only with the locker key; items can't be mixed", async () => {
  const seed = rnd(64);
  const key = M.lockerKey(seed);
  const pub = M.newPersona(seed);
  const voice = rnd(30_000);
  const rec = await M.sealEvidence({ bytes: voice, kind: "voice", mime: "audio/mp4", capturedAt: T0, note: "reading the reference paragraph" }, key, { persona: pub, stamper, now: T0 });
  const raw = new TextEncoder().encode(JSON.stringify(rec));
  assert.ok(!contains(Buffer.from(rec.blob, "base64url"), voice.subarray(0, 32)), "no media bytes in the clear");
  assert.ok(!contains(Buffer.from(rec.blob, "base64url"), M.mediaHash(voice)), "not even the hash");
  for (const s of ["audio/mp4", "voice", "reference", pub.id]) assert.ok(!contains(raw, new TextEncoder().encode(s)), `"${s}" visible in the record`);

  const item = await M.openEvidence(rec, key);
  assert.deepEqual(item.bytes, voice);
  assert.equal(item.kind, "voice");
  assert.equal(item.note, "reading the reference paragraph");
  assert.equal(M.verifyMediaCredential(item.credential, item.bytes, { stampKeys, expectSigner: pub.id }).ok, true);

  await code(M.openEvidence(rec, M.lockerKey(rnd(64))), "decrypt_failed");
  const rec2 = await M.sealEvidence({ bytes: rnd(100), kind: "photo", mime: "image/jpeg", capturedAt: T0 }, key, { persona: pub, stamper, now: T0 });
  await code(M.openEvidence({ ...rec, key: rec2.key }, key), "decrypt_failed");
  await code(M.openEvidence({ ...rec2, id: rec.id }, key), "decrypt_failed");
  const blob = Buffer.from(rec.blob, "base64url"); blob[100] ^= 1;
  await code(M.openEvidence({ ...rec, blob: blob.toString("base64url") }, key), "decrypt_failed");
  await assert.rejects(M.sealEvidence({ bytes: voice, kind: "voice", mime: "audio/mp4", capturedAt: T0 }, key, { persona: pub, now: T0 }), (e) => e.code === "stamp_required");
});

test("locker release: signed and stamped, names who it went to, expires, and can't be edited", async () => {
  const seed = rnd(64);
  const key = M.lockerKey(seed);
  const pub = M.newPersona(seed);
  const photo = rnd(10_000);
  const item = await M.openEvidence(await M.sealEvidence({ bytes: photo, kind: "photo", mime: "image/heic", capturedAt: T0 }, key, { persona: pub, stamper, now: T0 }), key);
  const packet = await M.makeRelease(item, { persona: pub, recipient: "LinkedIn trust & safety", purpose: "impersonation report", days: 30, stamper, now: T0 + DAY });
  const ok = M.verifyRelease(packet, photo, { stampKeys, expectSigner: pub.id, now: T0 + 2 * DAY });
  assert.equal(ok.ok, true);
  assert.equal(ok.recipient, "LinkedIn trust & safety");
  assert.equal(ok.capturedAt, T0);

  assert.equal(M.verifyRelease(packet, photo, { stampKeys, now: T0 + 40 * DAY }).reason, "expired");
  assert.equal(M.verifyRelease({ ...packet, release: { ...packet.release, recipient: "anyone" } }, photo, { stampKeys, now: T0 + DAY }).reason, "bad_signature");
  assert.equal(M.verifyRelease({ ...packet, release: { ...packet.release, expiresAt: T0 + 400 * DAY } }, photo, { stampKeys, now: T0 + DAY }).reason, "bad_signature");
  const other = rnd(10_000);
  assert.equal(M.verifyRelease(packet, other, { stampKeys, now: T0 + DAY }).reason, "media_bytes_changed");
  assert.equal(M.verifyRelease(packet, photo, { stampKeys: otherKeys, now: T0 + DAY }).reason, "media_not_live");

  const stranger = M.newPersona(rnd(64));
  await assert.rejects(M.makeRelease(item, { persona: stranger, recipient: "x", stamper, now: T0 }), (e) => e.code === "bad_persona");
  await assert.rejects(M.makeRelease(item, { persona: pub, recipient: "", stamper, now: T0 }), (e) => e.code === "bad_evidence");
  await assert.rejects(M.makeRelease(item, { persona: pub, recipient: "x", days: 400, stamper, now: T0 }), (e) => e.code === "bad_evidence");
});

test("no matcher: nothing in the proving-it's-you API compares one voice or face with another", () => {
  const api = [M.makeChallenge, M.sendChallenge, M.readChallenge, M.replyToChallenge, M.checkReply, M.encodeMedia, M.decodeMedia,
    M.makeMediaCredential, M.verifyMediaCredential, M.sealEvidence, M.openEvidence, M.makeRelease, M.verifyRelease];
  for (const fn of api) assert.ok(!/match|compar|similar|embed|feature|template|liveness/i.test(fn.name), `${fn.name} looks like a matcher`);
  for (const name of Object.keys(M)) assert.ok(!/voiceprint|faceprint|biometric|embedding/i.test(name), `${name} exported`);
});

test("fuzz: mutated challenges, replies and credentials fail only with MsgError or ok:false", async () => {
  const seed = Number(process.env.MSG_FUZZ_SEED ?? Math.floor(Math.random() * 2 ** 31));
  let x = seed;
  const next = () => (x = (x * 1103515245 + 12345) % 2 ** 31);
  const mutate = (b) => { const o = Uint8Array.from(b); for (let i = 0; i < 1 + (next() % 4); i++) o[next() % o.length] = next() % 256; return o; };
  const { pending } = M.makeChallenge({ now: T0 });
  const goodC = new TextEncoder().encode(JSON.stringify({ v: 1, id: Buffer.from(pending.id, "hex").toString("base64url"), p: "call", n: "", exp: T0 + MIN }));
  const goodR = new TextEncoder().encode(JSON.stringify({ v: 1, re: Buffer.from(pending.id, "hex").toString("base64url"), a: "yes", r: Buffer.from(rnd(16)).toString("base64url") }));
  const fakeSession = { convId: rnd(16) };
  try {
    for (let i = 0; i < 300; i++) {
      for (const [kind, good, fn] of [
        ["challenge", goodC, (m) => M.readChallenge(m, { now: T0 })],
        ["challenge-reply", goodR, (m) => M.checkReply(fakeSession, pending, m, { now: T0 })],
        ["media", M.encodeMedia({ bytes: rnd(64), kind: "voice", mime: "audio/mp4", capturedAt: T0 }), (m) => M.decodeMedia(m)],
      ]) {
        try { fn({ kind, body: mutate(good), at: T0, live: true, duress: false }); }
        catch (e) { assert.ok(e instanceof M.MsgError && e.code, `${kind}: ${e?.name} ${e?.message}`); }
      }
    }
  } catch (e) { e.message += ` (MSG_FUZZ_SEED=${seed})`; throw e; }
  // credentials never throw, whatever is fed to them
  for (const junk of [null, {}, { v: 1, type: "humid-media-credential" }, { v: 1, type: "humid-media-credential", kind: "voice", mime: "audio/mp4", capturedAt: 1, signer: { pub: {} } }]) {
    assert.equal(M.verifyMediaCredential(junk, rnd(10), { stampKeys }).ok, false);
    assert.equal(M.verifyRelease({ credential: junk, release: junk }, rnd(10), { stampKeys }).ok, false);
  }
});
