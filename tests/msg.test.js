// @humid/msg (HumID 4.0, provisional): person-to-person messaging.
// Each test names the property it proves. Where the 2026 security audit asked
// for a stronger kind of test than the rest of the repo has (unlinkability by
// protocol rather than string search; fuzzing that accepts only the module's
// own error type; rollback; drops), the test says so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { verify as nodeVerify, createPublicKey, constants, randomBytes } from "node:crypto";
import { newIssuerKey, blindSign } from "@humid/pass/issuer";
import * as M from "@humid/msg";

const rnd = (n) => new Uint8Array(randomBytes(n));
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 9, 20, 13, 0, 0);

const issuer = newIssuerKey(2048);
const stampKeys = M.importStampKeys([{ ...issuer.publicView, issuing: true }]);
const issuerLog = [];
const stamper = M.makeStamper(stampKeys, async (blinded) => { issuerLog.push(Buffer.from(blinded).toString("hex")); return blindSign(issuer, blinded); });

const contains = (hay, needle) => Buffer.from(hay).indexOf(Buffer.from(needle)) >= 0;
const code = async (p, c) => { try { await p; } catch (e) { assert.ok(e instanceof M.MsgError, `expected MsgError, got ${e?.name}: ${e?.message}`); assert.equal(e.code, c); return; } assert.fail(`expected ${c}`); };

/** Run the whole meeting: A invites, B requests, A accepts, B receives the accept. */
async function meet({ seedA = rnd(64), seedB = rnd(64), relay = M.memoryRelay({ now: () => T0 }), now = T0, stamps = true, uses = 1 } = {}) {
  const inv = await M.createInvite(seedA, { now, uses });
  relay.put(inv.box, inv.wire);
  const [bundle] = relay.take(M.inviteBoxOf(M.parseInviteCode(inv.code).secret), { keep: true });
  const opened = await M.openInvite(inv.code, bundle, { now });
  const req = await M.requestContact(seedB, opened, { intro: "from the workshop", stamper: stamps ? stamper : null, now });
  relay.put(req.box, req.wire);
  const [reqWire] = relay.take(inv.state.replyBox);
  const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
  const shown = await M.readRequest(inv.state, personaA, reqWire, { now, stampKeys });
  const a = M.acceptRequest(inv.state, personaA, shown, { now });
  const acc = await a.encrypt("accept", "", { now, stamper: stamps ? stamper : null });
  relay.put(acc.box, acc.wire);
  const b = req.session;
  const got = b.inboxes(now).flatMap((box) => relay.take(box));
  assert.equal(got.length, 1);
  const first = await b.decrypt(got[0], { now, stampKeys });
  return { a, b, inv, opened, req, reqWire, shown, personaA, relay, first, seedA, seedB };
}

/* ---------------- personas ---------------- */

test("persona: same seed + salt → same keys; new salt → unrelated keys and ID", () => {
  const seed = rnd(64);
  const p1 = M.newPersona(seed);
  const again = M.personaFromSalt(seed, p1.salt);
  assert.equal(again.id, p1.id);
  assert.deepEqual(again.pub.dsaPk, p1.pub.dsaPk);
  const p2 = M.newPersona(seed);
  assert.notEqual(p2.id, p1.id);
  for (const k of ["kemPk", "dsaPk", "slhPk", "xPk"]) assert.ok(!contains(p2.pub[k], p1.pub[k].subarray(0, 16)), `${k} shares bytes`);
  assert.match(p1.id, /^HC-[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/);
});

test("safety code: 100 bits, the same on both sides, changes if any key is swapped", () => {
  const a = M.newPersona(rnd(64)), b = M.newPersona(rnd(64)), c = M.newPersona(rnd(64));
  const s = M.safetyCode(a.pub, b.pub);
  assert.equal(s, M.safetyCode(b.pub, a.pub));
  assert.equal(s.replace(/-/g, "").length, 20);
  assert.notEqual(s, M.safetyCode(a.pub, c.pub));
  assert.notEqual(s, M.safetyCode(a.pub, { ...b.pub, slhPk: c.pub.slhPk }), "swapping only the hash-based key is caught");
});

/* ---------------- invite codes ---------------- */

test("invite code: round trip, forgiving input, typos caught on the phone", () => {
  const secret = rnd(16), pin = rnd(10);
  const c = M.formatInviteCode(secret, pin);
  assert.match(c, /^HI-/);
  assert.deepEqual(M.parseInviteCode(c), { secret, pin });
  assert.deepEqual(M.parseInviteCode(c.toLowerCase().replace(/-/g, " ")), { secret, pin });
  const chars = c.split("");
  const i = 8; chars[i] = chars[i] === "Z" ? "Y" : "Z";
  assert.throws(() => M.parseInviteCode(chars.join("")), (e) => e.code === "bad_invite_code");
  assert.throws(() => M.parseInviteCode("HA-not-an-invite"), (e) => e.code === "bad_invite_code");
});

/* ---------------- meeting ---------------- */

test("meet: invite → request with live stamp → approve → connected; both see the same safety code", async () => {
  const { a, b, shown, req, first, inv } = await meet();
  assert.equal(shown.from, req.persona.id);
  assert.equal(shown.intro, "from the workshop");
  assert.equal(shown.live, true, "a live human made the request");
  assert.equal(shown.safetyCode, b.safetyCode);
  assert.equal(a.safetyCode, b.safetyCode);
  assert.equal(first.kind, "accept");
  assert.equal(first.live, true);
  assert.equal(b.status, "connected");
  assert.equal(b.peerId, inv.state.personaId);
  assert.equal(a.peerId, req.persona.id);
  assert.ok(inv.state.closed, "a one-use invite erases its one-time keys once used");
  assert.ok(inv.state.otkSk.every((x) => x === 0));
});

test("chat both ways; each message can carry its own live stamp", async () => {
  const { a, b } = await meet();
  for (let i = 0; i < 4; i++) {
    const m = await b.encrypt("text", `b${i}`, { now: T0, stamper: i % 2 ? stamper : null });
    const r = await a.decrypt(m.wire, { now: T0, stampKeys });
    assert.equal(r.text, `b${i}`);
    assert.equal(r.live, i % 2 ? true : null);
    const m2 = await a.encrypt("text", `a${i}`, { now: T0 });
    assert.equal((await b.decrypt(m2.wire, { now: T0 })).text, `a${i}`);
  }
});

test("stamps: a valid RSASSA-PSS signature for OpenSSL; useless on any other message; issuer never sees it", async () => {
  const c = M.messageCommitment({ convId: rnd(16), senderFp: rnd(32), nonce: rnd(16), kind: "text", body: rnd(10) });
  const before = issuerLog.length;
  const st = await stamper(c);
  const inp = Buffer.from(st.input.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const sig = Buffer.from(st.sig.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  assert.ok(nodeVerify("sha384", inp, { key: createPublicKey(issuer.sk), padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }, sig));
  assert.ok(M.verifyStamp(stampKeys, st, c));
  assert.ok(!M.verifyStamp(stampKeys, st, rnd(32)), "a stamp can't be moved to another message");
  const seen = issuerLog.slice(before).join("");
  assert.ok(!seen.includes(sig.toString("hex")) && !seen.includes(inp.toString("hex").slice(64, 160)), "the issuer saw only the blinded value");
  const b1 = M.blindStamp(stampKeys, c).blinded, b2 = M.blindStamp(stampKeys, c).blinded;
  assert.notDeepEqual(b1, b2, "the same message blinds differently every time");
  assert.throws(() => M.importStampKeys([1, 2, 3].map(() => ({ ...issuer.publicView, issuing: true }))), (e) => e.code === "too_many_stamp_keys");
});

test("the relay can't read, swap or forge an invite", async () => {
  const seedA = rnd(64);
  const inv = await M.createInvite(seedA, { now: T0 });
  const flipped = inv.wire.slice(); flipped[100] ^= 1;
  await code(M.openInvite(inv.code, flipped, { now: T0 }), "invite_mismatch");
  const other = await M.createInvite(rnd(64), { now: T0 });
  await code(M.openInvite(inv.code, other.wire, { now: T0 }), "invite_mismatch");
  await code(M.openInvite(inv.code, inv.wire, { now: T0 + 2 * DAY }), "invite_expired");
  for (const k of ["kemPk", "dsaPk", "xPk"]) assert.ok(!contains(inv.wire, inv.persona.pub[k].subarray(0, 24)), "the bundle is ciphertext");
});

test("a request made without the invite secret is refused, even with the real bundle keys", async () => {
  const seedA = rnd(64);
  const inv = await M.createInvite(seedA, { now: T0 });
  const opened = await M.openInvite(inv.code, inv.wire, { now: T0 });
  const forged = await M.requestContact(rnd(64), { ...opened, secret: rnd(20) }, { now: T0 });
  const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
  await code(M.readRequest(inv.state, personaA, forged.wire, { now: T0 }), "not_for_us");
  const real = await M.requestContact(rnd(64), opened, { now: T0 });
  const tampered = real.wire.slice(); tampered[real.wire.length - 2000] ^= 0x40;
  await code(M.readRequest(inv.state, personaA, tampered, { now: T0 }), "not_for_us");
  await code(M.readRequest(inv.state, personaA, real.wire, { now: T0 + 2 * DAY }), "invite_expired");
  const ok = await M.readRequest(inv.state, personaA, real.wire, { now: T0 });
  assert.equal(ok.live, null, "no stamp: shown as not proven live");
});

test("requests can't be replayed: a used invite, and a request already handled", async () => {
  const seedA = rnd(64);
  const inv = await M.createInvite(seedA, { now: T0, uses: 2 });
  const opened = await M.openInvite(inv.code, inv.wire, { now: T0 });
  const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
  const r1 = await M.requestContact(rnd(64), opened, { now: T0 });
  const shown = await M.readRequest(inv.state, personaA, r1.wire, { now: T0 });
  M.acceptRequest(inv.state, personaA, shown, { now: T0 });
  await code(M.readRequest(inv.state, personaA, r1.wire, { now: T0 }), "replay_or_old");
  const r2 = await M.requestContact(rnd(64), opened, { now: T0 });
  M.declineRequest(inv.state, await M.readRequest(inv.state, personaA, r2.wire, { now: T0 }));
  await code(M.readRequest(inv.state, personaA, r2.wire, { now: T0 }), "replay_or_old");
  const r3 = await M.requestContact(rnd(64), opened, { now: T0 });
  M.acceptRequest(inv.state, personaA, await M.readRequest(inv.state, personaA, r3.wire, { now: T0 }), { now: T0 });
  await code(M.readRequest(inv.state, personaA, r3.wire, { now: T0 }), "invite_used");
});

test("the requester can't send until approved", async () => {
  const inv = await M.createInvite(rnd(64), { now: T0 });
  const req = await M.requestContact(rnd(64), await M.openInvite(inv.code, inv.wire, { now: T0 }), { now: T0 });
  assert.equal(req.session.status, "requested");
  await code(req.session.encrypt("text", "hello?", { now: T0 }), "not_accepted");
});

test("dual signatures: ML-DSA alone or SLH-DSA alone is not enough", () => {
  const p = M.newPersona(rnd(64));
  const msg = rnd(64);
  const good = M.dualSign("request", msg, p.keys);
  assert.ok(M.dualVerify("request", msg, good, p.pub));
  const other = M.dualSign("request", rnd(64), p.keys);
  assert.ok(!M.dualVerify("request", msg, { dsa: good.dsa, slh: other.slh }, p.pub), "a lattice-only forgery fails");
  assert.ok(!M.dualVerify("request", msg, { dsa: other.dsa, slh: good.slh }, p.pub), "a hash-only forgery fails");
  assert.ok(!M.dualVerify("bundle", msg, good, p.pub), "a signature can't move between purposes");
});

/* ---------------- the ratchet ---------------- */

test("out of order, replay, tamper: everything opens once, nothing opens twice, a bad message moves nothing", async () => {
  const { a, b } = await meet({ stamps: false });
  const sent = [];
  for (let i = 0; i < 5; i++) sent.push(await b.encrypt("text", `m${i}`, { now: T0 }));
  for (const i of [3, 1, 4, 0, 2]) assert.equal((await a.decrypt(sent[i].wire, { now: T0 })).text, `m${i}`);
  await code(a.decrypt(sent[2].wire, { now: T0 }), "replay_or_old");
  const next = await b.encrypt("text", "after", { now: T0 });
  const bad = next.wire.slice(); bad[2000] ^= 1;
  const v = a.version;
  await code(a.decrypt(bad, { now: T0 }), "not_for_us");
  assert.equal(a.version, v, "state untouched by a tampered message");
  assert.equal((await a.decrypt(next.wire, { now: T0 })).text, "after");
});

test("forward secrecy and healing: a stolen copy of the state reads neither the past nor, after one round trip, the future", async () => {
  const { a, b } = await meet({ stamps: false });
  const past = await a.encrypt("text", "before theft", { now: T0 });
  await b.decrypt(past.wire, { now: T0 });
  const stolen = M.Session.fromJSON(JSON.parse(JSON.stringify(b.toJSON())));
  await code(stolen.decrypt(past.wire, { now: T0 }), "replay_or_old");
  // The conversation moves on: b replies, a replies.
  await a.decrypt((await b.encrypt("text", "reply", { now: T0 })).wire, { now: T0 });
  const future = await a.encrypt("text", "after healing", { now: T0 });
  assert.equal((await b.decrypt(future.wire, { now: T0 })).text, "after healing");
  // The thief's copy can't follow: it never saw b's new ratchet secrets.
  await assert.rejects(stolen.decrypt(future.wire, { now: T0 }), (e) => e instanceof M.MsgError && ["decrypt_failed", "replay_or_old"].includes(e.code));
});

test("a relay that drops a message is caught: the gap is reported", async () => {
  const { a, b } = await meet({ stamps: false });
  const m1 = await b.encrypt("text", "dropped", { now: T0 });
  const m2 = await b.encrypt("text", "delivered", { now: T0 });
  await a.decrypt(m2.wire, { now: T0 });
  assert.equal(a.gaps({ now: T0 + 60_000 }).missing, 0, "not yet: it may just be late");
  assert.equal(a.gaps({ now: T0 + 11 * 60_000 }).missing, 1);
  assert.equal((await a.decrypt(m1.wire, { now: T0 + 12 * 60_000 })).text, "dropped", "a late message still opens");
  assert.equal(a.gaps({ now: T0 + 13 * 60_000 }).missing, 0);
});

test("a flood of skipped messages is refused", async () => {
  const { a, b } = await meet({ stamps: false });
  let last;
  for (let i = 0; i <= M.MAX_SKIP + 1; i++) last = await b.encrypt("text", "x", { now: T0 });
  await code(a.decrypt(last.wire, { now: T0 }), "too_many_skipped");
});

test("duress flag and closing travel inside the encryption", async () => {
  const { a, b } = await meet({ stamps: false });
  const d = await b.encrypt("text", "all fine here", { now: T0, duress: true });
  assert.equal((await a.decrypt(d.wire, { now: T0 })).duress, true);
  const c = await a.encrypt("close", "", { now: T0 });
  assert.equal(a.status, "closed");
  await b.decrypt(c.wire, { now: T0 });
  assert.equal(b.status, "closed");
  await code(b.encrypt("text", "hello?", { now: T0 }), "closed");
});

/* ---------------- at rest ---------------- */

test("sealed state: round trip; older copy refused (rollback); another conversation's copy refused", async () => {
  const { a, b } = await meet({ stamps: false });
  const key = rnd(32);
  const v1 = await b.seal(key);
  const m = await a.encrypt("text", "one", { now: T0 });
  await b.decrypt(m.wire, { now: T0 });
  const v2 = await b.seal(key);
  const convId = b.convId;
  const restored = await M.openSession(key, v2, { convId, minVersion: b.version });
  const m2 = await a.encrypt("text", "two", { now: T0 });
  assert.equal((await restored.decrypt(m2.wire, { now: T0 })).text, "two");
  await code(M.openSession(key, v1, { convId, minVersion: b.version }), "rolled_back");
  await code(M.openSession(rnd(32), v2, { convId }), "decrypt_failed");
  await code(M.openSession(key, v2, { convId: rnd(16) }), "wrong_conversation");
  await code(M.openSession(key, v2), "bad_request");
  const forgedHead = v1.slice(); forgedHead[23] += 9; // claim a newer version
  await code(M.openSession(key, forgedHead, { convId, minVersion: b.version }), "decrypt_failed");
});

/* ---------------- what the relay and the issuer learn ---------------- */

test("unlinkability, by the protocol: the relay sees fixed sizes and daily-rotating random boxes, nothing else", async () => {
  const { a, b, relay, inv, req } = await meet();
  const sizes = new Set(relay.observed.filter((o) => o.op === "put").map((o) => o.size));
  for (const s of sizes) assert.ok(M.isWireSize(s));
  // Every box differs per direction and per day.
  const day0 = [...a.inboxes(T0), ...b.inboxes(T0)];
  assert.equal(new Set(day0).size, day0.length);
  assert.notDeepEqual(a.inboxes(T0), a.inboxes(T0 + 3 * DAY));
  // No persona key, persona id, or invite secret appears in anything the relay stored.
  const wires = [inv.wire, req.wire, (await a.encrypt("text", "x", { now: T0 })).wire];
  const personas = [M.decodePub(a.toJSON().peer.pub), b.peerPub];
  for (const w of wires) {
    for (const p of personas) for (const k of ["kemPk", "dsaPk", "slhPk", "xPk"]) assert.ok(!contains(w, p[k].subarray(0, 24)));
    assert.ok(!contains(w, new TextEncoder().encode("HC-")));
    assert.ok(!contains(w, M.parseInviteCode(inv.code).pin), "the code's persona pin isn't on the wire either");
    assert.equal(w[0], M.WIRE_VERSION);
  }
});

test("unlinkability across contacts: two contacts of one person see unrelated IDs and keys", async () => {
  const seedA = rnd(64);
  const one = await meet({ seedA, stamps: false });
  const two = await meet({ seedA, stamps: false });
  assert.notEqual(one.b.peerId, two.b.peerId);
  const p1 = one.b.peerPub, p2 = two.b.peerPub;
  for (const k of ["kemPk", "dsaPk", "slhPk", "xPk"]) assert.ok(!contains(p1[k], p2[k].subarray(0, 16)));
  assert.notEqual(one.b.safetyCode, two.b.safetyCode);
});

/* ---------------- relay rules ---------------- */

test("relay: IPv6 rate limits count a whole /64; v4-mapped counts as v4", () => {
  assert.equal(M.rateKey("2001:db8:1:2::1"), M.rateKey("2001:db8:1:2:ffff:ffff:ffff:ffff"));
  assert.notEqual(M.rateKey("2001:db8:1:2::1"), M.rateKey("2001:db8:1:3::1"));
  assert.equal(M.rateKey("[2001:DB8:1:2::7%eth0]"), M.rateKey("2001:db8:1:2::8"));
  assert.equal(M.rateKey("::ffff:192.0.2.1"), M.rateKey("192.0.2.1"));
  let t = T0;
  const relay = M.memoryRelay({ now: () => t, depositsPerMinute: 3 });
  const box = "a".repeat(32), w = new Uint8Array(4096); w[0] = 1;
  for (let i = 1; i <= 3; i++) relay.put(box, w, { ip: `2001:db8:1:2::${i}` });
  assert.throws(() => relay.put(box, w, { ip: "2001:db8:1:2::99" }), (e) => e.code === "rate_limited");
  relay.put(box, w, { ip: "2001:db8:9:9::1" });
  t += 60_000;
  relay.put(box, w, { ip: "2001:db8:1:2::99" });
});

test("relay: an empty box and a box that never existed answer identically; sizes and caps enforced; old objects expire", () => {
  let t = T0;
  const relay = M.memoryRelay({ now: () => t, maxPerBox: 2 });
  const used = "b".repeat(32), never = "c".repeat(32), w = new Uint8Array(4096); w[0] = 1;
  relay.put(used, w); relay.take(used);
  assert.deepEqual(relay.take(used), relay.take(never));
  assert.throws(() => relay.put(used, new Uint8Array(5000)), (e) => e.code === "bad_size");
  assert.throws(() => relay.put("NOT-A-BOX", w), (e) => e.code === "bad_box");
  relay.put(used, w); relay.put(used, w);
  assert.throws(() => relay.put(used, w), (e) => e.code === "box_full");
  t += M.RELAY_DEFAULTS.ttlMs + 1;
  assert.deepEqual(relay.take(used), []);
  assert.equal(relay.totalBytes, 0);
});

/* ---------------- swappable primitives ---------------- */

test("backend: the platform's crypto can replace the JS maths only if it agrees byte for byte", () => {
  assert.ok(M.checkBackend(M.backend()));
  const ref = M.backend();
  const broken = { ...ref, name: "broken", x25519: { publicKey: () => new Uint8Array(32), shared: ref.x25519.shared } };
  assert.throws(() => M.useBackend(broken), (e) => e.code === "backend_mismatch");
  const lazyKem = { ...ref, name: "lazy", kem: { ...ref.kem, decapsulate: () => new Uint8Array(32) } };
  assert.throws(() => M.useBackend(lazyKem), (e) => e.code === "backend_mismatch");
  let calls = 0;
  const wrapped = { ...ref, name: "wrapped", kem: { ...ref.kem, encapsulate: (pk) => { calls++; return ref.kem.encapsulate(pk); } } };
  M.useBackend(wrapped);
  try { M.newPersona(rnd(64)); assert.equal(M.backend().name, "wrapped"); }
  finally { M.resetBackend(); }
  assert.ok(calls > 0);
});


/* ---------------- fixes from the independent review ---------------- */

test("someone else who learns the code can't pose as the inviter (the code pins the inviter's persona)", async () => {
  // Mallory knows a code's secret and seals HER bundle under it. The bundle opens, but it carries
  // Mallory's persona, not the one the code pins. Modelled with a real bundle under its own secret,
  // opened with another persona's pin: exactly what Mallory's forgery looks like to the invitee.
  const real = await M.createInvite(rnd(64), { now: T0 });
  const mallory = await M.createInvite(rnd(64), { now: T0 });
  const { secret } = M.parseInviteCode(mallory.code);
  const { pin } = M.parseInviteCode(real.code);
  await code(M.openInvite({ secret, pin }, mallory.wire, { now: T0 }), "invite_mismatch");
  assert.ok((await M.openInvite(mallory.code, mallory.wire, { now: T0 })).id === mallory.persona.id, "with its own pin it opens");
});

test("a duress message and a stamped message are the same size on the wire as an ordinary one", async () => {
  const { a, b } = await meet({ stamps: false });
  const body = "x".repeat(600);
  const plain = await b.encrypt("text", body, { now: T0 });
  const duress = await b.encrypt("text", body, { now: T0, duress: true });
  const stamped = await b.encrypt("text", body, { now: T0, stamper });
  assert.equal(duress.wire.length, plain.wire.length);
  assert.equal(stamped.wire.length, plain.wire.length);
  for (const m of [plain, duress, stamped]) await a.decrypt(m.wire, { now: T0 });
});

test("persist hook: nothing goes out unless the new state was saved first", async () => {
  const { a, b } = await meet({ stamps: false });
  let fail = true, saved = 0;
  const key = rnd(32);
  const guarded = M.Session.fromJSON(b.toJSON(), { persist: async (s) => { if (fail) throw new Error("disk full"); saved = await s.seal(key); } });
  const v = guarded.version;
  await code(guarded.encrypt("text", "lost?", { now: T0 }), "persist_failed");
  assert.equal(guarded.version, v, "the step was undone");
  fail = false;
  const m = await guarded.encrypt("text", "kept", { now: T0 });
  assert.ok(saved instanceof Uint8Array);
  assert.equal((await a.decrypt(m.wire, { now: T0 })).text, "kept");
});

test("a rolled-back sender never repeats a message key and nonce (per-message salt)", async () => {
  const { a, b } = await meet({ stamps: false });
  await b.encrypt("text", "warm up", { now: T0 });
  const snapshot = b.toJSON();
  const m1 = await b.encrypt("text", "first", { now: T0 });
  const rolled = M.Session.fromJSON(snapshot);
  const m2 = await rolled.encrypt("text", "first", { now: T0 });
  assert.notDeepEqual(m1.wire, m2.wire, "same chain position, same text, different ciphertext");
  assert.equal(m1.wire.length, m2.wire.length);
});

test("text that isn't valid UTF-8 is refused without moving the ratchet", async () => {
  const { a, b } = await meet({ stamps: false });
  const bad = await b.encrypt("text", Uint8Array.of(0xff, 0xfe, 0xfd), { now: T0 });
  const v = a.version;
  await code(a.decrypt(bad.wire, { now: T0 }), "malformed");
  assert.equal(a.version, v);
  await code(a.decrypt(bad.wire, { now: T0 }), "malformed"); // not "replay_or_old": nothing was consumed
  assert.equal((await a.decrypt((await b.encrypt("text", "fine", { now: T0 })).wire, { now: T0 })).text, "fine");
});

test("malformed ML-KEM keys are refused when they arrive (FIPS 203 modulus check)", () => {
  const p = M.newPersona(rnd(64));
  assert.ok(M.isValidKemPk(p.pub.kemPk));
  const bad = p.pub.kemPk.slice(); bad[0] = 0xff; bad[1] |= 0x0f; // coefficient 4095 ≥ 3329
  assert.ok(!M.isValidKemPk(bad));
  assert.throws(() => M.decodePub({ ...M.encodePub(p.pub), kem: Buffer.from(bad).toString("base64url") }), (e) => e.code === "bad_key");
});

test("skipped message keys are forgotten after the relay's retention time", async () => {
  const { a, b } = await meet({ stamps: false });
  const withheld = await b.encrypt("text", "withheld", { now: T0 });
  await a.decrypt((await b.encrypt("text", "later", { now: T0 })).wire, { now: T0 });
  assert.equal(a.gaps({ now: T0 + 3600_000 }).missing, 1);
  await a.decrypt((await b.encrypt("text", "much later", { now: T0 })).wire, { now: T0 + M.SKIPPED_TTL_MS + 1 });
  assert.equal(a.gaps({ now: T0 + M.SKIPPED_TTL_MS + 2 }).missing, 0, "its key is gone");
  await code(a.decrypt(withheld.wire, { now: T0 + M.SKIPPED_TTL_MS + 3 }), "replay_or_old");
});

test("stamps: a retired key stops counting; a stamp key that is also a pass key is refused", async () => {
  const keys = M.importStampKeys([{ ...issuer.publicView, issuing: true, acceptUntil: "2026-12-31" }]);
  const c = rnd(32);
  const st = await M.makeStamper(keys, async (bl) => blindSign(issuer, bl))(c);
  assert.ok(M.verifyStamp(keys, st, c, { now: Date.UTC(2026, 11, 31, 23) }));
  assert.ok(!M.verifyStamp(keys, st, c, { now: Date.UTC(2027, 0, 1, 1) }));
  assert.throws(() => M.importStampKeys([{ ...issuer.publicView, issuing: true }], { passKeys: [{ id: issuer.publicView.id }] }), (e) => e.code === "bad_stamp_key");
});

test("relay: a flood of new addresses can't reset a busy client's rate limit", () => {
  let t = T0;
  const relay = M.memoryRelay({ now: () => t, depositsPerMinute: 2, maxRateKeys: 50 });
  const box = "d".repeat(32), w = new Uint8Array(4096); w[0] = 1;
  relay.put(box, w, { ip: "198.51.100.7" }); relay.put(box, w, { ip: "198.51.100.7" });
  for (let i = 0; i < 100; i++) { try { relay.put(box, w, { ip: `203.0.113.${i}` }); } catch {} }
  assert.throws(() => relay.put(box, w, { ip: "198.51.100.7" }), (e) => e.code === "rate_limited");
});

/* ---------------- fuzzing ---------------- */
// Audit: "one fixed random seed, 3,000 cases; any error type accepted". Here the
// seed changes every run and is printed on failure (rerun with MSG_FUZZ_SEED),
// and the ONLY acceptable failure is a MsgError with a code.

function prng(seed) {
  let s = seed >>> 0;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 2 ** 32; };
}

test("fuzz: mutated wires, requests, invites and stored state fail only with MsgError", async (t) => {
  const seed = Number(process.env.MSG_FUZZ_SEED ?? (Date.now() & 0x7fffffff));
  const r = prng(seed);
  const n = Number(process.env.MSG_FUZZ_CASES ?? 200);
  const { a, b, inv, reqWire, personaA } = await meet({ stamps: false });
  const msg = (await b.encrypt("text", "fuzz target", { now: T0 })).wire;
  const key = rnd(32);
  const stored = await a.seal(key);
  const mutate = (x) => {
    const y = x.slice();
    const kind = Math.floor(r() * 4);
    if (kind === 0) { for (let i = 0; i < 1 + r() * 8; i++) y[Math.floor(r() * y.length)] ^= 1 << Math.floor(r() * 8); return y; }
    if (kind === 1) return y.subarray(0, Math.floor(r() * y.length));
    if (kind === 2) { const z = new Uint8Array(M.BUCKETS[Math.floor(r() * 3)]); crypto.getRandomValues(z); z[0] = 1; return z; }
    const z = new Uint8Array(y.length); z.set(y.subarray(0, Math.floor(r() * y.length))); return z;
  };
  const st = { ...inv.state, used: 0, uses: 99 }; // a fresh view of the (closed) invite, for reading only
  st.otkSk = rnd(st.otkSk.length); st.otxSk = rnd(32); st.secret = rnd(16);
  for (let i = 0; i < n; i++) {
    const tries = [
      () => a.decrypt(mutate(msg), { now: T0 }),
      () => M.readRequest(st, personaA, mutate(reqWire), { now: T0 }),
      () => M.openInvite(inv.code, mutate(inv.wire), { now: T0 }),
      () => M.openSession(key, mutate(stored), { convId: a.convId }),
      async () => M.parseInviteCode(String.fromCharCode(...mutate(new TextEncoder().encode(inv.code)).filter((c) => c > 31 && c < 127))),
    ];
    const which = Math.floor(r() * tries.length);
    try { await tries[which](); }
    catch (e) {
      if (!(e instanceof M.MsgError) || typeof e.code !== "string") {
        t.diagnostic(`MSG_FUZZ_SEED=${seed} case ${i} target ${which}`);
        assert.fail(`non-MsgError (${e?.name}: ${e?.message}) — rerun with MSG_FUZZ_SEED=${seed}`);
      }
    }
  }
  // After all that, the real conversation still works.
  assert.equal((await a.decrypt(msg, { now: T0 })).text, "fuzz target");
});
