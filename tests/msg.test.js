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

// Tests that aren't about stamp-key epochs use one key whose epoch covers every test date.
const ALWAYS = { notBefore: 0, notAfter: Date.UTC(2200, 0, 1) };
const issuer = newIssuerKey(2048);
const stampKeys = M.importStampKeys([{ ...issuer.publicView, ...ALWAYS, issuing: true }]);
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
  const inv = await M.createInvite(seedA, { now: T0 });
  const opened = await M.openInvite(inv.code, inv.wire, { now: T0 });
  const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
  // declined: can't be shown again, and the invite stays open for the right person
  const r2 = await M.requestContact(rnd(64), opened, { now: T0 });
  M.declineRequest(inv.state, await M.readRequest(inv.state, personaA, r2.wire, { now: T0 }));
  await code(M.readRequest(inv.state, personaA, r2.wire, { now: T0 }), "replay_or_old");
  // accepted: the invite is spent, for that request and any other
  const r1 = await M.requestContact(rnd(64), opened, { now: T0 });
  M.acceptRequest(inv.state, personaA, await M.readRequest(inv.state, personaA, r1.wire, { now: T0 }), { now: T0 });
  await code(M.readRequest(inv.state, personaA, r1.wire, { now: T0 }), "invite_used");
  const r3 = await M.requestContact(rnd(64), opened, { now: T0 });
  await code(M.readRequest(inv.state, personaA, r3.wire, { now: T0 }), "invite_used");
});

test("PC-26: an invite admits one person, so no two contacts ever share a persona ID", async () => {
  await code(M.createInvite(rnd(64), { now: T0, uses: 20 }), "bad_uses");
  await code(M.createInvite(rnd(64), { now: T0, uses: 2 }), "bad_uses");
  // a saved invite from before this that claims several uses still admits only one
  const seedA = rnd(64);
  const inv = await M.createInvite(seedA, { now: T0 });
  inv.state.uses = 20;
  const opened = await M.openInvite(inv.code, inv.wire, { now: T0 });
  const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
  const r1 = await M.requestContact(rnd(64), opened, { now: T0 });
  const r2 = await M.requestContact(rnd(64), opened, { now: T0 });
  const s1 = await M.readRequest(inv.state, personaA, r1.wire, { now: T0 });
  const s2 = await M.readRequest(inv.state, personaA, r2.wire, { now: T0 });
  M.acceptRequest(inv.state, personaA, s1, { now: T0 });
  assert.throws(() => M.acceptRequest(inv.state, personaA, s2, { now: T0 }), (e) => e.code === "invite_used");
  assert.equal(inv.state.closed, true);
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
  assert.throws(() => M.useBackend(broken), (e) => e instanceof M.MsgError && e.code === "backend_mismatch_x25519");
  const lazyKem = { ...ref, name: "lazy", kem: { ...ref.kem, decapsulate: () => new Uint8Array(32) } };
  assert.throws(() => M.useBackend(lazyKem), (e) => e instanceof M.MsgError && e.code === "backend_mismatch_ml_kem");
  let calls = 0;
  const wrapped = { ...ref, name: "wrapped", kem: { ...ref.kem, encapsulate: (pk) => { calls++; return ref.kem.encapsulate(pk); } } };
  M.useBackend(wrapped);
  try { M.newPersona(rnd(64)); assert.equal(M.backend().name, "wrapped"); }
  finally { M.resetBackend(); }
  assert.ok(calls > 0);
});

/* checkBackend (audit PC-12): every primitive is exercised, so a replacement that gets a negative case wrong is refused. */

const REF = M.backend();
const same = (a, b) => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
const oneBitApart = (a, b) => {
  if (a.length !== b.length) return false;
  let bits = 0;
  for (let i = 0; i < a.length && bits < 2; i++) for (let x = a[i] ^ b[i]; x; x &= x - 1) bits++;
  return bits === 1;
};
/** A verify that is right on everything the reference accepts, plus whatever `alsoAccept` lets through near a signature it has seen verify. */
const lenientVerify = (refVerify, alsoAccept) => {
  const seen = [];
  return (sig, msg, pk) => {
    if (refVerify(sig, msg, pk)) { seen.push({ sig, msg, pk }); return true; }
    return seen.some((g) => alsoAccept(g, { sig, msg, pk }));
  };
};
const VERIFY_DEFECTS = {
  // defect name: [what the lenient verify also lets through, what checkBackend must say]
  "a flipped signature bit": [(g, x) => same(g.msg, x.msg) && same(g.pk, x.pk) && oneBitApart(g.sig, x.sig), /accepted a signature with a bit flipped/],
  "a flipped message bit": [(g, x) => same(g.sig, x.sig) && same(g.pk, x.pk) && oneBitApart(g.msg, x.msg), /accepted a message with a bit flipped/],
  "a wrong (different valid) public key": [(g, x) => same(g.sig, x.sig) && same(g.msg, x.msg), /accepted a different valid public key/],
  "a truncated signature": [(g, x) => same(g.msg, x.msg) && same(g.pk, x.pk) && x.sig.length < g.sig.length && same(g.sig.subarray(0, x.sig.length), x.sig), /accepted a truncated signature/],
};
const refused = (b, code, why = /./) => {
  assert.throws(() => M.useBackend(b), (e) => e instanceof M.MsgError && e.code === code && why.test(e.message), `${b.name} should be refused with ${code} (${why})`);
  assert.equal(M.backend(), REF, "a refused backend must not be installed");
};

test("checkBackend: the honest reference backend still passes, in reasonable time", () => {
  const t = performance.now();
  assert.equal(M.checkBackend(REF), true);
  const ms = performance.now() - t;
  assert.ok(ms < 10_000, `checkBackend took ${Math.round(ms)} ms`);
  // A faithful wrapper (what a native bridge looks like) is accepted and installed.
  const wrapped = { name: "faithful wrapper", kem: { ...REF.kem }, dsa: { ...REF.dsa }, slh: { ...REF.slh }, x25519: { ...REF.x25519 } };
  try { M.useBackend(wrapped); assert.equal(M.backend().name, "faithful wrapper"); }
  finally { M.resetBackend(); }
});

test("checkBackend regression (audit PC-12 PoC): the three malicious backends it got accepted are refused", () => {
  // (a) SLH-DSA verify that always says yes: it used to be accepted, after which dualVerify took a random SLH-DSA signature.
  const slhStub = { ...REF, name: "native-bridge(slh stub)", slh: { ...REF.slh, verify: () => true, sign: () => new Uint8Array(M.SIZES.slhSig) } };
  refused(slhStub, "backend_mismatch_slh_dsa", /SLH-DSA/);
  const p = M.newPersona(rnd(64));
  const m = rnd(64);
  const good = M.dualSign("request", m, p.keys);
  assert.equal(M.dualVerify("request", m, good, p.pub), true);
  assert.equal(M.dualVerify("request", m, { dsa: good.dsa, slh: rnd(M.SIZES.slhSig) }, p.pub), false);
  // (b) X25519 shared secret that is a constant: every dh1/dh2/dh3 and ratchet DH output would have been 0x42...
  refused({ ...REF, name: "native-bridge(x25519 const)", x25519: { ...REF.x25519, shared: () => new Uint8Array(32).fill(0x42) } }, "backend_mismatch_x25519", /RFC 7748/);
  // (c) ML-DSA verify that ignores the public key when pk[0] === 0 (caught every run: one wrong key starts with a zero byte).
  refused({ ...REF, name: "dsa verify that ignores pk", dsa: { ...REF.dsa, verify: (sig, mm, pk) => REF.dsa.verify(sig, mm, pk) || (sig.length === M.SIZES.dsaSig && pk[0] === 0x00) } }, "backend_mismatch_ml_dsa", /different valid public key/);
});

for (const [scheme, key, code] of [["ML-DSA-87", "dsa", "backend_mismatch_ml_dsa"], ["SLH-DSA", "slh", "backend_mismatch_slh_dsa"]]) {
  for (const [defect, [alsoAccept, why]] of Object.entries(VERIFY_DEFECTS)) {
    test(`checkBackend: a ${scheme} verify that accepts ${defect} is refused`, () => {
      refused({ ...REF, name: `${key} accepts ${defect}`, [key]: { ...REF[key], verify: lenientVerify(REF[key].verify, alsoAccept) } }, code, why);
    });
  }
  test(`checkBackend: ${scheme} signatures the reference can't verify are refused`, () => {
    refused({ ...REF, name: `${key} signs garbage`, [key]: { ...REF[key], sign: (msg, sk) => { const s = REF[key].sign(msg, sk); s[7] ^= 1; return s; } } }, code, /reference rejects the candidate's signature/);
  });
  test(`checkBackend: a ${scheme} verify that rejects the reference's signatures is refused`, () => {
    let n = 0;
    refused({ ...REF, name: `${key} rejects the first valid signature`, [key]: { ...REF[key], verify: (s, mm, pk) => n++ > 0 && REF[key].verify(s, mm, pk) } }, code, /rejected the reference's signature/);
  });
}

test("checkBackend: X25519 that differs from RFC 7748 or the reference is refused", () => {
  const x = (name, over) => ({ ...REF, name, x25519: { ...REF.x25519, ...over } });
  // Wrong on the RFC 7748 §6.1 vector (arguments swapped, a natural bridging mistake).
  refused(x("x25519 swapped args", { shared: (sk, pk) => REF.x25519.shared(pk, sk) }), "backend_mismatch_x25519", /RFC 7748/);
  // Right on the published vector, wrong on fresh keys.
  let first = 2;
  refused(x("x25519 right only twice", { shared: (sk, pk) => (first-- > 0 ? REF.x25519.shared(sk, pk) : new Uint8Array(32).fill(7)) }), "backend_mismatch_x25519", /shared secret/);
});

test("checkBackend: X25519 that accepts low-order points (or doesn't mask the top bit) like the reference doesn't is refused", () => {
  const zeroOnLowOrder = (sk, pk) => { try { return REF.x25519.shared(sk, pk); } catch { return new Uint8Array(32); } };
  refused({ ...REF, name: "x25519 all-zero on low order", x25519: { ...REF.x25519, shared: zeroOnLowOrder } }, "backend_mismatch_x25519", /low-order/);
  const strictTopBit = (sk, pk) => { if (pk[31] & 0x80) throw new Error("top bit set"); return REF.x25519.shared(sk, pk); };
  refused({ ...REF, name: "x25519 refuses the top bit", x25519: { ...REF.x25519, shared: strictTopBit } }, "backend_mismatch_x25519", /top bit/);
});

test("checkBackend: ML-KEM decapsulation must interoperate both ways and reject exactly like FIPS 203", async () => {
  const { shake256 } = await import("@noble/hashes/sha3.js");
  // FIPS 203 implicit rejection value J(z ‖ c): z is the last 32 bytes of the decapsulation key.
  const rejection = (ct, sk) => shake256(Buffer.concat([sk.subarray(sk.length - 32), ct]), { dkLen: 32 });
  const isRejection = (ss, ct, sk) => same(ss, rejection(ct, sk));
  const k = (name, over) => ({ ...REF, name, kem: { ...REF.kem, ...over } });
  // Explicit (zero) rejection instead of J(z ‖ c).
  refused(k("kem explicit rejection", { decapsulate: (ct, sk) => { const ss = REF.kem.decapsulate(ct, sk); return isRejection(ss, ct, sk) ? new Uint8Array(32) : ss; } }), "backend_mismatch_ml_kem", /implicit rejection/);
  // A missing re-encryption check: a ciphertext one bit away from a good one yields the good one's secret.
  const good = [];
  refused(k("kem ignores tampering", { decapsulate: (ct, sk) => {
    const ss = REF.kem.decapsulate(ct, sk);
    if (!isRejection(ss, ct, sk)) { good.push({ ct, ss }); return ss; }
    return good.find((g) => oneBitApart(g.ct, ct))?.ss ?? ss;
  } }), "backend_mismatch_ml_kem", /gave the real shared secret/);
  // A secret key in its own encoding: self-consistent, but not interchangeable with the reference's.
  refused(k("kem private sk encoding", {
    keygen: (seed) => { const kp = REF.kem.keygen(seed); return { publicKey: kp.publicKey, secretKey: Uint8Array.of(0xaa, ...kp.secretKey) }; },
    decapsulate: (ct, sk) => REF.kem.decapsulate(ct, sk.subarray(1)),
  }), "backend_mismatch_ml_kem", /secret key encoding/);
  // Throwing on a modified ciphertext is not implicit rejection either.
  refused(k("kem throws on bad ct", { decapsulate: (ct, sk) => { const ss = REF.kem.decapsulate(ct, sk); if (isRejection(ss, ct, sk)) throw new Error("bad ct"); return ss; } }), "backend_mismatch_ml_kem", /bad ct/);
});

test("checkBackend: a backend missing a primitive or throwing a foreign error is refused with the module's own error", () => {
  const { slh, ...noSlh } = REF; void slh;
  refused({ ...noSlh, name: "no slh" }, "backend_mismatch_slh_dsa");
  refused({ ...REF, name: "dsa keygen throws", dsa: { ...REF.dsa, keygen: () => { throw new TypeError("bridge down"); } } }, "backend_mismatch_ml_dsa");
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
  const keys = M.importStampKeys([{ ...issuer.publicView, ...ALWAYS, issuing: true, acceptUntil: "2026-12-31" }]);
  const c = rnd(32);
  const st = await M.makeStamper(keys, async (bl) => blindSign(issuer, bl))(c);
  assert.ok(M.verifyStamp(keys, st, c, { now: Date.UTC(2026, 11, 31, 23) }));
  assert.ok(!M.verifyStamp(keys, st, c, { now: Date.UTC(2027, 0, 1, 1) }));
  assert.throws(() => M.importStampKeys([{ ...issuer.publicView, ...ALWAYS, issuing: true }], { passKeys: [{ id: issuer.publicView.id }] }), (e) => e.code === "bad_stamp_key");
});

test("relay: a flood of new addresses can't reset a busy client's rate limit", () => {
  let t = T0;
  const relay = M.memoryRelay({ now: () => t, depositsPerMinute: 2, maxRateKeys: 50 });
  const box = "d".repeat(32), w = new Uint8Array(4096); w[0] = 1;
  relay.put(box, w, { ip: "198.51.100.7" }); relay.put(box, w, { ip: "198.51.100.7" });
  for (let i = 0; i < 100; i++) { try { relay.put(box, w, { ip: `203.0.113.${i}` }); } catch {} }
  assert.throws(() => relay.put(box, w, { ip: "198.51.100.7" }), (e) => e.code === "rate_limited");
  // ...and they can't lock a new one out either (MSG-05: the limiter never fails closed)
  const fresh = M.memoryRelay({ now: () => t, maxRateKeys: 50 });
  for (let i = 0; i < 200; i++) fresh.take("e".repeat(32), { ip: `2001:db8:0:${i.toString(16)}::1` });
  assert.deepEqual(fresh.take("e".repeat(32), { ip: "198.51.100.9" }), []);
});

/* ---------------- polling: backfill and linkage (security review MSG-04, MSG-02) ---------------- */

test("MSG-04: a phone away for days still gets what was sent meanwhile (backfill from lastPolled)", async () => {
  const { a, b, relay } = await meet({ stamps: false });
  const lastPolled = T0;
  const sent = await a.encrypt("text", "are you ok?", { now: T0 + 3600_000 });
  relay.put(sent.box, sent.wire);
  const later = T0 + 2 * DAY + 600_000;
  assert.ok(!b.inboxes(later).includes(sent.box), "today's poll alone would miss it");
  const boxes = b.inboxesSince(lastPolled, later);
  assert.ok(boxes.includes(sent.box), "the backfill covers the day it was sent");
  const [w] = boxes.flatMap((x) => relay.take(x));
  assert.equal((await b.decrypt(w, { now: later })).text, "are you ok?");
  // never further back than the relay keeps anything; never polled before: just yesterday and today
  assert.equal(b.inboxesSince(T0 - 60 * DAY, T0).length, M.BACKFILL_DAYS + 1);
  assert.deepEqual(b.inboxesSince(null, T0), b.inboxes(T0));
});

test("MSG-04: a message that never arrives shows as a gap", async () => {
  const { a, b } = await meet({ stamps: false });
  await a.encrypt("text", "lost", { now: T0 });
  const next = await a.encrypt("text", "arrived", { now: T0 + 1000 });
  await b.decrypt(next.wire, { now: T0 + 1000 });
  assert.equal(b.gaps({ now: T0 + 11 * 60_000 }).missing, 1);
});

test("MSG-02: one day's poll doesn't name the next day's mailbox (except near midnight UTC)", async () => {
  const { b } = await meet({ stamps: false });
  const noon = (k) => Date.UTC(2026, 9, 20 + k, 12);
  for (let k = 0; k < 4; k++) {
    const today = new Set(b.inboxes(noon(k))), tomorrow = b.inboxes(noon(k + 1));
    // day k+1's poll asks for box(k) and box(k+1); day k's asks for box(k-1) and box(k): one shared,
    // the one both phones must still check for a message sent late on day k
    assert.equal(tomorrow.filter((x) => today.has(x)).length, 1, `day ${k} and ${k + 1} share only the day in between`);
    const twoOn = b.inboxes(noon(k + 2));
    assert.equal(twoOn.filter((x) => today.has(x)).length, 0, "polls two days apart share nothing: no chain");
  }
  const nearMidnight = Date.UTC(2026, 9, 20, 23, 59);
  assert.equal(b.inboxes(nearMidnight).length, 3, "tomorrow's box only within 2 minutes of midnight");
  assert.equal(b.inboxes(Date.UTC(2026, 9, 20, 23, 50)).length, 2);
});


/* ---------------- delete ---------------- */

const conv = async (opts) => { const m = await meet({ stamps: false, ...opts }); return { ...m, A: new M.Conversation(m.a), B: new M.Conversation(m.b) }; };
const postTo = (relay, p) => relay.put(p.box, p.wire, { tag: p.retractTag });
const fetchFor = (relay, c, now = T0) => c.session.inboxes(now).flatMap((box) => relay.take(box));
const deliver = async (relay, to, now = T0) => { const out = []; for (const w of fetchFor(relay, to, now)) out.push(await to.receive(w, { now })); return out; };

test("delete for me: gone from this phone only; the contact keeps their copy", async () => {
  const { A, B, relay } = await conv();
  const sent = await A.send("keep this between us", { now: T0 });
  postTo(relay, sent);
  await deliver(relay, B);
  assert.deepEqual((await A.delete(sent.id, { now: T0 })), { deleted: true });
  assert.equal(A.messages(T0).length, 0);
  assert.equal(B.messages(T0)[0].text, "keep this between us");
  assert.deepEqual(await A.delete(sent.id, { now: T0 }), { deleted: false });
});

test("a deleted message can't be recovered from any earlier save: every save uses a new key", async () => {
  const { A, B, relay } = await conv();
  const sent = await A.send("delete me", { now: T0 });
  postTo(relay, sent);
  await deliver(relay, B);
  const before = await B.store.seal(T0);
  await B.delete(sent.id, { now: T0 });
  const after = await B.store.seal(T0);
  assert.notDeepEqual(before.key, after.key);
  const reopened = await M.MessageStore.open(after.key, after.blob, { convId: B.session.convId });
  assert.equal(reopened.size, 0);
  // The old save opens only with the old key; once the app overwrites that key, nothing opens it.
  await code(M.MessageStore.open(after.key, before.blob, { convId: B.session.convId }), "decrypt_failed");
  assert.equal((await M.MessageStore.open(before.key, before.blob, { convId: B.session.convId })).size, 1, "which is why the old key must be destroyed");
  await code(M.MessageStore.open(after.key, after.blob, { convId: rnd(16) }), "wrong_conversation");
});

test("delete for both, after delivery: erased on the contact's phone too", async () => {
  const { A, B, relay } = await conv();
  const sent = await A.send("I shouldn't have said that", { now: T0 });
  postTo(relay, sent);
  await deliver(relay, B);
  const r = await A.delete(sent.id, { forBoth: true, now: T0 });
  assert.equal(relay.retract(r.unsend.box, r.unsend.retract), false, "already delivered: the relay no longer has it");
  postTo(relay, r.send);
  const [got] = await deliver(relay, B);
  assert.equal(got.kind, "delete");
  assert.equal(got.deleted, 1);
  assert.equal(B.messages(T0).length, 0);
  assert.equal(A.messages(T0).length, 0);
});

test("media through a conversation: kept, shown, survives a save, and delete for both covers it", async () => {
  const { A, B, relay } = await conv();
  const bytes = rnd(300);
  const body = M.encodeMedia({ bytes, kind: "voice", mime: "audio/mp4", capturedAt: T0 });
  const sent = await A.sendMedia(body, { now: T0 });
  postTo(relay, sent);
  const [got] = await deliver(relay, B);
  assert.equal(got.kind, "media");
  const [shown] = B.messages(T0);
  assert.equal(shown.kind, "media");
  assert.deepEqual(M.decodeMedia(shown).bytes, bytes);
  const saved = await B.store.seal(T0);
  assert.equal((await M.MessageStore.open(saved.key, saved.blob, { convId: B.session.convId })).size, 1);
  const r = await A.delete(sent.id, { forBoth: true, now: T0 });
  postTo(relay, r.send);
  const [del] = await deliver(relay, B);
  assert.equal(del.deleted, 1);
  assert.equal(B.messages(T0).length, 0);
  assert.throws(() => A.sendMedia("not bytes"), (e) => e.code === "bad_media");
});

test("a contact can never delete what you sent", async () => {
  const { A, B, relay } = await conv();
  const mine = await A.send("my words", { now: T0 });
  postTo(relay, mine);
  await deliver(relay, B);
  // B tries to erase A's copy of A's own message.
  const evil = await B.session.encrypt("delete", M.deleteBody([{ id: mine.id, pos: { dh: "0".repeat(64), n: 0 } }]), { now: T0 });
  postTo(relay, evil);
  const [got] = await deliver(relay, A);
  assert.equal(got.refused, 1);
  assert.equal(got.deleted, 0);
  assert.equal(A.messages(T0)[0].text, "my words");
});

test("delete for both, before delivery: unsent at the relay, and a kept copy can never be opened", async () => {
  const { A, B, relay } = await conv();
  const sent = await A.send("wrong person!", { now: T0 });
  postTo(relay, sent);
  const keptCopy = sent.wire.slice(); // someone (a relay, a network tap) kept the ciphertext
  const r = await A.delete(sent.id, { forBoth: true, now: T0 });
  assert.equal(relay.retract(r.unsend.box, r.unsend.retract), true, "unsent: it never reached the contact");
  assert.equal(relay.retract(r.unsend.box, r.unsend.retract), false);
  postTo(relay, r.send);
  const got = await deliver(relay, B);
  assert.equal(got.length, 1);
  assert.equal(got[0].kind, "delete");
  assert.equal(got[0].destroyed, 1, "the contact's phone destroyed the key that would have opened it");
  await code(B.receive(keptCopy, { now: T0 }), "replay_or_old");
  assert.equal(B.messages(T0).length, 0);
  assert.equal(B.session.gaps({ now: T0 + DAY }).missing, 0, "not reported as a missing message");
});

test("delete for both across a ratchet step: the old chain's key is still destroyed", async () => {
  const { A, B, relay } = await conv();
  const sent = await A.send("first", { now: T0 });       // A's chain 1
  const reply = await B.send("hi", { now: T0 });         // B replies; A's next send starts a new chain
  postTo(relay, reply);
  await deliver(relay, A);
  const r = await A.delete(sent.id, { forBoth: true, now: T0 });
  const [got] = [await B.receive(r.send.wire, { now: T0 })]; // the delete arrives before the message
  assert.equal(got.destroyed, 1);
  await code(B.receive(sent.wire, { now: T0 }), "replay_or_old");
});

test("delete for both refuses what isn't yours, and anything after the conversation ended, without losing your copy", async () => {
  const { A, B, relay } = await conv();
  const theirs = await B.send("from B", { now: T0 });
  postTo(relay, theirs);
  await deliver(relay, A);
  await code(A.delete(theirs.id, { forBoth: true, now: T0 }), "not_yours");
  await code(A.delete("A".repeat(22), { forBoth: true, now: T0 }), "not_found");
  const mine = await A.send("from A", { now: T0 });
  const end = await B.session.encrypt("close", "", { now: T0 });
  await A.receive(end.wire, { now: T0 });
  await code(A.delete(mine.id, { forBoth: true, now: T0 }), "closed");
  assert.ok(A.messages(T0).some((m) => m.id === mine.id), "still here: you can delete it for yourself");
  assert.deepEqual(await A.delete(mine.id, { now: T0 }), { deleted: true });
});

test("unsend: only the sender's token works; the relay keeps no token", () => {
  const relay = M.memoryRelay({ now: () => T0 });
  const box = "e".repeat(32), w = new Uint8Array(4096); w[0] = 1;
  const { retract, retractTag } = M.newRetract();
  relay.put(box, w, { tag: retractTag });
  assert.equal(relay.retract(box, rnd(16)), false);
  assert.equal(relay.retract("f".repeat(32), retract), false, "a wrong box answers the same as a wrong token");
  assert.throws(() => relay.put(box, w, { tag: "not-a-tag" }), (e) => e.code === "bad_tag");
  assert.equal(relay.retract(box, retract), true);
  assert.deepEqual(relay.take(box), []);
  assert.equal(relay.totalBytes, 0);
  assert.ok(!JSON.stringify(relay.observed).includes(Buffer.from(retract).toString("hex")));
});

test("disappearing messages: either side sets the timer; messages vanish on both phones and from saves", async () => {
  const { A, B, relay } = await conv();
  await code(A.setTimer(5_000, { now: T0 }), "bad_timer");
  postTo(relay, await A.setTimer(60_000, { now: T0 }));
  const [t] = await deliver(relay, B);
  assert.equal(t.timer, 60_000);
  assert.equal(A.timer, 60_000);
  assert.equal(B.timer, 60_000);
  const sent = await A.send("this will vanish", { now: T0 });
  postTo(relay, sent);
  const [got] = await deliver(relay, B, T0 + 1_000);
  assert.equal(got.ttlMs, 60_000);
  assert.equal(B.messages(T0 + 60_000).length, 1, "counts down from arrival");
  assert.equal(B.messages(T0 + 61_001).length, 0);
  assert.equal(A.messages(T0 + 60_001).length, 0);
  const saved = await B.store.seal(T0 + 61_001);
  assert.equal((await M.MessageStore.open(saved.key, saved.blob, { convId: B.session.convId })).size, 0);
  const back = await B.send("mine vanish too", { now: T0 });
  postTo(relay, back);
  assert.equal((await deliver(relay, A))[0].ttlMs, 60_000);
  postTo(relay, await B.setTimer(0, { now: T0 }));
  await deliver(relay, A);
  assert.equal(A.timer, 0);
});

test("forget: the conversation and every key gone from this phone; for both, your messages vanish from theirs too", async () => {
  const { A, B, relay } = await conv();
  for (const t of ["a1", "a2", "a3"]) postTo(relay, await A.send(t, { now: T0 }));
  for (const t of ["b1", "b2"]) postTo(relay, await B.send(t, { now: T0 }));
  await deliver(relay, B); await deliver(relay, A);
  const secrets = [A.session.s.RK, A.session.s.sendWire, A.session.s.recvBox, A.session.s.CKs];
  const out = await A.forget({ forBoth: true, now: T0 });
  assert.equal(out.send.length, 2, "one delete for your messages, then the close");
  for (const p of out.send) postTo(relay, p);
  const got = await deliver(relay, B);
  assert.deepEqual(got.map((g) => g.kind), ["delete", "close"]);
  assert.deepEqual(B.messages(T0).map((m) => m.text), ["b1", "b2"], "only B's own messages remain on B's phone");
  assert.equal(B.status, "closed");
  assert.equal(A.status, "erased");
  assert.equal(A.store.size, 0);
  for (const k of secrets) assert.ok(k.every((x) => x === 0), "key material overwritten");
  await code(A.send("hello?", { now: T0 }), "erased");
  await code(A.session.seal(rnd(32)), "erased");
  assert.deepEqual(A.session.inboxes(T0), []);
});

test("forget for me only: nothing is sent; the contact's phone is untouched", async () => {
  const { A, B, relay } = await conv();
  const sent = await A.send("still on B's phone", { now: T0 });
  postTo(relay, sent);
  await A.posted([sent.id]);
  await deliver(relay, B);
  const out = await A.forget({ now: T0 });
  assert.deepEqual(out, { done: true, send: [], unsend: [], pending: [], left: 0 });
  assert.equal(B.messages(T0).length, 1);
  assert.equal(B.status, "connected");
});

test("cancel an invite: the bundle comes off the relay and requests to it can't be read", async () => {
  const seedA = rnd(64);
  const relay = M.memoryRelay({ now: () => T0 });
  const inv = await M.createInvite(seedA, { now: T0 });
  relay.put(inv.box, inv.wire, { tag: inv.retractTag });
  const opened = await M.openInvite(inv.code, relay.take(inv.box, { keep: true })[0], { now: T0 });
  const req = await M.requestContact(rnd(64), opened, { now: T0 });
  const down = M.cancelInvite(inv.state);
  assert.equal(relay.retract(down.box, down.retract), true);
  assert.deepEqual(relay.take(inv.box, { keep: true }), [], "no one else can fetch it with the code");
  await code(M.readRequest(inv.state, M.personaFromSalt(seedA, inv.state.personaSalt), req.wire, { now: T0 }), "invite_used");
  assert.ok(inv.state.otkSk.every((x) => x === 0));
});

test("withdraw a contact request before it's read", async () => {
  const relay = M.memoryRelay({ now: () => T0 });
  const inv = await M.createInvite(rnd(64), { now: T0 });
  const req = await M.requestContact(rnd(64), await M.openInvite(inv.code, inv.wire, { now: T0 }), { now: T0 });
  relay.put(req.box, req.wire, { tag: req.retractTag });
  assert.equal(relay.retract(req.box, req.retract), true);
  assert.deepEqual(relay.take(inv.state.replyBox), []);
});

test("delete and timer messages are checked on the way out and on the way in", async () => {
  const { a } = await meet({ stamps: false });
  await code(a.encrypt("delete", new TextEncoder().encode(JSON.stringify({ d: [] })), { now: T0 }), "bad_delete");
  await code(a.encrypt("delete", new TextEncoder().encode(JSON.stringify({ d: [{ id: "x", dh: "y", n: -1 }] })), { now: T0 }), "bad_delete");
  await code(a.encrypt("timer", "5", { now: T0 }), "bad_timer");
  await code(a.encrypt("text", "hi", { now: T0, ttlMs: 10 }), "bad_timer");
  const many = Array.from({ length: M.MAX_DELETE + 1 }, () => ({ id: "A".repeat(22), pos: { dh: "0".repeat(64), n: 0 } }));
  assert.throws(() => M.deleteBody(many), (e) => e instanceof M.MsgError && e.code === "bad_delete");
  assert.throws(() => M.deleteBody([{ id: "A".repeat(22) }]), (e) => e instanceof M.MsgError && e.code === "bad_delete", "a record with no ratchet position");
});


/* ---------------- delete: fixes from the second review ---------------- */

test("delete for both survives the 'end' arriving first", async () => {
  const { A, B, relay } = await conv();
  postTo(relay, await A.send("secret", { now: T0 }));
  await deliver(relay, B);
  const out = await A.forget({ forBoth: true, now: T0 });
  const [del, close] = out.send;
  await B.receive(close.wire, { now: T0 });
  assert.equal(B.status, "closed");
  const got = await B.receive(del.wire, { now: T0 });
  assert.equal(got.deleted, 1);
  assert.equal(B.messages(T0).length, 0);
  await code(B.receive(close.wire, { now: T0 }), "replay_or_old");
});

test("saved conversations: a new key every save, so the key for a deleted, undelivered message is gone from storage", async () => {
  const { A, B, relay } = await conv();
  const m1 = await A.send("never meant to arrive", { now: T0 });
  const m2 = await A.send("second", { now: T0 });
  await B.receive(m2.wire, { now: T0 });            // m1's key is now set aside on B's phone
  const s1 = await B.seal(T0);
  const r = await A.delete(m1.id, { forBoth: true, now: T0 });
  await B.receive(r.send.wire, { now: T0 });
  const s2 = await B.seal(T0);
  assert.notDeepEqual(s1.key, s2.key);
  await code(M.Conversation.open(s2.key, s1.blob, { convId: B.session.convId }), "decrypt_failed");
  const restored = await M.Conversation.open(s2.key, s2.blob, { convId: B.session.convId });
  await code(restored.receive(m1.wire, { now: T0 }), "replay_or_old");
  assert.deepEqual(restored.messages(T0).map((x) => x.text), ["second"]);
  // The old save still holds that key, which is exactly why the app overwrites the old key:
  const old = await M.Conversation.open(s1.key, s1.blob, { convId: B.session.convId });
  assert.equal((await old.receive(m1.wire, { now: T0 })).text, "never meant to arrive");
});

test("persist: every change is saved before anything is handed back; a failed save hands nothing back", async () => {
  const m = await meet({ stamps: false });
  const saves = [];
  let fail = false;
  const A = new M.Conversation(m.a, null, { persist: async (sv) => { if (fail) throw new Error("disk full"); saves.push(sv); } });
  const sent = await A.send("saved first", { now: T0 });
  const last = saves.at(-1);
  const back = await M.Conversation.open(last.key, last.blob, { convId: m.a.convId });
  assert.deepEqual(back.messages(T0).map((x) => x.text), ["saved first"]);
  assert.equal(back.session.version, A.session.version);
  fail = true;
  await code(A.send("not handed out", { now: T0 }), "persist_failed");
  assert.ok(sent.wire instanceof Uint8Array);
});

test("a session's new state isn't visible to anyone else until its save succeeded", async () => {
  const { a } = await meet({ stamps: false });
  const outer = M.Session.fromJSON(a.toJSON(), {
    persist: async (view) => {
      assert.equal(view.version, before + 1, "the save sees the new state");
      assert.equal(outer.version, before, "everyone else still sees the saved one");
    },
  });
  const before = outer.version;
  await outer.encrypt("text", "x", { now: T0 });
  assert.equal(outer.version, before + 1);
});

test("forget waits for a send or receive already running, and refuses anything after it", async () => {
  const { A } = await conv();
  const sending = A.send("in flight", { now: T0 });
  const forgetting = A.forget({ forBoth: true, now: T0 });
  const sent = await sending;
  const out = await forgetting;
  assert.equal(out.unsend.length, 1, "the in-flight message is covered");
  assert.equal(out.send.length, 2);
  await code(A.send("after", { now: T0 }), "erased");
  assert.ok(sent.wire);
  // receive in flight, then forget: nothing is left behind
  const { B: B2, A: A2 } = await conv();
  const incoming = await A2.session.encrypt("text", "hello", { now: T0 });
  const receiving = B2.receive(incoming.wire, { now: T0 });
  const gone = B2.forget({ now: T0 });
  await receiving; await gone;
  assert.equal(B2.store.size, 0);
});

test("one of your disappearing messages can still be unsent or deleted for both after it disappears from your phone", async () => {
  const { A, B, relay } = await conv();
  postTo(relay, await A.setTimer(60_000, { now: T0 }));
  await deliver(relay, B);
  const sent = await A.send("vanishing, never fetched", { now: T0 });
  postTo(relay, sent);
  const later = T0 + 61_000;
  assert.equal(A.messages(later).length, 0, "gone from the screen");
  const r = await A.delete(sent.id, { forBoth: true, now: later });
  assert.equal(relay.retract(r.unsend.box, r.unsend.retract), true, "and still unsendable");
  postTo(relay, r.send);
  const got = await deliver(relay, B, later);
  assert.deepEqual(got.map((g) => g.kind), ["delete"]);
  // forget covers them too
  const s2 = await A.send("another", { now: later });
  postTo(relay, s2);
  const out = await A.forget({ forBoth: true, now: later + 61_000 });
  assert.equal(out.unsend.length, 1);
});

test("forget for both on an ended conversation still returns the unsend tokens", async () => {
  const { A, B, relay } = await conv();
  const sent = await A.send("not fetched yet", { now: T0 });
  postTo(relay, sent);
  await A.receive((await B.session.encrypt("close", "", { now: T0 })).wire, { now: T0 });
  const out = await A.forget({ forBoth: true, now: T0 });
  assert.equal(out.send.length, 0);
  assert.equal(out.unsend.length, 1);
  assert.equal(relay.retract(out.unsend[0].box, out.unsend[0].retract), true);
});

test("disappearing timers: both phones always agree; your own timer also applies to what you receive", async () => {
  const { A, B, relay } = await conv();
  // Both change it at the same moment: the shorter wins on both phones.
  const ta = await A.setTimer(3_600_000, { now: T0 });
  const tb = await B.setTimer(60_000, { now: T0 });
  await B.receive(ta.wire, { now: T0 }); await A.receive(tb.wire, { now: T0 });
  assert.equal(A.timer, 60_000); assert.equal(B.timer, 60_000);
  // Later change wins on both, whatever order they arrive in.
  const tc = await A.setTimer(120_000, { now: T0 + 5_000 });
  const td = await B.setTimer(0, { now: T0 + 9_000 });
  await A.receive(td.wire, { now: T0 }); await B.receive(tc.wire, { now: T0 });
  assert.equal(A.timer, 0); assert.equal(B.timer, 0);
  // A sender ignoring the timer can't make your copy permanent.
  postTo(relay, await B.setTimer(60_000, { now: T0 + 20_000 }));
  await deliver(relay, A);
  const sneaky = await A.session.encrypt("text", "keep forever?", { now: T0, ttlMs: 0 });
  const got = await B.receive(sneaky.wire, { now: T0 + 30_000 });
  assert.equal(got.ttlMs, 60_000);
  assert.equal(B.messages(T0 + 90_001).length, 0);
});

test("a contact flooding deletes can't grow the tombstone list without bound", () => {
  const store = new M.MessageStore(rnd(16));
  const ids = Array.from({ length: M.MAX_TOMBSTONES + 1000 }, () => Buffer.from(rnd(16)).toString("base64url"));
  store.applyRemoteDelete(ids, T0);
  assert.equal(store.s.tomb.length, M.MAX_TOMBSTONES);
  assert.equal(store.tombIds.size, M.MAX_TOMBSTONES);
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
  const st = { ...inv.state, used: 0, uses: 1, closed: false }; // a fresh view of the (closed) invite, for reading only
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
