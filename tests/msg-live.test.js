// The human-to-human rule (packages/msg/src/live.js): nobody interacts on HumID without a
// live check. Each test names the step it proves cannot happen without one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { newIssuerKey, blindSign } from "@humid/pass/issuer";
import * as M from "@humid/msg";

const rnd = (n) => new Uint8Array(randomBytes(n));
const T0 = Date.UTC(2026, 9, 22, 3, 0, 0);
const MIN = 60_000;

const issuer = newIssuerKey(2048);
const stampKeys = M.importStampKeys([{ ...issuer.publicView, issuing: true }]);
let checks = 0; // live checks the "server" saw (one blind signature request each)
const askServer = async (blinded) => { checks++; return blindSign(issuer, blinded); };
const stamper = M.makeStamper(stampKeys, askServer);
/** A stamper that does a whole batch inside ONE live check, as the app's does. */
const batchStamper = Object.assign(async (c) => stamper(c), {
  async many(commits) {
    checks++;
    const out = [];
    for (const c of commits) {
      const { blinded, draft } = M.blindStamp(stampKeys, c);
      out.push(M.finalizeStamp(stampKeys, draft, blindSign(issuer, blinded)));
    }
    return out;
  },
});
// A stamp from a key nobody published: looks like a stamp, isn't one.
const rogue = newIssuerKey(2048);
const rogueKeys = M.importStampKeys([{ ...rogue.publicView, issuing: true }]);
const rogueStamper = M.makeStamper(rogueKeys, async (b) => blindSign(rogue, b));

const code = async (p, c) => {
  try { await p; } catch (e) { assert.ok(e instanceof M.MsgError, `expected MsgError, got ${e?.name}: ${e?.message}`); assert.equal(e.code, c); return; }
  assert.fail(`expected ${c}`);
};

/** A and B meet under the rule; returns both Conversations (strict) and the relay. */
async function meetStrict({ now = T0, reqStamper = stamper, accStamper = stamper } = {}) {
  const relay = M.memoryRelay({ now: () => now });
  const seedA = rnd(64), seedB = rnd(64);
  const inv = await M.createInvite(seedA, { now });
  relay.put(inv.box, inv.wire);
  const [bundle] = relay.take(inv.box, { keep: true });
  const opened = await M.openInvite(inv.code, bundle, { now });
  const req = await M.requestContact(seedB, opened, { stamper: reqStamper, now, requireLive: true });
  relay.put(req.box, req.wire);
  const [reqWire] = relay.take(inv.state.replyBox);
  const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
  const shown = await M.readRequest(inv.state, personaA, reqWire, { now, stampKeys, requireLive: true });
  const a = new M.Conversation(M.acceptRequest(inv.state, personaA, shown, { now }), null, { requireLive: true });
  const acc = await a.accept({ now, stamper: accStamper });
  relay.put(acc.box, acc.wire);
  const b = new M.Conversation(req.session, null, { requireLive: true });
  const got = b.session.inboxes(now).flatMap((box) => relay.take(box));
  const first = await b.receive(got[0], { now, stampKeys });
  return { a, b, relay, first, shown, inv };
}

const deliver = async (relay, to, now, opts = {}) => {
  const out = [];
  for (const box of to.session.inboxes(now)) for (const w of relay.take(box)) out.push(await to.receive(w, { now, stampKeys, ...opts }));
  return out;
};

/* ---------- the freshness rule ---------- */

test("live state: validated only while BOTH sides' checks are fresh; it lapses", () => {
  const W = M.LIVE_WINDOW_MS;
  let s = M.liveState({ ownAt: T0, peerAt: T0 - MIN, now: T0 });
  assert.equal(s.live, true);
  assert.equal(s.until, T0 - MIN + W, "lapses with the older of the two");
  assert.equal(M.liveState({ ownAt: T0, peerAt: T0 - W, now: T0 }).needs, "peer");
  assert.equal(M.liveState({ ownAt: T0 - W - 1, peerAt: T0, now: T0 }).needs, "own");
  assert.equal(M.liveState({ ownAt: null, peerAt: null, now: T0 }).needs, "both");
  // a check stamped far in the future (a fast clock) is not fresh
  assert.equal(M.liveState({ ownAt: T0, peerAt: T0 + 10 * MIN, now: T0 }).peer.fresh, false);
  assert.throws(() => M.liveState({ windowMs: 1000 }), RangeError);
  assert.equal(M.canRead({ ownAt: T0 - W + 1, now: T0 }), true);
  assert.equal(M.canRead({ ownAt: T0 - W, now: T0 }), false);
});

test("live state: the contact's time is when they sent it, never later than when it arrived", () => {
  assert.equal(M.peerLiveAt({ live: true, sentAt: T0 - MIN, receivedAt: T0 }), T0 - MIN);
  assert.equal(M.peerLiveAt({ live: true, sentAt: T0 + 60 * MIN, receivedAt: T0 }), T0, "a fast clock can't stretch freshness");
  assert.equal(M.peerLiveAt({ live: false, sentAt: T0, receivedAt: T0 }), null);
  assert.equal(M.peerLiveAt({ live: null, sentAt: T0, receivedAt: T0 }), null, "unstamped never counts");
});

/* ---------- meeting ---------- */

test("rule: a request can't even be made without a live check", async () => {
  const seedA = rnd(64);
  const inv = await M.createInvite(seedA, { now: T0 });
  const opened = await M.openInvite(inv.code, inv.wire, { now: T0 });
  await code(M.requestContact(rnd(64), opened, { now: T0, requireLive: true }), "stamp_required");
  await code(M.requestContact(rnd(64), opened, { now: T0, requireLive: true, stamper: async () => null }), "stamp_required");
});

test("rule: a request without a valid live stamp is never shown (missing, forged, or wrong key)", async () => {
  for (const [name, s] of [["unstamped", null], ["rogue key", rogueStamper]]) {
    const seedA = rnd(64);
    const inv = await M.createInvite(seedA, { now: T0 });
    const opened = await M.openInvite(inv.code, inv.wire, { now: T0 });
    const req = await M.requestContact(rnd(64), opened, { now: T0, stamper: s });
    const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
    await code(M.readRequest(inv.state, personaA, req.wire, { now: T0, stampKeys, requireLive: true }), "not_live");
    // and without the issuer's keys, nothing can be judged, so nothing is shown
    await code(M.readRequest(inv.state, personaA, req.wire, { now: T0, requireLive: true }), "no_stamp_keys");
    assert.equal(inv.state.used, 0, `${name}: the invite is still usable by the real person`);
  }
});

test("rule: an acceptance must carry a live stamp; an unstamped accept doesn't connect the requester", async () => {
  await code(meetStrict({ accStamper: null }), "stamp_required");
  // An approver whose app skipped the rule: the requester's phone discards the accept.
  const relay = M.memoryRelay({ now: () => T0 });
  const seedA = rnd(64);
  const inv = await M.createInvite(seedA, { now: T0 });
  const opened = await M.openInvite(inv.code, inv.wire, { now: T0 });
  const req = await M.requestContact(rnd(64), opened, { stamper, now: T0, requireLive: true });
  const personaA = M.personaFromSalt(seedA, inv.state.personaSalt);
  const shown = await M.readRequest(inv.state, personaA, req.wire, { now: T0, stampKeys, requireLive: true });
  const lax = M.acceptRequest(inv.state, personaA, shown, { now: T0 });
  const acc = await lax.encrypt("accept", "", { now: T0 }); // no stamp
  relay.put(acc.box, acc.wire);
  const b = new M.Conversation(req.session, null, { requireLive: true });
  const [r] = await deliver(relay, b, T0);
  assert.equal(r.refused, "not_live");
  assert.equal(b.status, "requested", "still not connected");
  assert.equal(b.peerLiveAt, null);
  await code(b.send("hello?", { stamper, now: T0 }), "not_accepted");
});

test("meet under the rule: request stamped, accept stamped, both sides proven live", async () => {
  const { a, b, first, shown } = await meetStrict();
  assert.equal(shown.live, true);
  assert.equal(first.kind, "accept");
  assert.equal(first.live, true);
  assert.equal(b.status, "connected");
  assert.equal(b.peerLiveAt, T0, "the acceptance proves the approver live");
  assert.equal(a.peerLiveAt, null, "the approver has seen no message yet (the request is checked in readRequest)");
});

/* ---------- messages ---------- */

test("rule: nothing is sent without a live stamp", async () => {
  const { a } = await meetStrict();
  await code(a.send("hi", { now: T0 }), "stamp_required");
  await code(a.send("hi", { now: T0, stamper: async () => null }), "stamp_required");
  await code(a.setTimer(60_000, { now: T0 }), "stamp_required");
  assert.equal(a.messages(T0).length, 0, "a refused send leaves nothing behind");
});

test("rule: an unstamped or forged message is discarded unread; the ratchet still moves on", async () => {
  const { a, b, relay } = await meetStrict();
  const t = T0 + MIN;
  // Two messages from a contact whose app broke the rule, then a proper one.
  await a.session.encrypt("text", "unstamped", { now: t }).then((r) => relay.put(r.box, r.wire));
  await a.session.encrypt("text", "rogue", { now: t, stamper: rogueStamper }).then((r) => relay.put(r.box, r.wire));
  await a.send("live", { now: t, stamper }).then((r) => relay.put(r.box, r.wire));
  const got = await deliver(relay, b, t);
  assert.deepEqual(got.map((r) => r.refused ?? r.text), ["not_live", "not_live", "live"]);
  assert.ok(!("text" in got[0]) && !("body" in got[0]), "a discarded message hands back no content");
  assert.deepEqual(b.messages(t).map((m) => new TextDecoder().decode(m.body)), ["live"]);
  assert.equal(b.peerLiveAt, t);
  // the refused messages' keys are gone: a replay is refused as old, not opened
  const st = b.session.toJSON();
  assert.equal(st.skipped.length, 0);
});

test("rule: an unstamped delete, timer or end from the contact changes nothing", async () => {
  const { a, b, relay } = await meetStrict();
  const t = T0 + MIN;
  const sent = await b.send("keep me", { now: t, stamper });
  relay.put(sent.box, sent.wire);
  await deliver(relay, a, t);
  const [mine] = a.messages(t);
  // a forged "delete for both" of a's own message, and an unstamped timer and end
  await a.session.encrypt("timer", "60000", { now: t, ttlMs: 0 }).then((r) => relay.put(r.box, r.wire));
  await a.session.encrypt("close", "", { now: t, ttlMs: 0 }).then((r) => relay.put(r.box, r.wire));
  const got = await deliver(relay, b, t);
  assert.ok(got.every((r) => r.refused === "not_live"));
  assert.equal(b.timer, 0);
  assert.equal(b.status, "connected");
  assert.ok(mine);
});

test("one action, one check: deleting a whole conversation for both is one live check", async () => {
  const { a, b, relay } = await meetStrict();
  let t = T0 + MIN;
  for (const x of ["one", "two", "three"]) relay.put(...(await a.send(x, { now: t, stamper }).then((r) => [r.box, r.wire])));
  await deliver(relay, b, t);
  assert.equal(b.messages(t).length, 3);
  t += MIN;
  const before = checks;
  const { send } = await a.forget({ forBoth: true, now: t, stamper: batchStamper });
  assert.equal(checks - before, 1, "the delete and the end were stamped in one check");
  for (const s of send) relay.put(s.box, s.wire);
  const got = await deliver(relay, b, t);
  assert.ok(got.every((r) => r.live === true && !r.refused));
  assert.equal(b.messages(t).length, 0);
  assert.equal(b.status, "closed");
});

test("forget for both refuses without a live check, and erases nothing", async () => {
  const { a } = await meetStrict();
  await a.send("still here", { now: T0, stamper });
  await code(a.forget({ forBoth: true, now: T0 }), "stamp_required");
  assert.equal(a.messages(T0).length, 1);
  assert.equal(a.status, "connected");
  // for me only: nothing is sent, so no check is needed
  await a.forget({ now: T0 });
  assert.equal(a.status, "erased");
});

test("a batch stamper can't be used to slip one stamp onto another message", async () => {
  const { a, b, relay } = await meetStrict();
  // A stamper whose batch returns the stamps in the wrong order: each message's stamp covers the other.
  const swapped = Object.assign(async () => null, { many: async (c) => (await batchStamper.many(c)).reverse() });
  const msgs = [];
  for (let i = 0; i < 2; i++) msgs.push(await a.send(`m${i}`, { now: T0, stamper }));
  for (const m of msgs) relay.put(m.box, m.wire);
  const { send } = await a.forget({ forBoth: true, now: T0, stamper: swapped });
  assert.equal(send.length, 2, "a delete and an end went out");
  for (const s of send) relay.put(s.box, s.wire);
  const got = await deliver(relay, b, T0);
  const proto = got.filter((x) => x.kind === "delete" || x.kind === "close");
  assert.equal(proto.length, 2);
  // each went out with the other's stamp: the contact refuses both and keeps the messages
  for (const r of proto) assert.equal(r.refused, "not_live");
  assert.equal(b.messages(T0).length, 2);
  assert.equal(b.status, "connected");
});

test("the contact's freshness comes from their live messages and survives a save", async () => {
  const { a, b, relay } = await meetStrict();
  const t = T0 + 2 * MIN;
  relay.put(...(await a.send("hi", { now: t, stamper }).then((r) => [r.box, r.wire])));
  await deliver(relay, b, t + 1000);
  assert.equal(b.peerLiveAt, t);
  const { blob, key } = await b.seal(t + 2000);
  const back = await M.Conversation.open(key, blob, { convId: b.session.convId, requireLive: true });
  assert.equal(back.peerLiveAt, t);
  assert.equal(back.requireLive, true);
  // live while both are fresh; lapses after the window
  assert.equal(M.liveState({ ownAt: t + 1000, peerAt: back.peerLiveAt, now: t + 2000 }).live, true);
  assert.equal(M.liveState({ ownAt: t + 1000, peerAt: back.peerLiveAt, now: t + M.LIVE_WINDOW_MS + 1 }).live, false);
});

test("strict and lax interoperate only one way: a strict phone never shows a lax phone's unstamped words", async () => {
  // A non-strict sender that DOES stamp is fine; it's the missing stamp that's refused.
  const { a, b, relay } = await meetStrict();
  const lax = new M.Conversation(a.session); // same session, rule off
  relay.put(...(await lax.send("stamped anyway", { now: T0, stamper }).then((r) => [r.box, r.wire])));
  relay.put(...(await lax.send("not stamped", { now: T0 }).then((r) => [r.box, r.wire])));
  const got = await deliver(relay, b, T0);
  assert.deepEqual(got.map((r) => r.refused ?? r.text), ["stamped anyway", "not_live"]);
});

test("receiving under the rule needs the issuer's keys; without them nothing moves", async () => {
  const { a, b, relay } = await meetStrict();
  relay.put(...(await a.send("hi", { now: T0, stamper }).then((r) => [r.box, r.wire])));
  const [w] = b.session.inboxes(T0).flatMap((box) => relay.take(box));
  await code(b.receive(w, { now: T0 }), "no_stamp_keys");
  const r = await b.receive(w, { now: T0, stampKeys });
  assert.equal(r.text, "hi", "the same wire still opens once the keys are there: nothing was consumed");
});

test("'I'm here': a stamped, empty receipt makes reading mutual; unstamped, it counts for nothing", async () => {
  const { a, b, relay } = await meetStrict();
  const t = T0 + 4 * MIN;
  relay.put(...(await a.here({ now: t, stamper }).then((r) => [r.box, r.wire])));
  const [r] = await deliver(relay, b, t);
  assert.equal(r.kind, "receipt");
  assert.equal(b.peerLiveAt, t, "the contact is proven live by opening, not only by sending");
  assert.equal(b.messages(t).length, 0, "nothing is shown");
  await code(a.here({ now: t }), "stamp_required");
  await a.session.encrypt("receipt", '{"here":1}', { now: t + 1000 }).then((x) => relay.put(x.box, x.wire));
  const [r2] = await deliver(relay, b, t + 1000);
  assert.equal(r2.refused, "not_live");
  assert.equal(b.peerLiveAt, t, "an unstamped one moves nothing");
});

/* ---------- one stamp, one message, once (security review H1) ---------- */

const HOUR = 60 * MIN, DAY = 24 * HOUR;
const recording = () => { const log = []; return { log, s: async (c) => { const st = await stamper(c); log.push(st); return st; } }; };

test("H1: a stamp can't be reused on a later copy of the same message to look live again", async () => {
  const { a, b } = await meetStrict();
  const rec = recording(), nonce = rnd(16);
  const w1 = await a.session.encrypt("receipt", '{"here":1}', { now: T0, ttlMs: 0, nonce, stamper: rec.s, requireLive: true });
  await b.receive(w1.wire, { now: T0, stampKeys });
  assert.equal(b.peerLiveAt, T0);
  // same id and body, same stamp, a fresh `at`: the stamp covers `at`, so it doesn't verify
  const t = T0 + DAY;
  const w2 = await a.session.encrypt("receipt", '{"here":1}', { now: t, ttlMs: 0, nonce, stamper: async () => rec.log[0], requireLive: true });
  const r = await b.receive(w2.wire, { now: t, stampKeys });
  assert.equal(r.refused, "not_live");
  assert.equal(b.peerLiveAt, T0, "freshness not refreshed");
});

test("H1: the very same stamped payload re-sent under a new ratchet position counts once", async () => {
  const { a, b } = await meetStrict();
  const rec = recording(), nonce = rnd(16);
  const w1 = await a.session.encrypt("receipt", '{"here":1}', { now: T0, ttlMs: 0, nonce, stamper: rec.s, requireLive: true });
  await b.receive(w1.wire, { now: T0, stampKeys });
  // identical payload (same at), new wire: the stamp verifies but its id was already seen
  const w2 = await a.session.encrypt("receipt", '{"here":1}', { now: T0, ttlMs: 0, nonce, stamper: async () => rec.log[0], requireLive: true });
  const r = await b.receive(w2.wire, { now: T0 + 4 * MIN, stampKeys, receivedAt: T0 + 4 * MIN });
  assert.equal(r.refused, "not_live");
  // and the seen ids survive a save
  const { blob, key } = await b.seal(T0 + 5 * MIN);
  const back = await M.Conversation.open(key, blob, { convId: b.session.convId, requireLive: true });
  const w3 = await a.session.encrypt("receipt", '{"here":1}', { now: T0, ttlMs: 0, nonce, stamper: async () => rec.log[0], requireLive: true });
  assert.equal((await back.receive(w3.wire, { now: T0 + 6 * MIN, stampKeys })).refused, "not_live");
});

test("H1: an old stamped timer change can't be replayed with a newer change time", async () => {
  const { a, b } = await meetStrict();
  const rec = recording(), nonce = rnd(16);
  const w1 = await a.session.encrypt("timer", String(HOUR), { now: T0, ttlMs: 0, nonce, stamper: rec.s, requireLive: true });
  await b.receive(w1.wire, { now: T0, stampKeys });
  const off = await b.setTimer(0, { now: T0 + MIN, stamper });
  await a.receive(off.wire, { now: T0 + MIN, stampKeys });
  const t = T0 + 10 * DAY;
  const w2 = await a.session.encrypt("timer", String(HOUR), { now: t, ttlMs: 0, nonce, stamper: async () => rec.log[0], requireLive: true });
  assert.equal((await b.receive(w2.wire, { now: t, stampKeys })).refused, "not_live");
  assert.equal(b.timer, 0);
});

test("H1: a future-dated message isn't live; freshness counts from when it came off the relay", async () => {
  const { a, b, relay } = await meetStrict();
  const w = await a.session.encrypt("receipt", '{"here":1}', { now: Date.UTC(2100, 0, 1), ttlMs: 0, stamper, requireLive: true });
  assert.equal((await b.receive(w.wire, { now: T0 + 3 * DAY, stampKeys })).refused, "not_live");
  // an honest one, fetched at T0 + 1 min but only read (opened) three days later
  const ok = await a.here({ now: T0 + MIN, stamper });
  relay.put(ok.box, ok.wire);
  const [wire] = b.session.inboxes(T0 + MIN).flatMap((x) => relay.take(x));
  await b.receive(wire, { now: T0 + 3 * DAY, receivedAt: T0 + MIN, stampKeys });
  assert.equal(b.peerLiveAt, T0 + MIN, "a three-day-old check doesn't show as live now");
  assert.equal(M.liveState({ ownAt: T0 + 3 * DAY, peerAt: b.peerLiveAt, now: T0 + 3 * DAY }).live, false);
});
