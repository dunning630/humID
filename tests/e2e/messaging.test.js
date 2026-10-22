// End to end: person to person under the human-to-human rule, against the real services.
// Two holders meet and talk through the relay service; every request, acceptance and message
// carries a live stamp the gateway issued only inside a live step-up over its exact blinded
// value. What each service could learn is checked by reading its database.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import * as M from "@humid/msg";
import { makeHolder } from "./holder.js";

let stack, alice, bob, aApi, bApi, keyset, aRelay, bRelay;
const T = () => Date.now();

/** The app's stamper: blind → one live step-up over exactly these values → finalize. */
function stamperFor(h, api) {
  const many = async (commits) => {
    const drafts = commits.map((c) => M.blindStamp(keyset, c));
    const t = await api.ticket("stamp");
    const sigs = await api.stamp({ kid: keyset.issuing.id, blinded: drafts.map((d) => d.blinded) }, { ticket: t, sign: (message) => h.stepUp({ message, live: t.live }) });
    return drafts.map((d, i) => M.finalizeStamp(keyset, d.draft, sigs[i]));
  };
  return Object.assign(async (c) => (await many([c]))[0], { many });
}

async function signedIn(h) {
  const api = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  await api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign });
  return api;
}

before(async () => {
  stack = await startStack({ relayOpts: { maxNetBytesPerDay: 4 * 1024 * 1024 } });
  alice = makeHolder("alice-msg");
  bob = makeHolder("bob-msg");
  aApi = await signedIn(alice);
  bApi = await signedIn(bob);
  const k = await aApi.msgKeys();
  keyset = M.importStampKeys(k.stamp.keys, { passKeys: k.passKeyIds.map((id) => ({ id })) });
  aRelay = aApi.relay();
  bRelay = bApi.relay();
});
after(async () => { aRelay?.close(); bRelay?.close(); await stack?.stop(); });

const dump = (file) => {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    return JSON.stringify(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()
      .map(({ name }) => db.prepare(`SELECT * FROM "${name}"`).all()), (k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v));
  } finally { db.close(); }
};

test("the server offers messaging; its stamp key is not its pass key", async () => {
  assert.ok((await aApi.server()).policy.messaging);
  const k = await aApi.msgKeys();
  assert.ok(k.stamp.keys.length >= 1 && k.stamp.keys.length <= 2);
  for (const s of k.stamp.keys) assert.ok(!k.passKeyIds.includes(s.id));
  // the app's own check: a server that stamps with its pass key is refused
  assert.throws(() => M.importStampKeys(k.stamp.keys, { passKeys: k.stamp.keys.map((x) => ({ id: x.id })) }), (e) => e.code === "bad_stamp_key");
});

test("no stamp without a live step-up", async () => {
  const { blinded } = M.blindStamp(keyset, new Uint8Array(32).fill(7));
  await assert.rejects(aApi.stamp({ kid: keyset.issuing.id, blinded: [blinded] }), (e) => e.code === "step_up_required");
});

test("a step-up approves exactly the blinded values it signed, once", async () => {
  const a = M.blindStamp(keyset, new Uint8Array(32).fill(1));
  const b = M.blindStamp(keyset, new Uint8Array(32).fill(2));
  // Signed over a, sent with b: the device signature covers the body, so it's rejected.
  const t = await aApi.ticket("stamp");
  await assert.rejects(
    aApi.stamp({ kid: keyset.issuing.id, blinded: [b.blinded] }, { ticket: t, sign: async (message) => {
      // what the check approved: the request with a's value in it
      const { stepUpMessage } = await import("@humid/htp");
      const body = new TextEncoder().encode(JSON.stringify({ kid: keyset.issuing.id, blinded: [Buffer.from(a.blinded).toString("base64url")] }));
      return alice.stepUp({ message: stepUpMessage(aApi.htp.session.th, t.seq, "POST", "/msg/stamp", body, t.at, t.actionBytes), live: t.live });
    } }),
    (e) => e.code === "bad_proof",
  );
  // A proper one works, and its approval can't be used again.
  const t2 = await aApi.ticket("stamp");
  const proof = { ticket: t2, sign: (message) => alice.stepUp({ message, live: t2.live }) };
  const [sig] = await aApi.stamp({ kid: keyset.issuing.id, blinded: [a.blinded] }, proof);
  assert.ok(M.finalizeStamp(keyset, a.draft, sig));
  await assert.rejects(aApi.stamp({ kid: keyset.issuing.id, blinded: [a.blinded] }, proof), (e) => /step_up_unknown|session_changed|ticket|replay/.test(e.code));
});

test("one check approves at most four stamps", async () => {
  const five = Array.from({ length: 5 }, (_, i) => M.blindStamp(keyset, new Uint8Array(32).fill(i)).blinded);
  const t = await aApi.ticket("stamp");
  await assert.rejects(aApi.stamp({ kid: keyset.issuing.id, blinded: five }, { ticket: t, sign: (message) => alice.stepUp({ message, live: t.live }) }), (e) => e.code === "bad_request");
});

test("the relay can't be used from a signed-in session (no account ever touches a mailbox)", async () => {
  const wire = new Uint8Array(4096); wire[0] = 1;
  await assert.rejects(aApi.htp.call("POST", "/msg/relay/put", { body: wire, headers: { "x-humid-box": "0".repeat(32) } }).then((r) => { if (!r.ok) throw Object.assign(new Error(r.json().error), { code: r.json().error }); }), (e) => e.code === "signed_in");
  // from its own anonymous session it works, and an empty box looks like one that never existed
  await aRelay.put("1".repeat(32), wire);
  const got = await aRelay.take(["1".repeat(32), "2".repeat(32)]);
  assert.equal(got.got["1".repeat(32)].length, 1);
  assert.deepEqual(await aRelay.take(["1".repeat(32)]), await aRelay.take(["3".repeat(32)]));
});

test("meet and talk under the rule, through the relay service, with real stamps", async () => {
  const aStamp = stamperFor(alice, aApi), bStamp = stamperFor(bob, bApi);
  const checksBefore = (await aApi.msgStats())[0]?.checks ?? 0;

  // Alice invites (her live check releases the account seed the persona comes from).
  const inv = await M.createInvite(alice.seed, { now: T() });
  await aRelay.put(inv.box, inv.wire, inv.retractTag);

  // Bob opens it with the code and asks to connect, stamped.
  const { got } = await bRelay.take([M.inviteBoxOf(M.parseInviteCode(inv.code).secret)], { keep: true });
  const opened = await M.openInvite(inv.code, Object.values(got)[0][0], { now: T() });
  const req = await M.requestContact(bob.seed, opened, { intro: "from the workshop", stamper: bStamp, requireLive: true, now: T() });
  await bRelay.put(req.box, req.wire, req.retractTag);

  // Alice reads it (refused if it weren't live), approves with a check; the accept is stamped.
  const [reqWire] = (await aRelay.take([inv.state.replyBox])).got[inv.state.replyBox];
  const personaA = M.personaFromSalt(alice.seed, inv.state.personaSalt);
  const shown = await M.readRequest(inv.state, personaA, reqWire, { now: T(), stampKeys: keyset, requireLive: true });
  assert.equal(shown.live, true);
  assert.equal(shown.intro, "from the workshop");
  const a = new M.Conversation(M.acceptRequest(inv.state, personaA, shown, { now: T() }), null, { requireLive: true });
  const acc = await a.accept({ stamper: aStamp, now: T() });
  await aRelay.put(acc.box, acc.wire, acc.retractTag);

  const b = new M.Conversation(req.session, null, { requireLive: true });
  const poll = async (c, relay) => {
    const boxes = c.session.inboxes(T());
    const { got } = await relay.take(boxes);
    const out = [];
    for (const box of boxes) for (const w of got[box] || []) out.push(await c.receive(w, { stampKeys: keyset, now: T() }));
    return out;
  };
  const [first] = await poll(b, bRelay);
  assert.equal(first.kind, "accept");
  assert.equal(first.live, true);
  assert.equal(b.status, "connected");
  assert.equal(b.session.safetyCode, a.session.safetyCode);

  // Chat both ways; each message one live check.
  for (const [from, to, fromRelay, toRelay, stamp, text] of [[a, b, aRelay, bRelay, aStamp, "hello Bob"], [b, a, bRelay, aRelay, bStamp, "hi Alice"]]) {
    const r = await from.send(text, { stamper: stamp, now: T() });
    await fromRelay.put(r.box, r.wire, r.retractTag);
    const [m] = await poll(to, toRelay);
    assert.equal(m.text, text);
    assert.equal(m.live, true);
    assert.ok(M.liveState({ ownAt: T(), peerAt: to.peerLiveAt, now: T() }).live, "both proven live within the window");
  }

  // Delete the conversation for both: one check, both messages stamped.
  const before = (await aApi.msgStats())[0];
  const { send } = await a.forget({ forBoth: true, stamper: aStamp, now: T() });
  for (const x of send) await aRelay.put(x.box, x.wire, x.retractTag);
  const after = (await aApi.msgStats())[0];
  assert.equal(after.checks - before.checks, 1);
  assert.equal(after.stamps - before.stamps, send.length);
  const gone = await poll(b, bRelay);
  assert.ok(gone.every((x) => !x.refused));
  assert.equal(b.status, "closed");
  assert.deepEqual(b.messages(T()).filter((m) => m.dir === "in"), []);

  // The issuer's books: totals per day, nothing more.
  const stats = await aApi.msgStats();
  assert.ok(stats[0].checks - checksBefore >= 5);
  assert.match(stats[0].day, /^\d{4}-\d{2}-\d{2}$/);
});

test("what the services could learn: no account, persona or content in the relay; no message in the issuer", async () => {
  const relayDb = dump(join(stack.root, "relay", "relay.db"));
  const accessDb = dump(join(stack.root, "access", "access.db"));
  for (const h of [alice, bob]) {
    for (const db of [relayDb, accessDb]) {
      assert.ok(!db.includes(h.id), "no account id");
      assert.ok(!db.includes(Buffer.from(h.pub.dsaPk).toString("hex").slice(0, 32)), "no account key");
    }
  }
  assert.ok(!relayDb.includes(Buffer.from("hello Bob").toString("hex")));
  assert.ok(!relayDb.includes("127.0.0.1"), "no address is written down");
  assert.ok(!accessDb.includes(Buffer.from("hello Bob").toString("hex")));
});

test("unsend at the relay: only the sender's token takes an object down, and only before it's fetched", async () => {
  const wire = new Uint8Array(4096); wire[0] = 1;
  const { retract, retractTag } = M.newRetract();
  const box = "b".repeat(32);
  await aRelay.put(box, wire, retractTag);
  assert.equal(await bRelay.retract(box, M.newRetract().retract), false, "someone else's token does nothing");
  assert.equal(await aRelay.retract(box, retract), true);
  assert.deepEqual((await bRelay.take([box])).got, {});
  await aRelay.put(box, wire, retractTag);
  await bRelay.take([box]);
  assert.equal(await aRelay.retract(box, retract), false, "already delivered");
});

test("one network can't fill the relay for everyone (PC-27): a daily byte quota per network", async () => {
  const wire = new Uint8Array(262144); wire[0] = 1;
  let refused = null;
  for (let i = 0; i < 40 && !refused; i++) {
    const box = i.toString(16).padStart(32, "a");
    await aRelay.put(box, wire).catch((e) => { refused = e; });
  }
  assert.ok(refused, "stopped before 40 × 256 KiB");
  assert.equal(refused.code, "quota");
});
