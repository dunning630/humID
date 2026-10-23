// SRV-30 / H-1: what the gateway's internal key (HUMID_INTERNAL_SK) alone gets: a compromised
// front host. It used to be both server-held halves of a split document and a wipe of the whole
// vault, with no phone, no live check and nothing in the holder's ledger
// (scratchpad poc/servers/gateway-key-is-master.test.js). Now vault, keyshare and identity check
// the holder's own step-up proof against the device keys identity vouches for, the vault releases
// an envelope only against the ledger's receipt for the open, and the Check-in sweep needs
// keyshare's erase token. The gateway's key releases nothing and deletes nothing.
//
// The recovery service too: every route that changes or releases recovery material (seal card,
// contacts, anchor, security keys, settings, link approval, help, cancelling an alert, station
// verification, closing) checks the holder's own proof against the body it received, so the
// gateway's key alone changes nothing there and can't alter what the holder approved.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { startStack } from "../e2e/stack.js";
import { makeHolder, sealSplitFor, anotherDevice } from "../e2e/holder.js";
import { newCard, cardTag, sealCardPart, quorumParts } from "@humid/recovery";
import { HumidApi } from "@humid/api";
import { signRequest, internalRequest, newStatementKeys, signStatement } from "@humid/svc";
import { ml_dsa87, stepUpMessage, actionBytes, liveMessage, b64u, random } from "@humid/htp";

let stack, alice, api, id, bob, bobApi;
before(async () => {
  bob = makeHolder("bob-gw"); // a hardened account with a setup card, and a verification station
  stack = await startStack({ messaging: false, checkin: "on", checkinSweepMs: 0, stations: [bob.id] });
  alice = makeHolder("alice-gw");
  api = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  await api.register({ pub: alice.pub, commit: alice.commit, device: alice.device, sign: alice.registerSign });
  const s = await sealSplitFor(alice, "will.txt", "secret");
  id = (await api.upload(s.envelope, s.index, s.share)).id;
  bobApi = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  const card = newCard();
  const sess = await bobApi.register({ pub: bob.pub, commit: bob.commit, device: bob.device, sign: bob.registerSign, card: { tag: cardTag(card.secret), blob: await sealCardPart(card.secret, quorumParts(bob.seed).card, bob.id) } });
  assert.equal(sess.cardSet, true, "the setup card, approved by the account key in the registration's check");
});
after(async () => { await stack?.stop(); });

const forged = (aud, method, path, body, claims) => internalRequest(`${stack.upstreams[aud]}${path}`, {
  method, body, headers: { "x-humid-assertion": signRequest(stack.internalSk, { aud, method, path, body, claims }), ...(body ? { "content-type": "application/json" } : {}) },
});
const status = async (aud, method, path, body, claims) => (await forged(aud, method, path, body, claims)).status;
const opens = async () => (await api.ledger()).entries.filter((e) => e.type === "object.opened").length;

/** A step-up proof as the gateway would forward it, made with a key the attacker controls. */
function attackerProof(method, path, { device = alice.deviceId, dsaSk = makeHolder("mallory").dkeys.dsaSk, vouch } = {}) {
  const th = random(32), nonce = random(16), at = Date.now(), exp = at + 30_000, seq = 1;
  const action = actionBytes({ method, path, device, nonce, exp });
  const sig = ml_dsa87.sign(stepUpMessage(th, seq, method, path, new Uint8Array(0), at, action), dsaSk);
  return { th: b64u(th), seq, at, m: method, p: path, body: "", nonce: b64u(nonce), exp, device, sig: b64u(sig), vouch };
}

test("the gateway's key alone releases neither half of a split document", async () => {
  const before = await opens();
  const claims = { sub: alice.id, stepUp: { at: Date.now(), proof: "forged", live: true } };
  assert.equal(await status("vault", "GET", `/objects/${id}`, undefined, claims), 403, "vault: no holder proof");
  assert.equal(await status("keyshare", "GET", `/shares/${id}`, undefined, claims), 403, "keyshare: no holder proof");
  // a proof the attacker signed, but identity never vouched for that key: refused
  const fake = attackerProof("GET", `/vault/objects/${id}`, { vouch: "x.y" });
  assert.equal(await status("vault", "GET", `/objects/${id}`, undefined, { ...claims, holder: fake }), 403);
  assert.equal(await status("keyshare", "GET", `/shares/${id}`, undefined, { ...claims, holder: fake }), 403);
  // a vouch made with a key that isn't the core role's: refused
  const notCore = newStatementKeys();
  const mallory = makeHolder("mallory2");
  const vouch = signStatement(notCore.sk, "device", { account: alice.id, device: alice.deviceId, dsaPk: b64u(mallory.dkeys.dsaPk) });
  const p = attackerProof("GET", `/vault/objects/${id}`, { dsaSk: mallory.dkeys.dsaSk, vouch });
  assert.equal(await status("keyshare", "GET", `/shares/${id}`, undefined, { ...claims, holder: p }), 403);
  assert.equal(await opens(), before, "and nothing was opened");
});

test("identity's vouch for the real device doesn't help without the device's own signature", async () => {
  // the front host can ask identity to vouch for the account's real device key (a public fact)…
  const v = await forged("identity", "POST", "/internal/vouch", Buffer.from(JSON.stringify({ account: alice.id, device: alice.deviceId })), {});
  assert.equal(v.status, 200);
  const { vouch } = JSON.parse(Buffer.from(v.body).toString());
  // …but can't sign as that device: a proof under any other key fails against it
  const p = attackerProof("GET", `/vault/objects/${id}`, { vouch });
  const claims = { sub: alice.id, stepUp: { at: Date.now() }, holder: p };
  assert.equal(await status("keyshare", "GET", `/shares/${id}`, undefined, claims), 401);
  assert.equal(await status("vault", "GET", `/objects/${id}`, undefined, claims), 401);
  // and identity won't vouch for a device key the account never added (that needs the account key)
  const other = anotherDevice(alice);
  const r = await forged("identity", "POST", "/internal/vouch", Buffer.from(JSON.stringify({ account: alice.id, device: other.deviceId })), {});
  assert.equal(r.status, 404);
});

test("the vault releases an envelope only against the ledger's receipt for that open", async () => {
  // a real, live open: the holder's own proof, as the gateway forwards it, is accepted once;
  // but replayed to the vault without a ledger receipt it is refused
  const t = await api.ticket("download", id);
  let holder = null;
  const out = await api.downloadWithShare(id, { ticket: t, sign: async (m) => ({ sig: ml_dsa87.sign(m, alice.dkeys.dsaSk), interrupt: alice.interrupt, live: alice.liveKey.sign(t.live) }) });
  assert.ok(out.share && out.envelope.length > 0, "the holder opens it");
  // a fresh, valid proof made by the holder's own keys, without a receipt
  const th = random(32), nonce = random(16), at = Date.now(), exp = at + 30_000, seq = 7, path = `/vault/objects/${id}`;
  const action = actionBytes({ method: "GET", path, device: alice.deviceId, nonce, exp });
  const v = JSON.parse(Buffer.from((await forged("identity", "POST", "/internal/vouch", Buffer.from(JSON.stringify({ account: alice.id, device: alice.deviceId })), {})).body).toString());
  holder = { th: b64u(th), seq, at, m: "GET", p: path, body: "", nonce: b64u(nonce), exp, device: alice.deviceId, sig: b64u(ml_dsa87.sign(stepUpMessage(th, seq, "GET", path, new Uint8Array(0), at, action), alice.dkeys.dsaSk)), live: b64u(alice.liveKey.sign(liveMessage(th, seq, "GET", path, at, action))), vouch: v.vouch };
  const r = await forged("vault", "GET", `/objects/${id}`, undefined, { sub: alice.id, stepUp: { at }, holder });
  assert.equal(r.status, 403, "no receipt from the ledger, no envelope");
  assert.equal(JSON.parse(Buffer.from(r.body).toString()).error, "not_vouched");
});

test("a keyshare release is sealed to the phone: the gateway forwards only ciphertext", async () => {
  // everything keyshare writes back to the gateway, for a real open
  const seen = [];
  const srv = stack.keyshare.server;
  const tap = (req, res) => {
    const end = res.end.bind(res);
    res.end = (chunk, ...rest) => { if (chunk) seen.push(Buffer.from(chunk).toString()); return end(chunk, ...rest); };
  };
  srv.prependListener("request", tap);
  try {
    const { share } = await api.downloadWithShare(id, alice.stepUp);
    const hex = Buffer.from(share).toString("hex"), b64 = Buffer.from(share).toString("base64url");
    assert.ok(seen.some((x) => x.includes('"sealed"')), "keyshare answered with a sealed key");
    assert.ok(!seen.some((x) => x.includes(hex) || x.includes(b64)), "the document key never crosses the gateway in the clear");
  } finally { srv.off("request", tap); }
});

test("the gateway's key alone deletes nothing", async () => {
  const n = (await api.list()).items.length;
  assert.ok(n > 0);
  // the Check-in sweep route: a bare gateway assertion, or the old {keep, before} body, is refused
  for (const body of [{ keep: [], before: Date.now() }, { token: "x.y" }, { token: signStatement(newStatementKeys().sk, "erased", { owner: alice.id, erasedAt: Date.now(), keep: [] }) }]) {
    assert.equal(await status("vault", "DELETE", "/internal/objects", Buffer.from(JSON.stringify(body)), { sub: alice.id }), 403);
  }
  // keyshare's real token for another account doesn't delete this one
  const tok = signStatement(stack.keysKeys.sk, "erased", { owner: "hid_" + "b".repeat(40), erasedAt: Date.now(), keep: [] });
  assert.equal(await status("vault", "DELETE", "/internal/objects", Buffer.from(JSON.stringify({ token: tok })), { sub: alice.id }), 403);
  // the step-up deletes, with a forged step-up claim and no holder proof
  const su = { sub: alice.id, stepUp: { at: Date.now() } };
  assert.equal(await status("vault", "DELETE", `/objects/${id}`, undefined, su), 403);
  assert.equal(await status("vault", "DELETE", "/objects", undefined, su), 403);
  assert.equal(await status("keyshare", "DELETE", `/shares/${id}`, undefined, su), 403);
  assert.equal(await status("keyshare", "DELETE", "/shares", undefined, su), 403);
  assert.equal(await status("identity", "DELETE", "/me", undefined, su), 403);
  // a duress erase needs the duress sign-in itself, and lifting a lockdown the holder's own check
  assert.equal(await status("keyshare", "POST", "/internal/checkin/erase", undefined, { sub: alice.id }), 403);
  assert.equal(await status("identity", "POST", `/internal/lockdown/${alice.id}/clear`, undefined, su), 403);
  for (const p of ["/internal/checkin/check", "/internal/checkin/disarm", "/internal/checkin/arm"]) {
    assert.equal(await status("keyshare", "POST", p, Buffer.from("{}"), su), 403, p);
  }
  // and a device enrolled more than moments ago can't be revoked through the enrolment-rollback route
  const db = new DatabaseSync(join(stack.root, "identity", "identity.db"));
  try { db.prepare("UPDATE device_keys SET enrolled_at = ? WHERE id = ?").run(new Date(Date.now() - 3_600_000).toISOString(), alice.deviceId); } finally { db.close(); }
  const rv = await forged("identity", "POST", `/internal/devices/${alice.deviceId}/revoke`, Buffer.from(JSON.stringify({ account: alice.id })), {});
  assert.equal(rv.status, 200);
  assert.equal((await api.list()).items.length, n, "every document is still there");
  const me = await api.me();
  assert.equal(me.devices.length, 1);
});

/* ---------------- the recovery service ---------------- */

const recoveryRows = () => {
  const db = new DatabaseSync(join(stack.root, "recovery", "recovery.db"), { readOnly: true });
  try {
    return {
      cards: db.prepare("SELECT account, tag FROM cards ORDER BY account").all().map((r) => ({ ...r })),
      settings: db.prepare("SELECT account, duress_alert FROM settings ORDER BY account").all().map((r) => ({ ...r })),
      guardians: db.prepare("SELECT COUNT(*) n FROM guardian_sets").get().n,
      keys: db.prepare("SELECT COUNT(*) n FROM seckeys").get().n,
    };
  } finally { db.close(); }
};
const vouchFor = async (h) => JSON.parse(Buffer.from((await forged("identity", "POST", "/internal/vouch", Buffer.from(JSON.stringify({ account: h.id, device: h.deviceId })), {})).body).toString()).vouch;

test("the gateway's key alone changes no recovery material, approves no link and vouches for no recovery", async () => {
  const before = recoveryRows();
  const tag = cardTag(newCard().secret);
  const j = (o) => Buffer.from(JSON.stringify(o));
  const routes = [
    ["PUT", "/card", j({ tag, blob: b64u(random(12 + 65 + 16)), epoch: 1 })],
    ["DELETE", "/card"],
    ["PUT", "/contacts", j({ threshold: 2, guardians: [], scheme: "quorum", epoch: 1 })],
    ["DELETE", "/contacts"],
    ["PUT", "/anchor", j({ sealedPart: b64u(random(64)), epoch: 1 })],
    ["DELETE", "/anchor"],
    ["POST", "/keys", j({ tag, blob: b64u(random(16)), epoch: 1 })],
    ["DELETE", `/keys/${"a".repeat(32)}`],
    ["DELETE", "/keys"],
    ["PUT", "/settings", j({ duressAlert: true })],
    ["POST", `/links/${"A".repeat(12)}/approve`, j({})],
    ["POST", `/help/${"A".repeat(16)}`, j({ owner: alice.id, envelope: "" })],
    ["POST", `/alerts/${"a".repeat(16)}/cancel`],
    ["POST", `/station/requests/${"A".repeat(16)}/verify`, j({ checks: { document: true, face: true, present: true } })],
    ["DELETE", "/escrow"],
  ];
  const vouch = await vouchFor(bob);
  for (const [m, p, body] of routes) {
    const claims = { sub: bob.id, dsaFp: "x", kemFp: "x", stepUp: { at: Date.now(), proof: "forged", live: true } };
    // no holder proof at all
    assert.equal(await status("recovery", m, p, body, claims), 403, `${m} ${p}: no proof`);
    // a proof made with another key, under identity's real vouch for bob's device
    const fake = attackerProof(m, `/recovery${p}`, { device: bob.deviceId, vouch });
    const st = await status("recovery", m, p, body, { ...claims, holder: fake });
    assert.ok(st === 401 || st === 403, `${m} ${p}: forged proof got ${st}`);
  }
  assert.deepEqual(recoveryRows(), before, "nothing changed");
});

test("a real approval from the holder can't be turned into a different change", async () => {
  // bob's own device signs PUT /recovery/settings { duressAlert: false }; the gateway sends { duressAlert: true }
  const p = "/recovery/settings", signed = Buffer.from(JSON.stringify({ duressAlert: false })), sent = Buffer.from(JSON.stringify({ duressAlert: true }));
  const th = random(32), nonce = random(16), at = Date.now(), exp = at + 30_000, seq = 3;
  const action = actionBytes({ method: "PUT", path: p, device: bob.deviceId, nonce, exp });
  const holder = { th: b64u(th), seq, at, m: "PUT", p, nonce: b64u(nonce), exp, device: bob.deviceId,
    sig: b64u(ml_dsa87.sign(stepUpMessage(th, seq, "PUT", p, signed, at, action), bob.dkeys.dsaSk)),
    live: b64u(bob.liveKey.sign(liveMessage(th, seq, "PUT", p, at, action))), vouch: await vouchFor(bob) };
  const claims = { sub: bob.id, stepUp: { at }, holder };
  assert.equal(await status("recovery", "PUT", "/settings", sent, claims), 401, "the body it signed, or nothing");
  assert.equal(recoveryRows().settings.length, 0);
  // the body it did sign goes through, once
  assert.equal(await status("recovery", "PUT", "/settings", signed, claims), 200);
  assert.equal(await status("recovery", "PUT", "/settings", signed, claims), 403, "used once");
});

test("a setup card needs the account key's own signature in the registration and identity's word that the account is new", async () => {
  const before = recoveryRows();
  const tag = cardTag(newCard().secret), blob = random(12 + 65 + 16);
  const body = Buffer.from(JSON.stringify({ tag, blob: b64u(blob) }));
  const notCore = newStatementKeys();
  for (const setupCard of [
    { created: "x.y", dsaPk: b64u(alice.pub.dsaPk), th: b64u(random(32)), sig: b64u(random(4627)) },
    { created: signStatement(notCore.sk, "created", { account: alice.id, th: "t" }), dsaPk: b64u(alice.pub.dsaPk), th: "t", sig: b64u(random(4627)) },
  ]) {
    assert.equal(await status("recovery", "PUT", "/card", body, { sub: alice.id, stepUp: { at: Date.now() }, setupCard }), 403);
  }
  assert.deepEqual(recoveryRows(), before);
});
