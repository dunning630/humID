// End to end: split keys, against the real services. The threat: spyware with kernel
// access copies the account keys out of a phone's memory the moment its owner passes a
// biometric check. These tests show what those keys are then worth.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { splitUnwrap, isSplit } from "@humid/crypto";
import { makeHolder, sealFor, sealSplitFor } from "./holder.js";

let stack, alice, api, splitId, plainId, share;
before(async () => {
  stack = await startStack({ shareReleasesPerHour: 6 });
  alice = makeHolder("alice-split");
  api = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  await api.register({ pub: alice.pub, commit: alice.commit, device: alice.device, sign: alice.registerSign });
});
after(async () => { await stack?.stop(); });

const dump = (db) => JSON.stringify(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()
  .map(({ name }) => db.prepare(`SELECT * FROM "${name}"`).all()), (k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v));
const hex = (b) => Buffer.from(b).toString("hex");

test("the server says it keeps split keys, so the app splits new documents", async () => {
  assert.equal((await api.server()).policy.splitKeys, true);
});

test("seal a split document: the envelope goes to the vault, its key to keyshare", async () => {
  const s = await sealSplitFor(alice, "will.txt", "Alice's will: the walnut desk goes to Sam.");
  share = s.share.slice();
  splitId = (await api.upload(s.envelope, s.index, s.share)).id;
  const p = await sealFor(alice, "old.txt", "sealed before split keys");
  plainId = (await api.upload(p.envelope, p.index)).id;
  const ledger = await api.ledger();
  assert.ok(ledger.entries.some((e) => e.type === "object.sealed" && e.detail.id === splitId && e.detail.split === true));
});

test("opening needs both keys, under ONE live check", async () => {
  const { envelope, share: got } = await api.downloadWithShare(splitId, alice.stepUp);
  assert.deepEqual(got, share);
  const outer = await alice.S.open(envelope, alice.keys);
  assert.ok(isSplit(outer.meta));
  assert.equal(outer.meta.name, "sealed", "the real name isn't in the outer layer either");
  const doc = await splitUnwrap(outer.bytes, got);
  assert.equal(new TextDecoder().decode(doc.bytes), "Alice's will: the walnut desk goes to Sam.");
  assert.equal(doc.meta.name, "will.txt");
  const ev = (await api.ledger()).entries.find((e) => e.type === "object.opened" && e.detail.id === splitId);
  assert.equal(ev.detail.split, true);
});

test("documents sealed before split keys still open", async () => {
  const { envelope, share: none } = await api.downloadWithShare(plainId, alice.stepUp);
  assert.equal(none, null);
  assert.equal(new TextDecoder().decode((await alice.S.open(envelope, alice.keys)).bytes), "sealed before split keys");
});

test("THE ATTACK: stolen account keys + a full copy of the vault open nothing", async () => {
  // everything the vault holds: its database and every blob on disk
  const vdir = join(stack.root, "vault");
  const vdb = new DatabaseSync(join(vdir, "vault.db"), { readOnly: true });
  const vaultText = dump(vdb);
  vdb.close();
  const blobs = readdirSync(join(vdir, "blobs"), { recursive: true }).map((f) => join(vdir, "blobs", String(f))).filter((f) => { try { return readFileSync(f).length > 0; } catch { return false; } });
  assert.ok(blobs.length >= 2);
  assert.ok(!vaultText.includes(hex(share)) && !blobs.some((f) => readFileSync(f).toString("hex").includes(hex(share))), "the vault never sees a document key");
  // the attacker has the account keys (alice.keys) and every envelope: each opens to a sealed inner layer only
  let opened = 0;
  for (const f of blobs) {
    let out;
    try { out = await alice.S.open(new Uint8Array(readFileSync(f)), alice.keys); } catch { continue; }
    if (!isSplit(out.meta)) continue; // the old, unsplit document: opens, as before
    opened++;
    assert.ok(!Buffer.from(out.bytes).toString().includes("walnut"));
    await assert.rejects(splitUnwrap(out.bytes, new Uint8Array(32)), (e) => e.code === "share_mismatch");
    await assert.rejects(splitUnwrap(out.bytes, null), (e) => e.code === "share_missing");
  }
  assert.equal(opened, 1);
});

test("keyshare holds only encrypted keys: no envelopes, names or account keys, and not the key in the clear", () => {
  const db = new DatabaseSync(join(stack.root, "keyshare", "keyshare.db"), { readOnly: true });
  const text = dump(db);
  db.close();
  assert.ok(!text.includes(hex(share)), "stored encrypted under share-key.bin");
  assert.ok(!/will\.txt|walnut|HUMID-SPLIT/.test(text));
  assert.ok(!text.includes(hex(alice.pub.dsaPk).slice(0, 64)) && !text.includes(hex(alice.pub.kemPk).slice(0, 64)));
});

test("a key is released only with a live step-up for that document", async () => {
  // no step-up: the vault refuses before keyshare is even asked
  await assert.rejects(api.downloadWithShare(splitId), (e) => e.code === "step_up_required");
  // keyshare itself refuses a request that carries no step-up
  const { signRequest } = await import("@humid/svc");
  const claims = (extra = {}) => signRequest(stack.internalSk, { aud: "keyshare", method: "GET", path: `/shares/${splitId}`, claims: { sub: alice.id, ...extra } });
  let r = await fetch(`${stack.upstreams.keyshare}/shares/${splitId}`, { headers: { "x-humid-assertion": claims() } });
  assert.equal(r.status, 403);
  // a stale step-up
  r = await fetch(`${stack.upstreams.keyshare}/shares/${splitId}`, { headers: { "x-humid-assertion": claims({ stepUp: { at: Date.now() - 120_000 } }) } });
  assert.equal(r.status, 403);
  // someone else's account
  r = await fetch(`${stack.upstreams.keyshare}/shares/${splitId}`, { headers: { "x-humid-assertion": claims({ sub: "hid_" + "1".repeat(40), stepUp: { at: Date.now() } }) } });
  assert.equal(r.status, 404);
});

test("a hijacked phone can't drain the vault: releases are capped per hour", async () => {
  // the stack allows 6 an hour; 1 is used above
  for (let i = 0; i < 5; i++) await api.downloadWithShare(splitId, alice.stepUp);
  await assert.rejects(api.downloadWithShare(splitId, alice.stepUp), (e) => e.status === 429 && e.code === "share_rate_limited");
  // and the refused open was never released or recorded as opened
  const opens = (await api.ledger()).entries.filter((e) => e.type === "object.opened" && e.detail.id === splitId).length;
  assert.equal(opens, 6);
});

test("if the key can't be stored, the upload is undone: no document without its key", async () => {
  const s = await sealSplitFor(alice, "orphan.txt", "should not survive");
  const before = (await api.list()).items.length;
  const real = stack.upstreams.keyshare;
  stack.upstreams.keyshare = "http://127.0.0.1:9"; // keyshare unreachable
  try {
    await assert.rejects(api.upload(s.envelope, s.index, s.share), (e) => e.code === "keyshare_unavailable");
  } finally { stack.upstreams.keyshare = real; }
  assert.equal((await api.list()).items.length, before);
});

test("deleting a document deletes its key; closing the account deletes them all", async () => {
  const s = await sealSplitFor(alice, "temp.txt", "temporary");
  const id = (await api.upload(s.envelope, s.index, s.share)).id;
  await api.remove(id, alice.stepUp);
  const count = () => { const db = new DatabaseSync(join(stack.root, "keyshare", "keyshare.db"), { readOnly: true }); const n = db.prepare("SELECT COUNT(*) AS n FROM shares").get().n; db.close(); return n; };
  assert.equal(count(), 1, "only the will's key is left");
  await api.closeIdentity(alice.stepUp);
  assert.equal(count(), 0);
});
