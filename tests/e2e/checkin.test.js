// End to end: Check-in (docs/CHECKIN.md), against the real services. A holder arms a timer
// before a high-stakes situation; a missed check-in locks the vault, and the end of the grace
// window (or a duress signal, or a keyshare restart) erases it for good: the keys that open
// its documents are destroyed, so even a backup of the server made since arming opens nothing.
// keyshare's monotonic clock is the test's to move; everything else runs on real time.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hkdfSync, createDecipheriv } from "node:crypto";
import { startStack } from "./stack.js";
import { HumidApi } from "@humid/api";
import { splitUnwrap } from "@humid/crypto";
import { makeHolder, sealFor, sealSplitFor } from "./holder.js";
import { createLedger } from "../../services/ledger/src/server.js";
import { signRequestAssertion } from "@humid/svc";
import { CHECKIN_WINDOWS_MS, CHECKIN_GRACE_MS } from "../../services/keyshare/src/server.js";

const H = 3_600_000, MIN = 60_000;
const SETTINGS = { windowMs: 2 * H, maxWindowMs: 8 * H, graceMs: 15 * MIN };
let mono = 1_000_000; // keyshare's clock
let stack;

before(async () => {
  stack = await startStack({ checkin: "on", checkinSweepMs: 0, keyshareClock: { mono: () => mono, tickMs: 0 } });
});
after(async () => { await stack?.stop(); });

/** A holder with a signed-in session. */
async function holder(label) {
  const h = makeHolder(label);
  const api = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  await api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign });
  return { h, api };
}
/** Another session for the same holder: an unlock, ordinary or with the duress gesture (signed into the sign-in). */
async function unlock(h, { duress = false } = {}) {
  const api = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  await api.login({ id: h.id, device: h.deviceId, sign: h.unlockSign(duress ? 1 : 0) });
  return api;
}
const split = async ({ h, api }, name, text) => {
  const s = await sealSplitFor(h, name, text);
  return (await api.upload(s.envelope, s.index, s.share)).id;
};
const openText = async ({ h, api }, id) => {
  const { envelope, share } = await api.downloadWithShare(id, h.stepUp);
  const outer = await h.S.open(envelope, h.keys);
  return new TextDecoder().decode((await splitUnwrap(outer.bytes, share)).bytes);
};
const events = async (api) => (await api.ledger()).entries.map((e) => e.type);
const rows = (owner) => {
  const db = new DatabaseSync(join(stack.root, "keyshare", "keyshare.db"), { readOnly: true });
  try { return db.prepare("SELECT object, fused FROM shares WHERE owner = ?").all(owner); } finally { db.close(); }
};
const vaultIds = async (api) => (await api.list()).items.map((i) => i.id);
const settle = async () => { stack.keyshare.tick(); await stack.gateway.sweepCheckin(); };

test("the server says it offers Check-in, with the settings keyshare accepts", async () => {
  const p = (await new HumidApi({ baseUrl: stack.baseUrl }).server()).policy;
  assert.deepEqual(p.checkin.windowsH.map((h) => h * H), CHECKIN_WINDOWS_MS);
  assert.deepEqual(p.checkin.graceMin.map((m) => m * MIN), CHECKIN_GRACE_MS);
});

test("off by default: no hint, no routes", async () => {
  const off = await startStack();
  try {
    const api = new HumidApi({ baseUrl: off.baseUrl, pinnedKid: off.gateway.htp.kid });
    assert.equal((await api.server()).policy.checkin, null);
    const h = makeHolder("check-in-off");
    await api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign });
    await assert.rejects(api.checkin(), (e) => e.status === 404);
  } finally { await off.stop(); }
});

test("arming needs a live check, and every document split so its erase can be final", async () => {
  const a = await holder("checkin-alice");
  assert.equal((await a.api.checkin()).state, "off");
  await assert.rejects(a.api.armCheckin(SETTINGS), (e) => e.code === "step_up_required" || e.status === 403);

  const p = await sealFor(a.h, "old.txt", "sealed before split keys");
  const old = (await a.api.upload(p.envelope, p.index)).id;
  await assert.rejects(a.api.armCheckin(SETTINGS, a.h.stepUp), (e) => e.code === "unsplit_items" && e.details.items.length === 1 && e.details.items[0] === old);
  await a.api.remove(old, a.h.stepUp);

  await assert.rejects(a.api.armCheckin({ ...SETTINGS, windowMs: 3 * H }, a.h.stepUp), (e) => e.code === "bad_checkin");
  await assert.rejects(a.api.armCheckin({ ...SETTINGS, maxWindowMs: H }, a.h.stepUp), (e) => e.code === "bad_checkin");

  const doc = await split(a, "will.txt", "The walnut desk goes to Sam.");
  const t = Date.now();
  const st = await a.api.armCheckin(SETTINGS, a.h.stepUp);
  assert.equal(st.state, "armed");
  assert.ok(Math.abs(st.deadline - (t + 2 * H)) < 5_000);
  assert.equal(st.erasesAt - st.deadline, 15 * MIN);
  assert.deepEqual(rows(a.h.id).map((r) => r.fused), [1], "its key is now under the fuse key");
  assert.equal(await openText(a, doc), "The walnut desk goes to Sam.", "documents open as usual while armed");
  const ev = (await a.api.ledger()).entries.find((e) => e.type === "checkin.armed");
  assert.equal(ev.detail.windowMs, 2 * H);
});

test("a missed check-in locks the vault; checking in during grace opens it again", async () => {
  const a = await holder("checkin-bob");
  const doc = await split(a, "notes.txt", "meet at the north gate");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  mono += 2 * H + 1;
  const st = await a.api.checkin();
  assert.equal(st.state, "locked");
  await assert.rejects(openText(a, doc), (e) => e.status === 423 && e.code === "checkin_missed");
  const s = await sealSplitFor(a.h, "new.txt", "sealed while locked");
  await assert.rejects(a.api.upload(s.envelope, s.index, s.share), (e) => e.status === 423);
  assert.deepEqual(await vaultIds(a.api), [doc], "the refused upload left nothing behind");

  const back = await a.api.checkIn({}, a.h.stepUp);
  assert.equal(back.state, "armed");
  assert.equal(await openText(a, doc), "meet at the north gate");
  assert.ok(!(await events(a.api)).some((t) => t.startsWith("checkin.") && t !== "checkin.armed"), "check-ins aren't in the ledger");
});

test("a longer window for the night, never past the armed maximum", async () => {
  const a = await holder("checkin-night");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  const t = Date.now();
  const st = await a.api.checkIn({ nextWindowMs: 8 * H }, a.h.stepUp);
  assert.ok(Math.abs(st.deadline - (t + 8 * H)) < 5_000);
  await assert.rejects(a.api.checkIn({ nextWindowMs: 24 * H }, a.h.stepUp), (e) => e.code === "bad_checkin");
  mono += 7 * H;
  assert.equal((await a.api.checkin()).state, "armed", "the night window holds");
  await a.api.checkIn({}, a.h.stepUp); // back to the usual 2 hours
  mono += 2 * H + 15 * MIN + 1;
  await settle();
  assert.equal((await a.api.checkin()).state, "erased");
});

test("THE ERASE: past the grace window the keys are destroyed, and a backup made since arming opens nothing", async () => {
  const a = await holder("checkin-carol");
  const doc = await split(a, "deed.txt", "Deed to the cabin on Fox River");
  const decoy = await split(a, "grocery.txt", "eggs, flour, coffee");
  // a backup of keyshare from BEFORE arming (see the limit below)
  const before = mkdtempSync(join(tmpdir(), "ks-before-"));
  cpSync(join(stack.root, "keyshare"), before, { recursive: true });

  await a.api.armCheckin({ ...SETTINGS, keep: [decoy] }, a.h.stepUp);
  assert.deepEqual(Object.fromEntries(rows(a.h.id).map((r) => [r.object, r.fused])), { [doc]: 1, [decoy]: 0 }, "the decoy stays out of the fuse");
  // last night's backup, made while armed: the database and the key file, everything on disk
  const backup = mkdtempSync(join(tmpdir(), "ks-backup-"));
  cpSync(join(stack.root, "keyshare"), backup, { recursive: true });

  mono += 2 * H + 15 * MIN + 1;
  await settle();
  assert.equal((await a.api.checkin()).state, "erased");
  assert.deepEqual(rows(a.h.id).map((r) => r.object), [decoy], "only the decoy's key is left");
  assert.deepEqual(await vaultIds(a.api), [decoy], "the vault dropped the erased envelopes");
  assert.equal(await openText(a, decoy), "eggs, flour, coffee", "a forced unlock still finds the decoy");
  const erased = (await a.api.ledger()).entries.find((e) => e.type === "checkin.erased");
  assert.equal(erased.detail.count, 1);

  // An attacker with the backup made while armed, share-key.bin included, and the account keys:
  const opened = tryShares(backup, a.h.id);
  assert.equal(opened.fused, 1);
  assert.equal(opened.ok, 1, "only the decoy's key opens");
  // Documented limit (docs/CHECKIN.md): a backup from BEFORE arming still holds the keys
  // of documents sealed before arming.
  assert.equal(tryShares(before, a.h.id).ok, 2);
  rmSync(backup, { recursive: true, force: true });
  rmSync(before, { recursive: true, force: true });

  // the HumID itself is untouched: new documents work
  const fresh = await split(a, "after.txt", "a new start");
  assert.equal(await openText(a, fresh), "a new start");
});

test("a duress unlock while armed erases at once, and the duress session still looks calm", async () => {
  const a = await holder("checkin-dan");
  const doc = await split(a, "passport.txt", "P<UTO DAN");
  const decoy = await split(a, "library.txt", "library card 4417");
  await a.api.armCheckin({ ...SETTINGS, keep: [decoy] }, a.h.stepUp);
  const real = await a.api.checkIn({}, a.h.stepUp);

  const forced = await unlock(a.h, { duress: true });
  await new Promise((r) => setTimeout(r, 300)); // the duress work runs after the reply
  assert.deepEqual(rows(a.h.id).map((r) => r.object), [decoy], "the fuse key is gone");

  const shown = await forced.checkin();
  assert.equal(shown.state, "armed");
  assert.deepEqual(Object.keys(shown), Object.keys(real), "the same fields, in the same order");
  const checked = await forced.checkIn({}, a.h.stepUp);
  assert.deepEqual(Object.keys(checked), Object.keys(real));
  assert.ok(checked.deadline > Date.now() + H);
  assert.equal(await openText({ h: a.h, api: forced }, decoy), "library card 4417", "the decoy opens");

  const safe = await unlock(a.h);
  assert.equal((await safe.checkin()).state, "erased");
  assert.ok(!(await vaultIds(safe)).includes(doc));
  const types = await events(safe);
  assert.ok(types.includes("checkin.erased") && types.includes("duress.signaled"));
});

test("PC-01: a bare presence request from a signed-in session can't erase or lock down an armed vault", async () => {
  const a = await holder("checkin-mallory-target");
  const doc = await split(a, "will.txt", "the real will");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  // Malware riding a live session (no biometric) sends the old duress report.
  const riding = await unlock(a.h);
  assert.deepEqual(await riding.presence(true), { ok: true }, "same answer as ever");
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(rows(a.h.id).length, 1, "the fuse key is still there");
  assert.equal(await openText(a, doc), "the real will");
  assert.equal((await a.api.duressStatus()).lockdown, false, "no lockdown either");
  assert.ok(!(await events(a.api)).includes("duress.signaled"));
});

test("PC-01: a duress flag the device key didn't sign is refused like any bad sign-in", async () => {
  const a = await holder("checkin-forged-flag");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  const api = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  // The device key signed d = 0; the request claims d = 1.
  const lying = async (m, ctx) => ({ ...(await a.h.unlockSign(0)(m, ctx)), d: 1 });
  await assert.rejects(api.login({ id: a.h.id, device: a.h.deviceId, sign: lying }), (e) => e.code === "bad_proof");
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(rows(a.h.id).length, 0, "nothing was split yet, and nothing was erased");
  assert.equal((await a.api.checkin()).state, "armed");
});

test("turning it off puts every key back; a later restart erases nothing", async () => {
  const a = await holder("checkin-erin");
  const doc = await split(a, "keys.txt", "spare key under the planter");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  assert.deepEqual((await a.api.disarmCheckin(a.h.stepUp)).state, "off");
  assert.deepEqual(rows(a.h.id).map((r) => r.fused), [0]);
  assert.ok((await events(a.api)).includes("checkin.disarmed"));
  await stack.restartKeyshare();
  await settle();
  assert.equal(await openText(a, doc), "spare key under the planter");
  assert.equal((await a.api.checkin()).state, "off");
});

test("a keyshare restart while armed erases the vault: its fuse keys lived in memory only", async () => {
  const a = await holder("checkin-fay");
  await split(a, "map.txt", "the safe house is on Elm");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  await stack.restartKeyshare();
  await settle();
  assert.equal((await a.api.checkin()).state, "erased");
  assert.deepEqual(await vaultIds(a.api), []);
});

test("an erase never waits for the ledger: the keys go now, the entry when it's back", async () => {
  const a = await holder("checkin-gus");
  await split(a, "ledger.txt", "accounts");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  const port = stack.ledger.server.address().port;
  await stack.ledger.stop();
  mono += 2 * H + 15 * MIN + 1;
  stack.keyshare.tick();
  assert.equal(rows(a.h.id).length, 0, "keys destroyed with the ledger down");
  await stack.gateway.sweepCheckin(); // can't write the entry yet: tries again later
  stack.ledger = createLedger({ port, dataDir: join(stack.root, "ledger"), internalPk: stack.internalPk });
  await stack.ledger.start();
  await stack.gateway.sweepCheckin();
  const erased = (await a.api.ledger()).entries.filter((e) => e.type === "checkin.erased");
  assert.equal(erased.length, 1);
  assert.equal(erased[0].detail.count, 1, "the count is the keys destroyed, not what a retried sweep found left");
});

test("one ledger entry per erase, even if a sweep's last step is lost", async () => {
  const a = await holder("checkin-hal");
  await split(a, "one.txt", "first");
  await split(a, "two.txt", "second");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  mono += 2 * H + 15 * MIN + 1;
  await settle();
  // as if keyshare never heard "cleaned": the next sweep sees the same erase again
  const db = new DatabaseSync(join(stack.root, "keyshare", "keyshare.db"));
  try { db.prepare("UPDATE checkin SET cleaned = 0 WHERE owner = ?").run(a.h.id); } finally { db.close(); }
  await stack.gateway.sweepCheckin();
  const erased = (await a.api.ledger()).entries.filter((e) => e.type === "checkin.erased");
  assert.equal(erased.length, 1, "not written twice");
  assert.equal(erased[0].detail.count, 2);
});

test("a sweep never takes a document uploaded after the erase", async () => {
  const a = await holder("checkin-ivy");
  const old = await split(a, "before.txt", "sealed while armed");
  await a.api.armCheckin(SETTINGS, a.h.stepUp);
  mono += 2 * H + 15 * MIN + 1;
  stack.keyshare.tick(); // erased; the sweep hasn't run yet
  const erasedAt = (await a.api.checkin()).erasedAt;
  const fresh = await split(a, "after.txt", "sealed after the erase");
  // the race: a sweep that listed what to keep before this upload's key reached keyshare
  const body = JSON.stringify({ keep: [], before: erasedAt });
  const assertion = signRequestAssertion(stack.internalSk, { iss: "gateway", aud: "vault", rid: crypto.randomUUID(), sub: a.h.id }, { method: "DELETE", path: "/internal/objects", body: Buffer.from(body) });
  const res = await fetch(`${stack.upstreams.vault}/internal/objects`, { method: "DELETE", headers: { "x-humid-assertion": assertion, "content-type": "application/json" }, body });
  assert.equal(res.status, 200);
  assert.deepEqual(await vaultIds(a.api), [fresh], "the erased envelope went; the new one stayed");
  assert.ok(!(await vaultIds(a.api)).includes(old));
  assert.equal(await openText(a, fresh), "sealed after the erase");
  await stack.gateway.sweepCheckin();
});

/** Open every share an attacker could from a copy of keyshare's data: { fused, ok }. */
function tryShares(dir, owner) {
  const master = Buffer.from(hkdfSync("sha3-256", readFileSync(join(dir, "share-key.bin")), Buffer.alloc(0), "HUMID-KEYSHARE-v1 at-rest", 32));
  const db = new DatabaseSync(join(dir, "keyshare.db"), { readOnly: true });
  const all = db.prepare("SELECT * FROM shares WHERE owner = ?").all(owner);
  db.close();
  let ok = 0;
  for (const r of all) {
    try {
      const d = createDecipheriv("aes-256-gcm", master, r.iv).setAAD(Buffer.from(`HUMID-KEYSHARE-v1\0${owner}\0${r.object}`));
      d.setAuthTag(Buffer.from(r.ct).subarray(-16));
      Buffer.concat([d.update(Buffer.from(r.ct).subarray(0, -16)), d.final()]);
      ok++;
    } catch { /* a fused share: needs the fuse key, which never touched disk */ }
  }
  return { fused: all.filter((r) => r.fused).length, ok };
}
