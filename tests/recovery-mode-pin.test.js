// V74-01 / V74-02 regressions: the recovery mode and its epoch can't be quietly deleted, rolled
// back or forked by the server. Statements are chained (each names the previous one's hash);
// the phone pins the newest it has checked in its sealed identity record and treats anything
// less as tampering (holder-only, no pieces made); identity is the source of truth and the
// gateway brings the recovery service back to it; the recovery service keeps a high-water mark
// so a deleted or older row reads as holder-only, not "from before modes". Real services, the
// real app modules (enroll, loadRecoveryMode, partOf), as the reviewer's PoCs drove them.
import "fake-indexeddb/auto";
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { HumidApi } from "@humid/api";
import { openStore } from "@humid/store";
import { ml_dsa87, random, b64u } from "@humid/htp";
import { suite } from "@humid/crypto";
import { signRequest } from "@humid/svc";
import { recoveryModeMessage, recoveryModeHash, RECMODE_GENESIS, quorumParts, newCard, cardTag, sealCardPart } from "@humid/recovery";
import { startStack } from "./e2e/stack.js";
import { liveKey, androidChain } from "./support/pki.js";
import { ROOTS, makeHolder, sealBytes } from "./e2e/holder.js";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { enroll } from "../apps/mobile/src/core/enroll.js";
import { loadRecoveryMode, judgeMode, signMode, mayMakePieces } from "../apps/mobile/src/core/recmode.js";
import { partOf } from "../apps/mobile/src/core/recovery.js";

const Suite = suite();
let stack;
before(async () => { stack = await startStack(); });
after(async () => { await stack?.stop(); });

function fakeHardwareGate() {
  const lk = liveKey();
  const secret = random(32);
  const rec = (purpose) => ({ method: "android-keystore-biometric", assurance: "hardware", purpose, at: new Date().toISOString() });
  return {
    id: "native", needsHold: false, lk, secret,
    async enroll({ challenge, attest }) {
      return { handle: { id: "h1" }, bindingId: b64u(random(16)).replace(/-/g, "+").replace(/_/g, "/"), secret: secret.slice(), interrupt: rec("enroll"),
        live: { pub: lk.pub, sig: lk.sign(challenge), attestation: { kind: "android-key", chain: androidChain({ root: ROOTS.android, challenge: attest, liveKey: lk }).chain } } };
    },
    async release(_h, { purpose, challenge }) { return { secret: secret.slice(), interrupt: rec(purpose), live: { sig: lk.sign(challenge) } }; },
    async forget() {},
  };
}
async function newPhone(mode) {
  R.api = new HumidApi({ baseUrl: stack.baseUrl });
  R.store = await openStore();
  await R.store.clearIdentity?.();
  S.ledger.value = null;
  S.server.value = { ...(await R.api.server()) };
  S.hwGate.value = { adapter: fakeHardwareGate(), probe: { available: true, proof: true, method: "android-keystore-biometric", assurance: "hardware", label: "fingerprint" } };
  assert.equal(await enroll(false, { soleBiometric: true, recoveryMode: mode }), true);
  return S.identity.value.server.id;
}
const recDb = (fn) => { const d = new DatabaseSync(`${stack.root}/recovery/recovery.db`); try { return fn(d); } finally { d.close(); } };
const idDb = (fn) => { const d = new DatabaseSync(`${stack.root}/identity/identity.db`); try { return fn(d); } finally { d.close(); } };
/** The recovery service's own view, straight from it (no gateway, so no reconciling). */
const direct = (acct) => fetch(`${stack.upstreams.recovery}/internal/recovery-mode/${acct}`, { headers: { "x-humid-assertion": signRequest(stack.internalSk, { aud: "recovery", method: "GET", path: `/internal/recovery-mode/${acct}` }) } }).then((r) => r.json());

test("V74-01: the operator deletes the recovery service's mode row; the phone and the server still say holder-only", async () => {
  const acct = await newPhone("holder-only");
  assert.deepEqual([(await loadRecoveryMode()).mode, S.recoveryMode.value.trusted], ["holder-only", true]);
  assert.equal(S.identity.value.modePin.version, 1, "pinned at setup");

  recDb((d) => d.prepare("DELETE FROM modes WHERE account = ?").run(acct));
  assert.deepEqual([(await direct(acct)).mode, (await direct(acct)).broken], ["holder-only", true], "the high-water mark remembers: a missing row isn't 'from before modes'");
  // Deleted from both of the recovery service's tables: the gateway restores identity's statement.
  recDb((d) => { d.prepare("DELETE FROM modes WHERE account = ?").run(acct); d.prepare("DELETE FROM mode_marks WHERE account = ?").run(acct); });
  const m = await loadRecoveryMode();
  assert.deepEqual([m.mode, m.trusted], ["holder-only", true], "healed from identity, never hardened");
  assert.equal((await direct(acct)).mode, "holder-only");
  // Deleted in identity AND the recovery service: the phone's pin catches it.
  recDb((d) => { d.prepare("DELETE FROM modes WHERE account = ?").run(acct); d.prepare("DELETE FROM mode_marks WHERE account = ?").run(acct); });
  idDb((d) => d.prepare("UPDATE identities SET recovery_mode = NULL, recovery_mode_version = NULL, recovery_mode_epoch = NULL, recovery_mode_sig = NULL, recovery_mode_prev = NULL WHERE id = ?").run(acct));
  const gone = await loadRecoveryMode();
  assert.deepEqual([gone.mode, gone.trusted, gone.reason], ["holder-only", false, "missing"], "a phone that pinned a mode never accepts 'none'");
  assert.equal(mayMakePieces(), false);
  assert.throws(() => partOf(random(64), "card"), (e) => e.code === "holder_only", "and makes no recovery piece on the server's say-so");
});

test("V74-02: the operator puts an older genuine statement back; the phone refuses it and the server heals", async () => {
  const acct = await newPhone("hardened");
  const { keys, stepUp } = await phoneKeys();
  const v1 = recDb((d) => d.prepare("SELECT * FROM modes WHERE account = ?").get(acct));
  // "Make new recovery pieces": v2, epoch 2, chained to v1 (signed as the app does).
  const st2 = signMode(acct, keys.dsaSk, "hardened", 2, 2, { mode: "hardened", version: 1, epoch: 1, prev: RECMODE_GENESIS });
  const api = R.api;
  await api.setRecoveryMode(st2, stepUp);
  assert.equal((await loadRecoveryMode()).epoch, 2);
  assert.equal(S.identity.value.modePin.version, 2, "the phone pinned v2");

  // Operator: the old genuine v1/e1 row back in the recovery service, mark included.
  recDb((d) => {
    d.prepare("UPDATE modes SET version = ?, epoch = ?, mode = ?, prev = ?, sig = ? WHERE account = ?").run(v1.version, v1.epoch, v1.mode, v1.prev, v1.sig, acct);
    d.prepare("UPDATE mode_marks SET version = 1, epoch = 1, hash = ? WHERE account = ?").run(recoveryModeHash(acct, { mode: v1.mode, version: 1, epoch: 1, prev: v1.prev }), acct);
  });
  const healed = await loadRecoveryMode();
  assert.deepEqual([healed.trusted, healed.version, healed.epoch], [true, 2, 2], "the gateway brought it back up to identity's v2");
  // An epoch-1 card is refused: the retired line stays retired.
  const card = newCard();
  await assert.rejects(api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, quorumParts(new Uint8Array(64), 1).card, acct), epoch: 1 }, stepUp), (e) => e.code === "stale_epoch");

  // Operator rolls back identity too: the phone's pin catches it, and no piece is made on epoch 1.
  idDb((d) => d.prepare("UPDATE identities SET recovery_mode = ?, recovery_mode_version = 1, recovery_mode_epoch = 1, recovery_mode_prev = ?, recovery_mode_sig = ? WHERE id = ?").run(v1.mode, v1.prev, v1.sig, acct));
  recDb((d) => {
    d.prepare("UPDATE modes SET version = ?, epoch = ?, mode = ?, prev = ?, sig = ? WHERE account = ?").run(v1.version, v1.epoch, v1.mode, v1.prev, v1.sig, acct);
    d.prepare("DELETE FROM mode_marks WHERE account = ?").run(acct);
  });
  const rolled = await loadRecoveryMode();
  assert.deepEqual([rolled.trusted, rolled.reason, rolled.mode], [false, "rolled back", "holder-only"]);
  assert.equal(rolled.epoch, 2, "the phone keeps the epoch it pinned");
  assert.throws(() => partOf(random(64), "card"), (e) => e.code === "holder_only");
});

test("V74-02: the signed ledger is a third witness: a mode_set newer than the served statement means rollback", async () => {
  await newPhone("hardened");
  const pin = S.identity.value.modePin;
  S.ledger.value = { ok: true, entries: [{ type: "recovery.mode_set", detail: { mode: "holder-only", version: 3, epoch: 3 } }] };
  const m = await loadRecoveryMode();
  assert.deepEqual([m.trusted, m.reason], [false, "rolled back"]);
  S.ledger.value = null;
  assert.equal(pin.version, 1);
});

test("judgeMode: chained statements only go forward; a fork or a gap that doesn't chain is refused", () => {
  const k = ml_dsa87.keygen();
  const acct = "hid_" + "cd".repeat(20);
  const s1 = signMode(acct, k.secretKey, "hardened", 1, 1);
  const s2 = signMode(acct, k.secretKey, "holder-only", 2, 2, s1);
  const fork2 = signMode(acct, k.secretKey, "hardened", 2, 2, s1);
  const s3 = signMode(acct, k.secretKey, "hardened", 3, 3, s2);
  const pin1 = { mode: s1.mode, version: 1, epoch: 1, prev: s1.prev }, pin2 = { mode: s2.mode, version: 2, epoch: 2, prev: s2.prev };
  assert.equal(judgeMode(acct, k.publicKey, s2, pin1).trusted, true);
  assert.equal(judgeMode(acct, k.publicKey, s2, pin1).newer, true);
  assert.equal(judgeMode(acct, k.publicKey, s1, pin2).reason, "rolled back");
  assert.equal(judgeMode(acct, k.publicKey, fork2, pin2).reason, "rolled back", "same version, different statement");
  assert.equal(judgeMode(acct, k.publicKey, s3, pin1).trusted, true, "a later one the other device made is fine: the account key signed it");
  assert.equal(judgeMode(acct, k.publicKey, { mode: "hardened", version: 0, epoch: 1, sig: null }, pin1).reason, "missing");
  // Version 2 or later must name the one before: there's no such thing as an unchained one.
  assert.throws(() => signMode(acct, k.secretKey, "hardened", 2, 2, null), /Not a recovery mode statement/);
  assert.throws(() => recoveryModeMessage(acct, "hardened", 2, 2, RECMODE_GENESIS));
  // A higher version that doesn't name the pinned one when it's the very next: a fork.
  const stray = signMode(acct, k.secretKey, "hardened", 2, 2, { ...s1, mode: "holder-only" });
  assert.equal(judgeMode(acct, k.publicKey, stray, pin1).reason, "forked");
});

test("V74-01: a device joining by link starts from the approving device's pin", async () => {
  // The hand-over format: the seed, then the pin, inside the envelope sealed by the account key.
  const h = makeHolder("link-pin");
  const pin = { mode: "holder-only", version: 4, epoch: 3, prev: "ab".repeat(32) };
  const bytes = new Uint8Array([...h.seed, ...new TextEncoder().encode(JSON.stringify({ modePin: pin }))]);
  const lk = Suite.deriveKeys(random(64));
  const envelope = await sealBytes(h, bytes, { kemPk: lk.kemPk, xPk: lk.xPk });
  const opened = (await Suite.open(envelope, lk)).bytes;
  assert.deepEqual(opened.slice(0, 64), h.seed, "the seed is unchanged");
  assert.deepEqual(JSON.parse(new TextDecoder().decode(opened.subarray(64))).modePin, pin);
});

/** This phone's account keys and a step-up signer, opened the way core/interrupt.js withKeys does. */
async function phoneKeys() {
  const id = S.identity.value, gate = S.hwGate.value.adapter;
  const both = await Suite.unwrapSeed(gate.secret, id.wrapped, Uint8Array.from(atob(id.bindingId), (c) => c.charCodeAt(0)));
  const keys = Suite.deriveKeys(both.slice(0, 64)), dk = Suite.deriveKeys(both.slice(64, 128));
  const stepUp = async ({ message, live }) => ({ sig: ml_dsa87.sign(message, dk.dsaSk), interrupt: { method: "android-keystore-biometric", assurance: "hardware" }, live: gate.lk.sign(live) });
  return { keys, stepUp };
}
