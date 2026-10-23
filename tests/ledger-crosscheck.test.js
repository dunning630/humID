// CRYPTO-01 on the phone: Activity shows "Verified on this phone" and "Published in the
// public log" only when the page it verified and the log describe the same history. A
// server that hides an event from the holder (while the log keeps it) gets a loud failure.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { loadLedger, checkContinuity } from "../apps/mobile/src/core/ledger.js";
import { histLedgerKey, ev, chain, maliciousServer } from "./support/ledger-server.js";

const honest = chain([ev("identity.created"), ev("device.added", { device: "dev_attacker", via: "card" }), ev("object.opened", { id: "will" })]);

// loadLedger starts a public-log check without waiting for it; let the previous test's finish
// before this one sets up, or its late write lands on this test's identity record.
const settle = () => new Promise((r) => setTimeout(r, 300));

async function phone(api) {
  await settle();
  const saved = [];
  R.api = api;
  R.store = { putIdentity: async (r) => { saved.push(r); } };
  S.offline.value = null; S.decoy.value = false; S.items.value = [];
  S.ledger.value = null; S.continuity.value = null;
  S.identity.value = { server: { id: "hid_x" }, ledgerKeyFp: histLedgerKey.fp, schema: 4 };
  return saved;
}

test("a history with an event hidden from the phone is a loud mismatch, never 'Verified' and 'Published'", async () => {
  const doctored = chain([ev("identity.created"), ev("object.opened", { id: "will" })]);
  await phone(maliciousServer({ shown: { page: doctored, all: doctored }, logged: honest }));
  await loadLedger();
  await checkContinuity();
  assert.equal(S.continuity.value.ok, false);
  assert.equal(S.continuity.value.mismatch, true);
  assert.equal(S.continuity.value.pending, undefined, "not 'checked later': a failure");
  assert.equal(S.ledger.value.ok, false, "the page no longer counts as verified");
  assert.match(S.ledger.value.reason, /doesn't match the public log/);
});

test("the honest history verifies, and the phone remembers the head the log confirmed", async () => {
  const saved = await phone(maliciousServer({ shown: { page: honest, all: honest }, logged: honest }));
  await loadLedger();
  await checkContinuity();
  assert.equal(S.ledger.value.ok, true, S.ledger.value.reason);
  assert.equal(S.continuity.value.ok, true, S.continuity.value.reason);
  assert.deepEqual(saved.at(-1).ledgerHead, { seq: 3, hash: honest[2].hash });

  // Later the server rolls the account back to before the attacker's device: refused.
  S.identity.value = { ...saved.at(-1), schema: 4 };
  R.api = maliciousServer({ shown: { page: honest.slice(0, 1), all: honest.slice(0, 1) }, logged: honest });
  await loadLedger();
  assert.equal(S.ledger.value.ok, false);
  assert.match(S.ledger.value.reason, /got shorter/);
});

test("more events since the last check than the phone will fetch: 'not verified', never 'Verified', nothing remembered", async () => {
  const long = chain(Array.from({ length: 12 }, (_, i) => ev(i ? "session.opened" : "identity.created")));
  const api = maliciousServer({ shown: { page: long.slice(-3), all: long }, logged: long });
  api.bridgeMax = 5; // stands in for BRIDGE_MAX (20,000): 9 entries between the old head and the page
  const saved = await phone(api);
  S.identity.value = { ...S.identity.value, ledgerHead: { seq: 1, hash: long[0].hash } };
  await loadLedger();
  await checkContinuity();
  assert.equal(S.ledger.value.ok, false, "not Verified");
  assert.equal(S.ledger.value.unverified, true, "and not a tamper alarm either");
  assert.match(S.ledger.value.reason, /too many to check here/);
  assert.equal(S.continuity.value.ok, false);
  assert.equal(S.continuity.value.pending, true);
  assert.ok(!saved.some((r) => r.ledgerHead && r.ledgerHead.seq !== 1), "the old head stays the anchor");
  // within the limit, the same history verifies
  api.bridgeMax = 20_000;
  await loadLedger();
  await checkContinuity();
  assert.equal(S.ledger.value.ok, true, S.ledger.value.reason);
  assert.equal(S.continuity.value.ok, true, S.continuity.value.reason);
});
