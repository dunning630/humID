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

function phone(api) {
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
  phone(maliciousServer({ shown: { page: doctored, all: doctored }, logged: honest }));
  await loadLedger();
  await checkContinuity();
  assert.equal(S.continuity.value.ok, false);
  assert.equal(S.continuity.value.mismatch, true);
  assert.equal(S.continuity.value.pending, undefined, "not 'checked later': a failure");
  assert.equal(S.ledger.value.ok, false, "the page no longer counts as verified");
  assert.match(S.ledger.value.reason, /doesn't match the public log/);
});

test("the honest history verifies, and the phone remembers the head the log confirmed", async () => {
  const saved = phone(maliciousServer({ shown: { page: honest, all: honest }, logged: honest }));
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
