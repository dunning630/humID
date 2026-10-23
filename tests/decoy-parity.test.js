// A decoy (duress) session must look like a calm, ordinary account (PC-16, APP-05, VAULT-06):
//   - Activity numbers its entries 1..n, with no gaps where hidden events were, and doesn't
//     claim the filtered list is complete
//   - the Duress screen lists the session's documents (the decoys), not "Nothing in your vault"
//   - Recovery shows a generic state: no witness names, no ID chip, no card date
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { decoyView } from "../apps/mobile/src/core/ledger.js";
import { loadRecovery } from "../apps/mobile/src/core/recovery.js";

const src = (f) => readFileSync(new URL(`../apps/mobile/src/${f}`, import.meta.url), "utf8");

test("the decoy Activity is numbered 1..n, keeps only calm events for the decoy documents", () => {
  const e = (seq, type, id) => ({ seq, type, at: seq * 1000, hash: `h${seq}`, detail: id ? { id } : {} });
  const ledger = {
    ok: true, keyFp: "k",
    entries: [
      e(1, "identity.created"), e(2, "session.opened"), e(3, "object.sealed", "real"), e(4, "object.sealed", "decoy"),
      e(5, "recovery.contacts_set"), e(6, "session.opened"), e(7, "object.opened", "real"), e(8, "duress.signaled"),
      e(9, "object.opened", "decoy"), e(10, "session.closed"),
    ],
  };
  const v = decoyView(ledger, [{ id: "decoy" }]);
  assert.deepEqual(v.entries.map((x) => x.seq), [1, 2, 3, 4, 5, 6], "no gaps");
  assert.deepEqual(v.entries.map((x) => x.type), ["identity.created", "session.opened", "object.sealed", "session.opened", "object.opened", "session.closed"]);
  assert.ok(v.entries.every((x) => !x.detail.id || x.detail.id === "decoy"), "nothing about other documents");
  assert.equal(v.decoy, true);
  assert.equal(ledger.entries[3].seq, 4, "the verified ledger itself is left as it was");
});

test("Activity says 'nothing altered or missing' only about a full list", () => {
  const a = src("screens/activity.jsx");
  assert.match(a, /l\.decoy \? `\$\{l\.entries\.length\} events` : `\$\{l\.entries\.length\} events, nothing altered or missing`/);
  assert.match(a, /<Fact k="Entry" v=\{`#\$\{e\.seq\}`\} \/>/, "the entry number shown is the (renumbered) seq");
});

test("the Duress screen lists the session's documents in a decoy session too", () => {
  const d = src("screens/you/duress.jsx");
  assert.match(d, /const items = S\.items\.value;/);
  assert.doesNotMatch(d, /decoy \? \[\] : S\.items\.value/);
  // and saving there sounds the same as a real save while changing nothing
  const safety = src("core/safety.js");
  assert.match(safety, /if \(S\.decoy\.value\) \{ toast\(enabled \? "Duress protection is on\." : "Duress protection is off\."\); return true; \}/);
});

test("Recovery in a decoy session: calm and generic, no names, no anchor, no card date", async () => {
  const calls = [];
  const ask = (name, v) => () => { calls.push(name); return Promise.resolve(v); };
  R.indexKey = null;
  R.api = {
    card: ask("card", { exists: true, scheme: "quorum", createdAt: "2026-10-22T10:00:00Z" }),
    contacts: ask("contacts", { n: 2, threshold: 2, scheme: "quorum", createdAt: "2026-10-21T10:00:00Z", guardians: [{ label: null }, { label: null }] }),
    anchor: ask("anchor", { available: true, exists: true, document: "passport", country: "UTO" }),
    settings: ask("settings", { duressAlert: true }),
    keys: ask("keys", { max: 4, keys: [{ id: "k1", createdAt: "2026-10-20" }] }),
    protectingAlerts: ask("protectingAlerts", []), station: ask("station", { station: true }),
  };
  S.offline.value = null;
  S.decoy.value = true;
  await loadRecovery();
  const r = S.recovery.value;
  assert.deepEqual(r.proofs, { witness: false, anchor: false, card: false, key: false });
  assert.equal(r.ready, false);
  assert.equal(r.card.exists, false);
  assert.equal(r.card.createdAt, undefined);
  assert.equal(r.anchor.exists, false);
  assert.equal(r.anchor.document, undefined);
  assert.deepEqual(r.contacts.names, []);
  assert.equal(r.contacts.n, 0);
  assert.deepEqual(r.keys.list, []);
  assert.equal(r.anchor.available, true, "what the server offers is the same for every account");
  assert.deepEqual(calls.slice(0, 5).sort(), ["anchor", "card", "contacts", "keys", "settings"], "the same requests as a real session");
  assert.ok(!calls.includes("protectingAlerts") && !calls.includes("station"));
  // the real session still sees the real setup
  S.decoy.value = false;
  await loadRecovery();
  assert.equal(S.recovery.value.card.exists, true);
  assert.equal(S.recovery.value.contacts.n, 2);
  S.resetSession();
});
