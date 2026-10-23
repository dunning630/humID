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
  const decoyBranch = safety.slice(safety.indexOf("export async function saveDuress"), safety.indexOf("try {", safety.indexOf("export async function saveDuress")));
  assert.match(decoyBranch, /if \(S\.decoy\.value\) \{[\s\S]*toast\(enabled \? "Duress protection is on\." : "Duress protection is off\."\);\s*return true;/);
  assert.doesNotMatch(decoyBranch, /putIdentity|updateIdentity|sealDuress/, "and saves nothing");
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

test("decoy Duress screen: off with nothing picked, then echoes what it saved, until the lock (verify-71 #2)", async () => {
  const { loadDuress, saveDuress } = await import("../apps/mobile/src/core/safety.js");
  S.resetSession();
  S.decoy.value = true;
  R.duressSetting = { enabled: true, gesture: "taps" }; // the real setting, open in memory
  await loadDuress();
  assert.deepEqual(S.duressInfo.value.setting, { enabled: false, gesture: "taps" }, "never the real setting");
  const d = src("screens/you/duress.jsx");
  assert.match(d, /new Set\(decoy \? S\.decoyEcho\.value\?\.decoys \|\| \[\] : items\.filter/, "nothing picked unless this session picked it");
  assert.ok(await saveDuress({ enabled: true, gesture: "hold" }));
  assert.deepEqual(S.duressInfo.value.setting, { enabled: true, gesture: "hold" }, "the save is echoed");
  await loadDuress();
  assert.deepEqual(S.duressInfo.value.setting, { enabled: true, gesture: "hold" }, "and still there when the screen opens again");
  S.resetSession();
  S.decoy.value = true;
  await loadDuress();
  assert.deepEqual(S.duressInfo.value.setting, { enabled: false, gesture: "taps" }, "gone after the lock");
  S.resetSession(); R.duressSetting = null;
});

test("an offline decoy session takes nothing personal from the offline copy (verify-71 #1)", async () => {
  const { decoyCopy } = await import("../apps/mobile/src/core/session.js");
  const real = {
    card: { exists: true, scheme: "quorum", createdAt: "2026-10-22T10:00:00Z" }, anchor: { available: true, exists: true, document: "passport", country: "UTO" },
    contacts: { n: 2, threshold: 2, names: ["Mum", "Sam"], scheme: "quorum" }, keys: { available: true, max: 4, list: [{ id: "k", name: "Blue key" }] },
    proofs: { witness: true, anchor: true, card: true, key: true }, ready: true, settings: { duressAlert: true },
  };
  const copy = { v: 1, account: "hid_x", items: [], devices: [{ id: "d" }], ledger: { ok: true, entries: [] }, recovery: real, duress: { lockdown: true, alert: true } };
  // what unlockOffline keeps for a decoy session
  const kept = decoyCopy(copy);
  assert.equal(kept.duress, undefined);
  assert.doesNotMatch(JSON.stringify(kept), /Mum|Sam|Blue key|passport|2026-10-22/);
  assert.deepEqual(kept.devices, copy.devices, "devices are the same in every session");
  // and loadRecovery reads it as a calm account, even from the full real copy
  for (const offline of [kept, copy]) {
    R.offline = offline;
    S.offline.value = { savedAt: "x" };
    S.decoy.value = true;
    await loadRecovery();
    const r = S.recovery.value;
    assert.deepEqual(r.proofs, { witness: false, anchor: false, card: false, key: false });
    assert.equal(r.card.exists, false);
    assert.deepEqual(r.contacts.names, []);
    assert.doesNotMatch(JSON.stringify(r), /Mum|Sam|Blue key|passport|2026-10-22/);
    assert.equal(r.anchor.available, true);
  }
  // a real offline session still shows its own setup
  R.offline = copy; S.decoy.value = false;
  await loadRecovery();
  assert.equal(S.recovery.value.card.exists, true);
  S.resetSession(); R.offline = null;
});

test("every read of the offline copy in core/ is decoy-safe", () => {
  // Each place that reads R.offline either filters for a decoy session itself, or reads data
  // a decoy session may show (devices: the same in every session; items: refresh filters to the
  // decoys; the ledger: loadLedger applies decoyView). unlockOffline keeps only decoyCopy().
  const core = new URL("../apps/mobile/src/core/", import.meta.url);
  const reads = [];
  for (const f of ["recovery.js", "safety.js", "vault.js", "devices.js", "ledger.js", "session.js"]) {
    readFileSync(new URL(f, core), "utf8").split("\n").forEach((line, i) => { if (/R\.offline\??\.\w/.test(line)) reads.push(`${f}:${line.trim().slice(0, 60)}`); });
  }
  const safe = [/^recovery\.js:const copy = R\.offline\?\.recovery/, /^safety\.js:if \(S\.offline\.value\) \{ S\.duressInfo/, /^vault\.js:/, /^devices\.js:/, /^ledger\.js:/];
  assert.deepEqual(reads.filter((r) => !safe.some((re) => re.test(r))), [], "a new read of the offline copy needs a decoy decision");
  // loadDuress checks decoy before the copy; loadLedger filters after it
  const safety = readFileSync(new URL("safety.js", core), "utf8");
  assert.ok(safety.indexOf("if (S.decoy.value) { S.duressInfo") < safety.indexOf("if (S.offline.value) { S.duressInfo"));
  assert.match(readFileSync(new URL("session.js", core), "utf8"), /R\.offline = duress \? decoyCopy\(copy\) : copy;/);
});
