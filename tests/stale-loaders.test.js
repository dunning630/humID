// An answer that lands after a lock must not show in the next session (verify-71 #4). Every
// loader that waits on the server takes the epoch first and drops a result from an earlier
// one (runtime.js stale()), and an unlock starts its session from nothing.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { loadRecovery, loadAlerts } from "../apps/mobile/src/core/recovery.js";
import { loadDevices } from "../apps/mobile/src/core/devices.js";
import { loadDuress, loadCheckin } from "../apps/mobile/src/core/safety.js";
import { loadAdminSummary } from "../apps/mobile/src/core/operators.js";

/** An API whose every answer waits until release() is called. */
function heldApi() {
  const waiting = [];
  const later = (v) => () => new Promise((r) => waiting.push(() => r(v)));
  return {
    release: async () => { while (waiting.length) waiting.shift()(); for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0)); },
    api: {
      card: later({ exists: true, scheme: "quorum", createdAt: "2026-10-22" }),
      contacts: later({ n: 2, threshold: 2, scheme: "quorum", guardians: [] }),
      anchor: later({ available: true, exists: true, document: "passport" }),
      settings: later({ duressAlert: true }),
      keys: later({ max: 4, keys: [] }),
      protectingAlerts: later([{ kind: "duress", at: 1 }]),
      station: later({ station: true }),
      alerts: later([{ ref: "r1", method: "quorum", platform: "Android" }]),
      me: later({ devices: [{ id: "d1" }, { id: "d2" }] }),
      duressStatus: later({ lockdown: true, since: 1 }),
      checkin: later({ state: "armed", deadline: Date.now() + 3600_000 }),
      adminSummary: later({ health: "ok" }),
      htp: { clockOffsetMs: () => 0 },
    },
  };
}

beforeEach(() => { S.resetSession(); S.offline.value = null; S.decoy.value = false; });

test("a real session's answers that land after the lock are dropped", async () => {
  const h = heldApi();
  R.api = h.api;
  S.session.value = { id: "s" }; // loadCheckin needs a session
  S.server.value = { policy: { checkin: true } };
  const runs = [loadRecovery(), loadAlerts(), loadDevices(), loadDuress(), loadCheckin(), loadAdminSummary()];
  R.epoch++;            // lock() (or an unlock's fresh session) while they wait
  S.resetSession();
  S.decoy.value = true; // the next session is a decoy one
  await h.release();
  await Promise.all(runs);
  assert.equal(S.recovery.value, null, "recovery");
  assert.deepEqual(S.alerts.value, [], "alerts");
  assert.deepEqual(S.protecting.value, [], "people you protect");
  assert.equal(S.station.value, null, "station");
  assert.equal(S.devices.value, null, "devices");
  assert.equal(S.duressInfo.value, null, "duress status");
  assert.equal(S.checkin.value, null, "heartbeat");
  assert.equal(S.adminSummary.value, null, "admin summary");
  S.server.value = null;
  R.hooks.stopCheckinWatch?.(); // a Heartbeat watch, if one started, would keep the process alive
});

test("in the same session they still land", async () => {
  const h = heldApi();
  R.api = h.api;
  const runs = [loadRecovery(), loadAlerts(), loadDevices()];
  await h.release();
  await Promise.all(runs);
  assert.equal(S.recovery.value?.card.exists, true);
  assert.equal(S.alerts.value.length, 1);
  assert.equal(S.devices.value.length, 2);
});

test("an unlock starts its session from nothing: online and offline", () => {
  const s = readFileSync(new URL("../apps/mobile/src/core/session.js", import.meta.url), "utf8").replace(/\r\n/g, "\n"); // CRLF on a Windows checkout
  const fn = (name) => { const i = s.indexOf(`function ${name}(`); return s.slice(i, s.indexOf("\n}\n", i)); };
  assert.match(fn("unlock"), /freshSession\(\);\s*\n\s*batch\(\(\) => \{ S\.session\.value = sess;/);
  assert.match(fn("unlockOffline"), /freshSession\(\);\s*\n\s*R\.offline = duress/);
  assert.match(fn("freshSession"), /R\.epoch\+\+;/);
  assert.match(fn("freshSession"), /S\.resetSession\(\)/);
});
