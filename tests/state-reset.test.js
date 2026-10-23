// What a lock forgets (apps/mobile/src/core/state.js resetSession, R1). Every signal in the
// app's state is either session-scoped, reset by lock, erase and reset, or on the explicit
// device-scoped list with a reason. A signal added later without a decision fails here.
// APP-07: the search, filters and tag filter typed in the real vault once survived a lock
// into the duress session ("Nothing matches “divorce”").
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as S from "../apps/mobile/src/core/state.js";
import { lock } from "../apps/mobile/src/core/session.js";
import { resetLocal } from "../apps/mobile/src/core/account.js";
import { R } from "../apps/mobile/src/core/runtime.js";

/** A writable signal (a computed has no setter). */
const writable = (x) => {
  if (!x || typeof x !== "object" || typeof x.peek !== "function") return false;
  for (let p = x; p; p = Object.getPrototypeOf(p)) { const d = Object.getOwnPropertyDescriptor(p, "value"); if (d) return !!d.set; }
  return false;
};
const signals = Object.entries(S).filter(([, v]) => writable(v));
const initial = new Map(signals.map(([k, v]) => [k, structuredClone(v.peek())]));
const sessionScoped = signals.map(([k]) => k).filter((k) => !(k in S.DEVICE_SCOPED));

/** A value of the same shape as the start, but different from it. */
const dirty = (v) => (typeof v === "string" ? `${v}dirty`
  : typeof v === "number" ? v + 42
    : typeof v === "boolean" ? !v
      : Array.isArray(v) ? [{ dirty: true }] : { dirty: true });
const dirtyAll = () => { for (const k of sessionScoped) S[k].value = dirty(initial.get(k)); };
const assertReset = (how) => {
  const left = sessionScoped.filter((k) => JSON.stringify(S[k].peek()) !== JSON.stringify(initial.get(k)));
  assert.deepEqual(left, [], `${how} left these session signals set`);
};

// Enough of the runtime for lock() and resetLocal() to run without a browser or a server.
R.api = { logout() {}, server: async () => ({}), htp: { close() {}, pinnedKid: null, server: null } };
R.store = { clearIdentity: async () => {}, clearVault: async () => {}, clearOffline: async () => {} };

test("every signal is session-scoped or on the device-scoped list, and the list names real signals", () => {
  const names = new Set(signals.map(([k]) => k));
  const stale = Object.keys(S.DEVICE_SCOPED).filter((k) => !names.has(k));
  assert.deepEqual(stale, [], "DEVICE_SCOPED names a signal that doesn't exist");
  for (const [k, why] of Object.entries(S.DEVICE_SCOPED)) assert.ok(typeof why === "string" && why.length > 8, `${k} needs a reason`);
  // the ones that leaked or could leak a session into the next must never be on it
  for (const k of ["query", "filter", "tagFilter", "items", "cardCode", "ledger", "recovery", "decoy", "viewer", "sheet", "push", "duressInfo", "thread", "msg"]) {
    assert.ok(sessionScoped.includes(k), `${k} is session-scoped`);
  }
});

test("resetSession puts every session signal back as it started", () => {
  dirtyAll();
  S.resetSession();
  assertReset("resetSession");
});

test("lock forgets the search, the filters and everything else the session showed (APP-07)", () => {
  S.view.value = "app";
  dirtyAll();
  S.offline.value = null; // a session signal lock() itself reads to decide whether to sign out
  S.query.value = "divorce"; S.filter.value = "id"; S.tagFilter.value = "family";
  lock();
  assert.equal(S.view.value, "locked");
  assert.equal(S.query.value, "");
  assert.equal(S.filter.value, "all");
  assert.equal(S.tagFilter.value, null);
  assertReset("lock()");
});

test("forgetting this device's HumID resets the session too", async () => {
  S.view.value = "app";
  S.identity.value = null;
  dirtyAll();
  await resetLocal();
  assert.equal(S.view.value, "welcome");
  assertReset("resetLocal()");
});

test("lock, erase and reset each call resetSession, and nothing keeps its own list", () => {
  const src = (f) => readFileSync(new URL(`../apps/mobile/src/core/${f}`, import.meta.url), "utf8").replace(/\r\n/g, "\n"); // CRLF on a Windows checkout
  const body = (s, name) => { const i = s.indexOf(`function ${name}(`); assert.ok(i >= 0, name); return s.slice(i, s.indexOf("\n}\n", i)); };
  assert.match(body(src("session.js"), "lock"), /S\.resetSession\(\)/);
  assert.match(body(src("account.js"), "eraseEverything"), /S\.resetSession\(\)/);
  assert.match(body(src("account.js"), "resetLocal"), /S\.resetSession\(\)/);
  // a hand-written reset list is how APP-07 happened: lock() no longer clears signals one by one
  assert.doesNotMatch(body(src("session.js"), "lock"), /S\.(items|ledger|recovery|devices)\.value\s*=/);
});
