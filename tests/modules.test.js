// Module-boundary tests: migrations, gate contract, suite registry, codec.
import { test } from "node:test";
import assert from "node:assert/strict";
import { migrateIdentity, IDENTITY_SCHEMA } from "../packages/store/src/migrations.js";
import { suite, supportedSuites, suiteForEnvelope } from "@humid/crypto";
import { adapter, GATE_CONTRACT, assertAdapter, DEMO_BUILD } from "@humid/gate";
import { demoAdapter } from "../packages/gate/src/adapters/demo.js";
import { unpack, isEnvelope } from "@humid/codec";

test("legacy hardware identity migrates to the gate layout", () => {
  const legacy = { mode: "hardware", credId: "Q1JFRA==", prfSalt: "U0FMVA==", wrapped: {}, commit: "x", pub: {} };
  const { record, changed } = migrateIdentity(legacy);
  assert.equal(changed, true);
  assert.equal(record.schema, IDENTITY_SCHEMA);
  assert.deepEqual(record.gate, { adapter: "webauthn-prf", handle: { credId: "Q1JFRA==", prfSalt: "U0FMVA==" } });
  assert.equal(record.bindingId, "Q1JFRA==");
  assert.equal(record.server, null); // schema 3: not yet registered with a vault server
  assert.equal(record.device, null);  // schema 4: no device key yet, so it must be set up again
  assert.equal(record.pending, null);
});

test("legacy demo identity keeps its secret", () => {
  const { record } = migrateIdentity({ mode: "demo", credId: "SUQ=", demoSecret: "U0VD" });
  assert.deepEqual(record.gate, { adapter: "demo", handle: { id: "SUQ=", demoSecret: "U0VD" } });
});

test("current records are left alone; future ones refuse to load", () => {
  assert.equal(migrateIdentity({ schema: IDENTITY_SCHEMA }).changed, false);
  assert.throws(() => migrateIdentity({ schema: IDENTITY_SCHEMA + 1 }), /newer HumID/);
});

test("every shipped gate honours the contract", () => {
  assertAdapter(adapter("native"));
  assertAdapter(demoAdapter);
  assert.throws(() => assertAdapter({ id: "x", probe() {}, enroll() {}, release() {}, contract: GATE_CONTRACT + 1 }), /contract/);
});

test("release builds have no way to unlock without a live biometric", () => {
  assert.equal(DEMO_BUILD, false);
  assert.throws(() => adapter("demo"), (e) => e.code === "unknown_identity");
  assert.throws(() => adapter("webauthn-prf"), (e) => e.code === "unknown_identity"); // passkeys can fall back to a PIN
});

test("demo gate round-trips its secret", async () => {
  const demo = demoAdapter;
  const e = await demo.enroll();
  const r = await demo.release(e.handle, { purpose: "seal" });
  assert.deepEqual(r.secret, e.secret);
  assert.equal(r.interrupt.assurance, "none");
  assert.equal(r.interrupt.uv, false);
});

test("envelopes route to the suite that sealed them", async () => {
  const S = suite();
  const keys = S.deriveKeys(crypto.getRandomValues(new Uint8Array(64)));
  const { envelope } = await S.seal({ bytes: new Uint8Array([1, 2, 3]), name: "n", type: "" }, keys, keys, { identityCommit: "c", interrupt: {} });
  assert.equal(isEnvelope(envelope), true);
  assert.equal(suiteForEnvelope(envelope).ID, "HUMID-PQ1");
  assert.deepEqual(supportedSuites(), ["HUMID-PQ1"]);
  assert.throws(() => suite("HUMID-PQ9"), /Update HumID/);
  assert.throws(() => unpack(new Uint8Array(20)), /Not a HumID envelope/);
});

test("the native shell freezes Object.prototype, and release builds can't reach loopback (V5 narrow web view)", async () => {
  const { readFile } = await import("node:fs/promises");
  const conf = JSON.parse(await readFile(new URL("../apps/mobile/src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  const sec = conf.app.security;
  assert.equal(sec.freezePrototype, true);
  // the release policy: no loopback anywhere; `tauri dev` (devCsp) may talk to a local server
  assert.doesNotMatch(sec.csp, /localhost:|127\.0\.0\.1|\[::1\]/);
  assert.match(sec.csp, /connect-src 'self' ipc: http:\/\/ipc\.localhost /);
  assert.match(sec.devCsp, /http:\/\/localhost:\*/);
  assert.equal(sec.devCsp.replace(" http://localhost:* http://127.0.0.1:*", ""), sec.csp, "devCsp is the release csp plus loopback, nothing else");
  // the navigation guard: loopback only in debug builds
  const shell = await readFile(new URL("../apps/mobile/src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(shell, /own_origin\(url, cfg!\(debug_assertions\)\)/);
});

test("the UI's libraries run with Object.prototype frozen, as the native shells run them", async () => {
  // Built the way apps/mobile/build.mjs builds them, then run in a fresh realm whose
  // Object.prototype is frozen first (Tauri's freezePrototype init script). Without the
  // rewrites in apps/mobile/frozen-prototype.mjs they throw ("Cannot assign to read only
  // property"). Rendering needs a DOM, so the whole app is covered by the browser checks
  // (tools/dev.mjs freezes the prototype as the shells do); here, compat's forwardRef copies
  // a props object with an own `constructor` key through Preact's copy loop, as a vnode copy
  // (re-render, Suspense) does.
  const esbuild = await import("esbuild");
  const vm = await import("node:vm");
  const { frozenPrototypeSafe } = await import("../apps/mobile/frozen-prototype.mjs");
  const entry = `
    import { signal, computed } from "@preact/signals-core";
    import qrcode from "qrcode-generator";
    import { forwardRef } from "preact/compat";
    const s = signal(41); const c = computed(() => s.value + 1);
    const q = qrcode(0, "M"); q.addData("HUMID"); q.make();
    const F = forwardRef((props) => props);
    const copied = F({ id: "x", constructor: undefined, ref: null });
    globalThis.out = { sum: +c, text: String(s), json: JSON.stringify({ c }), url: q.createDataURL(2, 0).slice(0, 22), props: { id: copied.id, own: Object.keys(copied).sort().join() } };`;
  const bundle = async (plugins) => (await esbuild.build({ stdin: { contents: entry, resolveDir: new URL("../apps/mobile/", import.meta.url).pathname }, bundle: true, write: false, format: "iife", plugins, logLevel: "silent" })).outputFiles[0].text;
  const run = (code) => { const ctx = vm.createContext({}); vm.runInContext("'use strict'; Object.freeze(Object.prototype);", ctx); vm.runInContext(code, ctx); return ctx.out; };
  const plain = await bundle([]), safe = await bundle([frozenPrototypeSafe]);
  assert.throws(() => run(`"use strict";${plain}`), /read only property/, "the plain libraries break under a frozen prototype (the test can see the problem)");
  const out = run(`"use strict";${safe}`);
  assert.deepEqual({ ...out, props: { ...out.props } }, { sum: 42, text: "41", json: '{"c":42}', url: "data:image/gif;base64,", props: { id: "x", own: "constructor,id" } });
});

test("service request logs name the route, never the ids or codes in the path", async () => {
  const { logPath } = await import("@humid/svc");
  assert.equal(logPath({ pattern: "/links/:code" }, "/links/ABCD1234EFGH"), "/links/:code");
  assert.equal(logPath(null, "/station/requests/ABCD1234EFGH/verify"), "/station/…");
  assert.doesNotMatch(logPath(null, "/x\nforged log line"), /\n/);
});

test("no workspace module can be published to npm by accident (PC-23)", async () => {
  const { readdir, readFile } = await import("node:fs/promises");
  const dir = new URL("../packages/", import.meta.url);
  const open = [];
  for (const name of await readdir(dir)) {
    const pkg = JSON.parse(await readFile(new URL(`${name}/package.json`, dir), "utf8"));
    if (pkg.private !== true) open.push(pkg.name);
  }
  assert.deepEqual(open, [], "every packages/*/package.json says \"private\": true");
});
