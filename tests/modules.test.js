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
