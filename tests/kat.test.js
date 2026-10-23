// Known-answer tests from NIST's ACVP vectors (tests/fixtures/acvp/, refreshed with
// tools/acvp-vectors.mjs) for every post-quantum primitive HumID ships: ML-KEM-1024
// (FIPS 203), ML-DSA-87 (FIPS 204) and SLH-DSA-SHA2-256f (FIPS 205), as implemented by the
// pinned @noble/post-quantum and used through the same imports the app and servers use.
// checkBackend and compat.test.js compare noble with itself; these compare it with NIST.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js"; // the copy every package pins (0.7.1)
import { ml_dsa87 } from "@humid/htp";
import { slh_dsa_sha2_256f } from "@noble/post-quantum/slh-dsa.js";
import { isValidKemPk } from "@humid/msg";

const dir = new URL("./fixtures/acvp/", import.meta.url);
const load = (name) => JSON.parse(gunzipSync(readFileSync(new URL(`${name}.json.gz`, dir))));
const h = (s) => new Uint8Array(Buffer.from(s, "hex"));
const hex = (b) => Buffer.from(b).toString("hex").toUpperCase();
const cases = (doc, pred = () => true) => doc.testGroups.filter(pred).flatMap((g) => g.tests.map((t) => ({ g, t })));

test("the vectors are NIST's, and every file is here", () => {
  const files = readdirSync(dir).filter((f) => f.endsWith(".json.gz")).sort();
  assert.deepEqual(files, ["ML-DSA-keyGen-FIPS204", "ML-DSA-sigGen-FIPS204", "ML-DSA-sigVer-FIPS204", "ML-KEM-encapDecap-FIPS203", "ML-KEM-keyGen-FIPS203", "SLH-DSA-keyGen-FIPS205", "SLH-DSA-sigGen-FIPS205", "SLH-DSA-sigVer-FIPS205"].map((f) => `${f}.json.gz`));
  for (const f of files) {
    const d = load(f.replace(".json.gz", ""));
    assert.match(d.source, /^https:\/\/github\.com\/usnistgov\/ACVP-Server\/blob\/[0-9a-f]{40}\//);
    assert.match(d.sourceSha256, /^[0-9a-f]{64}$/);
    assert.ok(d.testGroups.every((g) => g.tests.length > 0));
  }
});

/* ---------------- ML-KEM-1024 (FIPS 203) ---------------- */

test("ML-KEM-1024 keyGen: (d, z) gives NIST's encapsulation and decapsulation keys", () => {
  const all = cases(load("ML-KEM-keyGen-FIPS203"), (g) => g.parameterSet === "ML-KEM-1024");
  assert.ok(all.length >= 10);
  for (const { t } of all) {
    const k = ml_kem1024.keygen(new Uint8Array([...h(t.d), ...h(t.z)])); // noble's seed is d ‖ z
    assert.equal(hex(k.publicKey), t.ek, `tcId ${t.tcId}`);
    assert.equal(hex(k.secretKey), t.dk, `tcId ${t.tcId}`);
  }
});

test("ML-KEM-1024 encapsulation with NIST's m gives its ciphertext and shared key", () => {
  const all = cases(load("ML-KEM-encapDecap-FIPS203"), (g) => g.function === "encapsulation");
  assert.ok(all.length >= 10);
  for (const { t } of all) {
    const r = ml_kem1024.encapsulate(h(t.ek), h(t.m));
    assert.equal(hex(r.cipherText), t.c, `tcId ${t.tcId}`);
    assert.equal(hex(r.sharedSecret), t.k, `tcId ${t.tcId}`);
  }
});

test("ML-KEM-1024 decapsulation, including NIST's malformed ciphertexts (implicit rejection)", () => {
  const all = cases(load("ML-KEM-encapDecap-FIPS203"), (g) => g.function === "decapsulation");
  assert.ok(all.length >= 10);
  for (const { t } of all) assert.equal(hex(ml_kem1024.decapsulate(h(t.c), h(t.dk))), t.k, `tcId ${t.tcId} (${t.reason})`);
});

test("ML-KEM-1024 key checks: NIST's bad encapsulation keys are refused, good ones accepted", () => {
  const all = cases(load("ML-KEM-encapDecap-FIPS203"), (g) => g.function === "encapsulationKeyCheck");
  assert.ok(all.some(({ t }) => t.testPassed) && all.some(({ t }) => !t.testPassed));
  for (const { t } of all) {
    let ok = true;
    try { ml_kem1024.encapsulate(h(t.ek)); } catch { ok = false; }
    assert.equal(ok, t.testPassed, `noble, tcId ${t.tcId} (${t.reason})`);
    assert.equal(isValidKemPk(h(t.ek)), t.testPassed, `@humid/msg isValidKemPk, tcId ${t.tcId}`);
  }
  for (const { t } of cases(load("ML-KEM-encapDecap-FIPS203"), (g) => g.function === "decapsulationKeyCheck")) {
    let ok = true;
    try { ml_kem1024.decapsulate(new Uint8Array(1568), h(t.dk)); } catch { ok = false; }
    assert.equal(ok, t.testPassed, `tcId ${t.tcId} (${t.reason})`);
  }
});

/* ---------------- ML-DSA-87 (FIPS 204) ---------------- */

test("ML-DSA-87 keyGen: NIST's seed gives its public and secret keys", () => {
  const all = cases(load("ML-DSA-keyGen-FIPS204"), (g) => g.parameterSet === "ML-DSA-87");
  assert.ok(all.length >= 10);
  for (const { t } of all) {
    const k = ml_dsa87.keygen(h(t.seed));
    assert.equal(hex(k.publicKey), t.pk, `tcId ${t.tcId}`);
    assert.equal(hex(k.secretKey), t.sk, `tcId ${t.tcId}`);
  }
});

test("ML-DSA-87 sigGen (pure, external): deterministic and hedged signatures match NIST's byte for byte", () => {
  const all = cases(load("ML-DSA-sigGen-FIPS204"));
  assert.ok(all.some(({ g }) => g.deterministic) && all.some(({ g }) => !g.deterministic));
  for (const { g, t } of all) {
    const sig = ml_dsa87.sign(h(t.message), h(t.sk), { context: h(t.context), extraEntropy: g.deterministic ? false : h(t.rnd) });
    assert.equal(hex(sig), t.signature, `tcId ${t.tcId}`);
  }
});

test("ML-DSA-87 sigVer: NIST's valid signatures verify; modified messages, commitments, z and hints don't", () => {
  const all = cases(load("ML-DSA-sigVer-FIPS204"));
  assert.ok(all.some(({ t }) => t.testPassed) && all.filter(({ t }) => !t.testPassed).length >= 5);
  for (const { t } of all) assert.equal(ml_dsa87.verify(h(t.signature), h(t.message), h(t.pk), { context: h(t.context) }), t.testPassed, `tcId ${t.tcId} (${t.reason})`);
});

/* ---------------- SLH-DSA-SHA2-256f (FIPS 205) ---------------- */

test("SLH-DSA-SHA2-256f keyGen: NIST's seeds give its keys", () => {
  const all = cases(load("SLH-DSA-keyGen-FIPS205"));
  assert.ok(all.length >= 10);
  for (const { t } of all) {
    const k = slh_dsa_sha2_256f.keygen(new Uint8Array([...h(t.skSeed), ...h(t.skPrf), ...h(t.pkSeed)]));
    assert.equal(hex(k.publicKey), t.pk, `tcId ${t.tcId}`);
    assert.equal(hex(k.secretKey), t.sk, `tcId ${t.tcId}`);
  }
});

test("SLH-DSA-SHA2-256f sigGen (pure, external, deterministic) matches NIST's signature", () => {
  for (const { t } of cases(load("SLH-DSA-sigGen-FIPS205"))) {
    assert.equal(hex(slh_dsa_sha2_256f.sign(h(t.message), h(t.sk), { context: h(t.context), extraEntropy: false })), t.signature, `tcId ${t.tcId}`);
  }
});

test("SLH-DSA-SHA2-256f sigVer: valid ones verify; modified R, FORS, hypertree, message and wrong lengths don't", () => {
  const all = cases(load("SLH-DSA-sigVer-FIPS205"));
  assert.ok(new Set(all.map(({ t }) => t.reason)).size >= 6);
  for (const { t } of all) assert.equal(slh_dsa_sha2_256f.verify(h(t.signature), h(t.message), h(t.pk), { context: h(t.context) }), t.testPassed, `tcId ${t.tcId} (${t.reason})`);
});
