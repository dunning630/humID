// Identity anchor: ICAO 9303 chip checks (passive + active authentication),
// the MRZ, and the renewal-stable anchor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { passiveAuth, activeAuth, anchorOf, parseMrz, checkDigit, readDg1 } from "@humid/anchor";
import { testCsca, testPassport, td3 } from "./support/passport.js";

const csca = testCsca();
const other = testCsca("Some Other Country");
const key = randomBytes(32);

test("check digits and the ICAO specimen MRZ", () => {
  assert.equal(checkDigit("L898902C3"), 6);
  assert.equal(checkDigit("740812"), 2);
  const f = parseMrz(td3());
  assert.equal(f.format, "TD3");
  assert.equal(f.surname, "ERIKSSON");
  assert.equal(f.given, "ANNA MARIA");
  assert.equal(f.issuer, "UTO");
  assert.throws(() => parseMrz(td3().replace("7408122", "7408123")), /date of birth/);
});

for (const dsKind of ["ec", "rsa", "pss"]) {
  test(`passive authentication accepts a genuine chip (document signer ${dsKind})`, () => {
    const p = testPassport({ csca, dsKind });
    const r = passiveAuth(p, { cscas: [csca.pem] });
    assert.equal(r.mrz.surname, "ERIKSSON");
    assert.equal(r.hasAaKey, true);
  });
}

test("passive authentication refuses altered data, a forged signature, an untrusted country, an expired document", () => {
  const p = testPassport({ csca });
  const altered = { ...p, dg1: testPassport({ csca, mrz: { surname: "MALLORY" } }).dg1 };
  assert.throws(() => passiveAuth(altered, { cscas: [csca.pem] }), (e) => e.code === "data_altered");
  assert.throws(() => passiveAuth(testPassport({ csca, tamper: "signature" }), { cscas: [csca.pem] }), (e) => e.code === "bad_signature");
  assert.throws(() => passiveAuth(p, { cscas: [other.pem] }), (e) => e.code === "untrusted_country");
  assert.throws(() => passiveAuth(p, { cscas: [] }), (e) => e.code === "no_trust");
  const old = testPassport({ csca, mrz: { expiry: "200101" } });
  assert.throws(() => passiveAuth(old, { cscas: [csca.pem] }), (e) => e.code === "expired");
  // Swapping in another chip's AA key is caught by the SOD hash.
  const swapped = { ...p, dg15: testPassport({ csca }).dg15 };
  assert.throws(() => passiveAuth(swapped, { cscas: [csca.pem] }), (e) => e.code === "data_altered");
});

for (const aaKind of ["rsa", "ec"]) {
  test(`active authentication: the chip answers this challenge (${aaKind}); a copy can't`, () => {
    const p = testPassport({ csca, aaKind });
    const nonce = randomBytes(8);
    assert.equal(activeAuth({ dg15: p.dg15, nonce, signature: p.answer(nonce) }), true);
    // A replayed answer to an old challenge, or a different chip's answer, fails.
    assert.throws(() => activeAuth({ dg15: p.dg15, nonce: randomBytes(8), signature: p.answer(nonce) }), (e) => e.code === "chip_not_present");
    const clone = testPassport({ csca, aaKind });
    assert.throws(() => activeAuth({ dg15: p.dg15, nonce, signature: clone.answer(nonce) }), (e) => e.code === "chip_not_present");
  });
}

test("the anchor survives renewal and differs between people", () => {
  const before = testPassport({ csca, mrz: { number: "L898902C3", expiry: "300101" } });
  const renewed = testPassport({ csca, mrz: { number: "X12345678", expiry: "360101" } });
  const someoneElse = testPassport({ csca, mrz: { given: "ANNA MARIE" } });
  const a = (p) => anchorOf(readDg1(p.dg1), key);
  assert.equal(a(before), a(renewed));
  assert.notEqual(a(before), a(someoneElse));
  assert.notEqual(anchorOf(readDg1(before.dg1), randomBytes(32)), a(before), "keyed by the server's secret");
});
