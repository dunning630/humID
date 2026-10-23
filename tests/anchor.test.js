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

test("passive authentication: the SOD's signer must be named, sign documents, and be from the document's country", () => {
  const ok = (p) => passiveAuth(p, { cscas: [csca.pem] });
  // a signer named by subject key id is fine too
  assert.equal(ok(testPassport({ csca, ds: { sid: "ski" } })).mrz.issuer, "UTO");
  // the SOD names a certificate it doesn't carry
  assert.throws(() => ok(testPassport({ csca, ds: { sid: "wrong" } })), (e) => e.code === "bad_signature");
  // a certificate without the document-signing key usage, or a CA, can't sign documents
  assert.throws(() => ok(testPassport({ csca, ds: { keyUsage: false } })), (e) => e.code === "bad_signature");
  assert.throws(() => ok(testPassport({ csca, ds: { ca: true } })), (e) => e.code === "bad_signature");
  // the content type attribute is required
  assert.throws(() => ok(testPassport({ csca, tamper: "contentType" })), (e) => e.code === "bad_chip_data");
  // a trusted country's signer vouching for another country's passport
  assert.throws(() => ok(testPassport({ csca, mrz: { issuer: "D", nationality: "D" } })), (e) => e.code === "country_mismatch");
  // a document signer naming a different country than its CSCA
  assert.throws(() => ok(testPassport({ csca, ds: { country: "DE" } })), (e) => e.code === "country_mismatch");
  // a CSCA with no country at all
  const nameless = testCsca("No Country", "");
  assert.throws(() => passiveAuth(testPassport({ csca: nameless }), { cscas: [nameless.pem] }), (e) => e.code === "country_mismatch");
  // the same country, written as ICAO does: Germany is "D" in an MRZ and DE in its certificates
  const de = testCsca("Germany", "DE");
  assert.equal(passiveAuth(testPassport({ csca: de, mrz: { issuer: "D", nationality: "D" } }), { cscas: [de.pem] }).mrz.issuer, "D");
});

test("passive authentication: every data group sent is checked against the SOD", () => {
  const p = testPassport({ csca, photo: Buffer.from("not really a jpeg") });
  assert.ok(passiveAuth(p, { cscas: [csca.pem] }));
  assert.throws(() => passiveAuth({ ...p, dg2: Buffer.from("a different face") }, { cscas: [csca.pem] }), (e) => e.code === "data_altered");
  assert.throws(() => passiveAuth({ ...p, dg11: Buffer.from("unsigned extra") }, { cscas: [csca.pem] }), (e) => e.code === "data_altered");
});

test("check digits and the ICAO specimen MRZ", () => {
  assert.equal(checkDigit("L898902C3"), 6);
  assert.equal(checkDigit("740812"), 2);
  const f = parseMrz(td3());
  assert.equal(f.format, "TD3");
  assert.equal(f.surname, "ERIKSSON");
  assert.equal(f.given, "ANNA MARIA");
  assert.equal(f.issuer, "UTO");
  assert.throws(() => parseMrz(td3().replace("7408122", "7408123")), /date of birth/);
  // the overall (composite) check digit and the personal number's are checked too
  const good = td3();
  const flip = (i) => good.slice(0, i) + (good[i] === "0" ? "1" : "0") + good.slice(i + 1);
  assert.throws(() => parseMrz(flip(87)), /overall check digit/);
  assert.throws(() => parseMrz(flip(86)), /personal number/);
  // a TD1 ID card (ICAO 9303-5 specimen) with every check digit right parses; the composite wrong doesn't
  const td1 = "I<UTOD231458907<<<<<<<<<<<<<<<" + "7408122F1204159UTO<<<<<<<<<<<6" + "ERIKSSON<<ANNA<MARIA<<<<<<<<<<";
  assert.equal(parseMrz(td1).number, "D23145890");
  assert.throws(() => parseMrz(td1.replace("<<<6E", "<<<5E")), /overall check digit/);
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

test("CREDS-08: passive authentication refuses a SHA-1 SOD unless asked, and then says so", () => {
  for (const dsKind of ["ec", "rsa"]) {
    const old = testPassport({ csca, dsKind, hash: "sha1" });
    assert.throws(() => passiveAuth(old, { cscas: [csca.pem] }), (e) => e.code === "weak_hash", dsKind);
    const r = passiveAuth(old, { cscas: [csca.pem], allowSha1: true });
    assert.equal(r.weakHash, true);
    assert.equal(r.hashAlg, "sha1");
  }
  // The same chip's other checks still run when SHA-1 is allowed.
  assert.throws(() => passiveAuth(testPassport({ csca, hash: "sha1", tamper: "signature" }), { cscas: [csca.pem], allowSha1: true }), (e) => e.code === "bad_signature");
  assert.throws(() => passiveAuth(testPassport({ csca, hash: "sha1" }), { cscas: [other.pem], allowSha1: true }), (e) => e.code === "untrusted_country");
  assert.equal(passiveAuth(testPassport({ csca }), { cscas: [csca.pem] }).weakHash, false);
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
