// Mobile IDs (ISO/IEC 18013-5): the reader session, issuer data
// authentication against an IACA root, and mdoc device authentication, against
// a simulated issuer and wallet whose crypto is node:crypto (tests/support/mdl.js).
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  encode, decode, get, Encoded, Tagged, CborError, ReaderSession, readEngagement, bleOptions, deviceRequest, verifyDeviceResponse,
  verifyIssuerSigned, encodeIssuerSigned, readVical, parseCertificate, MDL_DOCTYPE, MDL_NS, AAMVA_NS, MdocError, SessionError,
} from "@humid/mdoc";
import { issuingAuthority, wallet, specimenMdl, issue, pem } from "./support/mdl.js";

/** One complete proximity read: QR → session → request → response → verified documents. */
function read(w, { roots, respond = {}, now } = {}) {
  const { qr } = w.engagement();
  const s = new ReaderSession(qr);
  const answer = w.respond(s.establish(deviceRequest([MDL_DOCTYPE])), respond);
  const { response } = s.receive(answer);
  return { docs: verifyDeviceResponse(response, { session: s, roots, now }), session: s, response, answer };
}
const code = (c) => (e) => { assert.ok(e instanceof MdocError || e instanceof SessionError, `got ${e?.constructor?.name}: ${e?.message}`); assert.equal(e.code, c); return true; };

test("CBOR: round trips, keeps tag-24 bytes exactly, refuses malformed input", () => {
  const v = new Map([[1, -7], ["a", [true, false, null, 1.5, new Uint8Array([1, 2])]], [-1, 2n ** 64n - 1n], [-2, -(2n ** 64n)], ["d", new Tagged(1004, "2024-01-02")]]);
  const back = decode(encode(v));
  assert.equal(get(back, 1), -7);
  assert.equal(get(back, -1), 2n ** 64n - 1n);
  assert.equal(get(back, -2), -(2n ** 64n));
  assert.throws(() => encode(2n ** 64n), CborError);
  assert.equal(get(back, "d").value, "2024-01-02");
  // A tag-24 item with a non-minimal length header is kept byte for byte.
  const inner = encode("hi");
  const odd = new Uint8Array([0xd8, 0x18, 0x59, 0x00, inner.length, ...inner]);
  const e = decode(odd);
  assert.ok(e instanceof Encoded);
  assert.deepEqual([...e.encoded], [...odd]);
  assert.deepEqual([...encode([e])].slice(1), [...odd], "re-encoding keeps the original bytes");
  assert.equal(e.value, "hi");
  // Indefinite lengths decode.
  assert.deepEqual(decode(new Uint8Array([0x9f, 0x01, 0x02, 0xff])), [1, 2]);
  assert.throws(() => decode(new Uint8Array([0xa2, 0x01, 0x01, 0x01, 0x02])), CborError, "duplicate map key");
  assert.throws(() => decode(new Uint8Array([0x82, 0x01])), CborError, "ends early");
  assert.throws(() => decode(new Uint8Array([0x01, 0x02])), CborError, "trailing bytes");
});

test("a US mobile driver's license over a full session: issuer, root and device all verify", () => {
  const authority = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
  const w = wallet({ authority });
  const { docs, session } = read(w, { roots: [authority.rootPem] });
  assert.equal(docs.length, 1);
  const d = docs[0];
  assert.equal(d.docType, MDL_DOCTYPE);
  assert.equal(d.chain, "trusted");
  assert.equal(d.root.subject.ST, "IL");
  assert.deepEqual(d.device, { method: "signature", ok: true });
  assert.equal(d.values[MDL_NS].family_name, "SPECIMEN");
  assert.equal(d.values[MDL_NS].birth_date.value, "1990-04-21");
  assert.equal(d.values[MDL_NS].issuing_jurisdiction, "US-IL");
  assert.equal(d.values[AAMVA_NS].DHS_compliance, "F");
  assert.ok(d.values[MDL_NS].portrait instanceof Uint8Array);
  assert.equal(d.values[MDL_NS].age_over_18, undefined, "HumID didn't ask for age attestations, so the wallet didn't send them");
  assert.equal(session.transcriptBytes[0], 0xd8, "SessionTranscriptBytes is tag-24 wrapped");
});

test("engagement QR: parsed, BLE options read, junk refused", () => {
  const w = wallet();
  const { qr } = w.engagement();
  const e = readEngagement(qr);
  assert.equal(e.version, "1.0");
  assert.equal(e.eDeviceKey.crvName, "P-256");
  const ble = bleOptions(e);
  assert.equal(ble.centralClient, true);
  assert.match(ble.centralUuid, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  assert.throws(() => readEngagement("https://example.com"), code("not_engagement"));
  assert.throws(() => readEngagement("mdoc:AAAA"), code("not_engagement"));
});

test("device MAC (ECDH with the reader's session key) verifies too", () => {
  const authority = issuingAuthority();
  const { docs } = read(wallet({ authority }), { roots: [authority.rootPem], respond: { mode: "mac" } });
  assert.deepEqual(docs[0].device, { method: "mac", ok: true });
});

test("copied data can't answer: wrong device key, missing device auth, or a replay into another session", () => {
  const authority = issuingAuthority();
  const w = wallet({ authority });
  assert.throws(() => read(w, { roots: [authority.rootPem], respond: { cloneKey: true } }), code("device_not_present"));
  assert.throws(() => read(w, { roots: [authority.rootPem], respond: { cloneKey: true, mode: "mac" } }), code("device_not_present"));
  assert.throws(() => read(w, { roots: [authority.rootPem], respond: { omitDeviceAuth: true } }), code("device_not_present"));

  // A genuine response, captured, then presented to a different reader session.
  const first = read(w, { roots: [authority.rootPem] });
  const other = new ReaderSession(w.engagement().qr);
  assert.throws(() => other.receive(first.answer), code("decrypt"), "another session's keys can't open it");
  assert.throws(() => verifyDeviceResponse(first.response, { session: other, roots: [authority.rootPem] }), code("device_not_present"), "nor does its device signature cover the new session");
});

test("forged or altered documents are refused", () => {
  const authority = issuingAuthority();
  assert.throws(() => read(wallet({ authority, issueOptions: { tamper: "value" } }), { roots: [authority.rootPem] }), code("data_altered"));
  assert.throws(() => read(wallet({ authority, issueOptions: { tamper: "signature" } }), { roots: [authority.rootPem] }), code("bad_signature"));
  // A signer certificate without the mdoc signer purpose.
  const wrongEku = issuingAuthority({ dsEku: ["1.3.6.1.5.5.7.3.1"] });
  assert.throws(() => read(wallet({ authority: wrongEku }), { roots: [wrongEku.rootPem] }), code("bad_signature"));
  // Asked for an mDL, got something else.
  const other = wallet({ authority, docType: "org.example.card" });
  const s = new ReaderSession(other.engagement().qr);
  const { response } = s.receive(other.respond(s.establish(deviceRequest([MDL_DOCTYPE]))));
  assert.throws(() => verifyDeviceResponse(response, { session: s, roots: [authority.rootPem], docType: MDL_DOCTYPE }), code("doc_type"));
});

test("trust: only issuers whose IACA root HumID trusts, from the matching country", () => {
  const authority = issuingAuthority();
  const stranger = issuingAuthority({ name: "Elsewhere DMV" });
  const w = wallet({ authority });
  assert.throws(() => read(w, { roots: [stranger.rootPem] }), code("untrusted_issuer"));
  // Same name, different key: the root's signature decides, not its name.
  const twin = issuingAuthority();
  assert.throws(() => read(w, { roots: [twin.rootPem] }), code("untrusted_issuer"));
  assert.throws(() => read(w, { roots: [] }), code("no_trust"));
  assert.equal(read(w).docs[0].chain, "unchecked", "without roots the issuer is never reported as trusted");
  // A state's root vouching for another country's document.
  const data = specimenMdl({ C: "US", ST: "UT" });
  data[MDL_NS].issuing_country = "CA";
  assert.throws(() => read(wallet({ authority, data }), { roots: [authority.rootPem] }), code("untrusted_issuer"));
  // …or another state's.
  const data2 = specimenMdl({ C: "US", ST: "UT" });
  data2[MDL_NS].issuing_jurisdiction = "US-NV";
  assert.throws(() => read(wallet({ authority, data: data2 }), { roots: [authority.rootPem] }), code("untrusted_issuer"));
});

test("validity: lapsed or not-yet-valid issuer signatures are refused", () => {
  const authority = issuingAuthority();
  const day = 86400e3;
  const lapsed = wallet({ authority, issueOptions: { validFrom: new Date(Date.now() - 20 * day), validUntil: new Date(Date.now() - day) } });
  assert.throws(() => read(lapsed, { roots: [authority.rootPem] }), code("signature_expired"));
  const early = wallet({ authority, issueOptions: { validFrom: new Date(Date.now() + day), validUntil: new Date(Date.now() + 9 * day) } });
  assert.throws(() => read(early, { roots: [authority.rootPem] }), code("not_yet_valid"));
});

test("selective disclosure: fewer elements still verify, and the stored copy re-verifies later", () => {
  const authority = issuingAuthority();
  const w = wallet({ authority });
  const { docs } = read(w, { roots: [authority.rootPem], respond: { only: ["family_name", "given_name", "birth_date", "expiry_date", "issuing_country", "DHS_compliance"] } });
  assert.deepEqual(Object.keys(docs[0].values[MDL_NS]).sort(), ["birth_date", "expiry_date", "family_name", "given_name", "issuing_country"]);
  const kept = encodeIssuerSigned(docs[0].issuerSigned);
  const again = verifyIssuerSigned(decode(kept), { docType: MDL_DOCTYPE, roots: [authority.rootPem] });
  assert.equal(again.values[MDL_NS].family_name, "SPECIMEN");
  assert.equal(again.chain, "trusted");
});

test("an EU digital identity (PID) document verifies through the same path", () => {
  const authority = issuingAuthority({ C: "DE", ST: null, name: "Bundesdruckerei Test" });
  const data = { "eu.europa.ec.eudi.pid.1": { family_name: "MUSTERMANN", given_name: "ERIKA", birth_date: new Tagged(1004, "1964-08-12"), issuing_country: "DE", expiry_date: new Tagged(1004, "2031-01-01"), nationality: "DE" } };
  const w = wallet({ authority, data, docType: "eu.europa.ec.eudi.pid.1" });
  const s = new ReaderSession(w.engagement().qr);
  const { response } = s.receive(w.respond(s.establish(deviceRequest(["eu.europa.ec.eudi.pid.1"]))));
  const [d] = verifyDeviceResponse(response, { session: s, roots: [authority.rootPem] });
  assert.equal(d.values["eu.europa.ec.eudi.pid.1"].family_name, "MUSTERMANN");
  assert.equal(d.chain, "trusted");
});

test("VICAL: a signed list of issuing-authority roots is read and its signature checked", () => {
  const a = issuingAuthority({ ST: "IL" }), b = issuingAuthority({ ST: "UT" });
  const provider = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const providerAuthority = issuingAuthority({ name: "Test VICAL Provider" });
  // Sign the VICAL with the provider's DS key; its certificate is in x5chain.
  const vical = new Map([["version", "1.0"], ["vicalProvider", "Test DTS"], ["date", new Tagged(0, "2026-10-01T00:00:00Z")],
    ["certificateInfos", [a, b].map((x) => new Map([["certificate", x.rootDer], ["docType", [MDL_DOCTYPE]], ["issuingCountry", "US"], ["stateOrProvinceName", x.ST]]))]]);
  const payload = encode(vical);
  const prot = encode(new Map([[1, -7]]));
  const sig = sign("sha256", encode(["Signature1", prot, new Uint8Array(0), payload]), { key: providerAuthority.ds.privateKey, dsaEncoding: "ieee-p1363" });
  const signed = encode([prot, new Map([[33, providerAuthority.dsDer]]), payload, new Uint8Array(sig)]);
  const list = readVical(signed, { providerRoots: [providerAuthority.rootDer] });
  assert.equal(list.provider, "Test DTS");
  assert.deepEqual(list.certificates.map((c) => c.state), ["IL", "UT"]);
  assert.equal(parseCertificate(list.certificates[0].der).subject.ST, "IL");
  assert.throws(() => readVical(signed, { providerRoots: [a.rootDer] }), /trusted provider/);
  const bad = decode(signed); bad[3][3] ^= 1;
  assert.throws(() => readVical(encode(bad)), /doesn't verify/);
  void provider;
});

/* ---------------- into the vault record, and as a recovery anchor ---------------- */

import { newRecord, applyMdoc, applyAamva, parseAamva, provenance, title, summary, encodeRecord, decodeRecord } from "@humid/idscan";
import { mdocAuth, mdocAnchorOf, mdocAnchorSummary } from "@humid/anchor";
import { randomBytes } from "node:crypto";
import { recheckMdocRecord } from "@humid/creds";

const b64 = (u) => Buffer.from(u).toString("base64");

test("record: a verified mobile license fills the same fields as the barcode, and outranks it", () => {
  const authority = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
  const { docs } = read(wallet({ authority }), { roots: [authority.rootPem] });
  const rec = newRecord("driver_license");
  applyMdoc(rec, docs[0], { b64, keep: encodeIssuerSigned(docs[0].issuerSigned) });
  assert.equal(rec.kind, "driver_license");
  assert.deepEqual(
    { surname: rec.fields.surname, given: rec.fields.given, suffix: rec.fields.suffix, birth: rec.fields.birth, sex: rec.fields.sex, issuer: rec.fields.issuer, region: rec.fields.region, expiry: rec.fields.expiry, number: rec.fields.number },
    { surname: "SPECIMEN", given: "JANE QUINN", suffix: "JR", birth: "1990-04-21", sex: "F", issuer: "USA", region: "IL", expiry: "2032-04-21", number: "D1234567" },
  );
  assert.equal(rec.fields.vehicleClass, "D", "AAMVA's US class wins over the international category");
  assert.equal(rec.fields.restrictions, "B");
  assert.equal(rec.fields.endorsements, "M");
  assert.equal(rec.fields.realId, true);
  assert.equal(rec.fields.height, "5′6″ (168 cm)");
  assert.equal(rec.fields.weight, "134 lb");
  assert.equal(rec.fields.organDonor, true);
  assert.deepEqual(rec.address, { street: "123 MAIN ST", street2: "", city: "SPRINGFIELD", region: "IL", postalCode: "62701", country: "USA" });
  assert.equal(rec.images.portrait.type, "image/jpeg");
  assert.equal(provenance(rec).level, "mdoc-unchecked", "stored flags alone don't earn the label (APP-05)");
  assert.equal(provenance(rec, { mdoc: recheckMdocRecord(rec, { roots: [authority.rootPem] }) }).level, "mdoc");
  assert.equal(provenance(rec, { mdoc: recheckMdocRecord(rec) }).level, "mdoc-unchecked", "signature fine, root not checked");
  const altered = structuredClone(rec); altered.fields.surname = "MALLORY";
  assert.equal(provenance(altered, { mdoc: recheckMdocRecord(altered, { roots: [authority.rootPem] }) }).level, "mdoc-mismatch");
  const other = issuingAuthority({ C: "US", ST: "IL", name: "Not Illinois" });
  assert.equal(provenance(rec, { mdoc: recheckMdocRecord(rec, { roots: [other.rootPem] }) }).level, "mdoc-mismatch");
  const stripped = structuredClone(rec); delete stripped.raw.mdoc;
  assert.equal(provenance(stripped, { mdoc: recheckMdocRecord(stripped, { roots: [authority.rootPem] }) }).level, "mdoc-mismatch");
  assert.equal(title(rec), "Driver's license · Illinois");
  assert.deepEqual(summary(rec), { kind: "driver_license", issuer: "USA", region: "IL", expiry: "2032-04-21" });
  // The barcode afterwards doesn't overwrite what the issuer signed.
  const before = rec.fields.surname;
  rec.source.surname = "mdoc";
  const fake = parseAamva("@\n\x1e\rANSI 636035090002DL00410278ZI03190008DLDCSOTHERNAME\nDACJANE\nDBB04211990\nDBA04212032\nDAQD1234567\nDCGUSA\nDAJIL\n");
  assert.ok(fake, "the specimen barcode parses");
  applyAamva(rec, fake);
  assert.equal(rec.fields.surname, before);
  // The record round-trips through sealing's encoding, with the issuer's signed data kept.
  const back = decodeRecord(encodeRecord(rec));
  assert.ok(back.raw.mdoc.issuerSigned.length > 100);
  assert.equal(back.verified.mdoc.chain, "trusted");
});

test("record: a state ID (no driving privileges) is an ID card; an unchecked root says so", () => {
  const authority = issuingAuthority();
  const data = specimenMdl();
  data["org.iso.18013.5.1"].driving_privileges = [];
  delete data["org.iso.18013.5.1.aamva"].domestic_driving_privileges;
  const { docs } = read(wallet({ authority, data }));
  const rec = applyMdoc(newRecord(), docs[0], { b64 });
  assert.equal(rec.kind, "id_card");
  assert.equal(provenance(rec).level, "mdoc-unchecked");
});

test("anchor: the server, as reader, accepts a live mobile ID from a trusted state and derives a renewal-stable anchor", () => {
  const authority = issuingAuthority({ C: "US", ST: "IL" });
  const key = randomBytes(32);
  const run = (w, opts = {}) => {
    const s = new ReaderSession(w.engagement().qr);           // the server's own ephemeral key
    const answer = w.respond(s.establish(deviceRequest([MDL_DOCTYPE])), opts); // relayed by the app
    return mdocAuth(s.receive(answer).response, { session: s, iacas: [authority.rootPem] });
  };
  const ok = run(wallet({ authority }));
  assert.equal(ok.identity.surname, "SPECIMEN");
  assert.equal(ok.device, "signature");
  assert.deepEqual(mdocAnchorSummary(ok.identity), { document: "mobile ID", country: "US", region: "IL" });
  // A renewed license (new number, new expiry, new device key) anchors the same.
  const renewed = specimenMdl({ C: "US", ST: "IL" });
  renewed["org.iso.18013.5.1"].document_number = "D7654321";
  renewed["org.iso.18013.5.1"].expiry_date = new Tagged(1004, "2036-04-21");
  assert.equal(mdocAnchorOf(run(wallet({ authority, data: renewed })).identity, key), mdocAnchorOf(ok.identity, key));
  // Copied data, an untrusted state, a lapsed license, or no live session: refused.
  assert.throws(() => run(wallet({ authority }), { cloneKey: true }), (e) => e.code === "device_not_present");
  const other = issuingAuthority({ C: "US", ST: "IL", name: "Impostor" });
  assert.throws(() => run(wallet({ authority: other })), (e) => e.code === "untrusted_country");
  const old = specimenMdl({ C: "US", ST: "IL" });
  old["org.iso.18013.5.1"].expiry_date = new Tagged(1004, "2020-01-01");
  assert.throws(() => run(wallet({ authority, data: old })), (e) => e.code === "expired");
  assert.throws(() => mdocAuth(new Uint8Array(), { iacas: [authority.rootPem] }), (e) => e.code === "no_chip_proof");
  assert.throws(() => mdocAuth(new Uint8Array(), { session: {}, iacas: [] }), (e) => e.code === "no_trust");
});

/* ---------------- CRD-01: who the issuer speaks for comes from the trust anchor ---------------- */

test("CRD-01: a trusted root can't vouch for another state's or country's license", () => {
  const il = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
  const forWi = (authority) => specimenMdl({ C: "US", ST: "WI" });
  // An Illinois root signing a license that says it's from Wisconsin.
  assert.throws(() => read(wallet({ authority: il, data: forWi(il) }), { roots: [il.rootPem] }), code("untrusted_issuer"));
  // A root that names no state can't confirm any state claim.
  const noState = issuingAuthority({ C: "US", ST: null, name: "Somewhere" });
  assert.throws(() => read(wallet({ authority: noState, data: specimenMdl({ C: "US", ST: "IL" }) }), { roots: [noState.rootPem] }), code("untrusted_issuer"));
  // ... unless the trust list that vouches for it says which state it speaks for.
  const { docs } = read(wallet({ authority: noState, data: specimenMdl({ C: "US", ST: "IL" }) }), { roots: [{ cert: noState.rootPem, country: "US", state: "IL", source: "vical" }] });
  assert.equal(docs[0].chain, "trusted");
  assert.equal(docs[0].state, "IL");
  assert.equal(docs[0].country, "US");
  assert.equal(docs[0].root.source, "vical");
  // The list and the certificate must agree when both say.
  assert.throws(() => read(wallet({ authority: il }), { roots: [{ cert: il.rootPem, country: "US", state: "WI" }] }), code("untrusted_issuer"));
  assert.throws(() => read(wallet({ authority: il }), { roots: [{ cert: il.rootPem, country: "CA" }] }), code("untrusted_issuer"));
  // A root trusted only for other document types.
  assert.throws(() => read(wallet({ authority: il }), { roots: [{ cert: il.rootPem, docTypes: ["eu.europa.ec.eudi.pid.1"] }] }), code("untrusted_issuer"));
  assert.equal(read(wallet({ authority: il }), { roots: [{ cert: il.rootPem, docTypes: [MDL_DOCTYPE] }] }).docs[0].state, "IL");
  // A document signer whose own subject names another state.
  const crossed = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS", dsSubject: { C: "US", ST: "WI", CN: "WI DS" } });
  assert.throws(() => read(wallet({ authority: crossed }), { roots: [crossed.rootPem] }), code("untrusted_issuer"));
  // A country claim with no state claim still has to match.
  const data = specimenMdl({ C: "US", ST: "IL" });
  delete data["org.iso.18013.5.1"].issuing_jurisdiction;
  data["org.iso.18013.5.1"].issuing_country = "CA";
  assert.throws(() => read(wallet({ authority: il, data }), { roots: [il.rootPem] }), code("untrusted_issuer"));
  // A root that names no country at all isn't usable.
  const nowhere = issuingAuthority({ C: null, ST: null, name: "Nowhere" });
  const d2 = specimenMdl({ C: "US", ST: "IL" }); delete d2["org.iso.18013.5.1"].issuing_country; delete d2["org.iso.18013.5.1"].issuing_jurisdiction;
  assert.throws(() => read(wallet({ authority: nowhere, data: d2 }), { roots: [nowhere.rootPem] }), code("untrusted_issuer"));
});

test("CRD-01 (review): a country or state claim in any namespace is held to the anchor", () => {
  const device = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey;
  const il = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
  for (const [ns, el] of [["org.iso.23220.1", { issuing_country: "CA" }], ["eu.europa.ec.eudi.pid.1", { issuing_country: "FR" }], ["org.iso.18013.5.1.aamva", { issuing_jurisdiction: "US-WI" }]]) {
    // Straight through issuer data authentication, whatever a reader asked for.
    const data = { ...specimenMdl({ C: "US", ST: "IL" }), [ns]: el };
    assert.throws(() => verifyIssuerSigned(issue(il, data, device), { roots: [il.rootPem] }), code("untrusted_issuer"), ns);
  }
  assert.equal(verifyIssuerSigned(issue(il, specimenMdl({ C: "US", ST: "IL" }), device), { roots: [il.rootPem] }).state, "IL");
  // A decoy mDL namespace with no country doesn't hide the claim in another one.
  const decoy = { "org.iso.18013.5.1": { family_name: "X" }, "eu.europa.ec.eudi.pid.1": { issuing_country: "FR" } };
  assert.throws(() => verifyIssuerSigned(issue(il, decoy, device), { roots: [il.rootPem] }), code("untrusted_issuer"));
});
