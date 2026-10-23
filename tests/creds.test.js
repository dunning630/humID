// @humid/creds end to end: Digital Credentials API requests and answers
// (ISO 18013-7 Annex C and OpenID4VP 1.0) for mobile licenses, EU PID (mdoc
// and SD-JWT VC); passport chips and ICAO master lists (server); license
// barcodes; minimised claims; SSN. The wallets in tests/support/dcwallet.js use
// independent crypto (node:crypto, @hpke/core, jose).
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, sign as nodeSign, verify as nodeVerify, createPublicKey } from "node:crypto";
import { deflateSync } from "node:zlib";
import * as jose from "jose";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { p256 } from "@noble/curves/nist.js";
import {
  credentialRequest, verifyCredentialResponse, checkStatus, fromLicenseBarcode, minimise, checkCommitment, ageOn, checkSsnFormat, ecbsvVerifier,
  claimsFor, CATALOG, TYPES, CredsError, REQUEST_TTL_MS, iacaFromVical,
} from "@humid/creds";
import { verifyPassportChip, cscasFromMasterList } from "@humid/creds/server";
import { hpkeKeyPair, hpkeOpen, hpkeSeal, encode, decode, get, Encoded, annexCRequest, readEncryptionInfo, openid4vpRedirectTranscript, MDL_DOCTYPE } from "@humid/mdoc";
import { issuingAuthority, wallet, specimenMdl } from "./support/mdl.js";
import { answerAnnexC, answerOpenId4Vp, deviceResponse, asked, oid4vpTranscript, thumbprint, issueSdJwt, presentSdJwt } from "./support/dcwallet.js";
import { testCsca, testPassport } from "./support/passport.js";
import { masterList } from "./support/masterlist.js";
import { seq, set, octet, int, oid, explicit, certificate, ecKeys, extension, keyUsage, name as nameOf } from "./support/pki.js";

const ORIGIN = "https://verify.humid.test";
const code = (c) => (e) => { assert.ok(e instanceof CredsError, `got ${e?.constructor?.name}: ${e?.message}`); assert.equal(e.code, c, e.message); return true; };
const b64u = (b) => Buffer.from(b).toString("base64url");
const sha256 = (b) => new Uint8Array(createHash("sha256").update(b).digest());

function illinois() {
  const authority = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
  return { authority, w: wallet({ authority }), trust: { iaca: [authority.rootPem] } };
}

/* ---------------- HPKE ---------------- */

test("HPKE (RFC 9180, DHKEM P-256 / HKDF-SHA256 / AES-128-GCM) interoperates with @hpke/core both ways", async () => {
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  const kp = hpkeKeyPair();
  const jwk = { kty: "EC", crv: "P-256", x: b64u(kp.publicKey.slice(1, 33)), y: b64u(kp.publicKey.slice(33)) };
  const info = new TextEncoder().encode("SessionTranscript");
  const pub = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
  const sender = await suite.createSenderContext({ recipientPublicKey: pub, info });
  const ct = new Uint8Array(await sender.seal(new TextEncoder().encode("DeviceResponse")));
  assert.equal(new TextDecoder().decode(hpkeOpen(kp, new Uint8Array(sender.enc), ct, { info })), "DeviceResponse");
  assert.throws(() => hpkeOpen(kp, new Uint8Array(sender.enc), ct, { info: new TextEncoder().encode("other") }), (e) => e.code === "decrypt");
  const priv = await crypto.subtle.importKey("jwk", { ...jwk, d: b64u(kp.secretKey) }, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const { enc, ciphertext } = hpkeSeal(kp.publicKey, new TextEncoder().encode("back"), { info });
  const r = await suite.createRecipientContext({ recipientKey: priv, enc: enc.slice().buffer, info });
  assert.equal(new TextDecoder().decode(await r.open(ciphertext)), "back");
});

/* ---------------- ISO 18013-7 Annex C (org-iso-mdoc) ---------------- */

test("Annex C: a mobile license through the browser picker verifies, sharing only what was asked", async () => {
  const { w, trust } = illinois();
  const { request, state } = credentialRequest({ types: ["mdl"], ask: "age_over_21", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
  assert.equal(request.mediation, "required");
  const entry = request.digital.requests[0];
  assert.equal(entry.protocol, "org-iso-mdoc");
  const [want] = asked(Buffer.from(entry.data.deviceRequest, "base64url"));
  assert.deepEqual(want.want, { "org.iso.18013.5.1": { age_over_21: true } }, "asks for one element, nothing else");
  const answer = await answerAnnexC(w, entry, { origin: ORIGIN });
  const [r] = verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: answer }, { trust });
  assert.equal(r.type, "mdl");
  assert.equal(r.assurance, "issuer+holder");
  assert.equal(r.claims.age_over_21, true);
  assert.equal(r.claims.family_name, undefined, "nothing beyond the ask");
  assert.equal(r.issuer.root.ST, "IL");
});

test("Annex C: a phishing site relaying the request, a replay, a timeout, tampering and copied data all fail", async () => {
  const { w, trust } = illinois();
  const make = () => credentialRequest({ types: ["mdl"], ask: "identity", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
  // The wallet answers on the attacker's origin: the browser puts that origin in the transcript.
  let { request, state } = make();
  const relayed = await answerAnnexC(w, request.digital.requests[0], { origin: "https://verify-humid.evil.test" });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: relayed }, { trust }), code("decrypt"));
  // Replay of a good answer.
  ({ request, state } = make());
  const good = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN });
  verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: good }, { trust });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: good }, { trust }), code("replayed"));
  // Too late.
  ({ request, state } = make());
  const late = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: late }, { trust, now: new Date(Date.now() + REQUEST_TTL_MS + 1000) }), code("expired_request"));
  // Ciphertext flipped.
  ({ request, state } = make());
  const flipped = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN, tamper: "cipher" });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: flipped }, { trust }), code("decrypt"));
  // The issuer's data copied to another phone: its key isn't the one in the MSO.
  ({ request, state } = make());
  const cloned = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN, cloneKey: ecKeys().privateKey });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: cloned }, { trust }), code("device_not_present"));
  // A MAC can't be checked online (no reader key): refused, not skipped.
  ({ request, state } = make());
  const mac = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN, mac: true });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: mac }, { trust }), code("device_not_present"));
});

test("Annex C: issuer trust is required; signature-only only when explicitly allowed, and never without the device proof", async () => {
  const { w } = illinois();
  let { request, state } = credentialRequest({ types: ["mdl"], ask: "identity", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
  let a = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: a }, { trust: { iaca: [issuingAuthority().rootPem] } }), code("untrusted_issuer"));
  ({ request, state } = credentialRequest({ types: ["mdl"], ask: "identity", origin: ORIGIN, protocols: ["org-iso-mdoc"] }));
  a = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: a }, { trust: {} }), code("no_trust"));
  ({ request, state } = credentialRequest({ types: ["mdl"], ask: "identity", origin: ORIGIN, protocols: ["org-iso-mdoc"] }));
  a = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN });
  const [r] = verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: a }, { allowUntrustedIssuer: true });
  assert.equal(r.assurance, "signature-only");
  assert.equal(r.claims.family_name, "SPECIMEN");
});

test("Annex C: a document type that wasn't asked for is refused", async () => {
  const { authority } = illinois();
  const photo = wallet({ authority, docType: "org.iso.23220.photoid.1", data: { "org.iso.23220.1": { given_name_unicode: "JANE" } } });
  const { request, state } = credentialRequest({ types: ["mdl"], ask: ["given_name"], origin: ORIGIN, protocols: ["org-iso-mdoc"] });
  // A wallet that ignores the request and sends its photo ID instead.
  const entry = request.digital.requests[0];
  const forged = { ...entry, data: { ...entry.data, deviceRequest: b64u(encode(new Map([["version", "1.0"], ["docRequests", [new Map([["itemsRequest", Encoded.of(new Map([["docType", "org.iso.23220.photoid.1"], ["nameSpaces", new Map([["org.iso.23220.1", new Map([["given_name_unicode", false]])]])]]))]])]]]))) } };
  const a = await answerAnnexC(photo, forged, { origin: ORIGIN });
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: a }, { trust: { iaca: [authority.rootPem] } }), code("doc_type"));
});

test("Annex C with ReaderAuth: the request carries a reader signature over the transcript and what it asks", () => {
  const reader = issuingAuthority({ C: "US", ST: "IL", name: "HumID Reader", dsEku: ["1.0.18013.5.1.6"] });
  const secretKey = new Uint8Array(Buffer.from(reader.ds.privateKey.export({ format: "jwk" }).d, "base64url"));
  const { request, state } = annexCRequest([{ docType: MDL_DOCTYPE, nameSpaces: { "org.iso.18013.5.1": { age_over_21: false } } }], { origin: ORIGIN, readerAuth: { key: { curve: p256, secretKey }, chain: [reader.dsDer] } });
  const [r] = asked(Buffer.from(request.data.deviceRequest, "base64url"));
  assert.ok(r.readerAuth, "readerAuth present");
  const [prot, unprot, payload, sig] = r.readerAuth;
  assert.equal(payload, null, "detached");
  assert.deepEqual([...get(unprot, 33)], [...reader.dsDer]);
  // Verify independently: ReaderAuthenticationBytes over the Annex C transcript the wallet computes itself.
  const transcript = [null, null, ["dcapi", sha256(encode([request.data.encryptionInfo, ORIGIN]))]];
  const ra = Encoded.of(["ReaderAuthentication", transcript, r.itemsRequest]).encoded;
  const tbs = encode(["Signature1", prot, new Uint8Array(0), ra]);
  assert.ok(nodeVerify("sha256", tbs, { key: reader.ds.publicKey, dsaEncoding: "ieee-p1363" }, sig));
  assert.equal(readEncryptionInfo(request.data.encryptionInfo).recipientPublicKey.crvName, "P-256");
  assert.ok(state.keyPair.secretKey instanceof Uint8Array);
});

/* ---------------- OpenID4VP 1.0 over the Digital Credentials API ---------------- */

test("OpenID4VP: one request offers mdl, EU PID mdoc and PID SD-JWT; an encrypted mdoc answer verifies", async () => {
  const { w, trust } = illinois();
  const { request, state } = credentialRequest({ types: ["mdl", "pid_mdoc", "pid_sdjwt"], ask: "identity", origin: ORIGIN });
  const [oid, ...annex] = request.digital.requests;
  assert.equal(oid.protocol, "openid4vp-v1-unsigned");
  assert.equal(annex.length, 2, "an Annex C entry per mdoc type, sharing one key");
  assert.equal(annex[0].data.encryptionInfo, annex[1].data.encryptionInfo);
  const d = oid.data;
  assert.equal(d.response_mode, "dc_api.jwt");
  assert.deepEqual(d.dcql_query.credentials.map((c) => c.id), ["mdl", "pid_mdoc", "pid_sdjwt"]);
  assert.deepEqual(d.dcql_query.credential_sets, [{ options: [["mdl"], ["pid_mdoc"], ["pid_sdjwt"]] }]);
  assert.deepEqual(d.dcql_query.credentials[0].meta, { doctype_value: MDL_DOCTYPE });
  assert.deepEqual(d.dcql_query.credentials[0].claims[0], { path: ["org.iso.18013.5.1", "given_name"], intent_to_retain: false });
  assert.deepEqual(d.dcql_query.credentials[2].claims.find((c) => c.path[0] === "birthdate"), { path: ["birthdate"] });
  assert.ok(!("d" in d.client_metadata.jwks.keys[0]), "no private key in the request");
  // The wallet computes the transcript itself: origin, nonce and the key's thumbprint.
  const tp = await thumbprint(d.client_metadata.jwks.keys[0]);
  const transcript = oid4vpTranscript(ORIGIN, d.nonce, tp);
  const want = { "org.iso.18013.5.1": Object.fromEntries(d.dcql_query.credentials[0].claims.map((c) => [c.path[1], true])) };
  const pres = b64u(deviceResponse(w, transcript, { want }));
  const answer = await answerOpenId4Vp(oid, { mdl: [pres] });
  assert.ok(typeof answer.response === "string" && answer.response.split(".").length === 5, "a compact JWE");
  const [r] = verifyCredentialResponse(state, { protocol: "openid4vp-v1-unsigned", data: answer }, { trust });
  assert.equal(r.type, "mdl");
  assert.equal(r.protocol, "openid4vp");
  assert.equal(r.assurance, "issuer+holder");
  assert.equal(r.claims.birth_date, "1990-04-21");
  assert.equal(r.claims.issuing_jurisdiction, "US-IL");
});

test("OpenID4VP: transcripts for another nonce, origin or key; unencrypted answers; unasked ids are refused", async () => {
  const { w, trust } = illinois();
  const run = async (mut, opts = {}) => {
    const { request, state } = credentialRequest({ types: ["mdl"], ask: "age_over_18", origin: ORIGIN, protocols: ["openid4vp"] });
    const d = request.digital.requests[0].data;
    const tp = await thumbprint(d.client_metadata.jwks.keys[0]);
    const t = mut.transcript ? mut.transcript(d, tp) : oid4vpTranscript(ORIGIN, d.nonce, tp);
    const pres = b64u(deviceResponse(w, t, { want: { "org.iso.18013.5.1": { age_over_18: true } } }));
    let answer = await answerOpenId4Vp(request.digital.requests[0], { [mut.id || "mdl"]: [pres] });
    if (mut.plain) answer = { vp_token: { mdl: [pres] } };
    return () => verifyCredentialResponse(state, { protocol: "openid4vp-v1-unsigned", data: answer }, { trust, ...opts });
  };
  assert.equal((await run({}))()[0].claims.age_over_18, true);
  assert.throws(await run({ transcript: (d, tp) => oid4vpTranscript(ORIGIN, "other-nonce", tp) }), code("device_not_present"));
  assert.throws(await run({ transcript: (d, tp) => oid4vpTranscript("https://evil.test", d.nonce, tp) }), code("device_not_present"));
  assert.throws(await run({ transcript: (d) => oid4vpTranscript(ORIGIN, d.nonce, null) }), code("device_not_present"));
  assert.throws(await run({ transcript: (d, tp) => openid4vpRedirectTranscript({ clientId: "x", nonce: d.nonce, jwkThumbprint: tp, responseUri: "https://x" }) }), code("device_not_present"));
  assert.throws(await run({ plain: true }), code("not_encrypted"));
  assert.throws(await run({ id: "pid_sdjwt" }), code("bad_response"));
});

test("OpenID4VP: an EU PID as SD-JWT VC, bound to origin: and the nonce, with age from age_equal_or_over", async () => {
  const pidAuthority = issuingAuthority({ C: "DE", ST: "", name: "PID Provider", dsSan: ["pid.example.eu"] });
  const holder = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const cred = await issueSdJwt({
    issuerKey: pidAuthority.ds.privateKey, x5c: [Buffer.from(pidAuthority.dsDer).toString("base64")], holderJwk: holder.publicKey.export({ format: "jwk" }),
    claims: { given_name: "ERIKA", family_name: "SPECIMEN", birthdate: "1964-08-12", age_equal_or_over: { 18: true, 21: true }, issuing_country: "DE" },
  });
  const trust = { sdjwt: { roots: [pidAuthority.rootPem] } };
  const { request, state } = credentialRequest({ types: ["pid_sdjwt"], ask: "age_over_18", origin: ORIGIN, protocols: ["openid4vp"] });
  const d = request.digital.requests[0].data;
  assert.deepEqual(d.dcql_query.credentials[0].claims, [{ path: ["age_equal_or_over", "18"] }]);
  const pres = await presentSdJwt(cred, { names: ["age_equal_or_over", "18"], holderKey: holder.privateKey, aud: `origin:${ORIGIN}`, nonce: d.nonce });
  const answer = await answerOpenId4Vp(request.digital.requests[0], { pid_sdjwt: [pres] });
  const [r] = verifyCredentialResponse(state, { protocol: "openid4vp-v1-unsigned", data: answer }, { trust });
  assert.equal(r.type, "pid_sdjwt");
  assert.equal(r.assurance, "issuer+holder");
  assert.equal(r.claims.age_over_18, true);
  assert.equal(r.claims.given_name, undefined);
  // The same presentation made for another site's audience.
  const again = credentialRequest({ types: ["pid_sdjwt"], ask: "age_over_18", origin: ORIGIN, protocols: ["openid4vp"] });
  const bad = await presentSdJwt(cred, { names: ["age_equal_or_over", "18"], holderKey: holder.privateKey, aud: "origin:https://evil.test", nonce: again.request.digital.requests[0].data.nonce });
  const ans2 = await answerOpenId4Vp(again.request.digital.requests[0], { pid_sdjwt: [bad] });
  assert.throws(() => verifyCredentialResponse(again.state, { protocol: "openid4vp-v1-unsigned", data: ans2 }, { trust }), code("bad_key_binding"));
});

test("revocation through creds: a revoked credential is found revoked and can't back a 'valid document' claim", async () => {
  const pidAuthority = issuingAuthority({ C: "DE", ST: "", name: "PID Provider", dsSan: ["pid.example.eu"] });
  const holder = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const uri = "https://pid.example.eu/status/1";
  const cred = await issueSdJwt({
    issuerKey: pidAuthority.ds.privateKey, x5c: [Buffer.from(pidAuthority.dsDer).toString("base64")], holderJwk: holder.publicKey.export({ format: "jwk" }),
    claims: { birthdate: "1964-08-12", date_of_expiry: "2031-01-01" }, status: { status_list: { idx: 3, uri } },
  });
  const trust = { sdjwt: { roots: [pidAuthority.rootPem] } };
  const { request, state } = credentialRequest({ types: ["pid_sdjwt"], ask: ["birth_date", "expiry_date"], origin: ORIGIN, protocols: ["openid4vp"] });
  const d = request.digital.requests[0].data;
  const pres = await presentSdJwt(cred, { names: ["birthdate", "date_of_expiry"], holderKey: holder.privateKey, aud: `origin:${ORIGIN}`, nonce: d.nonce });
  const [r] = verifyCredentialResponse(state, { protocol: "openid4vp-v1-unsigned", data: await answerOpenId4Vp(request.digital.requests[0], { pid_sdjwt: [pres] }) }, { trust });
  assert.deepEqual(r.statusRef, { idx: 3, uri });
  const list = new Uint8Array(16); list[0] = 1 << 3;
  const token = await new jose.SignJWT({ sub: uri, iat: Math.floor(Date.now() / 1000), status_list: { bits: 1, lst: deflateSync(list).toString("base64url") } })
    .setProtectedHeader({ alg: "ES256", typ: "statuslist+jwt", x5c: [Buffer.from(pidAuthority.dsDer).toString("base64")] }).sign(pidAuthority.ds.privateKey);
  let fetched = null;
  const s = await checkStatus(r, { fetchList: async (u) => { fetched = u; return token; }, trust });
  assert.equal(fetched, uri);
  assert.equal(s.status, "revoked");
  assert.equal(minimise(r, { share: ["valid_document", "age_over_21"] }).facts.valid_document, false);
});

/* ---------------- minimised claims ---------------- */

test("minimise: only the facts asked for, ages derived when not stated, identifying facts need consent, commitment binds a persona", async () => {
  const { w, trust } = illinois();
  const { request, state } = credentialRequest({ types: ["mdl"], ask: "vault", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
  const [r] = verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN }) }, { trust });
  const now = new Date("2026-10-20T12:00:00Z");
  // This license names no status list: "valid document" rests on its expiry date alone, so it must be asked for and is stated.
  assert.throws(() => minimise(r, { share: ["valid_document"], now }), code("unchecked"));
  await checkStatus(r, {});
  assert.throws(() => minimise(r, { share: ["valid_document"], now }), code("unchecked"));
  const c = minimise(r, { share: ["age_over_21", "age_over_65", "valid_document", "issuing_jurisdiction"], allowUnchecked: true, now });
  assert.deepEqual(c.facts, { age_over_21: true, age_over_65: false, valid_document: true, issuing_jurisdiction: "US-IL" });
  assert.deepEqual(c.basis.valid_document, { expiry: c.basis.valid_document.expiry, revocation: "no-list", holder: "proven" });
  assert.deepEqual(c.derived, ["age_over_21", "age_over_65"], "the vault ask doesn't include age flags, so they come from the birth date");
  assert.equal(c.assurance, "issuer+holder");
  assert.ok(!JSON.stringify(c).includes("SPECIMEN") && !JSON.stringify(c).includes("D1234567"), "no name, no number");
  assert.throws(() => minimise(r, { share: ["family_name"] }), code("identifying"));
  assert.equal(minimise(r, { share: ["family_name"], identifying: true }).facts.family_name, "SPECIMEN");
  assert.throws(() => minimise(r, { share: ["portrait"], identifying: true }), code("bad_request"));
  const persona = "HC-7F3K-QM4T-9ZXA-B2C1-R8W0";
  const bound = minimise(r, { share: ["age_over_21"], persona, now });
  assert.equal(bound.commitment.length, 64);
  assert.ok(checkCommitment(bound));
  assert.ok(!checkCommitment({ ...bound, facts: { age_over_21: false } }));
  assert.ok(!checkCommitment({ ...bound, persona: "HC-0000-0000-0000-0000-0000" }));
  assert.throws(() => minimise(r, { share: ["age_over_21"], persona: "not-a-persona" }), code("bad_request"));
  assert.equal(ageOn("2005-10-21", now), 20);
  assert.equal(ageOn("2005-10-20", now), 21);
});

test("CREDS-05: valid_document is never asserted when revocation wasn't checked or the holder wasn't proven, unless asked and stated", async () => {
  const csca = testCsca("Utopia");
  const now = new Date();
  // A passport chip with no Active Authentication key: issuer-signed, but the data could be a copy.
  const r = verifyPassportChip(testPassport({ csca, aaKind: null }), { cscas: [csca.pem], now });
  assert.equal(r.holderBound, false);
  assert.equal(r.status, null, "revocation never consulted");
  assert.throws(() => minimise(r, { share: ["valid_document"], now }), code("unchecked"));
  // A passport has no status list; even checked, the basis is still weaker than "valid".
  await checkStatus(r, {});
  assert.throws(() => minimise(r, { share: ["valid_document"], now }), code("unchecked"));
  const weak = minimise(r, { share: ["valid_document"], allowUnchecked: true, now, persona: "HC-7F3K-QM4T-9ZXA-B2C1-R8W0" });
  assert.equal(weak.facts.valid_document, true);
  assert.equal(weak.assurance, "issuer");
  assert.deepEqual(weak.basis.valid_document, { expiry: "2034-12-31", revocation: "no-list", holder: "not-proven" });
  assert.ok(checkCommitment(weak), "the basis is inside the commitment");
  assert.ok(!checkCommitment({ ...weak, basis: { valid_document: { ...weak.basis.valid_document, holder: "proven" } } }), "and can't be upgraded afterwards");
  // A negative answer needs no status check: once expired, the document is simply not valid.
  assert.equal(minimise(r, { share: ["valid_document"], now: new Date("2035-06-01T00:00:00Z") }).facts.valid_document, false);
  // An answer from the issuer that isn't valid, revoked or suspended can't back it either way.
  const odd = { ...r, holderBound: true, status: { status: "application-specific" } };
  assert.throws(() => minimise(odd, { share: ["valid_document"], allowUnchecked: true, now }), code("not_available"));
});

/* ---------------- license barcode ---------------- */

test("a physical license barcode is read, labelled 'printed', and can't back a claim", () => {
  const barcode = "@\n\x1e\rANSI 636035100002DL00410278ZI03190008DLDAQD1234567\nDCSSPECIMEN\nDACJANE\nDADQ\nDBB04211990\nDBA04212032\nDBD02012024\nDBC2\nDAJIL\nDCGUSA\nDAYBRO\nDAU066 in\nDAG123 MAIN ST\nDAISPRINGFIELD\nDAK62701\nDCF0000000000\nDCK00000000000\nDDEN\nDDFN\nDDGN\nZIZIA\n";
  const r = fromLicenseBarcode(barcode);
  assert.equal(r.assurance, "printed");
  assert.equal(r.claims.family_name, "SPECIMEN");
  assert.equal(r.claims.birth_date, "1990-04-21");
  assert.equal(r.issuer.jurisdiction, "IL");
  assert.throws(() => minimise(r, { share: ["age_over_21"] }), code("not_verified"));
  assert.throws(() => fromLicenseBarcode("hello"), code("bad_document"));
});

/* ---------------- passports (server) ---------------- */

test("passport chip through creds/server: passive + active authentication → issuer+holder; no AA key → issuer only", () => {
  const csca = testCsca();
  const p = testPassport({ csca, aaKind: "ec" });
  const nonce = new Uint8Array(8).fill(7);
  const r = verifyPassportChip(p, { cscas: [csca.pem], active: { nonce, signature: p.answer(nonce) } });
  assert.equal(r.type, "passport_chip");
  assert.equal(r.assurance, "issuer+holder");
  assert.equal(r.claims.family_name, "ERIKSSON");
  assert.equal(r.claims.birth_date, "1974-08-12");
  assert.equal(r.claims.expiry_date, "2034-12-31");
  assert.equal(minimise(r, { share: ["age_over_21"] }).facts.age_over_21, true);
  assert.throws(() => verifyPassportChip(p, { cscas: [csca.pem] }), code("no_chip_proof"));
  assert.throws(() => verifyPassportChip(p, { cscas: [csca.pem], active: { nonce, signature: p.answer(new Uint8Array(8)) } }), code("chip_not_present"));
  assert.throws(() => verifyPassportChip(p, { cscas: [testCsca().pem], active: { nonce, signature: p.answer(nonce) } }), code("untrusted_country"));
  const noAa = testPassport({ csca, aaKind: null });
  const r2 = verifyPassportChip(noAa, { cscas: [csca.pem] });
  assert.equal(r2.assurance, "issuer");
  assert.equal(r2.holderBound, false);
});

test("ICAO master list: CSCAs vouched for by a trusted publisher; a tampered list or another publisher is refused", () => {
  const publisher = testCsca("Test Publisher CSCA", "DE");
  const uto = testCsca("Utopia CSCA", "UT");
  const other = testCsca("Other CSCA", "FR");
  const ml = masterList({ publisher, cscas: [uto, other] });
  const cscas = cscasFromMasterList(ml, { publisherCscas: [publisher.pem] });
  assert.equal(cscas.length, 2);
  const p = testPassport({ csca: uto, aaKind: null });
  assert.equal(verifyPassportChip(p, { cscas }).assurance, "issuer", "a passport checks against a CSCA from the list");
  assert.throws(() => cscasFromMasterList(ml, { publisherCscas: [testCsca("X", "DE").pem] }), code("untrusted_country"));
  assert.throws(() => cscasFromMasterList(masterList({ publisher, cscas: [uto, other], tamper: true }), { publisherCscas: [publisher.pem] }), code("data_altered"));
  assert.throws(() => cscasFromMasterList(ml, { publisherCscas: [] }), code("no_trust"));
  // Review F1: a certificate under the publisher's CSCA without the master list signer key usage
  // (for example one of its passport Document Signers) can't publish a list.
  const evil = testCsca("Attacker CSCA", "UT");
  assert.throws(() => cscasFromMasterList(masterList({ publisher, cscas: [evil], eku: false }), { publisherCscas: [publisher.pem] }), code("bad_signature"));
  // Review F2: no SHA-1 signatures.
  assert.throws(() => cscasFromMasterList(masterList({ publisher, cscas: [uto], sha1: true }), { publisherCscas: [publisher.pem] }), code("unsupported"));
});

/* ---------------- SSN ---------------- */

test("SSN: structure only, or eCBSV for a permitted entity with consent; the number never appears in results or errors", async () => {
  assert.deepEqual(checkSsnFormat("123-45-6789"), { valid: true, reason: null });
  for (const bad of ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000", "078-05-1120", "12345678", "abc-de-fghi"]) assert.equal(checkSsnFormat(bad).valid, false, bad);
  await assert.rejects(ecbsvVerifier().verify({ ssn: "123-45-6789" }), code("not_permitted"));
  const consent = { method: "electronic", signedAt: "2026-10-20T15:00:00Z", text: "I authorize SSA to verify my SSN to …" };
  let sent = null;
  const v = ecbsvVerifier({ permittedEntity: true, send: async (req) => { sent = req; return { match: false, mismatched: ["dateOfBirth", "junk"], deceased: false }; } });
  await assert.rejects(v.verify({ ssn: "123-45-6789", firstName: "JANE", lastName: "SPECIMEN", dateOfBirth: "1990-04-21" }), code("no_consent"));
  await assert.rejects(v.verify({ ssn: "666-45-6789", firstName: "JANE", lastName: "SPECIMEN", dateOfBirth: "1990-04-21", consent }), code("bad_ssn"));
  const r = await v.verify({ ssn: "123-45-6789", firstName: "JANE", lastName: "SPECIMEN", dateOfBirth: "1990-04-21", consent });
  assert.equal(sent.ssn, "123456789");
  assert.deepEqual(r.mismatched, ["dateOfBirth"]);
  assert.equal(r.match, false);
  assert.ok(!JSON.stringify(r).includes("6789"), "the result carries no part of the number");
  const failing = ecbsvVerifier({ permittedEntity: true, send: async () => { throw new Error("SSA said no for 123456789"); } });
  await assert.rejects(failing.verify({ ssn: "123-45-6789", firstName: "J", lastName: "S", dateOfBirth: "1990-04-21", consent }), (e) => e.code === "registry_unavailable" && !/\d{4}/.test(e.message));
});

/* ---------------- catalog, requests, fuzz ---------------- */

test("catalog and request building: every type and purpose maps; bad asks and origins are refused", () => {
  for (const t of Object.keys(TYPES)) assert.ok(CATALOG.find((c) => c.id === t));
  assert.ok(CATALOG.find((c) => c.id === "ssn").where.includes("eCBSV"));
  assert.throws(() => claimsFor(["shoe_size"]), code("bad_request"));
  assert.throws(() => credentialRequest({ origin: "http://evil.test" }), (e) => e.code === "bad_origin");
  assert.throws(() => credentialRequest({ types: ["pid_sdjwt"], ask: ["issuing_jurisdiction"], origin: ORIGIN }), code("bad_request"));
  const { request } = credentialRequest({ types: ["mdl"], ask: "age_over_18", origin: "http://localhost:5173" });
  assert.equal(request.digital.requests.length, 2);
});

test("fuzz: random corruption of an Annex C answer gives a coded error, never a crash or a pass", async () => {
  const { w, trust } = illinois();
  const seed = Number(process.env.CREDS_FUZZ_SEED || Date.now() % 1e9);
  let x = seed;
  const rnd = (n) => { x = (x * 1103515245 + 12345) & 0x7fffffff; return x % n; };
  const cases = Number(process.env.CREDS_FUZZ_CASES || 60);
  for (let i = 0; i < cases; i++) {
    const { request, state } = credentialRequest({ types: ["mdl"], ask: "identity", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
    const a = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN });
    const bytes = Buffer.from(a.response, "base64url");
    for (let k = 0; k < 1 + rnd(4); k++) bytes[rnd(bytes.length)] ^= 1 + rnd(255);
    try {
      verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: { response: bytes.toString("base64url") } }, { trust });
      assert.fail(`corruption verified (seed ${seed}, case ${i})`);
    } catch (e) {
      assert.ok(e instanceof CredsError && typeof e.code === "string", `seed ${seed}, case ${i}: ${e?.constructor?.name} ${e?.message}`);
    }
  }
});
