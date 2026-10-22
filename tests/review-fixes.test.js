// Regression tests for the independent security review of v4/credentials
// (2026-10-21). Each test is the reviewer's attack, now refused. F1, F2 (ICAO
// master lists) are in tests/creds.test.js; F3, F4 (SD-JWT issuer trust) and the
// VICAL checks (F6) are in tests/sdjwt.test.js and tests/mdoc.test.js.
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign, createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import * as jose from "jose";
import { SessionTranscript } from "@owf/mdoc";
import {
  encode, decode, get, Encoded, Tagged, annexCTranscript, annexCRequest, annexCOpen, openid4vpDcApiTranscript, openid4vpRedirectTranscript, hpkeSeal, verifyDeviceResponse, MdocError,
} from "@humid/mdoc";
import { checkStatusCwt, checkStatusJwt, SdJwtError, StatusError, JoseError } from "@humid/sdjwt";
import { credentialRequest, verifyCredentialResponse, minimise, checkCommitment, iacaFromVical, CredsError } from "@humid/creds";
import { verifyPassportChip } from "@humid/creds/server";
import { issuingAuthority, wallet } from "./support/mdl.js";
import { answerAnnexC, deviceResponse } from "./support/dcwallet.js";
import { testCsca, testPassport } from "./support/passport.js";

const ORIGIN = "https://verify.humid.test";
const sha256 = (b) => new Uint8Array(createHash("sha256").update(b).digest());
const ctx = { crypto: { digest: async ({ bytes }) => sha256(bytes) } };
const code = (c) => (e) => { assert.ok(e instanceof CredsError || e instanceof MdocError || e instanceof StatusError || e instanceof SdJwtError || e instanceof JoseError, `got ${e?.constructor?.name}: ${e?.message}`); assert.equal(e.code, c, e.message); return true; };

test("I1: session transcripts and the HPKE info match an independent implementation (@owf/mdoc)", async () => {
  const ei = "gmVkY2FwaaJlbm9uY2VYIPlv505ZK3Y93ZZhO-Wi4HqqHWHismrehHtGtNx3fxOx";
  const theirs = await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url: ei, origin: ORIGIN }, ctx);
  // Annex C's HPKE info is the transcript's plain CBOR encoding; ours must be byte for byte the same.
  assert.deepEqual([...encode(annexCTranscript(ei, ORIGIN))], [...theirs.encode()]);
  const tp = sha256(new Uint8Array([1, 2, 3]));
  const o = await SessionTranscript.forOid4VpDcApi({ origin: ORIGIN, nonce: "n-123", jwkThumbprint: tp }, ctx);
  assert.deepEqual([...encode(openid4vpDcApiTranscript({ origin: ORIGIN, nonce: "n-123", jwkThumbprint: tp }))], [...o.encode()]);
  const on = await SessionTranscript.forOid4VpDcApi({ origin: ORIGIN, nonce: "n-123", jwkThumbprint: null }, ctx);
  assert.deepEqual([...encode(openid4vpDcApiTranscript({ origin: ORIGIN, nonce: "n-123" }))], [...on.encode()]);
  // And an answer sealed the way @owf/mdoc seals it (info = its transcript bytes) opens here.
  const { request, state } = annexCRequest([{ docType: "org.iso.18013.5.1.mDL", nameSpaces: { "org.iso.18013.5.1": { age_over_21: false } } }], { origin: ORIGIN });
  const info = (await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url: request.data.encryptionInfo, origin: ORIGIN }, ctx)).encode();
  const { enc, ciphertext } = hpkeSeal(state.keyPair.publicKey, new TextEncoder().encode("DeviceResponse"), { info });
  const opened = annexCOpen(state, { response: Buffer.from(encode(["dcapi", new Map([["enc", enc], ["cipherText", ciphertext]])])).toString("base64url") });
  assert.equal(new TextDecoder().decode(opened.response), "DeviceResponse");
  const r = await SessionTranscript.forOid4Vp({ clientId: "x509_san_dns:verify.humid.test", nonce: "n", jwkThumbprint: tp, responseUri: "https://verify.humid.test/cb" }, ctx);
  assert.deepEqual([...encode(openid4vpRedirectTranscript({ clientId: "x509_san_dns:verify.humid.test", nonce: "n", jwkThumbprint: tp, responseUri: "https://verify.humid.test/cb" }))], [...r.encode()]);
});

/** Encrypt an arbitrary DeviceResponse to an Annex C request, as anyone can (the key is in the request). */
function hostileAnswer(request, deviceResponseBytes) {
  const { encryptionInfo } = request.data;
  const rk = get(decode(Buffer.from(encryptionInfo, "base64url"))[1], "recipientPublicKey");
  const pub = new Uint8Array([4, ...get(rk, -2), ...get(rk, -3)]);
  const { enc, ciphertext } = hpkeSeal(pub, deviceResponseBytes, { info: encode(annexCTranscript(encryptionInfo, ORIGIN)) });
  return { response: Buffer.from(encode(["dcapi", new Map([["enc", enc], ["cipherText", ciphertext]])])).toString("base64url") };
}

test("F5: malformed but well-encrypted answers give coded refusals, never raw exceptions", async () => {
  const authority = issuingAuthority({ C: "US", ST: "IL" });
  const trust = { iaca: [authority.rootPem] };
  const doc = (issuerSigned) => new Map([["docType", "org.iso.18013.5.1.mDL"], ["issuerSigned", issuerSigned], ["deviceSigned", new Map()]]);
  const bad = [
    encode(new Map([["version", "1.0"], ["documents", "abc"], ["status", 0]])),
    encode(new Map([["version", "1.0"], ["documents", [doc(new Map([["issuerAuth", 5]]))]], ["status", 0]])),
    encode(new Map([["version", "1.0"], ["documents", [doc(new Map([["issuerAuth", [new Uint8Array([0xff]), new Map(), new Uint8Array(1), new Uint8Array(64)]]]))]], ["status", 0]])),
    encode(new Map([["version", "1.0"], ["documents", [doc(5)]], ["status", 0]])),
    encode(new Map([["version", "1.0"], ["documents", [5]], ["status", 0]])),
    encode([1, 2, 3]),
    new Uint8Array([0xa1]),
  ];
  for (const [i, b] of bad.entries()) {
    const { request, state } = credentialRequest({ types: ["mdl"], ask: "identity", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
    assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: hostileAnswer(request.digital.requests[0], b) }, { trust }),
      (e) => e instanceof CredsError && typeof e.code === "string", `case ${i}`);
  }
  // A huge date in documentErrors doesn't crash the verifier (it's only reported).
  const w = wallet({ authority });
  const { request, state } = credentialRequest({ types: ["mdl"], ask: "age_over_21", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
  const t = annexCTranscript(request.digital.requests[0].data.encryptionInfo, ORIGIN);
  const good = decode(deviceResponse(w, t, { want: { "org.iso.18013.5.1": { age_over_21: true } } }));
  good.set("documentErrors", [new Map([["x", new Tagged(1, 1e300)]])]);
  const [r] = verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: hostileAnswer(request.digital.requests[0], encode(good)) }, { trust });
  assert.equal(r.claims.age_over_21, true);
  // Server: non-byte chip input is a bad request, not a Node error code.
  const csca = testCsca();
  const p = testPassport({ csca, aaKind: "ec" });
  assert.throws(() => verifyPassportChip(p, { cscas: [csca.pem], active: { nonce: new Uint8Array(8), signature: 12345 } }), code("bad_request"));
  assert.throws(() => verifyPassportChip(null, { cscas: [csca.pem] }), code("bad_request"));
});

test("F7: a Document Signer without the mobile ID key usage or the signing bit, or a CA as signer, is refused", async () => {
  for (const opts of [{ dsEku: [] }, { dsKu: [6, 0x40] }]) {
    const authority = issuingAuthority({ C: "US", ST: "IL", ...opts });
    const w = wallet({ authority });
    const { request, state } = credentialRequest({ types: ["mdl"], ask: "age_over_21", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
    const a = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN });
    assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: a }, { trust: { iaca: [authority.rootPem] } }), code("bad_signature"), JSON.stringify(opts));
  }
});

test("F9: a photo ID claiming another country than its issuer's root is refused; the reported country is the root's", async () => {
  const ut = issuingAuthority({ C: "US", ST: "UT", name: "Utopia Photo ID" });
  const data = (country) => ({ "org.iso.23220.1": { given_name_unicode: "JANE", family_name_unicode: "SPECIMEN", birth_date: new Tagged(1004, "1990-04-21"), issuing_country: country, age_over_21: true } });
  const ask = async (country, ask = ["given_name", "issuing_country"]) => {
    const w = wallet({ authority: ut, docType: "org.iso.23220.photoid.1", data: data(country) });
    const { request, state } = credentialRequest({ types: ["photoid"], ask, origin: ORIGIN, protocols: ["org-iso-mdoc"] });
    const a = await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN, docType: "org.iso.23220.photoid.1" });
    return () => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: a }, { trust: { iaca: [ut.rootPem] } });
  };
  assert.throws(await ask("CA"), code("untrusted_issuer"));
  const [ok] = (await ask("US"))();
  assert.equal(ok.issuer.country, "US");
  // The holder withholds issuing_country: the claim still says the root's country, never one the document asserts.
  const [quiet] = (await ask("CA", ["age_over_21"]))();
  assert.equal(quiet.issuer.country, "US");
  assert.equal(minimise(quiet, { share: ["issuing_country"] }).facts.issuing_country, "US");
});

test("F8: status lists need a sound chain (no CA leaf, valid root) and, through creds, the credential's own root", async () => {
  const a = issuingAuthority({ C: "US", ST: "UT" });
  const other = issuingAuthority({ C: "US", ST: "UT", name: "Other" });
  const uri = "https://dmv.utopia.test/status/1";
  const ref = { idx: 1, uri };
  const iat = Math.floor(Date.now() / 1000);
  const claims = encode(new Map([[2, uri], [6, iat], [65533, new Map([["bits", 1], ["lst", new Uint8Array(deflateSync(new Uint8Array(4)))]])]]));
  const cwt = (key, chain) => {
    const prot = encode(new Map([[1, -7], [16, "application/statuslist+cwt"]]));
    const sig = nodeSign("sha256", encode(["Signature1", prot, new Uint8Array(0), claims]), { key, dsaEncoding: "ieee-p1363" });
    return encode([prot, new Map([[33, chain.length === 1 ? chain[0] : chain]]), claims, new Uint8Array(sig)]);
  };
  assert.equal((await checkStatusCwt(cwt(a.ds.privateKey, [a.dsDer]), ref, { roots: [a.rootPem] })).status, "valid");
  // The root itself (a CA certificate) as the list's signer.
  await assert.rejects(checkStatusCwt(cwt(a.root.privateKey, [a.rootDer]), ref, { roots: [a.rootPem] }), code("bad_chain"));
  // Another trusted issuer's list for this credential.
  const fp = (await import("@humid/mdoc")).parseCertificate(a.rootDer).fingerprint;
  await assert.rejects(checkStatusCwt(cwt(other.ds.privateKey, [other.dsDer]), ref, { roots: [a.rootPem, other.rootPem], root: fp }), code("untrusted_issuer"));
  assert.equal((await checkStatusCwt(cwt(a.ds.privateKey, [a.dsDer]), ref, { roots: [a.rootPem, other.rootPem], root: fp })).status, "valid");
  const jwt = await new jose.SignJWT({ sub: uri, iat, status_list: { bits: 1, lst: deflateSync(new Uint8Array(4)).toString("base64url") } })
    .setProtectedHeader({ alg: "ES256", typ: "statuslist+jwt", x5c: [Buffer.from(other.dsDer).toString("base64")] }).sign(other.ds.privateKey);
  await assert.rejects(checkStatusJwt(jwt, ref, { trust: { roots: [a.rootPem, other.rootPem] }, root: fp }), code("untrusted_issuer"));
});

test("F10: a claim's commitment is salted, so the same facts never commit to the same value", async () => {
  const authority = issuingAuthority({ C: "US", ST: "IL" });
  const w = wallet({ authority });
  const results = [];
  for (let i = 0; i < 2; i++) {
    const { request, state } = credentialRequest({ types: ["mdl"], ask: ["birth_date"], origin: ORIGIN, protocols: ["org-iso-mdoc"] });
    [results[i]] = verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data: await answerAnnexC(w, request.digital.requests[0], { origin: ORIGIN }) }, { trust: { iaca: [authority.rootPem] } });
  }
  const persona = "HC-7F3K-QM4T-9ZXA-B2C1-R8W0";
  const now = new Date("2026-10-21T12:00:00Z");
  const c1 = minimise(results[0], { share: ["birth_date"], identifying: true, persona, now });
  const c2 = minimise(results[1], { share: ["birth_date"], identifying: true, persona, now });
  assert.equal(c1.salt.length, 64);
  assert.notEqual(c1.commitment, c2.commitment);
  assert.ok(checkCommitment(c1) && checkCommitment(c2));
  assert.ok(!checkCommitment({ ...c1, salt: c2.salt }));
});

test("F6 through creds: a VICAL needs its provider, a VICAL signer, and freshness; rollbacks are refused", () => {
  const provider = issuingAuthority({ name: "DTS", dsEku: ["1.0.18013.5.1.8"], dsKu: [6, 0x40] });
  const il = issuingAuthority({ ST: "IL" });
  const make = ({ date = new Date(Date.now() - 86400e3), next, id = 3, key = provider.ds.privateKey, cert = provider.dsDer } = {}) => {
    const t = (d) => new Tagged(0, d.toISOString().replace(/\.\d+Z$/, "Z"));
    const v = new Map([["version", "1.0"], ["vicalProvider", "DTS"], ["date", t(date)], ["vicalIssueID", id], ...(next ? [["nextUpdate", t(next)]] : []),
      ["certificateInfos", [new Map([["certificate", il.rootDer], ["docType", ["org.iso.18013.5.1.mDL"]], ["issuingCountry", "US"], ["stateOrProvinceName", "IL"]])]]]);
    const payload = encode(v), prot = encode(new Map([[1, -7]]));
    const sig = nodeSign("sha256", encode(["Signature1", prot, new Uint8Array(0), payload]), { key, dsaEncoding: "ieee-p1363" });
    return encode([prot, new Map([[33, cert]]), payload, new Uint8Array(sig)]);
  };
  const roots = [provider.rootDer];
  assert.equal(iacaFromVical(make(), { providerRoots: roots }).length, 1);
  assert.throws(() => iacaFromVical(make(), { providerRoots: [] }), code("no_trust"));
  assert.throws(() => iacaFromVical(make({ next: new Date(Date.now() - 3600e3) }), { providerRoots: roots }), code("stale_vical"));
  assert.throws(() => iacaFromVical(make({ date: new Date(Date.now() - 800 * 86400e3) }), { providerRoots: roots }), code("stale_vical"));
  assert.throws(() => iacaFromVical(make({ id: 2 }), { providerRoots: roots, minIssueId: 3 }), code("stale_vical"));
  assert.throws(() => iacaFromVical(make({ key: il.ds.privateKey, cert: il.dsDer }), { providerRoots: [il.rootDer] }), code("bad_signature"));
  assert.throws(() => iacaFromVical(new Uint8Array([1, 2, 3]), { providerRoots: roots }), code("bad_vical"));
});

test("CI fuzz find (2026-10-21): a signature re-encoded with non-zero unused trailing bits is refused, not tolerated", async () => {
  const { verifySdJwtVc, unb64u } = await import("@humid/sdjwt");
  const { fromBase64url } = await import("@humid/mdoc");
  const { issueSdJwt, presentSdJwt } = await import("./support/dcwallet.js");
  const a = issuingAuthority({ C: "DE", ST: "", name: "P", dsSan: ["pid.example.eu"] });
  const h = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const cred = await issueSdJwt({ issuerKey: a.ds.privateKey, x5c: [Buffer.from(a.dsDer).toString("base64")], claims: { given_name: "E" }, holderJwk: h.publicKey.export({ format: "jwk" }) });
  const p = await presentSdJwt(cred, { names: ["given_name"], holderKey: h.privateKey, aud: "A", nonce: "N" });
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  // ES256: 64 bytes → 86 characters, the last carrying 4 unused bits. Same bytes, different text.
  const sib = (str) => { const i = A.indexOf(str.at(-1)); return str.slice(0, -1) + A[(i & ~15) | ((i + 1) & 15)]; };
  assert.equal(verifySdJwtVc(p, { trust: { roots: [a.rootPem] }, nonce: "N", aud: "A" }).keyBinding.ok, true);
  assert.throws(() => verifySdJwtVc(sib(p), { trust: { roots: [a.rootPem] }, nonce: "N", aud: "A" }), (e) => e.code === "malformed");
  const parts = p.split("~"); parts[0] = sib(parts[0]);
  assert.throws(() => verifySdJwtVc(parts.join("~"), { trust: { roots: [a.rootPem] }, nonce: "N", aud: "A" }), (e) => e.code === "malformed");
  assert.throws(() => unb64u("QR"), (e) => e.code === "malformed");
  assert.deepEqual([...unb64u("QQ")], [65]);
  assert.throws(() => fromBase64url("QR"), (e) => e.code === "bad_response");
});
