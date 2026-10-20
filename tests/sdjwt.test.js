// SD-JWT VC (EU PID and similar): issuer chain, disclosures, key binding, and
// Token Status List revocation. Credentials are made by an independent JOSE
// library (jose) in tests/support/dcwallet.js.
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import * as jose from "jose";
import {
  verifySdJwtVc, splitSdJwt, issuerMetadataUrl, keyFromIssuerMetadata, checkStatusJwt, checkStatusCwt, statusReference, statusAt,
  jwkThumbprint, decryptJwe, ecdhKeyPair, SdJwtError, StatusError, JoseError,
} from "@humid/sdjwt";
import { encode } from "@humid/mdoc";
import { issuingAuthority } from "./support/mdl.js";
import { issueSdJwt, presentSdJwt, thumbprint } from "./support/dcwallet.js";

const AUD = "origin:https://verify.humid.test";
const NONCE = "n-0S6_WzA2Mj";
const ec = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
const x5cOf = (der) => [Buffer.from(der).toString("base64")];
const code = (c) => (e) => { assert.ok(e instanceof SdJwtError || e instanceof StatusError || e instanceof JoseError, `got ${e?.constructor?.name}: ${e?.message}`); assert.equal(e.code, c, e.message); return true; };

const PID = { family_name: "SPECIMEN", given_name: "ERIKA", birth_date: "1990-08-12", age_over_18: true, nationalities: ["DE"], address: { street_address: "HEIDESTRASSE 17", locality: "KOELN", postal_code: "51147", country: "DE" } };

async function setup(opts = {}) {
  const authority = issuingAuthority({ C: "DE", ST: "", name: "PID Provider" });
  const holder = ec();
  const holderJwk = holder.publicKey.export({ format: "jwk" });
  const cred = await issueSdJwt({ issuerKey: authority.ds.privateKey, x5c: x5cOf(authority.dsDer), claims: PID, holderJwk, ...opts });
  return { authority, holder, holderJwk, cred, trust: { roots: [authority.rootPem] } };
}

test("an EU PID as SD-JWT VC: trusted chain, only the chosen claims, bound to this request", async () => {
  const { holder, cred, trust } = await setup();
  const p = await presentSdJwt(cred, { names: ["given_name", "age_over_18"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  const r = verifySdJwtVc(p, { trust, nonce: NONCE, aud: AUD });
  assert.equal(r.vct, "urn:eudi:pid:1");
  assert.equal(r.claims.given_name, "ERIKA");
  assert.equal(r.claims.age_over_18, true);
  assert.equal(r.claims.family_name, undefined, "undisclosed claims stay hidden");
  assert.equal(r.claims.birth_date, undefined);
  assert.deepEqual(r.disclosed.sort(), ["age_over_18", "given_name"]);
  assert.equal(r.keyBinding.ok, true);
  assert.equal(r.issuer.root.subject.C, "DE");
  assert.ok(!("_sd" in r.claims) && !("_sd_alg" in r.claims));
});

test("nested disclosures (address) resolve; every disclosure must be signed and used once", async () => {
  const { holder, cred, trust } = await setup();
  const p = await presentSdJwt(cred, { names: ["address"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  const r = verifySdJwtVc(p, { trust, nonce: NONCE, aud: AUD });
  assert.equal(r.claims.address.locality, "KOELN");
  // A disclosure the issuer never signed, slipped in before the KB-JWT: the KB-JWT's sd_hash catches it.
  const forged = Buffer.from(JSON.stringify(["salt", "age_over_21", true])).toString("base64url");
  const parts = splitSdJwt(p);
  const injected = `${parts.jwt}~${[...parts.disclosures, forged].join("~")}~${parts.kb}`;
  assert.throws(() => verifySdJwtVc(injected, { trust, nonce: NONCE, aud: AUD }), code("bad_disclosure"));
  // Even with a matching sd_hash (holder colluding), an unsigned disclosure is refused.
  const colluding = await presentSdJwt({ jwt: cred.jwt, disclosures: [...cred.disclosures, forged] }, { names: ["age_over_21", "given_name"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  assert.throws(() => verifySdJwtVc(colluding, { trust, nonce: NONCE, aud: AUD }), code("bad_disclosure"));
  // The same disclosure twice.
  const twice = await presentSdJwt({ jwt: cred.jwt, disclosures: [cred.disclosures[0], cred.disclosures[0]] }, { names: [JSON.parse(Buffer.from(cred.disclosures[0], "base64url"))[1]], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  assert.throws(() => verifySdJwtVc(twice, { trust, nonce: NONCE, aud: AUD }), code("bad_disclosure"));
});

test("key binding: wrong nonce, wrong site, stale, missing, altered, or another key are all refused", async () => {
  const { holder, cred, trust } = await setup();
  const make = (o = {}) => presentSdJwt(cred, { names: ["given_name"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE, ...o });
  assert.throws(() => verifySdJwtVc("not an sd-jwt", {}), code("malformed"));
  await assert.rejects(async () => verifySdJwtVc(await make({ nonce: "other" }), { trust, nonce: NONCE, aud: AUD }), code("bad_key_binding"));
  await assert.rejects(async () => verifySdJwtVc(await make({ aud: "origin:https://evil.test" }), { trust, nonce: NONCE, aud: AUD }), code("bad_key_binding"));
  await assert.rejects(async () => verifySdJwtVc(await make({ iat: Math.floor(Date.now() / 1000) - 3600 }), { trust, nonce: NONCE, aud: AUD }), code("bad_key_binding"));
  await assert.rejects(async () => verifySdJwtVc(await make({ keyBind: false }), { trust, nonce: NONCE, aud: AUD }), code("no_key_binding"));
  await assert.rejects(async () => verifySdJwtVc(await make({ sdHashOverride: "AAAA" }), { trust, nonce: NONCE, aud: AUD }), code("bad_key_binding"));
  await assert.rejects(async () => verifySdJwtVc(await make({ holderKey: ec().privateKey }), { trust, nonce: NONCE, aud: AUD }), code("bad_signature"));
  // Without key binding, only when the caller explicitly allows it.
  const r = verifySdJwtVc(await make({ keyBind: false }), { trust, requireKeyBinding: false });
  assert.equal(r.keyBinding.ok, false);
});

test("issuer trust: untrusted root, broken chain, tampered payload, alg none and expiry are refused", async () => {
  const { holder, cred, trust } = await setup();
  const p = await presentSdJwt(cred, { names: ["given_name"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  assert.throws(() => verifySdJwtVc(p, { trust: { roots: [issuingAuthority().rootPem] }, nonce: NONCE, aud: AUD }), code("untrusted_issuer"));
  assert.throws(() => verifySdJwtVc(p, { trust: { roots: [] }, nonce: NONCE, aud: AUD }), code("no_trust"));
  assert.throws(() => verifySdJwtVc(p, { trust: { ...trust, issuers: ["https://someone-else.example"] }, nonce: NONCE, aud: AUD }), code("untrusted_issuer"));
  // Change the payload under the signature.
  const [h, body, sig] = cred.jwt.split(".");
  const payload = JSON.parse(Buffer.from(body, "base64url"));
  payload.vct = "urn:eudi:pid:other";
  const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${sig}`;
  const pt = await presentSdJwt({ jwt: tampered, disclosures: cred.disclosures }, { names: ["given_name"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  assert.throws(() => verifySdJwtVc(pt, { trust, nonce: NONCE, aud: AUD }), code("bad_signature"));
  // alg: none
  const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "dc+sd-jwt", x5c: JSON.parse(Buffer.from(h, "base64url")).x5c })).toString("base64url")}.${body}.`;
  assert.throws(() => verifySdJwtVc(`${none}~`, { trust, requireKeyBinding: false }), code("unsupported_alg"));
  // Expired
  const old = await setup({ exp: Math.floor(Date.now() / 1000) - 7200 });
  const po = await presentSdJwt(old.cred, { names: ["given_name"], holderKey: old.holder.privateKey, aud: AUD, nonce: NONCE });
  assert.throws(() => verifySdJwtVc(po, { trust: old.trust, nonce: NONCE, aud: AUD }), code("expired"));
  // Wrong typ
  const t = await setup({ typ: "JWT" });
  const ptyp = await presentSdJwt(t.cred, { names: ["given_name"], holderKey: t.holder.privateKey, aud: AUD, nonce: NONCE });
  assert.throws(() => verifySdJwtVc(ptyp, { trust: t.trust, nonce: NONCE, aud: AUD }), code("bad_type"));
});

test("a pinned issuer key (issuer metadata) instead of a certificate chain", async () => {
  const issuer = ec();
  const jwk = { ...issuer.publicKey.export({ format: "jwk" }), kid: "k1" };
  const holder = ec();
  const cred = await issueSdJwt({ issuerKey: issuer.privateKey, kid: "k1", iss: "https://issuer.example/tenant/", claims: { given_name: "ERIKA" }, holderJwk: holder.publicKey.export({ format: "jwk" }) });
  const p = await presentSdJwt(cred, { names: ["given_name"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  assert.equal(issuerMetadataUrl("https://issuer.example/tenant/"), "https://issuer.example/.well-known/jwt-vc-issuer/tenant");
  assert.equal(issuerMetadataUrl("https://issuer.example"), "https://issuer.example/.well-known/jwt-vc-issuer");
  assert.throws(() => issuerMetadataUrl("http://issuer.example"), code("bad_issuer"));
  const metadata = { issuer: "https://issuer.example/tenant/", jwks: { keys: [jwk] } };
  const resolveKey = ({ iss, header }) => keyFromIssuerMetadata(metadata, { iss, kid: header.kid });
  const r = verifySdJwtVc(p, { trust: { resolveKey }, nonce: NONCE, aud: AUD });
  assert.equal(r.issuer.pinned, true);
  assert.throws(() => keyFromIssuerMetadata({ ...metadata, issuer: "https://evil.example" }, { iss: metadata.issuer, kid: "k1" }), code("bad_issuer"));
  assert.throws(() => verifySdJwtVc(p, { trust: {}, nonce: NONCE, aud: AUD }), code("untrusted_issuer"));
});

test("JWK thumbprints match RFC 7638 (independent: jose)", async () => {
  const jwk = ec().publicKey.export({ format: "jwk" });
  assert.deepEqual([...jwkThumbprint(jwk)], [...(await thumbprint(jwk))]);
  // RFC 7638 section 3.1 example (RSA).
  const rfc = { kty: "RSA", e: "AQAB", n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" };
  assert.equal(Buffer.from(jwkThumbprint(rfc)).toString("base64url"), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
});

test("JWE ECDH-ES decrypt interoperates with jose (A128GCM and A256GCM), and refuses a key it wasn't made for", async () => {
  for (const enc of ["A128GCM", "A256GCM"]) {
    const kp = ecdhKeyPair();
    const pub = await jose.importJWK(kp.jwk, "ECDH-ES");
    const token = await new jose.CompactEncrypt(Buffer.from('{"vp_token":{}}')).setProtectedHeader({ alg: "ECDH-ES", enc, kid: kp.jwk.kid, apu: "QWxpY2U", apv: "Qm9i" }).encrypt(pub);
    assert.equal(Buffer.from(decryptJwe(token, kp)).toString(), '{"vp_token":{}}');
    assert.throws(() => decryptJwe(token, { ...ecdhKeyPair(), jwk: { ...ecdhKeyPair().jwk, kid: kp.jwk.kid } }), code("decrypt"));
  }
  const kp = ecdhKeyPair();
  const pub = await jose.importJWK(kp.jwk, "ECDH-ES+A128KW");
  const wrapped = await new jose.CompactEncrypt(Buffer.from("{}")).setProtectedHeader({ alg: "ECDH-ES+A128KW", enc: "A128GCM" }).encrypt(pub);
  assert.throws(() => decryptJwe(wrapped, kp), code("unsupported_alg"));
});

/* ---------------- Token Status List ---------------- */

/** A status list with `bits` per entry; entries: { idx: value }. */
function listBytes(bits, size, entries) {
  const b = new Uint8Array(Math.ceil((size * bits) / 8));
  for (const [i, v] of Object.entries(entries)) { const bit = Number(i) * bits; b[bit >> 3] |= v << (bit % 8); }
  return b;
}

test("status list bit order matches the draft's example (LSB first)", () => {
  // Draft example: indices 0..15 = 1,0,0,1,1,1,0,1, 1,1,0,0,0,1,0,1 → bytes 0xB9, 0xA3.
  const list = Uint8Array.of(0xb9, 0xa3);
  const want = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
  want.forEach((v, i) => assert.equal(statusAt(list, 1, i).value, v, `index ${i}`));
  const two = listBytes(2, 8, { 3: 2, 5: 1 });
  assert.equal(statusAt(two, 2, 3).status, "suspended");
  assert.equal(statusAt(two, 2, 5).status, "revoked");
  assert.equal(statusAt(two, 2, 4).status, "valid");
  assert.throws(() => statusAt(two, 2, 99), code("bad_status_ref"));
  assert.throws(() => statusAt(two, 3, 0), code("bad_status_list"));
});

test("a revoked SD-JWT VC is found revoked; a forged, stale or mismatched list is refused", async () => {
  const uri = "https://pid.example.eu/status/7";
  const { authority, holder, cred, trust } = await setup({ status: { status_list: { idx: 1234, uri } } });
  const p = await presentSdJwt(cred, { names: ["given_name"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  const r = verifySdJwtVc(p, { trust, nonce: NONCE, aud: AUD });
  const ref = statusReference(r);
  assert.deepEqual(ref, { idx: 1234, uri });
  const iat = Math.floor(Date.now() / 1000);
  const token = async ({ entries = { 1234: 1 }, sub = uri, key = authority.ds.privateKey, x5c = x5cOf(authority.dsDer), at = iat, typ = "statuslist+jwt" } = {}) =>
    new jose.SignJWT({ sub, iat: at, ttl: 43200, status_list: { bits: 1, lst: deflateSync(listBytes(1, 4096, entries)).toString("base64url") } })
      .setProtectedHeader({ alg: "ES256", typ, x5c }).sign(key);
  assert.equal((await checkStatusJwt(await token(), ref, { trust })).status, "revoked");
  assert.equal((await checkStatusJwt(await token({ entries: {} }), ref, { trust })).status, "valid");
  await assert.rejects(checkStatusJwt(await token({ sub: "https://pid.example.eu/status/8" }), ref, { trust }), code("bad_status_list"));
  await assert.rejects(checkStatusJwt(await token({ key: ec().privateKey }), ref, { trust }), code("bad_signature"));
  await assert.rejects(checkStatusJwt(await token({ at: iat - 2 * 86400 }), ref, { trust }), code("stale_status"));
  await assert.rejects(checkStatusJwt(await token({ typ: "JWT" }), ref, { trust }), code("bad_status_list"));
  assert.throws(() => statusReference({ status: { status_list: { idx: 1, uri: "http://insecure.example/s" } } }), code("bad_status_ref"));
  // A compression bomb stops at the cap.
  const bomb = await new jose.SignJWT({ sub: uri, iat, status_list: { bits: 1, lst: deflateSync(new Uint8Array(20 << 20)).toString("base64url") } }).setProtectedHeader({ alg: "ES256", typ: "statuslist+jwt", x5c: x5cOf(authority.dsDer) }).sign(authority.ds.privateKey);
  await assert.rejects(checkStatusJwt(bomb, ref, { trust }), code("bad_status_list"));
});

test("a status list as CWT (the form mdoc issuers use)", async () => {
  const authority = issuingAuthority({ C: "US", ST: "UT" });
  const uri = "https://dmv.utopia.test/status/1";
  const ref = { idx: 9, uri };
  const iat = Math.floor(Date.now() / 1000);
  const claims = encode(new Map([[2, uri], [6, iat], [65534, 43200], [65533, new Map([["bits", 2], ["lst", new Uint8Array(deflateSync(listBytes(2, 64, { 9: 2 })))]])]]));
  const { createSign } = await import("node:crypto");
  const sign1 = (payload, key) => {
    const prot = encode(new Map([[1, -7], [16, "application/statuslist+cwt"]]));
    const tbs = encode(["Signature1", prot, new Uint8Array(0), payload]);
    const s = createSign("sha256"); s.update(tbs);
    return encode([prot, new Map([[33, authority.dsDer]]), payload, new Uint8Array(s.sign({ key, dsaEncoding: "ieee-p1363" }))]);
  };
  const r = await checkStatusCwt(sign1(claims, authority.ds.privateKey), ref, { roots: [authority.rootPem] });
  assert.equal(r.status, "suspended");
  await assert.rejects(checkStatusCwt(sign1(claims, ec().privateKey), ref, { roots: [authority.rootPem] }), code("bad_signature"));
  await assert.rejects(checkStatusCwt(sign1(claims, authority.ds.privateKey), ref, { roots: [issuingAuthority().rootPem] }), code("untrusted_issuer"));
});

test("fuzz: random mutations of a valid presentation never verify and never throw anything but a coded error", async () => {
  const { holder, cred, trust } = await setup();
  const p = await presentSdJwt(cred, { names: ["given_name", "address"], holderKey: holder.privateKey, aud: AUD, nonce: NONCE });
  const seed = Number(process.env.SDJWT_FUZZ_SEED || Date.now() % 1e9);
  let x = seed;
  const rnd = (n) => { x = (x * 1103515245 + 12345) & 0x7fffffff; return x % n; };
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_~.";
  const cases = Number(process.env.SDJWT_FUZZ_CASES || 400);
  for (let i = 0; i < cases; i++) {
    const a = p.split("");
    const k = 1 + rnd(3);
    for (let j = 0; j < k; j++) a[rnd(a.length)] = alphabet[rnd(alphabet.length)];
    const m = a.join("");
    if (m === p) continue;
    try {
      verifySdJwtVc(m, { trust, nonce: NONCE, aud: AUD });
      assert.fail(`mutation verified (seed ${seed}, case ${i})`);
    } catch (e) {
      assert.ok((e instanceof SdJwtError || e instanceof JoseError) && typeof e.code === "string", `seed ${seed}, case ${i}: ${e?.constructor?.name} ${e?.message}`);
    }
  }
});
