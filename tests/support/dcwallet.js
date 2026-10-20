// A simulated wallet answering online requests (W3C Digital Credentials API):
// ISO 18013-7 Annex C (org-iso-mdoc, HPKE) and OpenID4VP (mso_mdoc and
// dc+sd-jwt, plain or encrypted with JWE). Its cryptography is independent of
// HumID's code: node:crypto for hashes and signatures, @hpke/core for HPKE,
// jose for JWS / JWE. Specimen data only.

import { createHash, sign } from "node:crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from "@hpke/core";
import * as jose from "jose";
import { encode, decode, get, Encoded } from "@humid/mdoc";

const u8 = (b) => new Uint8Array(b);
const sha256 = (b) => u8(createHash("sha256").update(b).digest());
const b64u = (b) => Buffer.from(b).toString("base64url");

/** The DeviceResponse a wallet `w` (tests/support/mdl.js) gives for `transcript`, sharing what was asked. */
export function deviceResponse(w, transcript, { docType = "org.iso.18013.5.1.mDL", want, only, cloneKey, keyFrom, mac = false } = {}) {
  const nameSpaces = new Map();
  for (const [ns, items] of get(w.issuerSigned, "nameSpaces")) {
    const asked = want ? want[ns] : null;
    const keep = items.filter((it) => { const n = get(it.value, "elementIdentifier"); return (!want || (asked && n in asked)) && (!only || only.includes(n)); });
    if (keep.length) nameSpaces.set(ns, keep);
  }
  const devNs = Encoded.of(new Map());
  const da = Encoded.of(["DeviceAuthentication", transcript, docType, devNs]).encoded;
  const prot = encode(new Map([[1, -7]]));
  const key = keyFrom || (cloneKey ? cloneKey : w.device.privateKey);
  const sig = u8(sign("sha256", encode(["Signature1", prot, new Uint8Array(0), da]), { key, dsaEncoding: "ieee-p1363" }));
  const deviceAuth = mac ? new Map([["deviceMac", [encode(new Map([[1, 5]])), new Map(), null, new Uint8Array(32)]]]) : new Map([["deviceSignature", [prot, new Map(), null, sig]]]);
  const doc = new Map([
    ["docType", docType],
    ["issuerSigned", new Map([["nameSpaces", nameSpaces], ["issuerAuth", get(w.issuerSigned, "issuerAuth")]])],
    ["deviceSigned", new Map([["nameSpaces", devNs], ["deviceAuth", deviceAuth]])],
  ]);
  return encode(new Map([["version", "1.0"], ["documents", [doc]], ["status", 0]]));
}

/** What a request asked for: { docType, want: { ns: { element: true } } }[] from a DeviceRequest. */
export function asked(deviceRequestBytes) {
  const dr = decode(deviceRequestBytes);
  return get(dr, "docRequests").map((r) => {
    const ir = get(r, "itemsRequest").value;
    const want = {};
    for (const [ns, els] of get(ir, "nameSpaces")) want[ns] = Object.fromEntries([...els].map(([k]) => [k, true]));
    return { docType: get(ir, "docType"), want, readerAuth: get(r, "readerAuth") || null, itemsRequest: get(r, "itemsRequest") };
  });
}

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

/**
 * Answer an org-iso-mdoc request as Safari / Chrome would hand it back:
 * { response: b64url(["dcapi", { enc, cipherText }]) }.
 * origin: the origin the browser saw (an attacker's page sees its own).
 */
export async function answerAnnexC(w, request, { origin, tamper, ...opts } = {}) {
  const { deviceRequest, encryptionInfo } = request.data;
  const ei = decode(Buffer.from(encryptionInfo, "base64url"));
  const rk = get(ei[1], "recipientPublicKey");
  const transcript = [null, null, ["dcapi", sha256(encode([encryptionInfo, origin]))]];
  const [first] = asked(Buffer.from(deviceRequest, "base64url"));
  const response = deviceResponse(w, transcript, { docType: first.docType, want: first.want, ...opts });
  const pub = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: b64u(get(rk, -2)), y: b64u(get(rk, -3)) }, { name: "ECDH", namedCurve: "P-256" }, true, []);
  const sender = await suite.createSenderContext({ recipientPublicKey: pub, info: Encoded.of(transcript).encoded });
  const cipherText = u8(await sender.seal(response));
  if (tamper === "cipher") cipherText[3] ^= 1;
  return { response: b64u(encode(["dcapi", new Map([["enc", u8(sender.enc)], ["cipherText", cipherText]])])) };
}

/* ---------------- SD-JWT VC issuer and holder ---------------- */

/**
 * An SD-JWT VC issuer (e.g. an EU PID provider) with an X.509 chain, and the credential it issues
 * to `holderKey`. claims are made selectively disclosable at the top level and inside `address`.
 */
export async function issueSdJwt({ issuerKey, x5c, kid, iss = "https://pid.example.eu", vct = "urn:eudi:pid:1", claims, holderJwk, status, typ = "dc+sd-jwt", exp, alg = "ES256", plain: plainClaims = {} }) {
  const disclosures = [];
  const conceal = (obj) => {
    const out = {}, sd = [];
    for (const [k, v] of Object.entries(obj)) {
      const value = v && typeof v === "object" && !Array.isArray(v) ? conceal(v) : v;
      const d = b64u(Buffer.from(JSON.stringify([b64u(crypto.getRandomValues(new Uint8Array(16))), k, value])));
      disclosures.push(d);
      sd.push(b64u(sha256(Buffer.from(d))));
    }
    out._sd = sd.sort();
    return out;
  };
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss, vct, iat: now, ...(exp !== null ? { exp: exp ?? now + 365 * 86400 } : {}), cnf: { jwk: holderJwk }, _sd_alg: "sha-256", ...plainClaims, ...conceal(claims) };
  if (status) payload.status = status;
  const header = { alg, typ, ...(x5c ? { x5c } : {}), ...(kid ? { kid } : {}) };
  const jwt = await new jose.CompactSign(Buffer.from(JSON.stringify(payload))).setProtectedHeader(header).sign(issuerKey);
  return { jwt, disclosures, sdJwt: `${jwt}~${disclosures.join("~")}~` };
}

/** The holder presents an SD-JWT VC, disclosing only `names` (top-level claim names; "address" includes its parts), with a KB-JWT. */
export async function presentSdJwt({ jwt, disclosures }, { names, holderKey, aud, nonce, iat = Math.floor(Date.now() / 1000), keyBind = true, sdHashOverride }) {
  const pick = disclosures.filter((d) => {
    const [, name] = JSON.parse(Buffer.from(d, "base64url").toString());
    return names.includes(name) || (names.includes("address") && ["street_address", "locality", "postal_code", "country"].includes(name));
  });
  const presented = `${jwt}~${pick.join("~")}~`;
  if (!keyBind) return presented;
  const sdHash = sdHashOverride || b64u(sha256(Buffer.from(presented)));
  const kb = await new jose.SignJWT({ nonce, aud, iat, sd_hash: sdHash }).setProtectedHeader({ alg: "ES256", typ: "kb+jwt" }).sign(holderKey);
  return presented + kb;
}

/* ---------------- OpenID4VP over the Digital Credentials API ---------------- */

/**
 * Answer an openid4vp-v1-unsigned request. presentations: { dcqlId: [presentation string] }.
 * When the request carries an encryption key (response_mode dc_api.jwt), the answer is a JWE.
 */
export async function answerOpenId4Vp(request, presentations, { encAlg } = {}) {
  const d = request.data;
  const vp = { vp_token: presentations };
  if (d.response_mode !== "dc_api.jwt") return vp;
  const jwk = d.client_metadata.jwks.keys[0];
  const enc = encAlg || d.client_metadata.encrypted_response_enc_values_supported?.[0] || "A128GCM";
  const key = await jose.importJWK(jwk, "ECDH-ES");
  const jwe = await new jose.CompactEncrypt(Buffer.from(JSON.stringify(vp))).setProtectedHeader({ alg: "ECDH-ES", enc, kid: jwk.kid }).encrypt(key);
  return { response: jwe };
}

/** The OpenID4VP DC API transcript, computed independently. thumbprint: raw bytes or null. */
export function oid4vpTranscript(origin, nonce, thumbprint) {
  return [null, null, ["OpenID4VPDCAPIHandover", sha256(encode([origin, nonce, thumbprint]))]];
}

/** RFC 7638 thumbprint, computed independently (jose). */
export const thumbprint = async (jwk) => u8(Buffer.from(await jose.calculateJwkThumbprint(jwk, "sha256"), "base64url"));
