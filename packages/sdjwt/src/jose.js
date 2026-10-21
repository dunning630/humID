// The JOSE pieces a verifier needs, in plain JavaScript (noble), so it runs in
// the app as well as on the server:
//
//   JWS compact   verify only; alg allow-list ES256 / ES384 / ES512 / EdDSA.
//                 "none" and anything else are refused before a key is used.
//   JWK           EC (P-256/384/521) and OKP (Ed25519) public keys; RFC 7638
//                 thumbprints.
//   x5c           a JWS header certificate chain, checked against trusted
//                 roots with @humid/mdoc's X.509 code (ECDSA certificates).
//   JWE compact   decrypt only: ECDH-ES (direct key agreement, Concat KDF)
//                 with A128GCM or A256GCM, P-256. That is what OpenID4VP's
//                 dc_api.jwt responses use. A fresh key per request.

import { p256, p384, p521 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { parseCertificate, issuedBy } from "@humid/mdoc";

export class JoseError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, m) => { throw new JoseError(code, m); };

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

export const b64u = (b) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
export function unb64u(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) fail("malformed", "Not base64url.");
  if (s.length % 4 === 1) fail("malformed", "Not base64url.");
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  let out;
  try { out = Uint8Array.from(atob(t + "===".slice((t.length + 3) % 4)), (c) => c.charCodeAt(0)); }
  catch { fail("malformed", "Not base64url."); }
  // Canonical only: unused trailing bits must be zero, so no two strings decode to the same bytes.
  if (b64u(out) !== s) fail("malformed", "Not canonical base64url.");
  return out;
}
const unb64 = (s) => { try { return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); } catch { fail("malformed", "A certificate in x5c isn't base64."); } };
export const jsonOf = (s, what = "token") => { try { return JSON.parse(td.decode(unb64u(s))); } catch (e) { if (e instanceof JoseError) throw e; fail("malformed", `The ${what} isn't valid JSON.`); } };
const cat = (...p) => { const o = new Uint8Array(p.reduce((s, x) => s + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);

const ALGS = {
  ES256: { curve: p256, hash: sha256, crv: "P-256", size: 32 },
  ES384: { curve: p384, hash: sha384, crv: "P-384", size: 48 },
  ES512: { curve: p521, hash: sha512, crv: "P-521", size: 66 },
  EdDSA: { curve: ed25519, crv: "Ed25519", size: 32 },
};
export const SUPPORTED_ALGS = Object.keys(ALGS);
const CURVE_BY_CRV = { "P-256": p256, "P-384": p384, "P-521": p521 };

/** A public JWK → { crv, curve, publicKey } (SEC1 uncompressed or raw Ed25519). Private parts are refused. */
export function jwkKey(jwk) {
  if (!isObj(jwk)) fail("bad_key", "The key isn't a JWK.");
  if ("d" in jwk) fail("bad_key", "A private key was sent where a public key belongs.");
  if (jwk.kty === "EC") {
    const curve = CURVE_BY_CRV[jwk.crv];
    if (!curve) fail("bad_key", `Curve ${jwk.crv} isn't supported.`);
    const x = unb64u(jwk.x), y = unb64u(jwk.y);
    const n = curve.lengths?.secretKey ?? Math.ceil(curve.Point.Fn.BITS / 8);
    if (x.length !== n || y.length !== n) fail("bad_key", "The key's coordinates are the wrong size.");
    const publicKey = cat(Uint8Array.of(4), x, y);
    try { curve.Point.fromBytes(publicKey); } catch { fail("bad_key", "The key isn't a point on its curve."); }
    return { crv: jwk.crv, curve, publicKey };
  }
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    const x = unb64u(jwk.x);
    if (x.length !== 32) fail("bad_key", "Malformed Ed25519 key.");
    return { crv: "Ed25519", curve: ed25519, publicKey: x };
  }
  fail("bad_key", `Key type ${jwk.kty} isn't supported.`);
}

/** RFC 7638 JWK thumbprint (SHA-256), raw 32 bytes. */
export function jwkThumbprint(jwk) {
  const members = jwk.kty === "EC" ? { crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y }
    : jwk.kty === "OKP" ? { crv: jwk.crv, kty: "OKP", x: jwk.x }
    : jwk.kty === "RSA" ? { e: jwk.e, kty: "RSA", n: jwk.n } : fail("bad_key", "Can't take the thumbprint of this key.");
  return sha256(te.encode(JSON.stringify(members)));
}

/** A certificate's key in the shape jwkKey returns (ECDSA certificates only). */
const certKey = (cert) => {
  if (!cert._curve) fail("unsupported", "The issuer's certificate key type isn't supported.");
  return { crv: cert.curve, curve: cert._curve, publicKey: cert.publicKey };
};

/** Split and decode a compact JWS. Nothing is trusted yet. */
export function parseJws(token) {
  if (typeof token !== "string") fail("malformed", "The token isn't text.");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]*$/.test(p))) fail("malformed", "The token isn't a compact JWS.");
  const header = jsonOf(parts[0], "token header");
  const payload = jsonOf(parts[1], "token payload");
  if (!isObj(header) || !isObj(payload)) fail("malformed", "The token's header or payload isn't an object.");
  if (header.crit !== undefined) fail("unsupported", "The token has critical header parameters HumID doesn't understand.");
  return { header, payload, signingInput: te.encode(`${parts[0]}.${parts[1]}`), signature: unb64u(parts[2]) };
}

/** Verify a parsed JWS with a key from jwkKey / certKey. alg must be allow-listed AND match the key. */
export function verifyJwsWith(jws, key, { algs = SUPPORTED_ALGS } = {}) {
  const alg = jws.header.alg;
  if (!algs.includes(alg) || !ALGS[alg]) fail("unsupported_alg", `Signature algorithm ${alg} isn't accepted.`);
  const a = ALGS[alg];
  if (a.crv !== key.crv) fail("bad_signature", "The signature algorithm doesn't match the key.");
  let ok = false;
  try {
    ok = alg === "EdDSA" ? ed25519.verify(jws.signature, jws.signingInput, key.publicKey)
      : jws.signature.length === a.size * 2 && a.curve.verify(jws.signature, a.hash(jws.signingInput), key.publicKey, { prehash: false, lowS: false, format: "compact" });
  } catch { ok = false; }
  if (!ok) fail("bad_signature", "The signature doesn't verify.");
  return true;
}

/** Trusted roots as parsed certificates (DER, PEM bundle or already parsed). */
export const parseRoots = (roots) => (roots || []).flatMap((r) => (r?.tbs ? [r] : typeof r === "string" ? (r.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((p) => parseCertificate(p)) : [parseCertificate(r)]));

/**
 * Validate a certificate chain (leaf first, DER) against trusted roots:
 * every certificate valid now; each issuer a CA allowed to sign certificates;
 * the leaf a signing (not CA) certificate; the top issued by, or identical to,
 * a trusted root, which must itself be valid now. Returns the leaf's key and
 * names, and the root (with its fingerprint, so callers can require the same one).
 */
export function chainKey(ders, { roots, now = new Date() }) {
  if (!Array.isArray(ders) || !ders.length || ders.length > 5) fail("bad_chain", "The certificate chain is missing or too long.");
  let chain;
  try { chain = ders.map((d) => parseCertificate(d)); } catch { fail("bad_chain", "A certificate in the chain can't be read."); }
  const anchors = parseRoots(roots);
  if (!anchors.length) fail("no_trust", "No trusted issuer roots are configured for this kind of credential.");
  const valid = (c) => now >= c.notBefore && now <= c.notAfter;
  for (const c of chain) if (!valid(c)) fail("bad_chain", "A certificate in the issuer's chain isn't valid now.");
  for (let i = 0; i < chain.length - 1; i++) {
    const up = chain[i + 1];
    if (!up.isCa || up.keyCertSign === false || !issuedBy(chain[i], up)) fail("bad_chain", "The issuer's certificate chain is broken.");
  }
  const leaf = chain[0];
  if (leaf.isCa) fail("bad_chain", "The issuer signed with a certificate authority's key, not a signing certificate.");
  if (leaf.digitalSignature === false) fail("bad_chain", "The issuer's certificate isn't allowed to sign.");
  const top = chain[chain.length - 1];
  const sameDer = (a, b) => a.der.length === b.der.length && a.der.every((x, i) => x === b.der[i]);
  const root = anchors.find((r) => sameDer(r, top) && chain.length > 1 && r.isCa) || anchors.find((r) => r.isCa && r.keyCertSign !== false && issuedBy(top, r));
  if (!root) fail("untrusted_issuer", "This credential's issuer isn't in HumID's trusted list.");
  if (!valid(root)) fail("untrusted_issuer", "The trusted root for this issuer isn't valid now.");
  return {
    key: certKey(leaf),
    leaf: { subject: leaf.subject, notAfter: leaf.notAfter.toISOString(), san: leaf.san },
    root: { subject: root.subject, fingerprint: root.fingerprint },
  };
}

/** A JWS header's x5c (base64 DER, leaf first) through chainKey. */
export function x5cKey(x5c, { roots, now = new Date() }) {
  if (!Array.isArray(x5c) || x5c.some((c) => typeof c !== "string")) fail("bad_chain", "The token's certificate chain is malformed.");
  return chainKey(x5c.map(unb64), { roots, now });
}

/* ---------------- JWE (decrypt) ---------------- */

/** A fresh ephemeral P-256 ECDH key for one encrypted response. jwk is what goes in the request. */
export function ecdhKeyPair({ kid = b64u(globalThis.crypto.getRandomValues(new Uint8Array(8))) } = {}) {
  const secretKey = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(secretKey, false);
  const jwk = { kty: "EC", crv: "P-256", x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33)), use: "enc", alg: "ECDH-ES", kid };
  return { secretKey, jwk };
}

/** RFC 7518 4.6.2 Concat KDF, one SHA-256 round per 32 bytes. */
function concatKdf(z, enc, bits, apu, apv) {
  const lp = (b) => cat(u32(b.length), b);
  const other = cat(lp(te.encode(enc)), lp(apu), lp(apv), u32(bits));
  const out = [];
  for (let i = 1; out.length * 32 < bits / 8; i++) out.push(sha256(cat(u32(i), z, other)));
  return cat(...out).slice(0, bits / 8);
}

const ENC = { A128GCM: 128, A256GCM: 256 };

/** Decrypt a compact JWE made to `keyPair` (ecdhKeyPair). Returns the plaintext bytes. */
export function decryptJwe(token, keyPair, { encs = ["A128GCM", "A256GCM"] } = {}) {
  if (typeof token !== "string") fail("malformed", "The encrypted response isn't text.");
  const parts = token.split(".");
  if (parts.length !== 5) fail("malformed", "The encrypted response isn't a compact JWE.");
  const header = jsonOf(parts[0], "encrypted response header");
  if (!isObj(header)) fail("malformed", "The encrypted response header isn't an object.");
  if (header.alg !== "ECDH-ES") fail("unsupported_alg", `Key agreement ${header.alg} isn't accepted.`);
  if (!ENC[header.enc] || !encs.includes(header.enc)) fail("unsupported_alg", `Content encryption ${header.enc} isn't accepted.`);
  if (header.zip !== undefined || header.crit !== undefined) fail("unsupported", "Compressed or critical-header responses aren't accepted.");
  if (parts[1] !== "") fail("malformed", "Direct key agreement must not carry an encrypted key.");
  if (header.kid !== undefined && keyPair.jwk.kid && header.kid !== keyPair.jwk.kid) fail("decrypt", "The response was encrypted to a different key.");
  const epk = jwkKey(header.epk);
  if (epk.crv !== "P-256") fail("unsupported", "The response's key agreement isn't on P-256.");
  const z = p256.getSharedSecret(keyPair.secretKey, epk.publicKey, true).slice(1);
  const apu = header.apu ? unb64u(header.apu) : new Uint8Array(0), apv = header.apv ? unb64u(header.apv) : new Uint8Array(0);
  const cek = concatKdf(z, header.enc, ENC[header.enc], apu, apv);
  const iv = unb64u(parts[2]), ct = unb64u(parts[3]), tag = unb64u(parts[4]);
  if (iv.length !== 12 || tag.length !== 16) fail("malformed", "The encrypted response's IV or tag is the wrong size.");
  try { return gcm(cek, iv, te.encode(parts[0])).decrypt(cat(ct, tag)); }
  catch { fail("decrypt", "The response couldn't be decrypted. It wasn't made for this request."); }
}
