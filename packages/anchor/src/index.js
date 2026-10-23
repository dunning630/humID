// @humid/anchor — the identity anchor for two-proof recovery. Server side.
//
// A passport or ID card chip (ICAO 9303) holds the holder's identity data
// (DG1, the MRZ), sometimes an Active Authentication key (DG15), and a
// Document Security Object (EF.SOD): hashes of every data group, signed by the
// issuing country's Document Signer, whose certificate is signed by that
// country's CSCA. HumID checks:
//
//   passive authentication   the data is genuine and unaltered: DG hashes match
//                            the SOD, the SOD signature verifies under the DS
//                            certificate, the DS certificate chains to a
//                            trusted CSCA, the document hasn't expired
//   active authentication    the chip itself is present right now: it signs a
//                            fresh server nonce with the private key whose
//                            public half is in DG15 (which the SOD covers).
//                            Copying a chip's files can't fake this.
//
// The anchor is a keyed hash of the identity fields that survive renewal, so a
// new passport still matches and the server never stores the fields.
// Nothing here sees a face or a photo.

import { X509Certificate, createHash, createPublicKey, publicDecrypt, verify as cryptoVerify, constants, createHmac } from "node:crypto";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse, kids, int, octets, oid, readTLV, CLASS, TAG } from "@humid/attest/der";
import { parseMrz, stableIdentity, expiryDate, MrzError } from "./mrz.js";
import { alpha2Of } from "./countries.js";

export { parseMrz, stableIdentity, checkDigit, expiryDate, MrzError } from "./mrz.js";
export { alpha2Of } from "./countries.js";
export { mdocAuth, mdocAnchorOf, mdocStableIdentity, mdocAnchorSummary, loadIacas, MdocAnchorError } from "./mdoc.js";

export class AnchorError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, message) => { throw new AnchorError(code, message); };

const HASHES = {
  "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512",
};
const SIG = {
  "1.2.840.113549.1.1.1": { kind: "rsa" },                     // rsaEncryption: hash from digestAlgorithm
  "1.2.840.113549.1.1.5": { kind: "rsa", hash: "sha1" },
  "1.2.840.113549.1.1.14": { kind: "rsa", hash: "sha224" },
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "sha256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "sha384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "sha512" },
  "1.2.840.113549.1.1.10": { kind: "pss" },
  "1.2.840.10045.2.1": { kind: "ecdsa" },                      // id-ecPublicKey: hash from digestAlgorithm
  "1.2.840.10045.4.1": { kind: "ecdsa", hash: "sha1" },
  "1.2.840.10045.4.3.1": { kind: "ecdsa", hash: "sha224" },
  "1.2.840.10045.4.3.2": { kind: "ecdsa", hash: "sha256" },
  "1.2.840.10045.4.3.3": { kind: "ecdsa", hash: "sha384" },
  "1.2.840.10045.4.3.4": { kind: "ecdsa", hash: "sha512" },
};
const OID = {
  signedData: "1.2.840.113549.1.7.2",
  ldsSecurityObject: "2.23.136.1.1.1",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
  countryName: "2.5.4.6",
  subjectKeyId: "2.5.29.14",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
};
const HASH_LEN = { sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64 };

const digest = (alg, ...parts) => { const h = createHash(alg); for (const p of parts) h.update(Buffer.from(p)); return h.digest(); };
const same = (a, b) => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
const ctx = (t, n) => t && t.cls === CLASS.context && t.tag === n;
const tryRead = (fn, code, message) => { try { return fn(); } catch (e) { if (e instanceof AnchorError) throw e; fail(code, message); } };

/** Strip an ICAO file's application tag (DG1 = 0x61, DG15 = 0x6F, SOD = 0x77) and return its inside. */
function unwrapFile(bytes, appTag, what) {
  const t = tryRead(() => parse(Buffer.from(bytes)), "bad_chip_data", `${what} can't be read.`);
  if (t.cls !== CLASS.application || t.tag !== appTag) fail("bad_chip_data", `${what} has the wrong file tag.`);
  return t;
}

/* ---------------- EF.SOD ---------------- */

function algorithm(t) {
  const k = kids(t);
  return { oid: oid(k[0]), params: k[1] || null };
}

/** Parse EF.SOD into what passive authentication needs. */
export function parseSod(sodBytes) {
  return tryRead(() => {
    const file = unwrapFile(sodBytes, 23, "The document security object");
    const ci = kids(parse(file.value));
    if (oid(ci[0]) !== OID.signedData) fail("bad_chip_data", "The document security object isn't CMS signed data.");
    const sd = kids(kids(ci[1])[0]);
    // SignedData: version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    const eci = kids(sd[2]);
    if (oid(eci[0]) !== OID.ldsSecurityObject) fail("bad_chip_data", "The signed content isn't an LDS security object.");
    const eContent = octets(kids(eci[1])[0]);
    const lds = kids(parse(eContent));
    const hashAlg = HASHES[algorithm(lds[1]).oid];
    if (!hashAlg) fail("unsupported", "The chip uses a hash HumID doesn't support.");
    const dgHashes = new Map(kids(lds[2]).map((d) => { const k = kids(d); return [int(k[0]), Buffer.from(octets(k[1]))]; }));
    let i = 3;
    const certs = [];
    if (ctx(sd[i], 0)) { for (const c of kids(sd[i])) certs.push(Buffer.from(c.raw)); i++; }
    if (ctx(sd[i], 1)) i++;
    const signers = kids(sd[i]);
    if (signers.length !== 1) fail("bad_chip_data", "The document security object must have exactly one signer.");
    const si = kids(signers[0]);
    // SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
    const sid = si[1];
    const siDigest = HASHES[algorithm(si[2]).oid];
    if (!ctx(si[3], 0)) fail("bad_chip_data", "The document security object has no signed attributes.");
    const attrs = new Map(kids(si[3]).map((a) => { const k = kids(a); return [oid(k[0]), kids(k[1])[0]]; }));
    // The signature covers the attributes encoded as a SET (tag 0x31), not as the [0] they're stored with.
    const signedAttrsDer = Buffer.from(si[3].raw);
    signedAttrsDer[0] = 0x31;
    return {
      hashAlg, dgHashes, eContent: Buffer.from(eContent), certs, sid,
      signerDigest: siDigest, signatureAlg: algorithm(si[4]), signature: Buffer.from(octets(si[5])),
      signedAttrsDer, contentTypeAttr: attrs.get(OID.contentType), messageDigestAttr: attrs.get(OID.messageDigest),
    };
  }, "bad_chip_data", "The document security object can't be read.");
}

/** PSS parameters: hash and salt length (RFC 4055 defaults: SHA-1, 20). */
function pssParams(params) {
  let hash = "sha1", saltLength = 20;
  if (params && params.tag === TAG.sequence) {
    for (const p of kids(params)) {
      if (ctx(p, 0)) hash = HASHES[algorithm(kids(p)[0]).oid] || hash;
      if (ctx(p, 2)) saltLength = int(kids(p)[0]);
    }
  }
  return { hash, saltLength };
}

/** Verify a CMS / X.509-style signature by `publicKey` over `data`. */
function verifyWith(publicKey, alg, digestAlg, data, signature) {
  const s = SIG[alg.oid];
  if (!s) fail("unsupported", "The chip uses a signature HumID doesn't support.");
  if (s.kind === "pss") {
    const { hash, saltLength } = pssParams(alg.params);
    return cryptoVerify(hash, data, { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength }, signature);
  }
  const hash = s.hash || digestAlg;
  if (!hash) fail("unsupported", "The signature's hash is unknown.");
  return cryptoVerify(hash, data, publicKey, signature);
}

/* ---------------- certificates: the fields passive authentication needs ---------------- */

/** countryName of an X.509 Name, or null. */
function countryOf(nameTlv) {
  for (const rdn of kids(nameTlv)) for (const atv of kids(rdn)) {
    const [t, v] = kids(atv);
    if (oid(t) === OID.countryName) return Buffer.from(v.value).toString("latin1").toUpperCase();
  }
  return null;
}

/**
 * The parts of a certificate X509Certificate doesn't expose: issuer and serial as
 * encoded (to match a CMS signer), subject key id, key usage, CA flag, countries.
 */
export function certFields(der) {
  return tryRead(() => {
    const tbs = kids(kids(parse(Buffer.from(der)))[0]);
    let i = ctx(tbs[0], 0) ? 1 : 0;
    const serial = Buffer.from(tbs[i].value); i++;
    i++; // signature algorithm
    const issuer = tbs[i]; i++;
    i++; // validity
    const subject = tbs[i]; i++;
    i++; // subject public key info
    let ski = null, keyUsage = null, ca = false;
    for (; i < tbs.length; i++) {
      if (!ctx(tbs[i], 3)) continue;
      for (const ext of kids(kids(tbs[i])[0])) {
        const e = kids(ext);
        const id = oid(e[0]);
        const val = parse(octets(e[e.length - 1]));
        if (id === OID.subjectKeyId) ski = Buffer.from(val.value);
        if (id === OID.keyUsage) keyUsage = Buffer.from(val.value); // BIT STRING: unused-bits byte, then bits
        if (id === OID.basicConstraints) { const b = kids(val); ca = !!b[0] && b[0].tag === TAG.boolean && b[0].value[0] !== 0; }
      }
    }
    return { serial, issuerDer: Buffer.from(issuer.raw), ski, keyUsage, ca, country: countryOf(subject), issuerCountry: countryOf(issuer) };
  }, "bad_chip_data", "A certificate can't be read.");
}

const DIGITAL_SIGNATURE = 0x80; // keyUsage bit 0
const canSign = (ku) => !!ku && ku.length >= 2 && (ku[1] & DIGITAL_SIGNATURE) !== 0;
const stripInt = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; return b.subarray(i); };

/** Does the CMS SignerIdentifier name this certificate? */
function signerIs(sid, f) {
  if (sid.cls === CLASS.universal && sid.tag === TAG.sequence) {
    const [issuer, serial] = kids(sid);
    return same(issuer.raw, f.issuerDer) && same(stripInt(serial.value), stripInt(f.serial));
  }
  if (ctx(sid, 0)) return !!f.ski && same(sid.value, f.ski);
  return false;
}

/* ---------------- trust: country signing CAs ---------------- */

/** Load CSCA certificates (PEM or DER files) from a directory. Missing directory = none. */
export function loadCscas(dir) {
  if (!dir || !existsSync(dir)) return [];
  const out = [];
  for (const f of readdirSync(dir)) {
    if (!/\.(pem|crt|cer|der)$/i.test(f)) continue;
    const raw = readFileSync(join(dir, f));
    const text = raw.toString("latin1");
    const blocks = text.includes("-----BEGIN CERTIFICATE-----") ? text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) : [raw];
    for (const b of blocks) { try { out.push(new X509Certificate(b)); } catch { /* skip unreadable */ } }
  }
  return out;
}

/**
 * CSCAs from a HumID trust store snapshot (written by @humid/creds'
 * createTrustStore().toJSON(), usually by tools/trust.mjs). Expired ones are
 * left out. A missing file gives []; a damaged one throws.
 */
export function loadCscasFromTrustFile(path, { now = new Date(), minRev = 0 } = {}) {
  if (!path || !existsSync(path)) return [];
  const s = JSON.parse(readFileSync(path, "utf8"));
  if (s?.v !== 1 || !Array.isArray(s.csca)) throw new Error("The trust store file is damaged or from another version.");
  if (!Number.isSafeInteger(s.rev) || s.rev < minRev) throw new Error("The trust store file is older than one already used.");
  const out = [];
  for (const e of s.csca) {
    if (e.notAfter && new Date(e.notAfter) < now) continue;
    try { out.push(new X509Certificate(Buffer.from(e.der, "base64"))); } catch { /* skip unreadable */ }
  }
  out.rev = s.rev;
  return out;
}

const asCert = (c) => (c instanceof X509Certificate ? c : new X509Certificate(c));

/* ---------------- passive authentication ---------------- */

/**
 * Check that the chip's data is genuine. chip: { dg1, sod, dg15? } (bytes).
 * cscas: trusted country signing CA certificates. Returns the parsed MRZ and what was proven.
 *
 * SHA-1 anywhere in the SOD (the data group hashes, the signer's digest or its
 * signature) is refused (`weak_hash`, review finding CREDS-08): Doc 9303 has
 * allowed only SHA-224/256/384/512 since its 7th edition (2015), and a
 * chosen-prefix collision on SHA-1 is practical. Passports issued under the
 * 6th edition with SHA-1 may still be in date; allowSha1: true accepts them and
 * the result says `weakHash: true`, for a caller that will treat them as weaker.
 */
export function passiveAuth(chip, opts = {}) {
  // Whatever a phone sends, the answer is a refusal with a reason, never a server error.
  return tryRead(() => passiveAuthInner(chip, opts), "bad_chip_data", "The chip data can't be read.");
}

function passiveAuthInner(chip, { cscas = [], now = new Date(), allowSha1 = false } = {}) {
  if (!chip?.dg1 || !chip?.sod) fail("bad_chip_data", "The chip data needs DG1 and the document security object.");
  if (!cscas.length) fail("no_trust", "This server has no country signing certificates configured, so it can't check ID chips yet.");
  const sod = parseSod(chip.sod);
  const weakHash = sodUsesSha1(sod);
  if (weakHash && !allowSha1) fail("weak_hash", "This document's chip is signed with SHA-1, which HumID no longer accepts as proof.");

  // 1. Every data group sent matches its signed hash (and every signed hash is the right size).
  for (const h of sod.dgHashes.values()) if (h.length !== HASH_LEN[sod.hashAlg]) fail("bad_chip_data", "The chip's signed record is malformed.");
  for (const [key, bytes] of Object.entries(chip)) {
    const m = /^dg([0-9]{1,2})$/.exec(key);
    if (!m || bytes == null) continue;
    const h = sod.dgHashes.get(Number(m[1]));
    if (!h || !same(digest(sod.hashAlg, bytes), h)) fail("data_altered", key === "dg1" ? "The identity data doesn't match the chip's signed record." : `Data group ${m[1]} doesn't match the chip's signed record.`);
  }

  // 2. Signed attributes bind the content: its type and its digest are both required.
  const mdAlg = sod.signerDigest || sod.hashAlg;
  const md = tryRead(() => octets(sod.messageDigestAttr), "bad_chip_data", "The document security object has no message digest.");
  if (!same(md, digest(mdAlg, sod.eContent))) fail("data_altered", "The chip's signed record was altered.");
  if (!sod.contentTypeAttr || tryRead(() => oid(sod.contentTypeAttr), "bad_chip_data", "Bad content type.") !== OID.ldsSecurityObject) fail("bad_chip_data", "The signed content type is missing or wrong.");

  // 3. The Document Signer the SOD names signed it, and it's a signing certificate.
  if (!sod.certs.length) fail("bad_chip_data", "The chip doesn't include its document signer certificate.");
  const named = sod.certs.filter((c) => signerIs(sod.sid, certFields(c)));
  if (named.length !== 1) fail("bad_signature", "The chip's signer doesn't match its certificate. The document may be forged.");
  const dsFields = certFields(named[0]);
  const ds = tryRead(() => new X509Certificate(named[0]), "bad_chip_data", "The document signer certificate can't be read.");
  let signed = false;
  try { signed = verifyWith(ds.publicKey, sod.signatureAlg, mdAlg, sod.signedAttrsDer, sod.signature); } catch (e) { if (e instanceof AnchorError) throw e; }
  if (!signed) fail("bad_signature", "The chip's signature doesn't verify. The document may be forged.");
  if (dsFields.ca || !canSign(dsFields.keyUsage)) fail("bad_signature", "The document signer certificate isn't one for signing documents.");
  if (now < new Date(ds.validFrom)) fail("bad_signature", "The document signer certificate isn't valid yet.");

  // 4. The Document Signer belongs to a trusted country.
  const csca = cscas.map(asCert).find((ca) => { try { return ds.checkIssued(ca) && ds.verify(ca.publicKey); } catch { return false; } });
  if (!csca) fail("untrusted_country", "This document's issuer isn't in the server's trusted country list.");
  if (now > new Date(csca.validTo) && now > new Date(ds.validTo)) fail("expired", "The issuing country's certificate has expired.");

  // 5. The MRZ, and the document must still be valid.
  const mrz = readDg1(chip.dg1);
  if (expiryDate(mrz.expiry) < now) fail("expired", "This document has expired. Use a valid passport or ID card.");

  // 6. One country throughout: the CSCA's, the document signer's, and the issuer the MRZ names.
  //    Otherwise any trusted country's signer could vouch for another country's document.
  const cscaCountry = certFields(csca.raw).country;
  const want = alpha2Of(mrz.issuer);
  if (!cscaCountry || !dsFields.country || cscaCountry !== dsFields.country || dsFields.issuerCountry !== cscaCountry) fail("country_mismatch", "The document's certificates don't agree on the issuing country.");
  if (!want || want !== cscaCountry) fail("country_mismatch", "The document's issuing country doesn't match the country that signed it.");

  // aaRequired: the SOD lists an Active Authentication key, so the chip can prove it's
  // present and must; leaving DG15 out doesn't make it a chip that can't.
  return { mrz, hashAlg: sod.hashAlg, weakHash, hasAaKey: sod.dgHashes.has(15) && !!chip.dg15, aaRequired: sod.dgHashes.has(15), issuerCountry: mrz.issuer, cscaSubject: csca.subject };
}

/** Does the SOD rest on SHA-1 anywhere: its data group hashes, its signer's digest, or its signature? */
function sodUsesSha1(sod) {
  const mdAlg = sod.signerDigest || sod.hashAlg;
  const spec = SIG[sod.signatureAlg.oid];
  const sigHash = spec?.kind === "pss" ? pssParams(sod.signatureAlg.params).hash : spec?.hash || mdAlg;
  return [sod.hashAlg, mdAlg, sigHash].includes("sha1");
}

/** DG1 (tag 0x61) → MRZ (tag 0x5F1F) → parsed fields. */
export function readDg1(dg1) {
  const file = unwrapFile(dg1, 1, "The identity data (DG1)");
  const inner = tryRead(() => readTLV(file.value, 0), "bad_chip_data", "The identity data can't be read.");
  if (inner.cls !== CLASS.application || inner.tag !== 0x1f) fail("bad_chip_data", "The identity data has no MRZ.");
  try { return parseMrz(Buffer.from(inner.value).toString("latin1")); }
  catch (e) { fail("bad_chip_data", e instanceof MrzError ? e.message : "The MRZ can't be read."); }
}

/* ---------------- active authentication ---------------- */

const ISO9796_TRAILERS = { 0x33: "sha1", 0x34: "sha256", 0x35: "sha512", 0x36: "sha384", 0x38: "sha224" };
const bigOf = (b) => BigInt("0x" + (Buffer.from(b).toString("hex") || "0"));
const bytesOf = (n, len) => Buffer.from(n.toString(16).padStart(len * 2, "0"), "hex");

/** The chip's AA public key from DG15 (tag 0x6F wrapping a SubjectPublicKeyInfo). */
export function readDg15(dg15) {
  const file = unwrapFile(dg15, 15, "The chip's authentication key (DG15)");
  return tryRead(() => createPublicKey({ key: Buffer.from(file.value), format: "der", type: "spki" }), "bad_chip_data", "The chip's authentication key can't be read.");
}

/** RSA AA: ISO/IEC 9796-2 digital signature scheme 1, partial message recovery. */
function verifyRsaAa(key, nonce, sig) {
  const jwk = key.export({ format: "jwk" });
  const n = bigOf(Buffer.from(jwk.n, "base64url"));
  const k = Buffer.from(jwk.n, "base64url").length;
  let m;
  try { m = bigOf(publicDecrypt({ key, padding: constants.RSA_NO_PADDING }, sig)); } catch { return false; }
  for (const cand of [m, n - m]) {
    const f = bytesOf(cand, k);
    if ((f[0] & 0xf0) !== 0x60) continue; // header 01 + partial-recovery bit
    let hash, tlen;
    if (f[k - 1] === 0xbc) { hash = "sha1"; tlen = 1; }
    else if (f[k - 1] === 0xcc && ISO9796_TRAILERS[f[k - 2]]) { hash = ISO9796_TRAILERS[f[k - 2]]; tlen = 2; }
    else continue;
    const hlen = HASH_LEN[hash];
    const m1 = f.subarray(1, k - tlen - hlen);
    const d = f.subarray(k - tlen - hlen, k - tlen);
    if (same(digest(hash, m1, nonce), d)) return true;
  }
  return false;
}

/** ECDSA AA (BSI TR-03111 plain r ‖ s). The hash comes from DG14; without it, the usual ones are tried. */
function verifyEcAa(key, nonce, sig, hash) {
  for (const h of hash ? [hash] : ["sha256", "sha1", "sha224", "sha384", "sha512"]) {
    try { if (cryptoVerify(h, nonce, { key, dsaEncoding: "ieee-p1363" }, sig)) return true; } catch { /* try the next */ }
  }
  return false;
}

/**
 * Check that the chip is physically present: it signed `nonce` (the server's
 * fresh challenge) with the private key behind DG15. dg15 must already be
 * covered by passive authentication.
 */
export function activeAuth({ dg15, nonce, signature, hash }) {
  if (!dg15 || !nonce || !signature) fail("no_chip_proof", "The chip didn't answer the challenge.");
  const key = readDg15(dg15);
  const ok = key.asymmetricKeyType === "rsa" ? verifyRsaAa(key, Buffer.from(nonce), Buffer.from(signature))
    : key.asymmetricKeyType === "ec" ? verifyEcAa(key, Buffer.from(nonce), Buffer.from(signature), hash)
    : false;
  if (!ok) fail("chip_not_present", "The chip's answer didn't verify. The chip data may have been copied.");
  return true;
}

/* ---------------- the anchor ---------------- */

/**
 * A keyed hash of the identity fields that survive renewal. `key` is a server
 * secret, so the anchor can't be recomputed from a stolen database plus
 * guessable personal details.
 */
export const anchorOf = (mrz, key) => createHmac("sha3-256", key).update(stableIdentity(mrz)).digest("hex");

/** Country and document kind only, for display ("Passport · USA"). Never names or numbers. */
export const anchorSummary = (mrz) => ({ document: mrz.documentCode?.startsWith("P") ? "passport" : "ID card", country: mrz.issuer });

/* ---------------- ICAO master lists ---------------- */

/** UTCTime or GeneralizedTime (whole seconds, Z) → Date. */
function timeOf(t) {
  const s = Buffer.from(t.value).toString("latin1");
  const m = t.tag === 23 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : t.tag === 24 ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : null;
  if (!m) fail("bad_master_list", "The master list's signing time can't be read.");
  let y = Number(m[1]);
  if (t.tag === 23) y += y < 50 ? 2000 : 1900;
  const d = new Date(Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  if (Number.isNaN(d.getTime())) fail("bad_master_list", "The master list's signing time can't be read.");
  return d;
}

const ML = { content: "2.23.136.1.1.2", signerEku: "2.23.136.1.1.3", extKeyUsage: "2.5.29.37" };

/**
 * Read an ICAO CSCA Master List (ICAO 9303 part 12): a CMS SignedData whose
 * content is the list of country signing CAs a publishing state has checked.
 * Germany's BSI, for example, publishes one openly. Trusting it means trusting
 * the publisher's vetting, so its signer must chain to a CSCA you already
 * trust for that publisher (`publisherCscas`).
 *
 * Returns { publisher, signer, signingTime, cscas: [X509Certificate] } (expired
 * CSCAs kept: a passport signed under one stays checkable until its own expiry
 * rules say not). signingTime is the signed CMS signing-time attribute (a Date,
 * or null when the list has none): master lists carry no issue number, so it is
 * what a store uses to refuse an older list replayed over a newer one.
 */
export function readMasterList(bytes, { publisherCscas = [], now = new Date() } = {}) {
  return tryRead(() => readMasterListInner(bytes, publisherCscas, now), "bad_master_list", "The master list can't be read.");
}

function readMasterListInner(bytes, publisherCscas, now) {
  if (!publisherCscas.length) fail("no_trust", "Reading a master list needs the publisher's own CSCA.");
  const ci = kids(parse(Buffer.from(bytes)));
  if (oid(ci[0]) !== OID.signedData) fail("bad_master_list", "The master list isn't CMS signed data.");
  const sd = kids(kids(ci[1])[0]);
  const eci = kids(sd[2]);
  if (oid(eci[0]) !== ML.content) fail("bad_master_list", "This CMS isn't a CSCA master list.");
  const eContent = octets(kids(eci[1])[0]);
  let i = 3;
  const certs = [];
  if (ctx(sd[i], 0)) { for (const c of kids(sd[i])) certs.push(Buffer.from(c.raw)); i++; }
  if (ctx(sd[i], 1)) i++;
  const signers = kids(sd[i]);
  if (signers.length !== 1) fail("bad_master_list", "The master list must have exactly one signer.");
  const si = kids(signers[0]);
  const digestAlg = HASHES[algorithm(si[2]).oid];
  if (!digestAlg || digestAlg === "sha1") fail("unsupported", "The master list uses a hash HumID doesn't accept.");
  if (!ctx(si[3], 0)) fail("bad_master_list", "The master list has no signed attributes.");
  const attrs = new Map(kids(si[3]).map((a) => { const k = kids(a); return [oid(k[0]), kids(k[1])[0]]; }));
  if (!attrs.get(OID.contentType) || oid(attrs.get(OID.contentType)) !== ML.content) fail("bad_master_list", "The master list's signed content type is wrong.");
  if (!attrs.get(OID.messageDigest) || !same(octets(attrs.get(OID.messageDigest)), digest(digestAlg, eContent))) fail("data_altered", "The master list was altered.");
  const signedAttrsDer = Buffer.from(si[3].raw);
  signedAttrsDer[0] = 0x31;

  const named = certs.filter((c) => signerIs(si[1], certFields(c)));
  if (named.length !== 1) fail("bad_signature", "The master list's signer certificate is missing.");
  const signer = new X509Certificate(named[0]);
  const f = certFields(named[0]);
  if (f.ca || !canSign(f.keyUsage)) fail("bad_signature", "The master list's signer isn't a signing certificate.");
  // ICAO 9303-12: a master list signer carries the master list signing key usage. A Document Signer under the same CSCA doesn't, and can't publish a list.
  const eku = Array.isArray(signer.keyUsage) ? signer.keyUsage : [];
  if (!eku.includes(ML.signerEku)) fail("bad_signature", "The master list isn't signed by a master list signer.");
  // No SHA-1 anywhere, and the signature's own hash must be the digest the attributes were made with.
  const sigAlg = algorithm(si[4]);
  const sigSpec = SIG[sigAlg.oid];
  const sigHash = sigSpec?.kind === "pss" ? pssParams(sigAlg.params).hash : sigSpec?.hash || digestAlg;
  if (!sigSpec || sigHash === "sha1" || sigHash !== digestAlg) fail("unsupported", "The master list's signature algorithm isn't accepted.");
  if (!verifyWith(signer.publicKey, sigAlg, digestAlg, signedAttrsDer, octets(si[5]))) fail("bad_signature", "The master list's signature doesn't verify.");
  if (now < new Date(signer.validFrom) || now > new Date(signer.validTo)) fail("bad_signature", "The master list's signer certificate isn't valid now.");
  const publisher = publisherCscas.map(asCert).find((ca) => { try { return signer.checkIssued(ca) && signer.verify(ca.publicKey); } catch { return false; } });
  if (!publisher) fail("untrusted_country", "The master list isn't signed by the publisher you trust.");

  // CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }
  const ml = kids(parse(eContent));
  if (int(ml[0]) !== 0) fail("unsupported", "Unknown master list version.");
  const cscas = [];
  for (const c of kids(ml[1])) {
    let x;
    try { x = new X509Certificate(Buffer.from(c.raw)); } catch { continue; }
    if (!certFields(x.raw).ca) continue; // only CA certificates belong in a CSCA list
    cscas.push(x);
  }
  const st = attrs.get(OID.signingTime);
  const signingTime = st ? timeOf(st) : null;
  return { publisher: certFields(publisher.raw).country, signer: signer.subject, signingTime, cscas };
}
