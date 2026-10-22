// @humid/mdoc — mobile IDs (ISO/IEC 18013-5 "mdoc"): US state mobile
// driver's licenses and IDs in Apple, Google and Samsung Wallet and state
// apps, and the same format used elsewhere (EU digital identity PID, other
// countries' mDLs). The counterpart of @humid/emrtd for passport chips:
//
//   session   reader side of the proximity session (QR / NFC engagement,
//             ECDH + HKDF session keys, AES-256-GCM messages)
//   request   DeviceRequest: which data elements HumID asks the wallet for
//   verify    issuer data authentication (MSO signature, IACA chain,
//             digests, validity) and mdoc authentication (device signature
//             or MAC over this session)
//   vical     reading a Verified Issuer Certificate Authority List (AAMVA's
//             Digital Trust Service publishes the US and Canadian roots)
//   dcapi     online requests through the browser's or phone's credential
//             picker (Digital Credentials API): ISO 18013-7 Annex C
//             (org-iso-mdoc, HPKE) and OpenID4VP session transcripts
//
// No transport or platform code: BLE / NFC move bytes, this decides.

import { encode, decode, get, Encoded, Tagged, plain } from "./cbor.js";
import { parse1, verifySign1, x5chain } from "./cose.js";
import { parseCertificate, issuedBy, curveOf, OIDS } from "./x509.js";
import { MdocError, coded } from "./verify.js";
import { sha256 } from "@noble/hashes/sha2.js";

export { encode, decode, get, plain, Encoded, Tagged, CborError } from "./cbor.js";
export { coseKey, ecCoseKey, parse1, verifySign1, verifyMac0, signSign1, macMac0, x5chain, ALG, CoseError } from "./cose.js";
export { parseCertificate, readCertificates, issuedBy, fromPem, X509Error, OIDS, readAnchors, stateCode, countryCode } from "./x509.js";
export { readEngagement, bleOptions, ReaderSession, sessionKey, ecdhX, SessionError, STATUS, RETRIEVAL } from "./session.js";
export { hpkeKeyPair, hpkeOpen, hpkeSeal, HpkeError } from "./hpke.js";
export {
  annexCRequest, annexCOpen, annexCTranscript, openid4vpDcApiTranscript, openid4vpRedirectTranscript, transcriptBytes,
  signedDeviceRequest, readEncryptionInfo, serializeOrigin, base64url, fromBase64url,
} from "./dcapi.js";
export { verifyIssuerSigned, verifyDeviceResponse, deviceAuthenticationBytes, encodeIssuerSigned, MdocError, coded } from "./verify.js";

export const MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
export const MDL_NS = "org.iso.18013.5.1";
export const AAMVA_NS = "org.iso.18013.5.1.aamva";
export const PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";
export const PHOTOID_DOCTYPE = "org.iso.23220.photoid.1";
export const PHOTOID_NS = "org.iso.23220.1";

/** What HumID asks for, per document type. Everything it shows on the ID card view, nothing it doesn't. */
export const REQUESTS = {
  [MDL_DOCTYPE]: {
    [MDL_NS]: [
      "family_name", "given_name", "birth_date", "issue_date", "expiry_date", "issuing_country", "issuing_authority",
      "issuing_jurisdiction", "document_number", "portrait", "driving_privileges", "sex", "height", "weight",
      "eye_colour", "hair_colour", "birth_place", "resident_address", "resident_city", "resident_state",
      "resident_postal_code", "resident_country", "nationality", "un_distinguishing_sign",
    ],
    [AAMVA_NS]: ["DHS_compliance", "organ_donor", "veteran", "name_suffix", "domestic_driving_privileges", "family_name_truncation", "given_name_truncation"],
  },
  [PID_DOCTYPE]: {
    [PID_DOCTYPE]: [
      "family_name", "given_name", "birth_date", "birth_place", "nationality", "sex", "issuing_country", "issuing_authority",
      "issuance_date", "expiry_date", "document_number", "portrait", "resident_address", "resident_city", "resident_postal_code", "resident_country",
    ],
  },
  [PHOTOID_DOCTYPE]: {
    [PHOTOID_NS]: [
      "family_name_unicode", "given_name_unicode", "birth_date", "portrait", "issue_date", "expiry_date", "issuing_authority_unicode",
      "issuing_country", "document_number", "sex", "nationality", "birthplace", "resident_address_unicode", "resident_city_unicode",
      "resident_postal_code", "resident_country",
    ],
  },
};

/**
 * DeviceRequest bytes. intentToRetain is true: HumID keeps what it's given,
 * sealed in the holder's own vault, and the wallet should say so.
 */
export function deviceRequest(docTypes = [MDL_DOCTYPE], { intentToRetain = true, elements } = {}) {
  const docRequests = docTypes.map((docType) => {
    const want = elements?.[docType] || REQUESTS[docType];
    if (!want) throw new Error(`no request defined for ${docType}`);
    const nameSpaces = new Map(Object.entries(want).map(([ns, names]) => [ns, new Map(names.map((n) => [n, intentToRetain]))]));
    return new Map([["itemsRequest", Encoded.of(new Map([["docType", docType], ["nameSpaces", nameSpaces]]))]]);
  });
  return encode(new Map([["version", "1.0"], ["docRequests", docRequests]]));
}

/**
 * A VICAL (ISO 18013-5 Annex C): a signed list of issuing-authority roots.
 * Checked before anything in it is trusted:
 *   - the signer certificate (first in x5chain) verifies the signature, isn't a
 *     CA, carries the VICAL signer key usage (1.0.18013.5.1.8) and is valid now
 *   - every link in the x5chain verifies (at most 4 certificates), each valid now
 *   - the chain reaches the provider HumID trusts: `providerRoots`
 *     (certificates), or `providerPins` (SHA-256 fingerprints, hex, of the
 *     provider's root or signer, pinned after confirming them with the provider
 *     out of band). One of the two is required, unless `inspect` is set: then the
 *     list is read for a person to look at, `trusted` is false and nothing in
 *     it may be used.
 *   - the list isn't dated in the future, isn't more than `graceDays` past its
 *     nextUpdate (or `maxAgeDays` old without one), and, when `minIssueId` is
 *     given (the last one seen), isn't older than it
 * Returns { provider, date, nextUpdate, issueId, trusted, signer, chain,
 *           certificates: [{ der, docTypes, country, state, authority }] }.
 */
export function readVical(bytes, { providerRoots, providerPins, now = new Date(), minIssueId, maxAgeDays = 400, graceDays = 0, inspect = false } = {}) {
  return coded(() => readVicalInner(bytes, { providerRoots, providerPins, now, minIssueId, maxAgeDays, graceDays, inspect }), "bad_vical", "The VICAL can't be read.");
}

function readVicalInner(bytes, { providerRoots, providerPins, now, minIssueId, maxAgeDays, graceDays, inspect }) {
  const bad = (code, m) => { throw new MdocError(code, m); };
  if (!providerRoots?.length && !providerPins?.length && !inspect) bad("no_trust", "A VICAL is only as good as its provider: pass the provider's root or its pinned fingerprint.");
  const sign1 = parse1(bytes instanceof Uint8Array ? decode(bytes) : bytes);
  const raw = x5chain(sign1);
  if (!raw.length) bad("bad_vical", "The VICAL has no signer certificate.");
  if (raw.length > 4) bad("bad_vical", "The VICAL's certificate chain is too long.");
  let chain;
  try { chain = raw.map((c) => parseCertificate(c)); } catch { bad("bad_vical", "A certificate in the VICAL's chain can't be read."); }
  const signer = chain[0];
  if (!signer._curve || !verifySign1(sign1, { curve: curveOf(signer), publicKey: signer.publicKey })) bad("bad_signature", "The VICAL's signature doesn't verify.");
  if (signer.isCa || !signer.eku.includes(OIDS.ekuVicalSigner)) bad("bad_signature", "The VICAL isn't signed by a VICAL signing certificate.");
  for (let i = 0; i < chain.length - 1; i++) if (!chain[i + 1].isCa || chain[i + 1].keyCertSign === false || !issuedBy(chain[i], chain[i + 1])) bad("bad_signature", "The VICAL's certificate chain is broken.");
  if (!inspect) {
    if (now < signer.notBefore || now > signer.notAfter) bad("bad_signature", "The VICAL's signing certificate isn't valid now.");
    for (const c of chain) if (now < c.notBefore || now > c.notAfter) bad("bad_signature", "A certificate in the VICAL's chain isn't valid now.");
  }
  const fp = (c) => toHexStr(sha256(c.der));
  const top = chain[chain.length - 1];
  let trusted = false;
  if (providerRoots?.length) {
    const roots = providerRoots.map((r) => (r?.tbs ? r : parseCertificate(r)));
    const same = (a, b) => a.der.length === b.der.length && a.der.every((x, i) => x === b.der[i]);
    const root = roots.find((r) => same(r, top) && r.isCa) || roots.find((r) => r.isCa && r.keyCertSign !== false && issuedBy(top, r));
    if (!root) bad("untrusted_issuer", "The VICAL isn't signed by a trusted provider.");
    if (now < root.notBefore || now > root.notAfter) bad("untrusted_issuer", "The VICAL provider's root isn't valid now.");
    trusted = true;
  }
  if (providerPins?.length) {
    const pins = providerPins.map((p) => String(p).toLowerCase().replace(/[^0-9a-f]/g, ""));
    if (!chain.some((c) => pins.includes(fp(c)))) bad("untrusted_issuer", "The VICAL isn't signed by a trusted provider.");
    trusted = true;
  }
  let v = decode(sign1.payload);
  if (v instanceof Encoded) v = v.value;
  const when = (x) => { if (x == null) return null; const d = new Date(x instanceof Tagged ? x.value : x); if (Number.isNaN(d.getTime())) bad("bad_vical", "The VICAL's dates can't be read."); return d; };
  const date = when(get(v, "date")), nextUpdate = when(get(v, "nextUpdate"));
  if (!date) bad("bad_vical", "The VICAL has no date.");
  if (!inspect) {
    if (date > new Date(now.getTime() + 86400e3)) bad("bad_vical", "The VICAL is dated in the future.");
    if (nextUpdate && now - nextUpdate > graceDays * 86400e3) bad("stale_vical", "The VICAL is past its next update. Fetch a fresh one.");
    if (now - date > maxAgeDays * 86400e3) bad("stale_vical", "The VICAL is too old. Fetch a fresh one.");
  }
  const issueId = get(v, "vicalIssueID") ?? null;
  if (minIssueId != null && (typeof issueId !== "number" || issueId < minIssueId)) bad("stale_vical", "This VICAL is older than one already seen (a rollback).");
  const infos = get(v, "certificateInfos");
  if (!Array.isArray(infos)) bad("bad_vical", "The VICAL lists no certificates.");
  return {
    provider: get(v, "vicalProvider"), date: date.toISOString(), nextUpdate: nextUpdate?.toISOString() || null, issueId,
    trusted,
    signer: { subject: signer.subject, notAfter: signer.notAfter.toISOString(), fingerprint: fp(signer) },
    chain: chain.map((c) => ({ subject: c.subject, issuer: c.issuer, notAfter: c.notAfter.toISOString(), fingerprint: fp(c), ca: c.isCa })),
    certificates: infos.map((c) => ({
      der: get(c, "certificate"), docTypes: get(c, "docType") || [], country: get(c, "issuingCountry") || null,
      state: get(c, "stateOrProvinceName") || null, authority: get(c, "issuingAuthority") || null,
    })).filter((c) => c.der instanceof Uint8Array),
  };
}

const toHexStr = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Element value → display string for dates (full-date tag 1004, tdate tag 0) and plain values. */
export const text = (v) => (v instanceof Tagged ? String(v.value) : v instanceof Uint8Array ? null : v == null ? null : typeof v === "object" ? plain(v) : v);
