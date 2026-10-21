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

export { encode, decode, get, plain, Encoded, Tagged, CborError } from "./cbor.js";
export { coseKey, ecCoseKey, parse1, verifySign1, verifyMac0, signSign1, macMac0, x5chain, ALG, CoseError } from "./cose.js";
export { parseCertificate, readCertificates, issuedBy, fromPem, X509Error, OIDS } from "./x509.js";
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
 *   - the signer certificate (x5chain) chains to one of `providerRoots`, is valid
 *     now, isn't a CA, and carries the VICAL signer key usage (1.0.18013.5.1.8)
 *   - the signature verifies
 *   - the list isn't dated in the future or past its nextUpdate, and, when
 *     `minIssueId` is given (the last one seen), isn't older than it
 * Returns { provider, date, nextUpdate, issueId, certificates: [{ der, docTypes, country, state, authority }] }.
 */
export function readVical(bytes, { providerRoots, now = new Date(), minIssueId, maxAgeDays = 400 } = {}) {
  return coded(() => readVicalInner(bytes, { providerRoots, now, minIssueId, maxAgeDays }), "bad_vical", "The VICAL can't be read.");
}

function readVicalInner(bytes, { providerRoots, now, minIssueId, maxAgeDays }) {
  const bad = (code, m) => { throw new MdocError(code, m); };
  if (!providerRoots?.length) bad("no_trust", "A VICAL is only as good as its provider: pass the provider's root.");
  const sign1 = parse1(bytes instanceof Uint8Array ? decode(bytes) : bytes);
  const chain = x5chain(sign1);
  if (!chain.length) bad("bad_vical", "The VICAL has no signer certificate.");
  const signer = parseCertificate(chain[0]);
  if (!signer._curve || !verifySign1(sign1, { curve: curveOf(signer), publicKey: signer.publicKey })) bad("bad_signature", "The VICAL's signature doesn't verify.");
  if (signer.isCa || !signer.eku.includes(OIDS.ekuVicalSigner)) bad("bad_signature", "The VICAL isn't signed by a VICAL signing certificate.");
  if (now < signer.notBefore || now > signer.notAfter) bad("bad_signature", "The VICAL's signing certificate isn't valid now.");
  const roots = providerRoots.map((r) => (r?.tbs ? r : parseCertificate(r)));
  const root = roots.find((r) => r.isCa && r.keyCertSign !== false && issuedBy(signer, r));
  if (!root) bad("untrusted_issuer", "The VICAL isn't signed by a trusted provider.");
  if (now < root.notBefore || now > root.notAfter) bad("untrusted_issuer", "The VICAL provider's root isn't valid now.");

  let v = decode(sign1.payload);
  if (v instanceof Encoded) v = v.value;
  const when = (x) => { if (x == null) return null; const d = new Date(x instanceof Tagged ? x.value : x); if (Number.isNaN(d.getTime())) bad("bad_vical", "The VICAL's dates can't be read."); return d; };
  const date = when(get(v, "date")), nextUpdate = when(get(v, "nextUpdate"));
  if (!date) bad("bad_vical", "The VICAL has no date.");
  if (date > new Date(now.getTime() + 86400e3)) bad("bad_vical", "The VICAL is dated in the future.");
  if (nextUpdate && now > nextUpdate) bad("stale_vical", "The VICAL is past its next update. Fetch a fresh one.");
  if (!nextUpdate && now - date > maxAgeDays * 86400e3) bad("stale_vical", "The VICAL is too old. Fetch a fresh one.");
  const issueId = get(v, "vicalIssueID") ?? null;
  if (minIssueId != null && (typeof issueId !== "number" || issueId < minIssueId)) bad("stale_vical", "This VICAL is older than one already seen (a rollback).");
  const infos = get(v, "certificateInfos");
  if (!Array.isArray(infos)) bad("bad_vical", "The VICAL lists no certificates.");
  return {
    provider: get(v, "vicalProvider"), date: date.toISOString(), nextUpdate: nextUpdate?.toISOString() || null, issueId,
    certificates: infos.map((c) => ({
      der: get(c, "certificate"), docTypes: get(c, "docType") || [], country: get(c, "issuingCountry") || null,
      state: get(c, "stateOrProvinceName") || null, authority: get(c, "issuingAuthority") || null,
    })).filter((c) => c.der instanceof Uint8Array),
  };
}

/** Element value → display string for dates (full-date tag 1004, tdate tag 0) and plain values. */
export const text = (v) => (v instanceof Tagged ? String(v.value) : v instanceof Uint8Array ? null : v == null ? null : typeof v === "object" ? plain(v) : v);
