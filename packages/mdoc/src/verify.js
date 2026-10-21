// Verifying an mdoc (ISO/IEC 18013-5 clause 9.3), the way @humid/anchor
// verifies a passport chip:
//
//   issuer data authentication   (like passive authentication)
//     - the Mobile Security Object is signed by the Document Signer whose
//       certificate is in the signature's x5chain header
//     - the Document Signer certificate is issued by a trusted IACA root
//       (the issuing state's or country's), carries the mdoc signer key
//       purpose, and its country matches the document's
//     - every data element shared hashes to the digest the MSO lists for it
//     - the MSO is for this document type and is valid now
//   mdoc authentication          (like active authentication)
//     - the wallet signed (or MACed) this session's transcript with the
//       device key the issuer put in the MSO. Copied data can't do that.

import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { decode, encode, get, plain, Encoded, Tagged } from "./cbor.js";
import { parse1, verifySign1, verifyMac0, x5chain, coseKey, CoseError } from "./cose.js";
import { parseCertificate, issuedBy, curveOf, OIDS, X509Error } from "./x509.js";
import { CborError } from "./cbor.js";

export class MdocError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, m) => { throw new MdocError(code, m); };

/** Anything a hostile document can make the parsers throw becomes a coded refusal. */
export function coded(fn, code = "bad_document", message = "The document is malformed.") {
  try { return fn(); } catch (e) {
    if (e instanceof MdocError) throw e;
    if (e instanceof CoseError || e instanceof CborError || e instanceof X509Error || e instanceof TypeError || e instanceof RangeError) throw new MdocError(code, message);
    throw e;
  }
}

/** Where each document type keeps issuing_country / issuing_jurisdiction. */
const COUNTRY_NS = {
  "org.iso.18013.5.1.mDL": "org.iso.18013.5.1",
  "eu.europa.ec.eudi.pid.1": "eu.europa.ec.eudi.pid.1",
  "org.iso.23220.photoid.1": "org.iso.23220.1",
};

const DIGESTS = { "SHA-256": sha256, "SHA-384": sha384, "SHA-512": sha512 };
const same = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((x, i) => x === b[i]);
const dateOf = (t) => {
  const s = t instanceof Tagged ? t.value : t;
  const d = new Date(typeof s === "number" ? s * 1000 : String(s));
  if (Number.isNaN(d.getTime())) fail("bad_mso", "The document's validity dates can't be read.");
  return d;
};

/** Roots: IACA certificates as DER bytes, PEM text, or already parsed. */
const asCerts = (roots) => (roots || []).flatMap((r) => {
  if (r && r.tbs) return [r];
  if (typeof r === "string") return (r.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((p) => parseCertificate(p));
  return [parseCertificate(r)];
});

/**
 * Issuer data authentication of one document's IssuerSigned.
 * roots: trusted IACA certificates; none means "signature checked, issuer
 * not yet checked" (chain: "unchecked"), never "trusted".
 */
export function verifyIssuerSigned(issuerSigned, opts = {}) {
  return coded(() => verifyIssuerSignedInner(issuerSigned, opts));
}

function verifyIssuerSignedInner(issuerSigned, { docType, roots, now = new Date() } = {}) {
  const auth = get(issuerSigned, "issuerAuth");
  if (!auth) fail("bad_document", "The document has no issuer signature.");
  const sign1 = parse1(auth);

  // The Document Signer certificate (leaf first).
  const chain = x5chain(sign1);
  if (!chain.length) fail("bad_document", "The issuer signature doesn't include its certificate.");
  let ds;
  try { ds = parseCertificate(chain[0]); } catch { fail("bad_document", "The issuer's certificate can't be read."); }
  if (!ds._curve) fail("unsupported", "The issuer's key type isn't supported.");
  if (!verifySign1(sign1, { curve: curveOf(ds), publicKey: ds.publicKey })) fail("bad_signature", "The issuer's signature doesn't verify. The document may be forged or altered.");

  // The Mobile Security Object.
  if (!(sign1.payload instanceof Uint8Array)) fail("bad_mso", "The issuer signature has no content.");
  let mso;
  try { const outer = decode(sign1.payload); mso = outer instanceof Encoded ? outer.value : outer; } catch { fail("bad_mso", "The signed content can't be read."); }
  const digestAlg = get(mso, "digestAlgorithm");
  const hash = DIGESTS[digestAlg];
  if (!hash) fail("unsupported", `The document uses digest ${digestAlg}, which HumID doesn't support.`);
  const msoDocType = get(mso, "docType");
  if (docType && msoDocType !== docType) fail("doc_type", "The signed document type doesn't match.");
  const validity = get(mso, "validityInfo");
  const signed = dateOf(get(validity, "signed")), validFrom = dateOf(get(validity, "validFrom")), validUntil = dateOf(get(validity, "validUntil"));
  const expectedUpdate = get(validity, "expectedUpdate") ? dateOf(get(validity, "expectedUpdate")) : null;
  if (now < validFrom) fail("not_yet_valid", "The document's signature isn't valid yet.");
  if (now > validUntil) fail("signature_expired", "The issuer's signature on this document has lapsed. Refresh it in the wallet, then share again.");
  if (signed < ds.notBefore || signed > ds.notAfter) fail("bad_signature", "The document was signed outside its signer certificate's validity.");
  // ISO 18013-5 Annex B: a Document Signer carries the mdlDS extended key usage and digitalSignature.
  if (!ds.eku.includes(OIDS.ekuMdlDs)) fail("bad_signature", "The signing certificate isn't allowed to sign mobile IDs.");
  if (ds.digitalSignature !== true || ds.isCa) fail("bad_signature", "The signing certificate isn't a document signing certificate.");

  // Every element shared matches its signed digest.
  const valueDigests = get(mso, "valueDigests");
  const nameSpaces = get(issuerSigned, "nameSpaces") || new Map();
  const values = {};
  const items = {};
  for (const [ns, list] of nameSpaces) {
    const digests = get(valueDigests, ns);
    if (!digests) fail("data_altered", `The issuer didn't sign the ${ns} data.`);
    values[ns] = {};
    items[ns] = [];
    for (const item of list) {
      if (!(item instanceof Encoded)) fail("bad_document", "A data element isn't encoded as the standard requires.");
      const it = item.value;
      const id = get(it, "digestID");
      const want = get(digests, id);
      if (!same(hash(item.encoded), want)) fail("data_altered", `"${get(it, "elementIdentifier")}" doesn't match the issuer's signature.`);
      const name = get(it, "elementIdentifier");
      if (typeof name !== "string") fail("bad_document", "A data element has no name.");
      if (Object.hasOwn(values[ns], name)) fail("bad_document", `"${name}" appears twice.`);
      values[ns][name] = get(it, "elementValue");
      items[ns].push(item);
    }
  }

  // The issuing authority's root.
  let trust = { chain: "unchecked", root: null };
  const iacas = asCerts(roots);
  if (roots) {
    if (!iacas.length) fail("no_trust", "No issuing-authority certificates are configured, so mobile IDs can't be checked yet.");
    // Intermediate certificates in x5chain (rare) are tried too.
    const path = chain.slice(1).map((c) => { try { return parseCertificate(c); } catch { return null; } }).filter(Boolean);
    const anchorFor = (cert, depth = 0) => {
      for (const r of iacas) if (issuedBy(cert, r)) return r;
      if (depth > 2) return null;
      for (const mid of path) {
        if (!mid.isCa || mid.keyCertSign === false || now < mid.notBefore || now > mid.notAfter || !issuedBy(cert, mid)) continue;
        const r = anchorFor(mid, depth + 1); if (r) return r;
      }
      return null;
    };
    const root = anchorFor(ds);
    if (!root) fail("untrusted_issuer", "This document's issuer isn't in HumID's trusted list.");
    if (!root.isCa || root.keyCertSign === false) fail("untrusted_issuer", "The issuer's root certificate isn't a certificate authority.");
    if (now < ds.notBefore || now > ds.notAfter) fail("untrusted_issuer", "The issuer's signing certificate isn't valid now.");
    if (now < root.notBefore || now > root.notAfter) fail("untrusted_issuer", "The issuing authority's root certificate isn't valid now.");
    // The country the document claims must be its issuing authority's, in the document type's own namespace.
    const own = values[COUNTRY_NS[msoDocType]] || {};
    const country = own.issuing_country;
    if (country != null && root.subject.C && String(country).toUpperCase() !== root.subject.C.toUpperCase()) fail("untrusted_issuer", "The document's country doesn't match its issuing authority.");
    // The state, when both sides name it as a code ("US-IL" / "IL"); free-text names aren't compared.
    const code = (v) => { const m = /^(?:[A-Z]{2}-)?([A-Z0-9]{1,3})$/.exec(String(v || "").toUpperCase().trim()); return m ? m[1] : null; };
    const juris = code(own.issuing_jurisdiction), st = code(root.subject.ST);
    if (juris && st && juris !== st) fail("untrusted_issuer", "The document's state doesn't match its issuing authority.");
    trust = { chain: "trusted", root: { subject: root.subject, notAfter: root.notAfter.toISOString(), fingerprint: root.fingerprint }, issuerCountry: root.subject.C ? root.subject.C.toUpperCase() : null };
  }

  const dki = get(mso, "deviceKeyInfo");
  const deviceKey = coseKey(get(dki, "deviceKey"));
  return {
    docType: msoDocType, values, items, digestAlgorithm: digestAlg,
    validity: { signed: signed.toISOString(), validFrom: validFrom.toISOString(), validUntil: validUntil.toISOString(), expectedUpdate: expectedUpdate?.toISOString() || null },
    signer: { subject: ds.subject, issuer: ds.issuer, notAfter: ds.notAfter.toISOString() },
    ...trust, deviceKey, mso,
  };
}

/** DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]). */
export function deviceAuthenticationBytes(transcript, docType, deviceNameSpacesBytes) {
  return Encoded.of(["DeviceAuthentication", transcript, docType, deviceNameSpacesBytes]).encoded;
}

/**
 * Verify a DeviceResponse. Pass the session (ReaderSession or { transcript,
 * eMacKey }) to require mdoc authentication; leave it out only when
 * re-checking stored data (device: "unchecked").
 */
export function verifyDeviceResponse(response, opts = {}) {
  return coded(() => verifyDeviceResponseInner(response, opts), "bad_response", "The wallet's answer is malformed.");
}

function verifyDeviceResponseInner(response, { session, roots, now = new Date(), docType } = {}) {
  let r;
  try { r = response instanceof Uint8Array ? decode(response) : response; } catch { fail("bad_response", "The wallet's answer can't be read."); }
  const status = get(r, "status");
  const docs = get(r, "documents") ?? [];
  if (!Array.isArray(docs)) fail("bad_response", "The wallet's answer is malformed.");
  const errors = get(r, "documentErrors");
  if (!docs.length) fail(status === 0 || status == null ? "nothing_shared" : "wallet_error", status ? `The wallet reported an error (${status}).` : "No document was shared.");
  return docs.map((d) => {
    const type = get(d, "docType");
    if (docType && type !== docType) fail("doc_type", "The wallet shared a different kind of document.");
    const issuer = verifyIssuerSigned(get(d, "issuerSigned"), { docType: type, roots, now });
    const deviceSigned = get(d, "deviceSigned");
    const nsBytes = get(deviceSigned, "nameSpaces");
    let device = { method: null, ok: null };
    if (session) {
      if (!(nsBytes instanceof Encoded)) fail("bad_document", "The wallet's signed part is malformed.");
      if ((nsBytes.value?.size ?? 0) > 0) fail("bad_document", "Device-signed data elements aren't supported.");
      const auth = get(deviceSigned, "deviceAuth");
      const payload = deviceAuthenticationBytes(session.transcript, type, nsBytes);
      if (get(auth, "deviceSignature")) {
        if (!verifySign1(parse1(get(auth, "deviceSignature")), issuer.deviceKey, { detached: payload })) fail("device_not_present", "The wallet's signature for this session doesn't verify. The document data may have been copied.");
        device = { method: "signature", ok: true };
      } else if (get(auth, "deviceMac")) {
        if (!session.eMacKey) fail("device_not_present", "This session can't check a MAC.");
        if (!verifyMac0(parse1(get(auth, "deviceMac")), session.eMacKey(issuer.deviceKey), { detached: payload })) fail("device_not_present", "The wallet's MAC for this session doesn't verify. The document data may have been copied.");
        device = { method: "mac", ok: true };
      } else fail("device_not_present", "The wallet didn't authenticate itself.");
    }
    let errs = null;
    if (errors) { try { errs = plain(errors); } catch { errs = { unreadable: true }; } }
    return { ...issuer, device, errors: errs, issuerSigned: get(d, "issuerSigned") };
  });
}

/** IssuerSigned → bytes to keep, so the issuer check can be repeated later. */
export const encodeIssuerSigned = (issuerSigned) => encode(issuerSigned);
