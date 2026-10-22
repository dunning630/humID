// Checking what a wallet sent back, whatever the protocol and format, into one
// result shape:
//
//   { type, format, protocol, assurance, issuer, holderBound, claims, values,
//     validUntil, statusRef, status }
//
//   assurance "issuer+holder"   trusted issuer AND the presenting device holds
//                               the credential's key (not a copy)
//             "issuer"          trusted issuer; holder not proven
//             "signature-only"  the issuer's signature verifies but its root
//                               isn't trusted (allowed only when asked for)
//             "printed"         read from an unsigned barcode or MRZ
//
// A request's state is used once and expires (REQUEST_TTL_MS). Anything that
// doesn't check out throws CredsError with a code and a plain-words message.

import { annexCOpen, verifyDeviceResponse, openid4vpDcApiTranscript, fromBase64url, MdocError, CborError, CoseError, X509Error, HpkeError, get } from "@humid/mdoc";
import { verifySdJwtVc, decryptJwe, checkStatusJwt, checkStatusCwt, statusReference, SdJwtError, JoseError, StatusError } from "@humid/sdjwt";
import { parseAamva } from "@humid/idscan";
import { TYPES } from "./catalog.js";
import { CredsError, fail } from "./request.js";

const td = new TextDecoder("utf-8", { fatal: true });
const MDOC_TYPE_BY_DOCTYPE = Object.fromEntries(Object.entries(TYPES).filter(([, t]) => t.docType).map(([k, t]) => [t.docType, k]));

/** Run a lower layer, turning its errors into CredsError with the same code. Parser errors on hostile input become "bad_response". */
const wrap = (fn) => {
  try { return fn(); } catch (e) {
    if (e instanceof CredsError) throw e;
    if (e instanceof MdocError || e instanceof SdJwtError || e instanceof JoseError || e instanceof StatusError || e instanceof HpkeError) throw new CredsError(e.code, e.message);
    if (e instanceof CborError || e instanceof CoseError || e instanceof X509Error || e instanceof TypeError || e instanceof RangeError) throw new CredsError("bad_response", "The wallet's answer is malformed.");
    throw e;
  }
};

const text = (v) => (v == null ? null : typeof v === "object" && "value" in v && "tag" in v ? String(v.value) : v instanceof Uint8Array ? null : typeof v === "object" ? null : String(v));
const date10 = (v) => { const s = text(v); return s && /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : null; };
const bool = (v) => (v === true || v === false ? v : null);

/** Normalise one verified mdoc into HumID's vocabulary. */
function fromMdoc(doc, protocol) {
  const type = MDOC_TYPE_BY_DOCTYPE[doc.docType];
  if (!type) fail("unsupported", `HumID doesn't accept ${doc.docType} documents.`);
  const v = doc.values[TYPES[type].ns] || {};
  const pick = (...k) => { for (const x of k) if (v[x] != null) return v[x]; return null; };
  const street = text(pick("resident_address", "resident_address_unicode"));
  const claims = {
    given_name: text(pick("given_name", "given_name_unicode")),
    family_name: text(pick("family_name", "family_name_unicode")),
    birth_date: date10(pick("birth_date")),
    age_over_18: bool(v.age_over_18), age_over_21: bool(v.age_over_21),
    document_number: text(v.document_number),
    expiry_date: date10(v.expiry_date),
    issuing_country: text(v.issuing_country)?.toUpperCase() || null,
    issuing_jurisdiction: text(v.issuing_jurisdiction)?.toUpperCase() || null,
    nationality: text(v.nationality),
    sex: text(v.sex),
    portrait: v.portrait instanceof Uint8Array ? v.portrait : null,
    address: street || v.resident_city ? { street, city: text(pick("resident_city", "resident_city_unicode")), region: text(v.resident_state), postal_code: text(v.resident_postal_code), country: text(v.resident_country) } : null,
  };
  const trusted = doc.chain === "trusted", holder = !!doc.device?.ok;
  if (trusted) {
    // Reported from the anchor the document was held to, in every case.
    claims.issuing_country = doc.country;
    claims.issuing_jurisdiction = doc.state ? `${doc.country}-${doc.state}` : null;
  }
  // Who issued it comes from the trust anchor (doc.country / doc.state), which
  // verifyIssuerSigned has already required the document's own claims to match.
  // Untrusted (signature-only): the document's word, said to be unconfirmed.
  return {
    type, format: "mso_mdoc", protocol, docType: doc.docType,
    assurance: trusted ? (holder ? "issuer+holder" : "issuer") : "signature-only",
    holderBound: holder,
    issuer: trusted
      ? { country: doc.country, jurisdiction: doc.state, bound: true, root: doc.root?.subject || null, rootFingerprint: doc.root?.fingerprint || null, rootSource: doc.root?.source || null, signer: doc.signer?.subject || null, keySource: "certificate" }
      : { country: claims.issuing_country, jurisdiction: claims.issuing_jurisdiction, bound: false, root: null, rootFingerprint: null, signer: doc.signer?.subject || null, keySource: "certificate" },
    claims: prune(claims), values: doc.values, validUntil: doc.validity.validUntil,
    statusRef: wrap(() => statusReference(doc.mso)), status: null,
    // What the holder's own ID record keeps, so the issuer check can be repeated later.
    detail: { chain: doc.chain, root: doc.root, signer: doc.signer, device: doc.device, digestAlgorithm: doc.digestAlgorithm, validity: doc.validity, issuerSigned: doc.issuerSigned },
  };
}

/** Normalise one verified SD-JWT VC. */
function fromSdJwt(r, protocol) {
  const type = Object.entries(TYPES).find(([, t]) => t.vct?.includes(r.vct))?.[0];
  if (!type) fail("unsupported", `HumID doesn't accept ${r.vct} credentials.`);
  const c = r.claims;
  const ages = c.age_equal_or_over && typeof c.age_equal_or_over === "object" ? c.age_equal_or_over : {};
  const a = c.address && typeof c.address === "object" ? c.address : null;
  const claims = {
    given_name: c.given_name ?? null, family_name: c.family_name ?? null, birth_date: date10(c.birthdate ?? c.birth_date),
    age_over_18: bool(ages["18"] ?? c.age_over_18), age_over_21: bool(ages["21"] ?? c.age_over_21),
    document_number: c.document_number ?? null, expiry_date: date10(c.date_of_expiry ?? c.expiry_date),
    issuing_country: typeof c.issuing_country === "string" ? c.issuing_country.toUpperCase() : null, issuing_jurisdiction: null,
    nationality: Array.isArray(c.nationalities) ? c.nationalities.join(",") : c.nationality ?? null, sex: c.sex != null ? String(c.sex) : null,
    portrait: null,
    address: a ? { street: a.street_address ?? null, city: a.locality ?? null, region: a.region ?? null, postal_code: a.postal_code ?? null, country: a.country ?? null } : null,
  };
  const holder = r.keyBinding.ok;
  // The issuer's country is the one its trust anchor speaks for. A country claim
  // nothing vouches for is dropped rather than reported as the issuer's.
  if (!r.issuer.country) delete claims.issuing_country;
  return {
    type, format: "dc+sd-jwt", protocol, vct: r.vct,
    assurance: holder ? "issuer+holder" : "issuer",
    holderBound: holder,
    issuer: {
      country: r.issuer.country, jurisdiction: r.issuer.state || null, bound: !!r.issuer.country,
      root: r.issuer.root?.subject || null, rootFingerprint: r.issuer.root?.fingerprint || null,
      signer: r.issuer.leaf?.subject || null, iss: r.iss, keySource: r.issuer.keySource,
    },
    claims: prune(claims), values: c, validUntil: r.validity.exp ? new Date(r.validity.exp * 1000).toISOString() : null,
    statusRef: wrap(() => statusReference(r)), status: null,
  };
}

const prune = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v != null));

function useState(state, now) {
  if (!state || state.v !== 1) fail("bad_state", "This answer doesn't belong to a request HumID made.");
  if (state.used) fail("replayed", "This request was already answered. Ask again.");
  if (now > state.expiresAt) fail("expired_request", "The request timed out. Ask again.");
  state.used = true;
}

/**
 * Check a DigitalCredential ({ protocol, data }) returned by navigator.credentials.get.
 *   trust: { iaca: [roots for mdoc issuers], sdjwt: { roots, resolveKey, issuers } }
 *   allowUntrustedIssuer: accept "signature-only" (for a holder filing their own ID before trust lists are set up)
 * Returns an array of results (normally one).
 */
export function verifyCredentialResponse(state, credential, opts = {}) {
  useState(state, (opts.now || new Date()).getTime());
  return wrap(() => verifyAnswer(state, credential, opts));
}

function verifyAnswer(state, credential, { trust = {}, now = new Date(), allowUntrustedIssuer = false } = {}) {
  const protocol = credential?.protocol;
  let data = credential?.data;
  if (typeof data === "string") { try { data = JSON.parse(data); } catch { fail("bad_response", "The wallet's answer can't be read."); } }
  if (!data || typeof data !== "object") fail("bad_response", "The wallet's answer is empty.");
  const roots = trust.iaca === undefined && allowUntrustedIssuer ? undefined : trust.iaca || [];

  if (protocol === "org-iso-mdoc") {
    const st = state.protocols["org-iso-mdoc"];
    if (!st) fail("bad_response", "The wallet answered with a protocol HumID didn't offer.");
    const { response, session } = wrap(() => annexCOpen(st, data));
    const docs = wrap(() => verifyDeviceResponse(response, { session, roots, now }));
    return docs.map((d) => {
      if (!st.docTypes.includes(d.docType)) fail("doc_type", "The wallet shared a kind of document that wasn't asked for.");
      return finish(fromMdoc(d, protocol), allowUntrustedIssuer);
    });
  }

  if (protocol === "openid4vp-v1-unsigned" || protocol === "openid4vp") {
    const st = state.protocols.openid4vp;
    if (!st) fail("bad_response", "The wallet answered with a protocol HumID didn't offer.");
    if (data.error) fail("wallet_error", `The wallet declined (${String(data.error).slice(0, 80)}).`);
    if (data.vp_token !== undefined) fail("not_encrypted", "The wallet's answer should have been encrypted to this request's key.");
    if (typeof data.response !== "string") fail("bad_response", "The wallet's answer has no encrypted response.");
    let body;
    try { body = JSON.parse(td.decode(wrap(() => decryptJwe(data.response, st.enc)))); } catch (e) { if (e instanceof CredsError) throw e; fail("bad_response", "The decrypted answer isn't JSON."); }
    const vp = body?.vp_token;
    if (!vp || typeof vp !== "object" || Array.isArray(vp)) fail("bad_response", "The answer has no vp_token.");
    const out = [];
    for (const [id, list] of Object.entries(vp)) {
      if (!st.ids.includes(id)) fail("bad_response", `The wallet answered "${id}", which wasn't asked for.`);
      const t = TYPES[id];
      for (const p of Array.isArray(list) ? list : [list]) {
        if (typeof p !== "string") fail("bad_response", "A presentation isn't text.");
        if (t.format === "mso_mdoc") {
          const session = { transcript: wrap(() => openid4vpDcApiTranscript({ origin: state.origin, nonce: st.nonce, jwkThumbprint: st.thumbprint })) };
          const docs = wrap(() => verifyDeviceResponse(fromBase64url(p), { session, roots, now, docType: t.docType }));
          out.push(...docs.map((d) => finish(fromMdoc(d, "openid4vp"), allowUntrustedIssuer)));
        } else {
          const r = wrap(() => verifySdJwtVc(p, { trust: trust.sdjwt || {}, nonce: st.nonce, aud: `origin:${state.origin}`, now, vcts: t.vct }));
          out.push(finish(fromSdJwt(r, "openid4vp"), allowUntrustedIssuer));
        }
      }
    }
    if (!out.length) fail("nothing_shared", "The wallet didn't share a credential.");
    return out;
  }

  fail("bad_response", `HumID doesn't accept the "${String(protocol).slice(0, 40)}" protocol.`);
}

function finish(result, allowUntrusted) {
  if (result.assurance === "signature-only" && !allowUntrusted) fail("untrusted_issuer", "This credential's issuer isn't in HumID's trusted list.");
  if (!result.holderBound) fail("device_not_present", "The wallet didn't prove it holds this credential. The data may have been copied.");
  return result;
}

/**
 * Check revocation. fetchList(uri) → the status list token (a statuslist+jwt
 * string or statuslist+cwt bytes); the app or server does the fetching.
 * Sets result.status to "valid" | "revoked" | "suspended" | … and returns it.
 */
export async function checkStatus(result, { fetchList, trust = {}, now = new Date(), maxAgeSeconds } = {}) {
  if (!result.statusRef) return (result.status = { status: "none", note: "The issuer gives this credential no status list." });
  if (!fetchList) fail("bad_request", "Checking status needs a way to fetch the issuer's list.");
  const token = await fetchList(result.statusRef.uri);
  try {
    result.status = typeof token === "string"
      ? await checkStatusJwt(token, result.statusRef, { trust: result.format === "dc+sd-jwt" ? trust.sdjwt || {} : { roots: trust.iaca || [] }, now, maxAgeSeconds, root: result.issuer?.rootFingerprint || undefined })
      : await checkStatusCwt(token, result.statusRef, { roots: (result.format === "dc+sd-jwt" ? trust.sdjwt?.roots : trust.iaca) || [], now, maxAgeSeconds, root: result.issuer?.rootFingerprint || undefined });
  } catch (e) { if (e instanceof StatusError || e instanceof JoseError) throw new CredsError(e.code, e.message); throw e; }
  return result.status;
}

/**
 * A physical US or Canadian license read from its PDF417 barcode. Never
 * "verified": the barcode isn't signed. Useful to compare with a mobile ID.
 */
export function fromLicenseBarcode(barcodeText) {
  const a = parseAamva(barcodeText);
  if (!a) fail("bad_document", "That isn't a driver's license barcode.");
  const f = a.fields;
  return {
    type: "license_barcode", format: "aamva-pdf417", protocol: "camera", assurance: "printed", holderBound: false,
    issuer: { country: f.issuer || null, jurisdiction: f.region || null, root: null, signer: null },
    claims: prune({ given_name: f.given || null, family_name: f.surname || null, birth_date: date10(f.birth), expiry_date: date10(f.expiry), document_number: f.number || null, issuing_country: f.issuer || null, issuing_jurisdiction: f.region || null }),
    values: null, validUntil: null, statusRef: null, status: null,
  };
}

export { get };
