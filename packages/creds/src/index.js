// @humid/creds — HumID 4.0 (provisional): ask for and check public identity
// credentials, whatever their format, with one call each way.
//
//   catalog   which credentials exist and what each can prove (mobile licenses
//             and IDs, EU digital identity, wallet photo IDs, passport and ID
//             chips, license barcodes, SSN)
//   request   a Digital Credentials API request (OpenID4VP + ISO 18013-7
//             Annex C) and the private state to check its answer
//   verify    the answer → one result shape, with issuer trust, holder
//             binding, revocation, and an honest assurance level
//   attest    the least that answers the question (over 21, valid ID from X),
//             committed to a persona for HumID 4.0
//   ssn       structure checks, and SSA's eCBSV for permitted entities only
//   trust     IACA roots from AAMVA's VICAL
//
// Passport and ID card chips: @humid/creds/server (Node only).

import { readVical } from "@humid/mdoc";

export { TYPES, CATALOG, CLAIMS, PURPOSES, MDL_DOCTYPE, PHOTOID_DOCTYPE, PID_DOCTYPE, PID_VCT } from "./catalog.js";
export { credentialRequest, claimsFor, mdocElements, CredsError, REQUEST_TTL_MS } from "./request.js";
export { verifyCredentialResponse, checkStatus, fromLicenseBarcode } from "./verify.js";
export { minimise, commit, checkCommitment, canonical, ageOn, FACTS, CLAIM_SCHEMA } from "./attest.js";
export { checkSsnFormat, ecbsvVerifier } from "./ssn.js";

/**
 * IACA roots for mobile IDs from a VICAL (e.g. AAMVA's Digital Trust Service),
 * whose own signature must chain to `providerRoots`. docType filters by what
 * each issuer may sign. Returns DER certificates to pass as trust.iaca.
 */
export function iacaFromVical(bytes, { providerRoots, docType } = {}) {
  if (!providerRoots?.length) throw new Error("A VICAL is only as good as its provider: pass the provider's root.");
  const v = readVical(bytes, { providerRoots });
  return v.certificates.filter((c) => !docType || !c.docTypes.length || c.docTypes.includes(docType)).map((c) => c.der);
}
