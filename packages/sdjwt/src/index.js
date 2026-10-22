// @humid/sdjwt — SD-JWT credentials (RFC 9901, SD-JWT VC) for HumID 4.0:
//
//   sdjwt    verify a presentation: issuer signature (x5c chain or a pinned /
//            metadata key), disclosures (each used exactly once), validity,
//            key binding to this request's nonce and audience
//   status   revocation and suspension from an IETF Token Status List
//   jose     JWS verify, JWK, x5c, ECDH-ES JWE decrypt (OpenID4VP dc_api.jwt)
//
// Verification only: HumID never issues these. No network; the app fetches.
export { verifySdJwtVc, splitSdJwt, resolveDisclosures, issuerMetadataUrl, keyFromIssuerMetadata, SdJwtError, VC_TYPES } from "./sdjwt.js";
export { checkStatusJwt, checkStatusCwt, statusReference, statusAt, inflate, StatusError, STATUS } from "./status.js";
export { parseJws, verifyJwsWith, jwkKey, jwkThumbprint, x5cKey, ecdhKeyPair, decryptJwe, b64u, unb64u, JoseError, SUPPORTED_ALGS } from "./jose.js";
