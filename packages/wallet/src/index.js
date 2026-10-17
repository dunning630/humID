// @humid/wallet — Apple Wallet passes into the vault, checked first.
//
//   readPkpass   unzip (bounded), manifest hashes, the issuer's CMS signature, the
//                chain to Apple's pinned roots, and pass.json matching its certificate
//   summarizePass / passIndex   what the app shows, and what the encrypted index carries
//
// Google Wallet has no file to export, so there is nothing to read from it.
export { readPkpass, summarizePass, passIndex, looksLikePass, MEDIA_TYPE, STYLE_LABEL } from "./pkpass.js";
export { readZip, crc32, WalletError, LIMITS } from "./zip.js";
export { parseCert, verifyWith, issuedBy, OID } from "./x509.js";
export { parseSignature } from "./cms.js";
export { APPLE_ROOTS } from "./roots.js";
