// @humid/idscan — reads identity documents into one record that HumID seals
// into the vault. Pure parsing, no camera or platform code:
//
//   mrz     passport and ID card machine-readable zones, tolerant of OCR
//           (check-digit repair, several frames voting)
//   aamva   US and Canadian driver's license and ID card barcodes (PDF417)
//   chip    passport and ID card chips: DG1, the DG2 photo, SOD hash checks
//   mdoc    mobile IDs (ISO 18013-5) verified by @humid/mdoc: field mapping
//   record  the one record they all fill, with where each field came from
export { checkDigit, parseMrz, parseMrzLines, findMrz, MrzConsensus, vote, mrzDate, kindOfCode, accessFromMrz } from "./mrz.js";
export { parseAamva, isAamva, aamvaDate } from "./aamva.js";
export { readDg1, readDg2, sodHashes, checkIntegrity, safeCheckIntegrity, chipIntegrityOk, tlvAt, tlvChildren } from "./chip.js";
export {
  SCHEMA, MEDIA_TYPE, KINDS, FIELDS, kindLabel, fieldsFor, newRecord, applyMrz, applyAamva, applyChip, applyMdoc, applyTyped, setImage,
  niceName, fullName, title, status, summary, provenance, recheckChip, encodeRecord, decodeRecord,
} from "./record.js";
export { COUNTRIES, REGIONS, ALPHA2, countryName, regionName } from "./places.js";
export { mdocFields, isMdocType, alpha3, imageType, MDOC_TYPES } from "./mdoc.js";
