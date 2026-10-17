// @humid/cards — the holder's payment cards in the vault, the same on every
// platform. No platform code: the camera engine hands over text, the NFC
// plugin (Android IsoDep, desktop PC/SC) hands over an APDU transport.
//
//   pan     Luhn check, network from the leading digits, formatting, masking, expiry
//   ocr     card front from OCR text, with frame consensus for live scanning
//   emv     contactless read of number and expiry (no payment, no security code)
//   record  the sealed record: what it holds, what it refuses, how apps show it
export { digits, luhn, BRANDS, brandOf, checkPan, formatPan, last4, maskPan, parseExpiry, expiryStatus, showExpiry } from "./pan.js";
export { readCardText, readCardBack, CardConsensus } from "./ocr.js";
export { readContactless, parseTrack2, tlv, find as findTlv, AIDS, CardReadError } from "./emv.js";
export {
  SCHEMA, MEDIA_TYPE, HANDLING, FIELDS, FORBIDDEN, newCard, applyRead, applyTyped, setStoreCvv, setImage, problems,
  brand, status, title, summary, view, encodeCard, decodeCard, CardRecordError,
} from "./record.js";
