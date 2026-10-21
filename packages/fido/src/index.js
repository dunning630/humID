// @humid/fido — a FIDO2 security key as a HumID recovery proof (docs/SECURITY-KEY.md).
// CTAP 2.1 over any ISO 7816 transport (the app's NFC plugin, PC/SC, a simulator);
// no platform code.
export { encode, decode, decodeFirst, CborError } from "./cbor.js";
export { FIDO_AID, selectFido, ctapMessage, command } from "./nfc.js";
export { FidoError } from "./errors.js";
export { Authenticator, parseAuthData, authenticate, pinBytes, padPin, PERMISSION, FLAG, CMD } from "./ctap.js";
export { RP_ID, RP_ID_HASH, SALT, CHALLENGE_BYTES, MIN_NEW_PIN, MAX_CANDIDATES, clientDataHash, unsuitable, inspectKey, addRecoveryKey, readRecoveryKey } from "./humid.js";
