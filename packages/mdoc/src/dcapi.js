// Mobile IDs requested online, through the browser's or the phone's own
// credential picker (W3C Digital Credentials API: navigator.credentials.get
// with `digital`), instead of a QR code and Bluetooth.
//
// Two request protocols carry an mdoc. Both end in the same DeviceResponse,
// checked by verifyDeviceResponse; they differ in the SessionTranscript the
// wallet signs, which is what binds the answer to THIS request on THIS site:
//
//   org-iso-mdoc         ISO/IEC TS 18013-7 Annex C. Safari 26 / iOS 26 and
//                        Chrome 141+. The response is HPKE-encrypted to a key
//                        the requester made for this request.
//     EncryptionInfo     = ["dcapi", { nonce, recipientPublicKey: COSE_Key }]
//     SessionTranscript  = [null, null, ["dcapi", SHA-256(cbor([b64url(EncryptionInfo), origin]))]]
//     EncryptedResponse  = ["dcapi", { enc, cipherText }]
//     HPKE               = DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM;
//                          info = CBOR(SessionTranscript) (not tag-24 wrapped), aad empty
//
//   openid4vp-v1-*       OpenID for Verifiable Presentations 1.0, Appendix B
//     SessionTranscript  = [null, null, ["OpenID4VPDCAPIHandover",
//                           SHA-256(cbor([origin, nonce, jwkThumbprint | null]))]]
//                          (jwkThumbprint: the raw SHA-256 JWK thumbprint of the
//                          verifier's response-encryption key, null when the
//                          response isn't encrypted; origin has no "origin:" prefix)
//     and, for redirect (non-browser) flows:
//                          ["OpenID4VPHandover", SHA-256(cbor([clientId, nonce, jwkThumbprint | null, responseUri]))]
//
// Optional ReaderAuth (ISO 18013-5 9.1.4): the requester signs what it asks
// for with a reader certificate. Apple Wallet requires one issued through
// Apple Business Connect; other wallets may show the requester's name from it.

import { sha256 } from "@noble/hashes/sha2.js";
import { encode, decode, get, Encoded } from "./cbor.js";
import { coseKey, ecCoseKey, signSign1, ALG } from "./cose.js";
import { hpkeKeyPair, hpkeOpen, HpkeError } from "./hpke.js";
import { MdocError } from "./verify.js";

const fail = (code, m) => { throw new MdocError(code, m); };
const b64u = (b) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = (s) => {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) fail("bad_response", "The response isn't base64url.");
  if (s.length % 4 === 1) fail("bad_response", "The response isn't base64url.");
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  let bin;
  try { bin = atob(t + "===".slice((t.length + 3) % 4)); } catch { fail("bad_response", "The response isn't base64url."); }
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
export { b64u as base64url, unb64u as fromBase64url };

/** An origin as the browser serialises it: scheme://host[:port], no path, no trailing slash. */
export function serializeOrigin(origin) {
  let u;
  try { u = new URL(origin); } catch { fail("bad_origin", "The origin isn't a URL."); }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && /^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname))) fail("bad_origin", "Mobile IDs can only be requested from an https origin.");
  return u.origin;
}

const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

/* ---------------- session transcripts ---------------- */

/** ISO 18013-7 Annex C. encryptionInfoB64: exactly the string sent in the request. */
export function annexCTranscript(encryptionInfoB64, origin) {
  const info = encode([encryptionInfoB64, serializeOrigin(origin)]);
  return [null, null, ["dcapi", sha256(info)]];
}

/** OpenID4VP 1.0 over the Digital Credentials API. thumbprint: 32 raw bytes or null. */
export function openid4vpDcApiTranscript({ origin, nonce, jwkThumbprint = null }) {
  if (typeof nonce !== "string" || !nonce) fail("bad_request", "The request needs a nonce.");
  if (jwkThumbprint != null && !(jwkThumbprint instanceof Uint8Array && jwkThumbprint.length === 32)) fail("bad_request", "The key thumbprint must be 32 raw bytes.");
  return [null, null, ["OpenID4VPDCAPIHandover", sha256(encode([serializeOrigin(origin), nonce, jwkThumbprint]))]];
}

/** OpenID4VP 1.0 redirect flow (a wallet on another device answering a response_uri). */
export function openid4vpRedirectTranscript({ clientId, nonce, jwkThumbprint = null, responseUri }) {
  if (!clientId || !nonce || !responseUri) fail("bad_request", "The redirect handover needs client_id, nonce and response_uri.");
  return [null, null, ["OpenID4VPHandover", sha256(encode([clientId, nonce, jwkThumbprint, responseUri]))]];
}

/** SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript), as ISO 18013-5 uses it for session-key salts. (Annex C's HPKE info is the plain encoding.) */
export const transcriptBytes = (transcript) => Encoded.of(transcript).encoded;

/* ---------------- requests ---------------- */

/**
 * DeviceRequest with optional ReaderAuth per document request.
 * items: [{ docType, nameSpaces: { ns: { element: intentToRetain } } }]
 * readerAuth: { key: { curve, secretKey }, chain: [DER…], alg } and the transcript it signs.
 */
export function signedDeviceRequest(items, { readerAuth, transcript } = {}) {
  const docRequests = items.map(({ docType, nameSpaces }) => {
    const ns = new Map(Object.entries(nameSpaces).map(([n, els]) => [n, new Map(Object.entries(els).map(([e, keep]) => [e, !!keep]))]));
    const itemsRequest = Encoded.of(new Map([["docType", docType], ["nameSpaces", ns]]));
    const req = new Map([["itemsRequest", itemsRequest]]);
    if (readerAuth) {
      if (!transcript) fail("bad_request", "Reader authentication needs the session transcript.");
      const ra = Encoded.of(["ReaderAuthentication", transcript, itemsRequest]).encoded;
      const unprotected = new Map([[33, readerAuth.chain.length === 1 ? readerAuth.chain[0] : readerAuth.chain]]);
      req.set("readerAuth", signSign1(ra, readerAuth.key, { alg: readerAuth.alg ?? ALG.ES256, unprotected, detached: true }));
    }
    return req;
  });
  return encode(new Map([["version", "1.0"], ["docRequests", docRequests]]));
}

/**
 * Build an org-iso-mdoc request for navigator.credentials.get. Keep `state`
 * on the side that will open the answer (it holds the decryption key) and
 * never send it anywhere.
 * items: as signedDeviceRequest; origin: the page's origin.
 */
export function annexCRequest(items, { origin, readerAuth, nonce = random(16), keyPair = hpkeKeyPair() } = {}) {
  const serialized = serializeOrigin(origin);
  const encryptionInfo = encode(["dcapi", new Map([["nonce", nonce], ["recipientPublicKey", ecCoseKey(keyPair.publicKey, 1)]])]);
  const encryptionInfoB64 = b64u(encryptionInfo);
  const transcript = annexCTranscript(encryptionInfoB64, serialized);
  const deviceRequest = signedDeviceRequest(items, { readerAuth, transcript });
  return {
    request: { protocol: "org-iso-mdoc", data: { deviceRequest: b64u(deviceRequest), encryptionInfo: encryptionInfoB64 } },
    state: { protocol: "org-iso-mdoc", origin: serialized, encryptionInfoB64, keyPair, transcript, docTypes: items.map((i) => i.docType), createdAt: Date.now() },
  };
}

/**
 * Open an org-iso-mdoc answer: data is the DigitalCredential's `data`
 * ({ response: b64url(EncryptedResponse) }). Returns { response (DeviceResponse
 * bytes), session: { transcript } } for verifyDeviceResponse.
 */
export function annexCOpen(state, data) {
  if (state?.protocol !== "org-iso-mdoc") fail("bad_state", "This request wasn't an org-iso-mdoc request.");
  const raw = typeof data === "string" ? data : data?.response;
  let er;
  try { er = decode(unb64u(raw)); } catch (e) { if (e instanceof MdocError) throw e; fail("bad_response", "The wallet's answer can't be read."); }
  if (!Array.isArray(er) || er[0] !== "dcapi") fail("bad_response", "The wallet's answer isn't an Annex C response.");
  const enc = get(er[1], "enc"), cipherText = get(er[1], "cipherText");
  if (!(enc instanceof Uint8Array) || !(cipherText instanceof Uint8Array)) fail("bad_response", "The wallet's answer is missing its encrypted part.");
  let response;
  // HPKE info is the SessionTranscript's own CBOR encoding, not the tag-24
  // SessionTranscriptBytes (checked against @owf/mdoc in tests/creds.test.js).
  try { response = hpkeOpen(state.keyPair, enc, cipherText, { info: encode(state.transcript) }); }
  catch (e) { if (e instanceof HpkeError) fail("decrypt", e.message); throw e; }
  return { response, session: { transcript: state.transcript } };
}

/** The request's recipient key, as a COSE_Key, for wallets (and tests) that read EncryptionInfo. */
export function readEncryptionInfo(b64) {
  const ei = decode(unb64u(b64));
  if (!Array.isArray(ei) || ei[0] !== "dcapi") fail("bad_request", "Not an Annex C EncryptionInfo.");
  return { nonce: get(ei[1], "nonce"), recipientPublicKey: coseKey(get(ei[1], "recipientPublicKey")) };
}
