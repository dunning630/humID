// The reader's side of an ISO/IEC 18013-5 proximity session (clause 9.1.1).
//
//   1. The holder shows a QR code ("mdoc:" + base64url DeviceEngagement), or
//      it arrives over NFC. It carries the wallet's ephemeral key EDeviceKey.
//   2. HumID makes its own ephemeral key EReaderKey on the same curve.
//      SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
//      binds both keys and how the devices met.
//   3. Session keys: HKDF-SHA-256 over ECDH(EReaderKey, EDeviceKey), salted
//      with SHA-256(SessionTranscriptBytes): SKReader and SKDevice.
//   4. The request and the response travel AES-256-GCM encrypted
//      (SessionEstablishment, SessionData), each direction with its own
//      counter-based IV.
//
// The transport (BLE, NFC, Wi-Fi Aware) is the platform's job; this file only
// turns bytes into bytes, like @humid/emrtd does for passport chips.

import { p256, p384, p521 } from "@noble/curves/nist.js";
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from "@noble/curves/misc.js";
import { gcm } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { encode, decode, get, Encoded } from "./cbor.js";
import { coseKey, ecCoseKey } from "./cose.js";

export class SessionError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, m) => { throw new SessionError(code, m); };
const te = new TextEncoder();

const CURVE_BY_CRV = { 1: p256, 2: p384, 3: p521, 8: brainpoolP256r1, 10: brainpoolP384r1, 11: brainpoolP512r1 };

export const RETRIEVAL = { 1: "nfc", 2: "ble", 3: "wifi-aware" };
/** SessionData status codes (ISO 18013-5 table 20). */
export const STATUS = { ERROR_ENCRYPTION: 10, ERROR_CBOR: 11, END: 20 };

const b64url = (s) => {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

/**
 * Read a DeviceEngagement: the text of the holder's QR code ("mdoc:…"), or
 * its bytes (NFC handover). Returns its parts and the exact bytes, which the
 * session transcript must reuse.
 */
export function readEngagement(input) {
  let bytes;
  if (typeof input === "string") {
    const s = input.trim();
    if (!/^mdoc:/i.test(s)) fail("not_engagement", "That QR code isn't a mobile ID (it should start with mdoc:).");
    try { bytes = b64url(s.slice(5)); } catch { fail("not_engagement", "The mobile ID QR code is damaged."); }
  } else bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let de;
  try { de = decode(bytes); } catch { fail("not_engagement", "The mobile ID QR code can't be read."); }
  const version = get(de, 0);
  const security = get(de, 1);
  if (typeof version !== "string" || !Array.isArray(security) || !(security[1] instanceof Encoded)) fail("not_engagement", "The mobile ID QR code is missing its key.");
  const cipherSuite = security[0];
  if (cipherSuite !== 1) fail("unsupported", `The wallet asked for cipher suite ${cipherSuite}; HumID supports suite 1.`);
  const eDeviceKeyBytes = security[1];
  const eDeviceKey = coseKey(eDeviceKeyBytes.value);
  if (!CURVE_BY_CRV[eDeviceKey.crv]) fail("unsupported", "The wallet's session key uses a curve HumID doesn't support.");
  const methods = (get(de, 2) || []).map((m) => ({ type: RETRIEVAL[m[0]] || m[0], version: m[1], options: m[2] }));
  return { bytes, version, cipherSuite, eDeviceKey, eDeviceKeyBytes, methods, item: de };
}

/** BLE options from an engagement: the service UUIDs the reader should use. */
export function bleOptions(engagement) {
  const m = engagement.methods.find((x) => x.type === "ble");
  if (!m) return null;
  const o = m.options;
  const uuid = (u) => (u instanceof Uint8Array ? [...u].map((x, i) => ([4, 6, 8, 10].includes(i) ? "-" : "") + x.toString(16).padStart(2, "0")).join("") : null);
  return {
    peripheralServer: get(o, 0) === true, centralClient: get(o, 1) === true,
    peripheralUuid: uuid(get(o, 10)), centralUuid: uuid(get(o, 11)), address: get(o, 20) || null,
  };
}

const ivFor = (who, counter) => {
  const iv = new Uint8Array(12);
  if (who === "device") iv[7] = 1;
  new DataView(iv.buffer).setUint32(8, counter);
  return iv;
};

/** SKReader / SKDevice / EMacKey: HKDF-SHA-256(ECDH x, salt = SHA-256(SessionTranscriptBytes), info). */
export function sessionKey(sharedX, transcriptBytes, info) {
  return hkdf(sha256, sharedX, sha256(transcriptBytes), te.encode(info), 32);
}

/** ECDH: the x coordinate of secret × public. */
export function ecdhX(curve, secretKey, publicKey) {
  return curve.getSharedSecret(secretKey, publicKey, true).slice(1);
}

/**
 * The reader's end of one session. `handover` is null for a QR engagement
 * (ISO 18013-5 9.1.5.1); NFC handovers pass their [HandoverSelect, HandoverRequest] here.
 */
export class ReaderSession {
  constructor(engagement, { handover = null, eReaderSecret } = {}) {
    this.engagement = typeof engagement === "string" || engagement instanceof Uint8Array ? readEngagement(engagement) : engagement;
    this.curve = CURVE_BY_CRV[this.engagement.eDeviceKey.crv];
    this.secret = eReaderSecret || this.curve.utils.randomSecretKey();
    const pub = this.curve.getPublicKey(this.secret, false);
    this.eReaderKeyBytes = Encoded.of(ecCoseKey(pub, this.engagement.eDeviceKey.crv));
    const transcript = [new Encoded(this.engagement.bytes), this.eReaderKeyBytes, handover];
    this.transcript = transcript;
    this.transcriptBytes = Encoded.of(transcript).encoded; // SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript)
    const z = ecdhX(this.curve, this.secret, this.engagement.eDeviceKey.publicKey);
    this.skReader = sessionKey(z, this.transcriptBytes, "SKReader");
    this.skDevice = sessionKey(z, this.transcriptBytes, "SKDevice");
    this.sent = 0;
    this.received = 0;
  }

  /** The device's MAC key for deviceMac, from its long-term key in the MSO (ISO 18013-5 9.1.3.5). */
  eMacKey(deviceKey) {
    if (deviceKey.curve !== this.curve) fail("bad_device_key", "The document's device key isn't on the session's curve.");
    return sessionKey(ecdhX(this.curve, this.secret, deviceKey.publicKey), this.transcriptBytes, "EMacKey");
  }

  encrypt(plain) { return gcm(this.skReader, ivFor("reader", ++this.sent)).encrypt(plain); }
  decrypt(cipher) {
    try { return gcm(this.skDevice, ivFor("device", ++this.received)).decrypt(cipher); }
    catch { fail("decrypt", "The wallet's answer couldn't be decrypted."); }
  }

  /** The first message to the wallet: SessionEstablishment { eReaderKey, data: encrypted DeviceRequest }. */
  establish(deviceRequestBytes) {
    return encode(new Map([["eReaderKey", this.eReaderKeyBytes], ["data", this.encrypt(deviceRequestBytes)]]));
  }

  /** A later message to the wallet: SessionData { data }, or { status: 20 } to end the session. */
  message(bytes) { return encode(new Map([["data", this.encrypt(bytes)]])); }
  end() { return encode(new Map([["status", STATUS.END]])); }

  /** The wallet's SessionData → the decrypted DeviceResponse bytes (or null if it only sent a status). */
  receive(sessionDataBytes) {
    let m;
    try { m = decode(sessionDataBytes); } catch { fail("bad_message", "The wallet's answer can't be read."); }
    const status = get(m, "status");
    const data = get(m, "data");
    if (data instanceof Uint8Array) return { response: this.decrypt(data), status: status ?? null };
    if (status === STATUS.END) fail("ended", "The wallet ended the session without sharing.");
    if (status != null) fail("wallet_error", `The wallet reported an error (${status}).`);
    fail("bad_message", "The wallet's answer is empty.");
  }
}
