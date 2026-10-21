// A simulated FIDO2 security key (CTAP 2.1 authenticator) reached over NFC.
//
// Written from the CTAP 2.1 specification ("Client to Authenticator Protocol",
// Proposed Standard 2021-06-15), independently of the HumID client in
// packages/fido, so that each checks the other. node:crypto only; the CBOR
// codec below is this file's own.
//
//   const key = simulatedKey({ pin: "123456" });
//   const rapdu = await key.transceive(apdu);   // response data ‖ SW1 SW2
//
// Layers:
//   ISO 7816-4 / CTAP §11.3   SELECT, NFCCTAP_MSG (+ CLA 0x90 command chaining,
//                             extended length), 61xx + GET RESPONSE, 9100 status
//                             updates + NFCCTAP_GETRESPONSE, NFCCTAP_CONTROL.
//   CTAP2 §6                  getInfo, clientPIN, makeCredential, getAssertion,
//                             getNextAssertion; PIN/UV auth protocols 1 and 2;
//                             hmac-secret and credProtect extensions (§12).
import crypto from "node:crypto";

export const FIDO_AID = Uint8Array.of(0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01);

// §8.2 status codes (only those this authenticator can return).
export const CTAP_STATUS = Object.freeze({
  OK: 0x00,
  INVALID_COMMAND: 0x01,
  INVALID_PARAMETER: 0x02,
  INVALID_LENGTH: 0x03,
  CBOR_UNEXPECTED_TYPE: 0x11,
  INVALID_CBOR: 0x12,
  MISSING_PARAMETER: 0x14,
  CREDENTIAL_EXCLUDED: 0x19,
  UNSUPPORTED_ALGORITHM: 0x26,
  KEY_STORE_FULL: 0x28,
  UNSUPPORTED_OPTION: 0x2b,
  INVALID_OPTION: 0x2c,
  NO_CREDENTIALS: 0x2e,
  NOT_ALLOWED: 0x30,
  PIN_INVALID: 0x31,
  PIN_BLOCKED: 0x32,
  PIN_AUTH_INVALID: 0x33,
  PIN_AUTH_BLOCKED: 0x34,
  PIN_NOT_SET: 0x35,
  PUAT_REQUIRED: 0x36,
  PIN_POLICY_VIOLATION: 0x37,
  REQUEST_TOO_LARGE: 0x39,
  INVALID_SUBCOMMAND: 0x3e,
  UNAUTHORIZED_PERMISSION: 0x40,
});
const S = CTAP_STATUS;

const MAX_MSG_SIZE = 1200; // advertised in getInfo (0x05)
const MAX_PIN_RETRIES = 8; // maxPINRetries (§6.5.2.1)
const NEXT_ASSERTION_TIMEOUT_MS = 30_000; // §6.3
const MAX_CHAIN = 0x10000; // ISO command chaining buffer
const DEFAULT_AAGUID = new TextEncoder().encode("humid-fido-sim-1"); // 16 bytes

// pinUvAuthToken permissions (§6.5.5.7)
const PERM_MC = 0x01;
const PERM_GA = 0x02;

// authenticatorData flags (WebAuthn §6.1)
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

class CtapError extends Error {
  constructor(code) {
    super(`CTAP status 0x${code.toString(16).padStart(2, "0")}`);
    this.code = code;
  }
}
const fail = (code) => {
  throw new CtapError(code);
};

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------
const u8 = (b) => new Uint8Array(b.buffer ? b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) : b);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const equal = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
const sha256 = (b) => u8(crypto.createHash("sha256").update(b).digest());
const hmacSha256 = (key, msg) => u8(crypto.createHmac("sha256", key).update(msg).digest());
const utf8 = (s) => new TextEncoder().encode(s);
const sw = (code, data = new Uint8Array(0)) => concat(data, Uint8Array.of(code >> 8, code & 0xff));
const be32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

// ---------------------------------------------------------------------------
// CBOR (RFC 8949), CTAP2 canonical form (§8 "Message Encoding")
// ---------------------------------------------------------------------------
// Encoding: integers, byte strings (Uint8Array), text, arrays, maps (Map or
// plain object), booleans. Map keys are sorted by: major type, then encoded
// length, then bytewise lexical order; every length is minimal.
// Decoding: definite lengths only, no tags, no duplicate keys, nesting depth at
// most 4 (CTAP2 limits messages to four levels of maps/arrays).
function cborHead(major, n) {
  const m = major << 5;
  if (typeof n === "bigint") {
    const b = new Uint8Array(9);
    b[0] = m | 27;
    new DataView(b.buffer).setBigUint64(1, n);
    return b;
  }
  if (n < 24) return Uint8Array.of(m | n);
  if (n < 0x100) return Uint8Array.of(m | 24, n);
  if (n < 0x10000) return Uint8Array.of(m | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return concat(Uint8Array.of(m | 26), be32(n));
  return cborHead(major, BigInt(n));
}

function compareKeys(a, b) {
  if (a[0] >> 5 !== b[0] >> 5) return (a[0] >> 5) - (b[0] >> 5);
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export function encodeCbor(v) {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new TypeError("CBOR: only integers");
    return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  }
  if (typeof v === "bigint") return v >= 0n ? cborHead(0, v) : cborHead(1, -1n - v);
  if (typeof v === "boolean") return Uint8Array.of(v ? 0xf5 : 0xf4);
  if (v === null) return Uint8Array.of(0xf6);
  if (typeof v === "string") {
    const b = utf8(v);
    return concat(cborHead(3, b.length), b);
  }
  if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v);
  if (Array.isArray(v)) return concat(cborHead(4, v.length), ...v.map(encodeCbor));
  if (typeof v === "object") {
    const entries = (v instanceof Map ? [...v.entries()] : Object.entries(v))
      .filter(([, x]) => x !== undefined)
      .map(([k, x]) => [encodeCbor(k), encodeCbor(x)])
      .sort((a, b) => compareKeys(a[0], b[0]));
    return concat(cborHead(5, entries.length), ...entries.flat());
  }
  throw new TypeError(`CBOR: cannot encode ${typeof v}`);
}

export function decodeCbor(bytes, { maxDepth = 4 } = {}) {
  const b = bytes instanceof Uint8Array ? bytes : u8(bytes);
  let i = 0;
  const bad = () => fail(S.INVALID_CBOR);
  const need = (n) => {
    if (i + n > b.length) bad();
  };
  const arg = (ai) => {
    if (ai < 24) return ai;
    const len = { 24: 1, 25: 2, 26: 4, 27: 8 }[ai];
    if (!len) bad(); // 28–30 reserved, 31 = indefinite length
    need(len);
    let n = 0n;
    for (let k = 0; k < len; k++) n = (n << 8n) | BigInt(b[i++]);
    return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
  };
  const item = (depth) => {
    need(1);
    const ib = b[i++];
    const major = ib >> 5;
    const ai = ib & 0x1f;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      return bad(); // floats and simple values have no place in CTAP2 messages
    }
    const n = arg(ai);
    switch (major) {
      case 0:
        return n;
      case 1:
        return typeof n === "bigint" ? -1n - n : -1 - n;
      case 2:
      case 3: {
        if (typeof n === "bigint") bad();
        need(n);
        const s = b.slice(i, i + n);
        i += n;
        if (major === 2) return s;
        try {
          return new TextDecoder("utf-8", { fatal: true }).decode(s);
        } catch {
          return bad();
        }
      }
      case 4: {
        if (depth >= maxDepth || typeof n === "bigint" || n > b.length) bad();
        const a = [];
        for (let k = 0; k < n; k++) a.push(item(depth + 1));
        return a;
      }
      case 5: {
        if (depth >= maxDepth || typeof n === "bigint" || n > b.length) bad();
        const m = new Map();
        for (let k = 0; k < n; k++) {
          const key = item(depth + 1);
          if (typeof key !== "number" && typeof key !== "string") bad();
          if (m.has(key)) bad();
          m.set(key, item(depth + 1));
        }
        return m;
      }
      default:
        return bad(); // major type 6: tags
    }
  };
  const v = item(0);
  if (i !== b.length) bad();
  return v;
}

// Parameter access with CTAP's error semantics: absent → MISSING_PARAMETER when
// required; present with the wrong type → CBOR_UNEXPECTED_TYPE.
const TYPES = {
  uint: (v) => Number.isSafeInteger(v) && v >= 0,
  int: (v) => Number.isSafeInteger(v),
  bytes: (v) => v instanceof Uint8Array,
  text: (v) => typeof v === "string",
  map: (v) => v instanceof Map,
  array: (v) => Array.isArray(v),
  bool: (v) => typeof v === "boolean",
};
function param(m, key, type, required = false) {
  const v = m.get(key);
  if (v === undefined) {
    if (required) fail(S.MISSING_PARAMETER);
    return undefined;
  }
  if (!TYPES[type](v)) fail(S.CBOR_UNEXPECTED_TYPE);
  return v;
}

// PublicKeyCredentialDescriptor {type, id}: entries of another type are ignored.
function descriptorId(d) {
  if (!(d instanceof Map)) fail(S.CBOR_UNEXPECTED_TYPE);
  const type = param(d, "type", "text", true);
  const id = param(d, "id", "bytes", true);
  return type === "public-key" ? id : null;
}

// ---------------------------------------------------------------------------
// PIN/UV auth protocols (§6.5.6 one, §6.5.7 two)
// ---------------------------------------------------------------------------
const aesCbc = (decrypt, key, iv, data) => {
  const c = (decrypt ? crypto.createDecipheriv : crypto.createCipheriv)("aes-256-cbc", key, iv);
  c.setAutoPadding(false);
  return u8(Buffer.concat([c.update(data), c.final()]));
};
const hkdf32 = (ikm, info) => u8(crypto.hkdfSync("sha256", ikm, new Uint8Array(32), utf8(info), 32));

const PIN_PROTOCOLS = {
  1: {
    kdf: (z) => sha256(z),
    encrypt: (key, pt) => aesCbc(false, key, new Uint8Array(16), pt),
    decrypt: (key, ct) => (ct.length % 16 === 0 ? aesCbc(true, key, new Uint8Array(16), ct) : null),
    authenticate: (key, msg) => hmacSha256(key, msg).subarray(0, 16),
  },
  2: {
    kdf: (z) => concat(hkdf32(z, "CTAP2 HMAC key"), hkdf32(z, "CTAP2 AES key")),
    encrypt: (key, pt) => {
      const iv = u8(crypto.randomBytes(16));
      return concat(iv, aesCbc(false, key.subarray(32), iv, pt));
    },
    decrypt: (key, ct) =>
      ct.length >= 16 && ct.length % 16 === 0 ? aesCbc(true, key.subarray(32), ct.subarray(0, 16), ct.subarray(16)) : null,
    // A pinUvAuthToken is used as-is (32 bytes); a shared secret's HMAC key is its first 32 bytes.
    authenticate: (key, msg) => hmacSha256(key.subarray(0, 32), msg),
  },
};
const verifyAuth = (proto, key, msg, sig) => equal(PIN_PROTOCOLS[proto].authenticate(key, msg), sig);

function coseEc2(x, y, alg) {
  return new Map([
    [1, 2], // kty: EC2
    [3, alg],
    [-1, 1], // crv: P-256
    [-2, x],
    [-3, y],
  ]);
}

// ---------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------
export function simulatedKey(options = {}) {
  return new SimulatedKey(options);
}

class SimulatedKey {
  // configuration
  #cfg;
  // persistent state (survives power cycles)
  #pinHash = null; // LEFT(SHA-256(PIN), 16)
  #pinRetries;
  #creds = []; // every credential this key made (resident and not)
  #counter = 0;
  #seq = 0;
  // volatile state (cleared by powerCycle)
  #consecutiveMismatches = 0;
  #keyAgreement = new Map(); // protocol → ECDH P-256 key pair
  #token = null; // { proto, value, permissions, rpId, uv }
  #next = null; // getNextAssertion state
  // NFC state
  #selected = false;
  #chain = [];
  #chainLength = 0;
  #pendingResult = null; // CTAP result awaiting NFCCTAP_GETRESPONSE: { body, polls }
  #responseRest = null; // rest of a 61xx-chained response

  constructor(o) {
    const cfg = {
      pin: o.pin ?? null,
      pinRetries: o.pinRetries ?? MAX_PIN_RETRIES,
      protocols: [...(o.protocols ?? [2, 1])],
      versions: [...(o.versions ?? ["FIDO_2_0", "FIDO_2_1"])],
      hmacSecret: o.hmacSecret ?? true,
      credProtect: o.credProtect ?? true,
      maxCredentials: o.maxCredentials ?? 25,
      counter: o.counter ?? "global",
      busyPolls: o.busyPolls ?? 0,
      minPinLength: o.minPinLength ?? 4,
      aaguid: u8(o.aaguid ?? DEFAULT_AAGUID),
    };
    if (cfg.aaguid.length !== 16) throw new TypeError("aaguid must be 16 bytes");
    if (!["global", "zero"].includes(cfg.counter)) throw new TypeError('counter must be "global" or "zero"');
    for (const p of cfg.protocols) if (!PIN_PROTOCOLS[p]) throw new TypeError(`unknown PIN protocol ${p}`);
    this.#cfg = Object.freeze(cfg);
    this.#pinRetries = cfg.pinRetries;
    if (cfg.pin !== null) this.#pinHash = sha256(utf8(cfg.pin)).subarray(0, 16);
    this.#regenerateKeyAgreement();
  }

  get #fido2() {
    return this.#cfg.versions.some((v) => v.startsWith("FIDO_2"));
  }
  get #ctap21() {
    return this.#cfg.versions.includes("FIDO_2_1");
  }

  // -- public API -----------------------------------------------------------

  async transceive(apdu) {
    return this.#apdu(apdu instanceof Uint8Array ? apdu : u8(apdu));
  }

  // Removing the key from the field: everything volatile is gone (§6.5.2.1:
  // keyAgreement and pinUvAuthToken are per power cycle; the 3-mismatch block lifts).
  powerCycle() {
    this.#consecutiveMismatches = 0;
    this.#token = null;
    this.#next = null;
    this.#regenerateKeyAgreement();
    this.#selected = false;
    this.#chain = [];
    this.#chainLength = 0;
    this.#pendingResult = null;
    this.#responseRest = null;
  }

  get state() {
    return Object.freeze({
      pinSet: this.#pinHash !== null,
      pinRetries: this.#pinRetries,
      counter: this.#counter,
      credentials: Object.freeze(
        this.#creds.map((c) =>
          Object.freeze({
            rpId: c.rpId,
            credentialId: c.id.slice(),
            userId: c.userId.slice(),
            credProtect: c.credProtect,
            discoverable: c.rk,
            hmacSecret: c.hmacSecret,
            signCount: c.signCount,
          }),
        ),
      ),
    });
  }

  // Same credentials (private keys and CredRandoms), PIN and counter: a perfect
  // copy, which then counts on its own.
  clone() {
    const k = new SimulatedKey(this.#cfg);
    k.#pinHash = this.#pinHash && this.#pinHash.slice();
    k.#pinRetries = this.#pinRetries;
    k.#creds = this.#creds.map((c) => ({ ...c }));
    k.#counter = this.#counter;
    k.#seq = this.#seq;
    return k;
  }

  // Test-only: what the key computes inside for hmac-secret, HMAC-SHA-256(CredRandom, salt),
  // so a test can check the value a client decrypted against the key's own secret.
  hmacSecretForTest(credentialId, salt, { uv = true } = {}) {
    const c = this.#creds.find((x) => equal(x.id, u8(credentialId)));
    if (!c) throw new Error("no such credential");
    return hmacSha256(uv ? c.credRandomWithUV : c.credRandomWithoutUV, u8(salt));
  }

  // -- ISO 7816-4 / CTAP §11.3 ----------------------------------------------

  #parseApdu(a) {
    if (a.length < 4) return null;
    const c = { cla: a[0], ins: a[1], p1: a[2], p2: a[3], data: new Uint8Array(0), le: null, extended: false };
    const n = a.length - 4;
    if (n === 0) return c; // case 1
    if (n === 1) {
      c.le = a[4] || 256; // case 2 short
      return c;
    }
    if (a[4] !== 0) {
      const lc = a[4]; // case 3/4 short
      if (n !== 1 + lc && n !== 2 + lc) return null;
      c.data = a.slice(5, 5 + lc);
      if (n === 2 + lc) c.le = a[5 + lc] || 256;
      return c;
    }
    c.extended = true;
    if (n === 3) {
      c.le = ((a[5] << 8) | a[6]) || 65536; // case 2 extended
      return c;
    }
    const lc = (a[5] << 8) | a[6]; // case 3/4 extended
    if (lc === 0 || (n !== 3 + lc && n !== 5 + lc)) return null;
    c.data = a.slice(7, 7 + lc);
    if (n === 5 + lc) c.le = ((a[7 + lc] << 8) | a[8 + lc]) || 65536;
    return c;
  }

  #apdu(a) {
    const c = this.#parseApdu(a);
    if (!c) return sw(0x6700);
    if (c.cla === 0x00 && c.ins === 0xc0) return this.#getResponse(c);
    this.#responseRest = null; // anything but GET RESPONSE abandons a chained response
    if (c.cla === 0x00 && c.ins === 0xa4) return this.#select(c);
    if (c.cla !== 0x00 && c.cla !== 0x80 && c.cla !== 0x90) return sw(0x6e00);
    if (!this.#selected) return sw(0x6985);
    if (c.cla === 0x00) return sw(0x6d00);
    if (!this.#fido2) return sw(0x6d00); // CTAP1-only: no NFCCTAP_MSG
    if (c.ins === 0x10) return this.#nfcctapMsg(c);
    if (c.cla === 0x90) return sw(0x6884); // chaining is only for NFCCTAP_MSG
    if (c.ins === 0x11) return this.#nfcctapGetResponse(c);
    if (c.ins === 0x12) return this.#nfcctapControl(c);
    return sw(0x6d00);
  }

  // §11.3.1 applet selection
  #select(c) {
    if (c.p1 !== 0x04) return sw(0x6a86);
    if (!equal(c.data, FIDO_AID)) return sw(0x6a82);
    this.#selected = true;
    this.#chain = [];
    this.#chainLength = 0;
    this.#pendingResult = null;
    // §11.3.1: a CTAP2-only authenticator answers "FIDO_2_0"; one that also
    // implements CTAP1/U2F answers "U2F_V2" for backwards compatibility.
    return sw(0x9000, utf8(this.#cfg.versions.includes("U2F_V2") ? "U2F_V2" : "FIDO_2_0"));
  }

  // §11.3.2 NFCCTAP_MSG, with ISO command chaining (CLA bit 0x10)
  #nfcctapMsg(c) {
    if ((c.p1 !== 0x00 && c.p1 !== 0x80) || c.p2 !== 0x00) return sw(0x6a86);
    this.#pendingResult = null;
    if (c.cla === 0x90) {
      this.#chainLength += c.data.length;
      if (this.#chainLength > MAX_CHAIN) {
        this.#chain = [];
        this.#chainLength = 0;
        return sw(0x6700);
      }
      this.#chain.push(c.data);
      return sw(0x9000);
    }
    const msg = concat(...this.#chain, c.data);
    this.#chain = [];
    this.#chainLength = 0;
    if (msg.length === 0) return sw(0x6700);
    const body = this.#ctap(msg);
    // §11.3.3: with P1 0x80 the authenticator may answer status updates (SW 9100,
    // data = STATUS byte, 0x01 PROCESSING) and the platform polls NFCCTAP_GETRESPONSE.
    if (c.p1 === 0x80 && this.#cfg.busyPolls > 0) {
      this.#pendingResult = { body, polls: this.#cfg.busyPolls - 1 };
      return sw(0x9100, Uint8Array.of(0x01));
    }
    return this.#deliver(body, c);
  }

  // §11.3.3 NFCCTAP_GETRESPONSE (80 11 00 00)
  #nfcctapGetResponse(c) {
    if (c.p1 !== 0x00 || c.p2 !== 0x00) return sw(0x6a86);
    const p = this.#pendingResult;
    if (!p) return sw(0x6985);
    if (p.polls > 0) {
      p.polls--;
      return sw(0x9100, Uint8Array.of(0x01));
    }
    this.#pendingResult = null;
    return this.#deliver(p.body, c);
  }

  // §11.3.4 NFCCTAP_CONTROL: P1 0x01 = CTAP_CONTROL_END_GETRESPONSE (cancel)
  #nfcctapControl(c) {
    if (c.p1 !== 0x01 || c.p2 !== 0x00) return sw(0x6a86);
    this.#pendingResult = null;
    return sw(0x9000);
  }

  // Response chaining: at most Ne bytes now (short APDU: Le, or 256 when absent;
  // extended APDU: Le, or 65536), the rest announced by 61xx for GET RESPONSE.
  #deliver(body, c) {
    const limit = c.le ?? (c.extended ? 65536 : 256);
    if (body.length <= limit) return sw(0x9000, body);
    this.#responseRest = body.slice(limit);
    return sw(0x6100 | Math.min(this.#responseRest.length, 256) % 256, body.subarray(0, limit));
  }

  #getResponse(c) {
    const rest = this.#responseRest;
    if (!rest) return sw(0x6985);
    if (c.p1 !== 0x00 || c.p2 !== 0x00) return sw(0x6a86);
    const n = Math.min(c.le ?? 256, rest.length);
    const chunk = rest.subarray(0, n);
    this.#responseRest = n < rest.length ? rest.slice(n) : null;
    const left = this.#responseRest?.length ?? 0;
    return sw(left ? 0x6100 | Math.min(left, 256) % 256 : 0x9000, chunk);
  }

  // -- CTAP2 command dispatch (§6, §8) ---------------------------------------

  #ctap(msg) {
    const cmd = msg[0];
    const payload = msg.subarray(1);
    // §6.3: getNextAssertion state lives only until the next other command.
    if (cmd !== 0x08) this.#next = null;
    try {
      if (msg.length > MAX_MSG_SIZE) fail(S.REQUEST_TOO_LARGE);
      const handler = {
        0x01: (p) => this.#makeCredential(p),
        0x02: (p) => this.#getAssertion(p),
        0x04: () => this.#getInfo(),
        0x06: (p) => this.#clientPin(p),
        0x08: () => this.#getNextAssertion(),
      }[cmd];
      if (!handler) fail(S.INVALID_COMMAND);
      let params = null;
      if (cmd === 0x04 || cmd === 0x08) {
        if (payload.length) fail(S.INVALID_LENGTH); // these take no parameters
      } else {
        if (!payload.length) fail(S.INVALID_LENGTH);
        params = decodeCbor(payload);
        if (!(params instanceof Map)) fail(S.CBOR_UNEXPECTED_TYPE);
      }
      const out = handler(params);
      return out === undefined ? Uint8Array.of(S.OK) : concat(Uint8Array.of(S.OK), encodeCbor(out));
    } catch (e) {
      if (e instanceof CtapError) return Uint8Array.of(e.code);
      throw e;
    }
  }

  // -- §6.4 authenticatorGetInfo --------------------------------------------

  #getInfo() {
    const extensions = [];
    if (this.#cfg.credProtect) extensions.push("credProtect");
    if (this.#cfg.hmacSecret) extensions.push("hmac-secret");
    const options = { rk: true, up: true, plat: false, clientPin: this.#pinHash !== null };
    if (this.#ctap21) options.pinUvAuthToken = true;
    const m = new Map();
    m.set(0x01, this.#cfg.versions);
    if (extensions.length) m.set(0x02, extensions);
    m.set(0x03, this.#cfg.aaguid);
    m.set(0x04, options);
    m.set(0x05, MAX_MSG_SIZE);
    if (this.#cfg.protocols.length) m.set(0x06, this.#cfg.protocols);
    m.set(0x09, ["nfc"]);
    if (this.#ctap21) {
      m.set(0x0a, [{ alg: -7, type: "public-key" }]);
      m.set(0x0d, this.#cfg.minPinLength);
      m.set(0x14, this.#cfg.maxCredentials - this.#creds.filter((c) => c.rk).length);
    }
    return m;
  }

  // -- §6.5 authenticatorClientPIN ------------------------------------------

  #regenerateKeyAgreement() {
    for (const p of this.#cfg.protocols) {
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.generateKeys();
      this.#keyAgreement.set(p, ecdh);
    }
  }

  #keyAgreementCose(proto) {
    const pub = this.#keyAgreement.get(proto).getPublicKey();
    return coseEc2(u8(pub.subarray(1, 33)), u8(pub.subarray(33, 65)), -25); // ECDH-ES+HKDF-256 (§6.5.6)
  }

  // decapsulate(peerCoseKey) → shared secret (§6.5.6 / §6.5.7)
  #sharedSecret(proto, cose) {
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (cose.get(1) !== 2 || cose.get(-1) !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
      fail(S.INVALID_PARAMETER);
    }
    if (x.length !== 32 || y.length !== 32) fail(S.INVALID_PARAMETER);
    let z;
    try {
      z = u8(this.#keyAgreement.get(proto).computeSecret(concat(Uint8Array.of(4), x, y))); // rejects points off the curve
    } catch {
      fail(S.INVALID_PARAMETER);
    }
    return PIN_PROTOCOLS[proto].kdf(z);
  }

  #clientPin(p) {
    const sub = param(p, 0x02, "uint", true);
    const proto = param(p, 0x01, "uint");
    if (sub !== 0x01 && proto === undefined) fail(S.MISSING_PARAMETER);
    if (proto !== undefined && !this.#cfg.protocols.includes(proto)) fail(S.INVALID_PARAMETER);
    switch (sub) {
      case 0x01: {
        // getPINRetries
        const m = new Map([[0x03, this.#pinRetries]]);
        if (this.#ctap21) m.set(0x04, this.#consecutiveMismatches >= 3); // powerCycleState
        return m;
      }
      case 0x02: // getKeyAgreement
        return new Map([[0x01, this.#keyAgreementCose(proto)]]);
      case 0x03:
        return this.#setPin(proto, p);
      case 0x04:
        return this.#changePin(proto, p);
      case 0x05: // getPinToken (legacy: mc + ga, no RP ID)
        return this.#getToken(proto, p, false);
      case 0x09: // getPinUvAuthTokenUsingPinWithPermissions
        if (!this.#ctap21) fail(S.INVALID_SUBCOMMAND);
        return this.#getToken(proto, p, true);
      default:
        return fail(S.INVALID_SUBCOMMAND);
    }
  }

  // newPinEnc → the new PIN, with §6.5.5.5's length and policy checks
  #decryptNewPin(proto, shared, newPinEnc) {
    const padded = PIN_PROTOCOLS[proto].decrypt(shared, newPinEnc);
    if (!padded || padded.length !== 64) fail(S.INVALID_PARAMETER);
    let end = padded.length;
    while (end > 0 && padded[end - 1] === 0) end--;
    const pin = padded.subarray(0, end);
    const codePoints = [...new TextDecoder().decode(pin)].length;
    if (codePoints < this.#cfg.minPinLength || pin.length > 63) fail(S.PIN_POLICY_VIOLATION);
    return pin;
  }

  #setPin(proto, p) {
    const ka = param(p, 0x03, "map", true);
    const auth = param(p, 0x04, "bytes", true);
    const newPinEnc = param(p, 0x05, "bytes", true);
    if (this.#pinHash) fail(S.PIN_AUTH_INVALID); // §6.5.5.5: a PIN is already set
    const shared = this.#sharedSecret(proto, ka);
    if (!verifyAuth(proto, shared, newPinEnc, auth)) fail(S.PIN_AUTH_INVALID);
    const pin = this.#decryptNewPin(proto, shared, newPinEnc);
    this.#pinHash = sha256(pin).subarray(0, 16);
    this.#pinRetries = MAX_PIN_RETRIES;
    this.#consecutiveMismatches = 0;
  }

  #changePin(proto, p) {
    const ka = param(p, 0x03, "map", true);
    const auth = param(p, 0x04, "bytes", true);
    const newPinEnc = param(p, 0x05, "bytes", true);
    const pinHashEnc = param(p, 0x06, "bytes", true);
    this.#pinGate();
    const shared = this.#sharedSecret(proto, ka);
    if (!verifyAuth(proto, shared, concat(newPinEnc, pinHashEnc), auth)) fail(S.PIN_AUTH_INVALID);
    this.#checkPinHash(proto, shared, pinHashEnc);
    const pin = this.#decryptNewPin(proto, shared, newPinEnc);
    this.#pinHash = sha256(pin).subarray(0, 16);
    this.#token = null; // resetPinUvAuthToken()
  }

  #pinGate() {
    if (!this.#pinHash) fail(S.PIN_NOT_SET);
    if (this.#pinRetries === 0) fail(S.PIN_BLOCKED);
    if (this.#consecutiveMismatches >= 3) fail(S.PIN_AUTH_BLOCKED); // until power cycle
  }

  // §6.5.5.7: the retry counter is decremented before the comparison, so tearing
  // the key away mid-check still costs a try.
  #checkPinHash(proto, shared, pinHashEnc) {
    if (pinHashEnc.length !== (proto === 1 ? 16 : 32)) fail(S.INVALID_PARAMETER);
    this.#pinRetries--;
    const pinHash = PIN_PROTOCOLS[proto].decrypt(shared, pinHashEnc);
    if (!equal(pinHash, this.#pinHash)) {
      this.#regenerateKeyAgreement();
      this.#consecutiveMismatches++;
      if (this.#pinRetries === 0) fail(S.PIN_BLOCKED);
      if (this.#consecutiveMismatches >= 3) fail(S.PIN_AUTH_BLOCKED);
      fail(S.PIN_INVALID);
    }
    this.#pinRetries = MAX_PIN_RETRIES;
    this.#consecutiveMismatches = 0;
  }

  #getToken(proto, p, withPermissions) {
    const ka = param(p, 0x03, "map", true);
    const pinHashEnc = param(p, 0x06, "bytes", true);
    let permissions = PERM_MC | PERM_GA;
    let rpId = null;
    if (withPermissions) {
      permissions = param(p, 0x09, "uint", true);
      rpId = param(p, 0x0a, "text") ?? null;
      if (permissions === 0) fail(S.INVALID_PARAMETER);
      if (permissions & ~(PERM_MC | PERM_GA)) fail(S.UNAUTHORIZED_PERMISSION); // cm, be, lbw, acfg: not offered
    } else if (p.has(0x09) || p.has(0x0a)) {
      fail(S.INVALID_PARAMETER);
    }
    this.#pinGate();
    const shared = this.#sharedSecret(proto, ka);
    this.#checkPinHash(proto, shared, pinHashEnc);
    // resetPinUvAuthToken() for every protocol, then beginUsingPinUvAuthToken()
    this.#token = { proto, value: u8(crypto.randomBytes(32)), permissions, rpId, uv: true };
    return new Map([[0x02, PIN_PROTOCOLS[proto].encrypt(shared, this.#token.value)]]);
  }

  // pinUvAuthParam check for makeCredential / getAssertion (§6.1.2 step 11, §6.2.2 step 6)
  #checkPinUvAuthParam(proto, pinUvAuthParam, clientDataHash, permission, rpId) {
    const t = this.#token;
    if (!t || t.proto !== proto || !verifyAuth(proto, t.value, clientDataHash, pinUvAuthParam)) fail(S.PIN_AUTH_INVALID);
    if (!this.#ctap21) return; // CTAP 2.0 tokens carry no permissions
    if (!(t.permissions & permission) || !t.uv) fail(S.PIN_AUTH_INVALID);
    if (t.rpId !== null && t.rpId !== rpId) fail(S.PIN_AUTH_INVALID);
    t.rpId ??= rpId;
  }

  // clearUserPresentFlag(), clearUserVerifiedFlag(), clearPinUvAuthTokenPermissionsExceptLbw():
  // CTAP 2.1 consumes the token's "cached UV" in any operation that collects user presence.
  #consumeToken() {
    if (this.#ctap21 && this.#token) {
      this.#token.uv = false;
      this.#token.permissions = 0;
    }
  }

  // Common pinUvAuthParam preamble (§6.1.2 steps 1–2, §6.2.2 steps 1–2)
  #pinUvPreamble(pinUvAuthParam, proto) {
    if (pinUvAuthParam === undefined) return;
    // A zero-length pinUvAuthParam asks for a touch (to pick a key); NFC presence is implied.
    if (pinUvAuthParam.length === 0) fail(this.#pinHash ? S.PIN_INVALID : S.PIN_NOT_SET);
    if (proto === undefined) fail(S.MISSING_PARAMETER);
    if (!this.#cfg.protocols.includes(proto)) fail(S.INVALID_PARAMETER);
  }

  #signCount() {
    return this.#cfg.counter === "global" ? ++this.#counter : 0;
  }

  // -- §6.1 authenticatorMakeCredential -------------------------------------

  #makeCredential(p) {
    const clientDataHash = param(p, 0x01, "bytes", true);
    const rp = param(p, 0x02, "map", true);
    const user = param(p, 0x03, "map", true);
    const pubKeyCredParams = param(p, 0x04, "array", true);
    const excludeList = param(p, 0x05, "array");
    const extensions = param(p, 0x06, "map");
    const options = param(p, 0x07, "map") ?? new Map();
    const pinUvAuthParam = param(p, 0x08, "bytes");
    const proto = param(p, 0x09, "uint");
    const rpId = param(rp, "id", "text", true);
    param(rp, "name", "text");
    const userId = param(user, "id", "bytes", true);
    const userName = param(user, "name", "text");
    const displayName = param(user, "displayName", "text");
    if (userId.length > 64) fail(S.INVALID_LENGTH);

    this.#pinUvPreamble(pinUvAuthParam, proto);

    // step 3: the first supported algorithm in the platform's order; only ES256 here
    let supported = false;
    for (const cp of pubKeyCredParams) {
      if (!(cp instanceof Map)) fail(S.CBOR_UNEXPECTED_TYPE);
      const type = param(cp, "type", "text", true);
      const alg = param(cp, "alg", "int", true);
      if (type === "public-key" && alg === -7) {
        supported = true;
        break;
      }
    }
    if (!supported) fail(S.UNSUPPORTED_ALGORITHM);

    // step 5: options
    const rk = param(options, "rk", "bool") ?? false;
    const up = param(options, "up", "bool");
    const uvOption = param(options, "uv", "bool");
    if (up === false) fail(S.INVALID_OPTION);
    if (uvOption === true && pinUvAuthParam === undefined) fail(S.INVALID_OPTION); // no built-in UV

    // steps 6–11: a key with a PIN makes credentials only with a pinUvAuthToken
    let uv = false;
    if (pinUvAuthParam === undefined) {
      if (this.#pinHash) fail(S.PUAT_REQUIRED);
    } else {
      this.#checkPinUvAuthParam(proto, pinUvAuthParam, clientDataHash, PERM_MC, rpId);
      uv = true;
    }

    // step 12: excludeList (a credProtect-3 credential is invisible without UV)
    for (const d of excludeList ?? []) {
      const id = descriptorId(d);
      const c = id && this.#find(id, rpId);
      if (c && (c.credProtect !== 3 || uv)) fail(S.CREDENTIAL_EXCLUDED);
    }

    // step 13: extensions (§12.1 credProtect, §12.5 hmac-secret); unknown ones are ignored
    const extOut = new Map();
    let credProtect = 1;
    let hmacSecret = false;
    if (extensions) {
      if (this.#cfg.credProtect && extensions.has("credProtect")) {
        const level = param(extensions, "credProtect", "uint");
        if (level >= 1 && level <= 3) {
          credProtect = level;
          extOut.set("credProtect", level);
        }
      }
      if (this.#cfg.hmacSecret && extensions.has("hmac-secret")) {
        if (param(extensions, "hmac-secret", "bool")) {
          hmacSecret = true;
          extOut.set("hmac-secret", true);
        }
      }
    }

    // step 15: discoverable credentials replace one for the same (rpId, userId)
    if (rk) {
      const i = this.#creds.findIndex((c) => c.rk && c.rpId === rpId && equal(c.userId, userId));
      if (i < 0 && this.#creds.filter((c) => c.rk).length >= this.#cfg.maxCredentials) fail(S.KEY_STORE_FULL);
      if (i >= 0) this.#creds.splice(i, 1);
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const cose = coseEc2(u8(Buffer.from(jwk.x, "base64url")), u8(Buffer.from(jwk.y, "base64url")), -7);
    const cred = {
      id: u8(crypto.randomBytes(48)),
      rpId,
      rpIdHash: sha256(utf8(rpId)),
      userId: userId.slice(),
      userName,
      displayName,
      rk,
      credProtect,
      hmacSecret,
      credRandomWithUV: u8(crypto.randomBytes(32)),
      credRandomWithoutUV: u8(crypto.randomBytes(32)),
      privateKey,
      cose,
      seq: ++this.#seq,
      signCount: 0,
    };
    cred.signCount = this.#signCount();
    this.#creds.push(cred);
    this.#consumeToken(); // up is always collected for makeCredential

    const flags = FLAG_UP | (uv ? FLAG_UV : 0) | FLAG_AT | (extOut.size ? FLAG_ED : 0);
    const authData = concat(
      cred.rpIdHash,
      Uint8Array.of(flags),
      be32(cred.signCount),
      this.#cfg.aaguid,
      Uint8Array.of(cred.id.length >> 8, cred.id.length & 0xff),
      cred.id,
      encodeCbor(cose),
      extOut.size ? encodeCbor(extOut) : new Uint8Array(0),
    );
    return new Map([
      [0x01, "none"],
      [0x02, authData],
      [0x03, new Map()],
    ]);
  }

  #find(id, rpId) {
    return this.#creds.find((c) => c.rpId === rpId && equal(c.id, id));
  }

  // -- §6.2 authenticatorGetAssertion ---------------------------------------

  #getAssertion(p) {
    const rpId = param(p, 0x01, "text", true);
    const clientDataHash = param(p, 0x02, "bytes", true);
    const allowList = param(p, 0x03, "array");
    const extensions = param(p, 0x04, "map");
    const options = param(p, 0x05, "map") ?? new Map();
    const pinUvAuthParam = param(p, 0x06, "bytes");
    const proto = param(p, 0x07, "uint");

    this.#pinUvPreamble(pinUvAuthParam, proto);

    const up = param(options, "up", "bool") ?? true;
    const uvOption = param(options, "uv", "bool");
    if (options.has("rk")) fail(S.UNSUPPORTED_OPTION);
    if (uvOption === true && pinUvAuthParam === undefined) fail(S.INVALID_OPTION);

    let uv = false;
    if (pinUvAuthParam !== undefined) {
      this.#checkPinUvAuthParam(proto, pinUvAuthParam, clientDataHash, PERM_GA, rpId);
      uv = true;
    }

    const hmacInput =
      this.#cfg.hmacSecret && extensions?.has("hmac-secret") ? this.#hmacSecretInput(param(extensions, "hmac-secret", "map")) : null;

    // step 7: locate credentials; credProtect (§12.1) hides level 3 without UV, and
    // level 2 without UV unless the platform names the credential
    let found;
    const byAllowList = allowList !== undefined && allowList.length > 0;
    if (byAllowList) {
      found = [];
      for (const d of allowList) {
        const id = descriptorId(d);
        const c = id && this.#find(id, rpId);
        if (c && !found.includes(c) && (c.credProtect !== 3 || uv)) found.push(c);
      }
      found = found.slice(0, 1); // with an allowList: one assertion, the first match
    } else {
      found = this.#creds
        .filter((c) => c.rk && c.rpId === rpId && (c.credProtect === 1 || uv))
        .sort((a, b) => b.seq - a.seq); // most recently created first
    }
    if (!found.length) fail(S.NO_CREDENTIALS);

    const ctx = { clientDataHash, up, uv, hmacInput, userDetails: uv && !byAllowList };
    const response = this.#assert(found[0], ctx);
    if (found.length > 1) {
      response.set(0x05, found.length);
      this.#next = { ...ctx, rest: found.slice(1), at: Date.now() };
    }
    if (up) this.#consumeToken();
    return response;
  }

  // §12.5 hmac-secret authenticator input: {1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: pinUvAuthProtocol}
  #hmacSecretInput(h) {
    const ka = param(h, 0x01, "map", true);
    const saltEnc = param(h, 0x02, "bytes", true);
    const saltAuth = param(h, 0x03, "bytes", true);
    const proto = param(h, 0x04, "uint") ?? 1;
    if (!this.#cfg.protocols.includes(proto)) fail(S.INVALID_PARAMETER);
    const shared = this.#sharedSecret(proto, ka);
    if (!verifyAuth(proto, shared, saltEnc, saltAuth)) fail(S.PIN_AUTH_INVALID);
    const salts = PIN_PROTOCOLS[proto].decrypt(shared, saltEnc);
    if (!salts || (salts.length !== 32 && salts.length !== 64)) fail(S.INVALID_LENGTH);
    return { proto, shared, salt1: salts.subarray(0, 32), salt2: salts.length === 64 ? salts.subarray(32) : null };
  }

  #assert(cred, { clientDataHash, up, uv, hmacInput, userDetails }) {
    const extOut = new Map();
    if (hmacInput && cred.hmacSecret) {
      const r = uv ? cred.credRandomWithUV : cred.credRandomWithoutUV;
      let out = hmacSha256(r, hmacInput.salt1);
      if (hmacInput.salt2) out = concat(out, hmacSha256(r, hmacInput.salt2));
      extOut.set("hmac-secret", PIN_PROTOCOLS[hmacInput.proto].encrypt(hmacInput.shared, out));
    }
    cred.signCount = this.#signCount();
    const flags = (up ? FLAG_UP : 0) | (uv ? FLAG_UV : 0) | (extOut.size ? FLAG_ED : 0);
    const authData = concat(
      cred.rpIdHash,
      Uint8Array.of(flags),
      be32(cred.signCount),
      extOut.size ? encodeCbor(extOut) : new Uint8Array(0),
    );
    const signature = u8(crypto.sign("sha256", concat(authData, clientDataHash), cred.privateKey)); // DER ECDSA
    const m = new Map([
      [0x01, { id: cred.id, type: "public-key" }],
      [0x02, authData],
      [0x03, signature],
    ]);
    if (cred.rk) {
      // user name and display name only after user verification, among several accounts
      const u = { id: cred.userId };
      if (userDetails) {
        if (cred.userName !== undefined) u.name = cred.userName;
        if (cred.displayName !== undefined) u.displayName = cred.displayName;
      }
      m.set(0x04, u);
    }
    return m;
  }

  // -- §6.3 authenticatorGetNextAssertion -----------------------------------

  #getNextAssertion() {
    const s = this.#next;
    if (!s || !s.rest.length || Date.now() - s.at > NEXT_ASSERTION_TIMEOUT_MS) {
      this.#next = null;
      fail(S.NOT_ALLOWED);
    }
    s.at = Date.now();
    return this.#assert(s.rest.shift(), s);
  }
}
