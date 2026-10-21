// The simulated FIDO2 security key (tests/support/fido-sim.js) on its own,
// driven by a small CTAP-over-NFC client written here with node:crypto only.
// (The real client, packages/fido, is tested against the simulator elsewhere;
// the simulator is also checked against Yubico's python-fido2 in
// tests/fido-crosscheck.test.js.)
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { simulatedKey, FIDO_AID, encodeCbor, decodeCbor, CTAP_STATUS as S } from "./support/fido-sim.js";

// ---------------------------------------------------------------------------
// A minimal test client
// ---------------------------------------------------------------------------
const hex = (s) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ""), "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");
const cat = (...p) => Uint8Array.from(Buffer.concat(p.map((x) => Buffer.from(x))));
const sha256 = (b) => Uint8Array.from(crypto.createHash("sha256").update(b).digest());
const hmac = (k, m) => Uint8Array.from(crypto.createHmac("sha256", k).update(m).digest());
const swOf = (r) => (r[r.length - 2] << 8) | r[r.length - 1];
const dataOf = (r) => r.subarray(0, r.length - 2);
const SELECT = cat(hex("00 A4 04 00 08"), FIDO_AID, [0x00]);

async function select(key) {
  const r = await key.transceive(SELECT);
  assert.equal(swOf(r), 0x9000);
  return Buffer.from(dataOf(r)).toString("ascii");
}

// Sends one CTAP message over NFCCTAP_MSG and returns the raw CTAP body.
//   mode "short": CLA 0x90 chaining in `chunk`-byte blocks; "extended": one extended APDU
async function exchange(key, msg, { p1 = 0x00, mode = "short", chunk = 255, le = 0x00, trace } = {}) {
  const log = (c, r) => trace?.push({ c, sw: swOf(r) });
  let r;
  if (mode === "extended") {
    const c = cat([0x80, 0x10, p1, 0x00, 0x00, msg.length >> 8, msg.length & 0xff], msg, [0x00, 0x00]);
    r = await key.transceive(c);
    log(c, r);
  } else {
    for (let off = 0; ; off += chunk) {
      const block = msg.subarray(off, off + chunk);
      const last = off + chunk >= msg.length;
      const c = cat([last ? 0x80 : 0x90, 0x10, p1, 0x00, block.length], block, last && le !== null ? [le] : []);
      r = await key.transceive(c);
      log(c, r);
      if (last) break;
      assert.equal(swOf(r), 0x9000, "chained block accepted");
    }
  }
  while (swOf(r) === 0x9100) {
    assert.deepEqual([...dataOf(r)], [0x01], "status update: PROCESSING");
    r = await key.transceive(hex("80 11 00 00 00"));
    log(null, r);
  }
  let body = dataOf(r);
  while ((swOf(r) & 0xff00) === 0x6100) {
    r = await key.transceive(cat(hex("00 C0 00 00"), [swOf(r) & 0xff]));
    log(null, r);
    body = cat(body, dataOf(r));
  }
  assert.equal(swOf(r), 0x9000);
  return body;
}

async function ctap(key, cmd, params, opts) {
  const msg = cat([cmd], params === undefined ? [] : encodeCbor(params));
  const body = await exchange(key, msg, opts);
  return { status: body[0], data: body.length > 1 ? decodeCbor(body.subarray(1)) : undefined };
}
async function ok(key, cmd, params, opts) {
  const r = await ctap(key, cmd, params, opts);
  assert.equal(r.status, 0, `CTAP status 0x${r.status.toString(16)}`);
  return r.data;
}

// PIN/UV auth protocols, as a platform runs them (CTAP 2.1 §6.5.6, §6.5.7)
const aes = (dec, key, iv, data) => {
  const c = (dec ? crypto.createDecipheriv : crypto.createCipheriv)("aes-256-cbc", key, iv);
  c.setAutoPadding(false);
  return Uint8Array.from(Buffer.concat([c.update(data), c.final()]));
};
const hkdf = (z, info) => Uint8Array.from(Buffer.from(crypto.hkdfSync("sha256", z, new Uint8Array(32), info, 32)));
const PROTO = {
  1: {
    kdf: (z) => sha256(z),
    enc: (k, p) => aes(false, k, new Uint8Array(16), p),
    dec: (k, c) => aes(true, k, new Uint8Array(16), c),
    auth: (k, m) => hmac(k, m).subarray(0, 16),
  },
  2: {
    kdf: (z) => cat(hkdf(z, "CTAP2 HMAC key"), hkdf(z, "CTAP2 AES key")),
    enc: (k, p) => {
      const iv = crypto.randomBytes(16);
      return cat(iv, aes(false, k.subarray(32), iv, p));
    },
    dec: (k, c) => aes(true, k.subarray(32), c.subarray(0, 16), c.subarray(16)),
    auth: (k, m) => hmac(k.length === 64 ? k.subarray(0, 32) : k, m),
  },
};

async function encapsulate(key, proto) {
  const r = await ok(key, 0x06, new Map([[1, proto], [2, 0x02]]));
  const peer = r.get(1);
  assert.equal(peer.get(3), -25);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  const z = ecdh.computeSecret(cat([4], peer.get(-2), peer.get(-3)));
  const pub = ecdh.getPublicKey();
  const cose = new Map([[1, 2], [3, -25], [-1, 1], [-2, pub.subarray(1, 33)], [-3, pub.subarray(33)]]);
  return { cose: new Map([...cose].map(([k, v]) => [k, v instanceof Buffer ? Uint8Array.from(v) : v])), shared: PROTO[proto].kdf(z) };
}

const padPin = (pin) => {
  const b = new Uint8Array(64);
  b.set(Buffer.from(pin, "utf8"));
  return b;
};

async function setPin(key, pin, proto = 2) {
  const { cose, shared } = await encapsulate(key, proto);
  const newPinEnc = PROTO[proto].enc(shared, padPin(pin));
  return ctap(key, 0x06, new Map([[1, proto], [2, 0x03], [3, cose], [4, PROTO[proto].auth(shared, newPinEnc)], [5, newPinEnc]]));
}

// Returns { status, token }. permissions null → legacy getPinToken (0x05).
async function getToken(key, pin, { proto = 2, permissions = 0x03, rpId } = {}) {
  const { cose, shared } = await encapsulate(key, proto);
  const pinHashEnc = PROTO[proto].enc(shared, sha256(Buffer.from(pin)).subarray(0, 16));
  const m = new Map([[1, proto], [2, permissions === null ? 0x05 : 0x09], [3, cose], [6, pinHashEnc]]);
  if (permissions !== null) m.set(9, permissions);
  if (rpId) m.set(10, rpId);
  const r = await ctap(key, 0x06, m);
  return { status: r.status, token: r.status === 0 ? PROTO[proto].dec(shared, r.data.get(2)) : null };
}
async function token(key, pin, opts) {
  const r = await getToken(key, pin, opts);
  assert.equal(r.status, 0);
  return r.token;
}

const RP = "recovery.humid.invalid";
const cdh = (s = "challenge") => sha256(Buffer.from(s));

async function makeCredential(key, { pin, proto = 2, rpId = RP, userId = crypto.randomBytes(16), rk = true, hmacSecret = true, credProtect = 3, alg = -7, extra } = {}) {
  const clientDataHash = cdh("mc");
  const m = new Map([
    [1, clientDataHash],
    [2, { id: rpId, name: "HumID" }],
    [3, { id: Uint8Array.from(userId), name: "parker", displayName: "Parker" }],
    [4, [{ alg, type: "public-key" }]],
    [7, { rk }],
  ]);
  const ext = {};
  if (hmacSecret) ext["hmac-secret"] = true;
  if (credProtect) ext.credProtect = credProtect;
  if (Object.keys(ext).length) m.set(6, ext);
  if (pin) {
    const t = await token(key, pin, { proto, permissions: 0x01, rpId });
    m.set(8, PROTO[proto].auth(t, clientDataHash));
    m.set(9, proto);
  }
  extra?.(m);
  return ctap(key, 0x01, m);
}

// Parses authenticatorData (WebAuthn §6.1)
function parseAuthData(a) {
  const out = { rpIdHash: a.subarray(0, 32), flags: a[32], signCount: Buffer.from(a).readUInt32BE(33) };
  let rest = a.subarray(37);
  if (out.flags & 0x40) {
    out.aaguid = rest.subarray(0, 16);
    const n = (rest[16] << 8) | rest[17];
    out.credentialId = rest.subarray(18, 18 + n);
    rest = rest.subarray(18 + n);
    const len = cborItemLength(rest);
    out.publicKey = decodeCbor(rest.subarray(0, len));
    rest = rest.subarray(len);
  }
  if (out.flags & 0x80) {
    out.extensions = decodeCbor(rest);
    rest = new Uint8Array(0);
  }
  assert.equal(rest.length, 0, "no trailing bytes in authData");
  return out;
}
// length of the first CBOR item (enough for COSE keys: maps of ints and byte strings)
function cborItemLength(b) {
  let i = 0;
  const arg = () => {
    const ai = b[i++] & 0x1f;
    if (ai < 24) return ai;
    const n = { 24: 1, 25: 2, 26: 4 }[ai];
    let v = 0;
    for (let k = 0; k < n; k++) v = v * 256 + b[i++];
    return v;
  };
  const item = () => {
    const major = b[i] >> 5;
    const n = arg();
    if (major === 2 || major === 3) i += n;
    else if (major === 4) for (let k = 0; k < n; k++) item();
    else if (major === 5) for (let k = 0; k < 2 * n; k++) item();
  };
  item();
  return i;
}

const coseToKey = (cose) =>
  crypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x: Buffer.from(cose.get(-2)).toString("base64url"), y: Buffer.from(cose.get(-3)).toString("base64url") },
    format: "jwk",
  });

// hmac-secret extension input (§12.5) and output decryption
async function hmacSecretInput(key, proto, salts, { sendProto = true } = {}) {
  const { cose, shared } = await encapsulate(key, proto);
  const saltEnc = PROTO[proto].enc(shared, cat(...salts));
  const m = new Map([[1, cose], [2, saltEnc], [3, PROTO[proto].auth(shared, saltEnc)]]);
  if (sendProto) m.set(4, proto);
  return { ext: { "hmac-secret": m }, decrypt: (out) => PROTO[proto].dec(shared, out) };
}

async function getAssertion(key, { pin, proto = 2, rpId = RP, allow, salts, saltProto = proto, up, clientDataHash = cdh("ga") } = {}) {
  const m = new Map([[1, rpId], [2, clientDataHash]]);
  if (allow) m.set(3, allow.map((id) => ({ id, type: "public-key" })));
  let hs;
  if (salts) {
    hs = await hmacSecretInput(key, saltProto, salts);
    m.set(4, hs.ext);
  }
  if (up !== undefined) m.set(5, { up });
  if (pin) {
    const t = await token(key, pin, { proto, permissions: 0x02, rpId });
    m.set(6, PROTO[proto].auth(t, clientDataHash));
    m.set(7, proto);
  }
  const r = await ctap(key, 0x02, m);
  if (r.status) return { status: r.status };
  const authData = parseAuthData(r.data.get(2));
  const secret = hs && authData.extensions?.get("hmac-secret") ? hs.decrypt(authData.extensions.get("hmac-secret")) : undefined;
  return { status: 0, r: r.data, authData, secret, clientDataHash, hs };
}

const PIN = "123456";
const SALT = sha256(Buffer.from("HUMID-KEY-v1 hmac-secret salt"));

async function keyWithCredential(opts = {}) {
  const key = simulatedKey({ pin: PIN, ...opts });
  await select(key);
  const mc = await makeCredential(key, { pin: PIN });
  assert.equal(mc.status, 0);
  const ad = parseAuthData(mc.data.get(2));
  return { key, id: ad.credentialId, publicKey: ad.publicKey };
}

// ---------------------------------------------------------------------------
// CBOR
// ---------------------------------------------------------------------------
test("CBOR: RFC 8949 vectors, CTAP2 canonical key order, malformed input refused", () => {
  const vectors = [
    [0, "00"], [23, "17"], [24, "1818"], [1000, "1903e8"], [1000000, "1a000f4240"], [-1, "20"], [-1000, "3903e7"],
    [true, "f5"], [false, "f4"], ["", "60"], ["IETF", "6449455446"], [Uint8Array.of(1, 2, 3, 4), "4401020304"],
    [[1, [2, 3], [4, 5]], "8301820203820405"], [{ a: 1, b: [2, 3] }, "a26161016162820203"],
  ];
  for (const [v, h] of vectors) {
    assert.equal(toHex(encodeCbor(v)), h);
    assert.deepEqual(decodeCbor(hex(h)), v instanceof Uint8Array || typeof v !== "object" ? v : decodeCbor(hex(h)));
  }
  // §8 canonical: major type, then length, then bytes: 1 < 2 < -1 < "a" < "bb"
  const m = new Map([["bb", 0], ["a", 0], [-1, 0], [2, 0], [1, 0]]);
  assert.equal(toHex(encodeCbor(m)), "a5" + "0100" + "0200" + "2000" + "616100" + "62626200");
  for (const bad of ["a1", "5f", "a20000 0000", "1c", "c0 00", "fa00000000", "62ff"]) {
    assert.throws(() => decodeCbor(hex(bad)), (e) => e.code === S.INVALID_CBOR, bad);
  }
});

// ---------------------------------------------------------------------------
// NFC
// ---------------------------------------------------------------------------
test("SELECT: FIDO_2_0; other AID 6A82; commands before SELECT 6985; U2F-only answers U2F_V2 and refuses NFCCTAP_MSG", async () => {
  const key = simulatedKey();
  assert.equal(swOf(await key.transceive(hex("80 10 00 00 01 04 00"))), 0x6985);
  assert.equal(swOf(await key.transceive(cat(hex("00 A4 04 00 07"), hex("A0000000031010"), [0]))), 0x6a82);
  assert.equal(await select(key), "FIDO_2_0");
  assert.equal(swOf(await key.transceive(hex("80 10 00 00 01 04 00"))), 0x9000);
  assert.equal(swOf(await key.transceive(hex("84 10 00 00 01 04 00"))), 0x6e00, "wrong CLA");
  assert.equal(swOf(await key.transceive(hex("80 20 00 00 01 04 00"))), 0x6d00, "wrong INS");

  const u2f = simulatedKey({ versions: ["U2F_V2"] });
  assert.equal(await select(u2f), "U2F_V2");
  assert.equal(swOf(await u2f.transceive(hex("80 10 00 00 01 04 00"))), 0x6d00);

  // §11.3.1: a key that implements CTAP1 as well answers "U2F_V2" (as a YubiKey 5 does),
  // and still speaks CTAP2: getInfo tells the platform what it is.
  const both = simulatedKey({ versions: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"] });
  assert.equal(await select(both), "U2F_V2");
  assert.deepEqual((await ok(both, 0x04)).get(1), ["U2F_V2", "FIDO_2_0", "FIDO_2_1"]);
});

test("NFCCTAP_MSG: unknown command 0x01, malformed CBOR 0x12, parameters of the wrong type 0x11", async () => {
  const key = simulatedKey();
  await select(key);
  assert.deepEqual([...(await exchange(key, Uint8Array.of(0x42)))], [S.INVALID_COMMAND]);
  assert.deepEqual([...(await exchange(key, Uint8Array.of(0x06, 0xa2, 0x01)))], [S.INVALID_CBOR]);
  assert.deepEqual([...(await exchange(key, Uint8Array.of(0x06, 0x82, 0x01, 0x02)))], [S.CBOR_UNEXPECTED_TYPE]);
  assert.equal((await ctap(key, 0x06, new Map([[1, 2]]))).status, S.MISSING_PARAMETER);
  assert.equal((await ctap(key, 0x06, new Map([[1, 2], [2, "x"]]))).status, S.CBOR_UNEXPECTED_TYPE);
});

test("a >255-byte command arrives by CLA 0x90 chaining and by extended length", async () => {
  const key = simulatedKey();
  await select(key);
  const m = new Map([
    [1, cdh()],
    [2, { id: RP }],
    [3, { id: Uint8Array.of(1, 2, 3), name: "n".repeat(200), displayName: "d".repeat(200) }],
    [4, [{ alg: -7, type: "public-key" }]],
    [7, { rk: true }],
  ]);
  const msg = cat([0x01], encodeCbor(m));
  assert.ok(msg.length > 255);
  for (const [mode, chunk] of [["short", 255], ["short", 7], ["extended"]]) {
    const trace = [];
    const body = await exchange(key, msg, { mode, chunk, trace });
    assert.equal(body[0], 0, mode);
    const cmds = trace.filter((t) => t.c);
    if (mode === "short") {
      assert.equal(cmds.length, Math.ceil(msg.length / chunk));
      assert.ok(cmds.slice(0, -1).every((t) => t.c[0] === 0x90 && t.sw === 0x9000));
      assert.equal(cmds.at(-1).c[0], 0x80);
    } else {
      assert.equal(cmds.length, 1);
      assert.deepEqual([...cmds[0].c.subarray(4, 7)], [0x00, msg.length >> 8, msg.length & 0xff], "extended Lc");
    }
  }
  assert.equal(key.state.credentials.length, 1, "replaced twice: same user");
  // a chain broken by another command is dropped: the next message starts afresh
  assert.equal(swOf(await key.transceive(hex("90 10 00 00 02 01 a1"))), 0x9000);
  assert.equal(swOf(await key.transceive(hex("90 11 00 00 00"))), 0x6884, "chaining is for NFCCTAP_MSG only");
  assert.deepEqual([...(await exchange(key, Uint8Array.of(0x04)))].slice(0, 1), [0x00]);
});

test("a >256-byte response: 61xx then GET RESPONSE, without Le, with a short Le, and after an extended command", async () => {
  // getAssertion over a discoverable credential with a 64-byte user id and two
  // hmac-secret salts (protocol 2: 16-byte IV + 64 bytes) is about 350 bytes.
  const key = simulatedKey({ pin: PIN, busyPolls: 1 });
  await select(key);
  for (const n of [1, 2]) assert.equal((await makeCredential(key, { pin: PIN, userId: new Uint8Array(64).fill(n) })).status, 0);
  // each exchange needs its own token (it is spent) and hmac-secret key agreement
  for (const [le, firstLen, p1] of [[null, 256, 0x00], [0x00, 256, 0x00], [0x40, 0x40, 0x00], [0x00, 256, 0x80]]) {
    const tk = await token(key, PIN, { permissions: 0x02 });
    const hsi = await hmacSecretInput(key, 2, [SALT, crypto.randomBytes(32)]);
    const cd = cdh(String(le));
    const req = cat([0x02], encodeCbor(new Map([[1, RP], [2, cd], [4, hsi.ext], [6, PROTO[2].auth(tk, cd)], [7, 2]])));
    const trace = [];
    const body = await exchange(key, req, { le, p1, trace });
    assert.ok(body.length > 300, `body ${body.length}`);
    assert.equal(body[0], 0);
    if (p1 === 0x80) assert.equal(trace.filter((t) => t.c).at(-1).sw, 0x9100, "busy first, then chained");
    const first = trace.find((t) => t.sw >> 8 === 0x61);
    assert.equal(first.sw >> 8, 0x61);
    const left = body.length - firstLen;
    assert.equal(first.sw & 0xff, left >= 256 ? 0 : left, "61xx states what is left");
    assert.equal(trace.at(-1).sw, 0x9000);
    const r = decodeCbor(body.subarray(1));
    assert.equal(r.get(5), 2);
    assert.equal(r.get(4).get("id").length, 64);
    const ad = parseAuthData(r.get(2));
    assert.equal(hsi.decrypt(ad.extensions.get("hmac-secret")).length, 64);
  }
  // an extended-length command with Le 0000 (65536) gets the whole response at once
  const tk = await token(key, PIN, { permissions: 0x02 });
  const hsi = await hmacSecretInput(key, 2, [SALT, crypto.randomBytes(32)]);
  const h = cdh();
  const req = cat([0x02], encodeCbor(new Map([[1, RP], [2, h], [4, hsi.ext], [6, PROTO[2].auth(tk, h)], [7, 2]])));
  const trace = [];
  const body = await exchange(key, req, { mode: "extended", trace });
  assert.ok(body.length > 300);
  assert.deepEqual(trace.map((x) => x.sw), [0x9000]);
  // GET RESPONSE with nothing pending
  assert.equal(swOf(await key.transceive(hex("00 C0 00 00 00"))), 0x6985);
});

test("NFCCTAP_MSG with P1=0x80: busyPolls × (01 9100), then the result via NFCCTAP_GETRESPONSE; P1=0x00 never 9100", async () => {
  const key = simulatedKey({ busyPolls: 3 });
  await select(key);
  const trace = [];
  const body = await exchange(key, Uint8Array.of(0x04), { p1: 0x80, trace });
  assert.equal(body[0], 0);
  assert.deepEqual(trace.map((t) => t.sw), [0x9100, 0x9100, 0x9100, 0x9000]);
  assert.deepEqual([...trace[1].c ?? []], [], "polls are GETRESPONSE");
  const t2 = [];
  await exchange(key, Uint8Array.of(0x04), { p1: 0x00, trace: t2 });
  assert.deepEqual(t2.map((t) => t.sw), [0x9000]);
  assert.equal(swOf(await key.transceive(hex("80 11 00 00 00"))), 0x6985, "nothing pending");
  // the result comes in the answer to the last NFCCTAP_GETRESPONSE, sized by its Le
  const t3 = [];
  const m = new Map([[1, cdh()], [2, { id: RP }], [3, { id: Uint8Array.of(9) }], [4, [{ alg: -7, type: "public-key" }]]]);
  const r = await exchange(key, cat([0x01], encodeCbor(m)), { p1: 0x80, trace: t3 });
  assert.equal(r[0], 0);
  assert.deepEqual(t3.map((t) => t.sw), [0x9100, 0x9100, 0x9100, 0x9000]);
  // NFCCTAP_CONTROL END_GETRESPONSE cancels a pending result
  assert.equal(swOf(await key.transceive(hex("80 10 80 00 01 04"))), 0x9100);
  assert.equal(swOf(await key.transceive(hex("80 12 01 00"))), 0x9000);
  assert.equal(swOf(await key.transceive(hex("80 11 00 00 00"))), 0x6985);
});

// ---------------------------------------------------------------------------
// getInfo, clientPIN
// ---------------------------------------------------------------------------
test("getInfo: versions, extensions, aaguid, options, maxMsgSize, protocols, minPINLength", async () => {
  const aaguid = crypto.randomBytes(16);
  const key = simulatedKey({ aaguid, minPinLength: 6, protocols: [2, 1] });
  await select(key);
  const info = await ok(key, 0x04);
  assert.deepEqual(info.get(1), ["FIDO_2_0", "FIDO_2_1"]);
  assert.deepEqual(info.get(2), ["credProtect", "hmac-secret"]);
  assert.equal(toHex(info.get(3)), toHex(aaguid));
  assert.deepEqual(Object.fromEntries(info.get(4)), { rk: true, up: true, plat: false, clientPin: false, pinUvAuthToken: true });
  assert.equal(info.get(5), 1200);
  assert.deepEqual(info.get(6), [2, 1]);
  assert.equal(info.get(0x0d), 6);
  // a CTAP 2.0 key with only protocol 1 and no extensions
  const old = simulatedKey({ versions: ["FIDO_2_0"], protocols: [1], hmacSecret: false, credProtect: false, pin: "1234" });
  await select(old);
  const i2 = await ok(old, 0x04);
  assert.equal(i2.has(2), false);
  assert.equal(i2.get(4).get("clientPin"), true);
  assert.equal(i2.get(4).has("pinUvAuthToken"), false);
  assert.equal(i2.has(0x0d), false);
  assert.equal((await ctap(old, 0x06, new Map([[1, 2], [2, 2]]))).status, S.INVALID_PARAMETER, "protocol 2 not offered");
  assert.equal((await getToken(old, "1234", { proto: 1 })).status, S.INVALID_SUBCOMMAND, "0x09 is CTAP 2.1");
  assert.equal((await getToken(old, "1234", { proto: 1, permissions: null })).status, 0);
});

for (const proto of [1, 2]) {
  test(`protocol ${proto}: setPIN, then getPinToken and getPinUvAuthTokenUsingPinWithPermissions`, async () => {
    const key = simulatedKey();
    await select(key);
    assert.equal(key.state.pinSet, false);
    assert.equal((await getToken(key, PIN, { proto })).status, S.PIN_NOT_SET);
    assert.equal((await setPin(key, PIN, proto)).status, 0);
    assert.equal(key.state.pinSet, true);
    assert.equal((await ok(key, 0x04)).get(4).get("clientPin"), true);
    assert.equal((await setPin(key, "654321", proto)).status, S.PIN_AUTH_INVALID, "already set");
    const legacy = await getToken(key, PIN, { proto, permissions: null });
    assert.equal(legacy.status, 0);
    assert.equal(legacy.token.length, 32);
    const t = await getToken(key, PIN, { proto, permissions: 0x03, rpId: RP });
    assert.equal(t.status, 0);
    assert.notEqual(toHex(t.token), toHex(legacy.token), "a new token per issue");
    assert.equal((await ok(key, 0x06, new Map([[1, proto], [2, 1]]))).get(3), 8);
    assert.equal((await getToken(key, PIN, { proto, permissions: 0 })).status, S.INVALID_PARAMETER);
    assert.equal((await getToken(key, PIN, { proto, permissions: 0x04 })).status, S.UNAUTHORIZED_PERMISSION, "credential management not offered");
  });
}

test("setPIN: bad pinUvAuthParam → PIN_AUTH_INVALID; PIN policy (minPINLength code points, 63 bytes) → PIN_POLICY_VIOLATION", async () => {
  const key = simulatedKey({ minPinLength: 6 });
  await select(key);
  const { cose, shared } = await encapsulate(key, 2);
  const enc = PROTO[2].enc(shared, padPin("12345678"));
  assert.equal((await ctap(key, 0x06, new Map([[1, 2], [2, 3], [3, cose], [4, new Uint8Array(32)], [5, enc]]))).status, S.PIN_AUTH_INVALID);
  assert.equal((await setPin(key, "12345")).status, S.PIN_POLICY_VIOLATION);
  assert.equal((await setPin(key, "ü".repeat(5))).status, S.PIN_POLICY_VIOLATION, "5 code points (10 bytes) is too short");
  assert.equal((await setPin(key, "x".repeat(64))).status, S.PIN_POLICY_VIOLATION, "64 bytes: over the 63-byte maximum");
  // 63 bytes exactly is the maximum
  const k2 = simulatedKey();
  await select(k2);
  assert.equal((await setPin(k2, "7".repeat(63))).status, 0);
  assert.equal((await getToken(k2, "7".repeat(63))).status, 0);
  assert.equal((await setPin(key, "ü".repeat(6))).status, 0);
  assert.equal((await getToken(key, "ü".repeat(6), { proto: 1 })).status, 0);
});

test("wrong PIN: retries count down, 3 in a row block until power cycle, 0 blocks for good; a right PIN resets to 8", async () => {
  const key = simulatedKey({ pin: PIN });
  await select(key);
  const retries = async () => (await ok(key, 0x06, new Map([[1, 2], [2, 1]]))).get(3);
  assert.equal((await getToken(key, "000000")).status, S.PIN_INVALID);
  assert.equal(await retries(), 7);
  assert.equal((await getToken(key, PIN)).status, 0);
  assert.equal(await retries(), 8, "reset by a right PIN");

  assert.equal((await getToken(key, "000000")).status, S.PIN_INVALID);
  assert.equal((await getToken(key, "000000", { proto: 1 })).status, S.PIN_INVALID);
  assert.equal((await getToken(key, "000000")).status, S.PIN_AUTH_BLOCKED);
  assert.equal(key.state.pinRetries, 5);
  assert.equal((await getToken(key, PIN)).status, S.PIN_AUTH_BLOCKED, "even the right PIN, until power cycle");
  assert.equal(key.state.pinRetries, 5, "a blocked attempt costs nothing");
  assert.equal((await ok(key, 0x06, new Map([[1, 2], [2, 1]]))).get(4), true, "powerCycleState");

  key.powerCycle();
  assert.equal(await select(key), "FIDO_2_0");
  for (const left of [4, 3]) {
    assert.equal((await getToken(key, "000000")).status, S.PIN_INVALID);
    assert.equal(key.state.pinRetries, left);
  }
  assert.equal((await getToken(key, "000000")).status, S.PIN_AUTH_BLOCKED);
  key.powerCycle();
  await select(key);
  assert.equal((await getToken(key, "000000")).status, S.PIN_INVALID);
  assert.equal((await getToken(key, "000000")).status, S.PIN_BLOCKED, "the last try");
  assert.equal(key.state.pinRetries, 0);
  key.powerCycle();
  await select(key);
  assert.equal((await getToken(key, PIN)).status, S.PIN_BLOCKED, "for good");

  const fresh = simulatedKey({ pin: PIN, pinRetries: 0 });
  await select(fresh);
  assert.equal((await getToken(fresh, PIN)).status, S.PIN_BLOCKED);
});

test("a wrong PIN regenerates the key agreement key: the old shared secret no longer works", async () => {
  const key = simulatedKey({ pin: PIN });
  await select(key);
  const a = await ok(key, 0x06, new Map([[1, 2], [2, 2]]));
  assert.equal((await getToken(key, "999999")).status, S.PIN_INVALID);
  const b = await ok(key, 0x06, new Map([[1, 2], [2, 2]]));
  assert.notEqual(toHex(a.get(1).get(-2)), toHex(b.get(1).get(-2)));
  const c = await ok(key, 0x06, new Map([[1, 2], [2, 2]]));
  assert.equal(toHex(b.get(1).get(-2)), toHex(c.get(1).get(-2)), "otherwise stable within a power cycle");
});

// ---------------------------------------------------------------------------
// makeCredential
// ---------------------------------------------------------------------------
test("makeCredential rk + hmac-secret + credProtect 3: authData parses, flags, counter, attested credential, extension outputs", async () => {
  const aaguid = crypto.randomBytes(16);
  const key = simulatedKey({ pin: PIN, aaguid });
  await select(key);
  const userId = crypto.randomBytes(32);
  const r = await makeCredential(key, { pin: PIN, userId });
  assert.equal(r.status, 0);
  assert.equal(r.data.get(1), "none");
  assert.equal(r.data.get(3).size, 0);
  const ad = parseAuthData(r.data.get(2));
  assert.equal(toHex(ad.rpIdHash), toHex(sha256(Buffer.from(RP))));
  assert.equal(ad.flags, 0x01 | 0x04 | 0x40 | 0x80);
  assert.equal(ad.signCount, 1);
  assert.equal(toHex(ad.aaguid), toHex(aaguid));
  assert.ok(ad.credentialId.length >= 32);
  assert.deepEqual([...ad.publicKey.keys()], [1, 3, -1, -2, -3]);
  assert.equal(ad.publicKey.get(1), 2);
  assert.equal(ad.publicKey.get(3), -7);
  assert.equal(ad.publicKey.get(-1), 1);
  coseToKey(ad.publicKey); // a valid P-256 point
  assert.deepEqual(Object.fromEntries(ad.extensions), { "hmac-secret": true, credProtect: 3 });
  const [c] = key.state.credentials;
  assert.equal(c.rpId, RP);
  assert.equal(toHex(c.credentialId), toHex(ad.credentialId));
  assert.equal(toHex(c.userId), toHex(userId));
  assert.equal(c.credProtect, 3);
});

test("makeCredential: PIN set → PUAT_REQUIRED without a token, PIN_AUTH_INVALID with a wrong one or without mc permission; ES256 only", async () => {
  const key = simulatedKey({ pin: PIN });
  await select(key);
  assert.equal((await makeCredential(key, {})).status, S.PUAT_REQUIRED);
  assert.equal((await makeCredential(key, { extra: (m) => (m.set(8, new Uint8Array(32)), m.set(9, 2)) })).status, S.PIN_AUTH_INVALID);
  const gaOnly = await token(key, PIN, { permissions: 0x02 });
  assert.equal((await makeCredential(key, { extra: (m) => (m.set(8, PROTO[2].auth(gaOnly, m.get(1))), m.set(9, 2)) })).status, S.PIN_AUTH_INVALID);
  const otherRp = await token(key, PIN, { permissions: 0x01, rpId: "example.com" });
  assert.equal((await makeCredential(key, { extra: (m) => (m.set(8, PROTO[2].auth(otherRp, m.get(1))), m.set(9, 2)) })).status, S.PIN_AUTH_INVALID);
  assert.equal((await makeCredential(key, { extra: (m) => m.set(8, new Uint8Array(16)) })).status, S.MISSING_PARAMETER, "protocol missing");
  assert.equal((await makeCredential(key, { pin: PIN, alg: -257 })).status, S.UNSUPPORTED_ALGORITHM);
  assert.equal((await makeCredential(key, { pin: PIN, extra: (m) => m.set(7, { rk: true, up: false }) })).status, S.INVALID_OPTION);
  assert.equal((await makeCredential(key, { pin: PIN })).status, 0);
  // the token is spent by the operation that collected presence (CTAP 2.1 §6.1.2)
  const t = await token(key, PIN, { permissions: 0x01 });
  const once = (m) => (m.set(8, PROTO[2].auth(t, m.get(1))), m.set(9, 2));
  assert.equal((await makeCredential(key, { extra: once })).status, 0);
  assert.equal((await makeCredential(key, { extra: once })).status, S.PIN_AUTH_INVALID);
});

test("makeCredential without a PIN: UV clear; excludeList; same user replaces the discoverable credential; KEY_STORE_FULL", async () => {
  const key = simulatedKey({ maxCredentials: 2 });
  await select(key);
  const u = crypto.randomBytes(8);
  const a = await makeCredential(key, { userId: u, credProtect: 0, hmacSecret: false });
  const ad = parseAuthData(a.data.get(2));
  assert.equal(ad.flags, 0x41, "UP + AT, no UV, no ED");
  assert.equal(
    (await makeCredential(key, { extra: (m) => m.set(5, [{ id: ad.credentialId, type: "public-key" }]) })).status,
    S.CREDENTIAL_EXCLUDED,
  );
  assert.equal((await makeCredential(key, { userId: u })).status, 0, "replaces");
  assert.equal(key.state.credentials.filter((c) => c.discoverable).length, 1);
  assert.equal((await makeCredential(key, {})).status, 0);
  assert.equal((await makeCredential(key, {})).status, S.KEY_STORE_FULL);
  assert.equal((await makeCredential(key, { rk: false })).status, 0, "non-resident credentials take no slot");
  assert.equal((await ok(key, 0x04)).get(0x14), 0, "remainingDiscoverableCredentials");
});

test("extensions the key does not offer are ignored", async () => {
  const key = simulatedKey({ hmacSecret: false, credProtect: false });
  await select(key);
  const r = await makeCredential(key, {});
  const ad = parseAuthData(r.data.get(2));
  assert.equal(ad.flags & 0x80, 0);
  assert.equal(ad.extensions, undefined);
  assert.equal(key.state.credentials[0].credProtect, 1);
});

// ---------------------------------------------------------------------------
// getAssertion, hmac-secret, credProtect
// ---------------------------------------------------------------------------
test("getAssertion: signature verifies with the COSE key over authData ‖ clientDataHash; UP+UV flags; user id", async () => {
  const { key, id, publicKey } = await keyWithCredential();
  const a = await getAssertion(key, { pin: PIN, allow: [id], clientDataHash: cdh("HUMID-KEY-v1 recover xyz") });
  assert.equal(a.status, 0);
  assert.equal(a.authData.flags, 0x05);
  assert.equal(toHex(a.r.get(1).get("id")), toHex(id));
  assert.equal(a.r.get(1).get("type"), "public-key");
  assert.ok(a.r.get(4).get("id") instanceof Uint8Array);
  assert.equal(a.r.has(5), false);
  const ok1 = crypto.verify("sha256", cat(a.r.get(2), a.clientDataHash), coseToKey(publicKey), a.r.get(3));
  assert.equal(ok1, true);
  const tampered = cat(a.r.get(2), cdh("other"));
  assert.equal(crypto.verify("sha256", tampered, coseToKey(publicKey), a.r.get(3)), false);
});

test("hmac-secret: same salt → same output across sessions and protocols; UV and no-UV differ; two salts", async () => {
  const { key, id } = await keyWithCredential({ counter: "zero" });
  const outs = [];
  for (const proto of [2, 1]) {
    for (let session = 0; session < 2; session++) {
      key.powerCycle();
      await select(key);
      const a = await getAssertion(key, { pin: PIN, proto, saltProto: proto, allow: [id], salts: [SALT] });
      assert.equal(a.status, 0);
      assert.equal(a.authData.flags, 0x01 | 0x04 | 0x80);
      assert.equal(a.secret.length, 32);
      outs.push(toHex(a.secret));
    }
  }
  assert.equal(new Set(outs).size, 1, "one S whatever the session or protocol");
  assert.equal(outs[0], toHex(key.hmacSecretForTest(id, SALT)));
  // pin protocol 2 token with a protocol 1 hmac-secret exchange (§12.5 field 4)
  const mixed = await getAssertion(key, { pin: PIN, proto: 2, saltProto: 1, allow: [id], salts: [SALT] });
  assert.equal(toHex(mixed.secret), outs[0]);

  // without UV: CredRandomWithoutUV. A credProtect-3 credential can't be used without UV,
  // so make a level-1 one.
  const k2 = simulatedKey();
  await select(k2);
  const r = await makeCredential(k2, { credProtect: 1 });
  const id2 = parseAuthData(r.data.get(2)).credentialId;
  const noUv = await getAssertion(k2, { allow: [id2], salts: [SALT] });
  assert.equal(noUv.authData.flags, 0x81);
  assert.equal(toHex(noUv.secret), toHex(k2.hmacSecretForTest(id2, SALT, { uv: false })));
  assert.notEqual(toHex(noUv.secret), toHex(k2.hmacSecretForTest(id2, SALT, { uv: true })));
  assert.equal((await setPin(k2, PIN)).status, 0);
  const withUv = await getAssertion(k2, { pin: PIN, allow: [id2], salts: [SALT] });
  assert.equal(toHex(withUv.secret), toHex(k2.hmacSecretForTest(id2, SALT, { uv: true })));
  assert.notEqual(toHex(withUv.secret), toHex(noUv.secret));

  // two salts → 64 bytes
  const salt2 = crypto.randomBytes(32);
  const two = await getAssertion(key, { pin: PIN, allow: [id], salts: [SALT, salt2] });
  assert.equal(two.secret.length, 64);
  assert.equal(toHex(two.secret.subarray(0, 32)), outs[0]);
  assert.equal(toHex(two.secret.subarray(32)), toHex(key.hmacSecretForTest(id, salt2)));

  // up: false is allowed with hmac-secret; no UP flag
  const silent = await getAssertion(k2, { allow: [id2], salts: [SALT], up: false });
  assert.equal(silent.authData.flags, 0x80);
  assert.equal(toHex(silent.secret), toHex(noUv.secret));
});

test("hmac-secret: protocol 1 is the default when field 4 is absent; bad saltAuth → PIN_AUTH_INVALID; bad salt length → INVALID_LENGTH", async () => {
  const { key, id } = await keyWithCredential();
  const run = async (ext) => {
    const t = await token(key, PIN, { permissions: 0x02 });
    const h = cdh();
    return ctap(key, 0x02, new Map([[1, RP], [2, h], [3, [{ id, type: "public-key" }]], [4, ext], [6, PROTO[2].auth(t, h)], [7, 2]]));
  };
  const v1 = await hmacSecretInput(key, 1, [SALT], { sendProto: false });
  const r = await run(v1.ext);
  assert.equal(r.status, 0);
  const out = parseAuthData(r.data.get(2)).extensions.get("hmac-secret");
  assert.equal(out.length, 32, "protocol 1: no IV");
  assert.equal(toHex(v1.decrypt(out)), toHex(key.hmacSecretForTest(id, SALT)));

  const bad = await hmacSecretInput(key, 2, [SALT]);
  bad.ext["hmac-secret"].set(3, new Uint8Array(32));
  assert.equal((await run(bad.ext)).status, S.PIN_AUTH_INVALID);
  const short = await hmacSecretInput(key, 2, [SALT.subarray(0, 16)]);
  assert.equal((await run(short.ext)).status, S.INVALID_LENGTH);
});

test("credProtect 3: invisible without UV, with or without an allowList; level 2 needs UV only for discovery", async () => {
  const key = simulatedKey();
  await select(key);
  const ids = {};
  for (const level of [1, 2, 3]) {
    const r = await makeCredential(key, { credProtect: level, userId: Uint8Array.of(level) });
    assert.equal(r.status, 0);
    ids[level] = parseAuthData(r.data.get(2)).credentialId;
  }
  assert.equal((await getAssertion(key, { allow: [ids[3]] })).status, S.NO_CREDENTIALS);
  assert.equal((await getAssertion(key, { allow: [ids[2]] })).status, 0);
  const disc = await getAssertion(key, {});
  assert.equal(disc.status, 0);
  assert.equal(toHex(disc.r.get(1).get("id")), toHex(ids[1]), "only level 1 is discoverable without UV");
  assert.equal(disc.r.has(5), false);

  assert.equal((await setPin(key, PIN)).status, 0);
  const withUv = await getAssertion(key, { pin: PIN });
  assert.equal(withUv.r.get(5), 3, "all three with UV");
  assert.equal((await getAssertion(key, { pin: PIN, allow: [ids[3]] })).status, 0);
  assert.equal((await getAssertion(key, { rpId: "example.com", pin: PIN })).status, S.NO_CREDENTIALS);
  // excludeList without UV does not reveal a level-3 credential
  const ex = (m) => m.set(5, [{ id: ids[3], type: "public-key" }]);
  assert.equal((await makeCredential(key, { pin: PIN, extra: ex })).status, S.CREDENTIAL_EXCLUDED);
});

test("discoverable: two credentials → numberOfCredentials 2, getNextAssertion with the same hmac-secret salt, then NOT_ALLOWED", async () => {
  const key = simulatedKey({ pin: PIN });
  await select(key);
  const made = [];
  for (const n of [1, 2]) {
    const r = await makeCredential(key, { pin: PIN, userId: Uint8Array.of(n) });
    made.push(parseAuthData(r.data.get(2)));
  }
  const first = await getAssertion(key, { pin: PIN, salts: [SALT] });
  assert.equal(first.status, 0);
  assert.equal(first.r.get(5), 2);
  assert.equal(toHex(first.r.get(1).get("id")), toHex(made[1].credentialId), "most recent first");
  assert.equal(first.r.get(4).get("name"), "parker", "user details with UV among several");
  assert.equal(toHex(first.secret), toHex(key.hmacSecretForTest(made[1].credentialId, SALT)));
  const next = await ctap(key, 0x08);
  assert.equal(next.status, 0);
  assert.equal(next.data.has(5), false);
  assert.equal(toHex(next.data.get(1).get("id")), toHex(made[0].credentialId));
  assert.deepEqual([...next.data.get(4).get("id")], [1]);
  const ad = parseAuthData(next.data.get(2));
  assert.equal(ad.flags, 0x85);
  assert.equal(toHex(first.hs.decrypt(ad.extensions.get("hmac-secret"))), toHex(key.hmacSecretForTest(made[0].credentialId, SALT)));
  assert.equal(
    crypto.verify("sha256", cat(next.data.get(2), first.clientDataHash), coseToKey(made[0].publicKey), next.data.get(3)),
    true,
  );
  assert.equal((await ctap(key, 0x08)).status, S.NOT_ALLOWED, "no more");
  // any other command in between ends it
  await getAssertion(key, { pin: PIN });
  await ok(key, 0x04);
  assert.equal((await ctap(key, 0x08)).status, S.NOT_ALLOWED);
});

test("getAssertion: pinUvAuthParam needs the ga permission and the token's RP; rk option refused", async () => {
  const { key, id } = await keyWithCredential();
  const run = async (t, rpId = RP) => {
    const h = cdh();
    return ctap(key, 0x02, new Map([[1, rpId], [2, h], [3, [{ id, type: "public-key" }]], [6, PROTO[2].auth(t, h)], [7, 2]]));
  };
  assert.equal((await run(await token(key, PIN, { permissions: 0x01 }))).status, S.PIN_AUTH_INVALID);
  assert.equal((await run(await token(key, PIN, { permissions: 0x02, rpId: "example.com" }))).status, S.PIN_AUTH_INVALID);
  assert.equal((await run(await token(key, PIN, { permissions: 0x02 }))).status, 0);
  const legacy = await token(key, PIN, { permissions: null });
  assert.equal((await run(legacy)).status, 0, "legacy getPinToken grants ga");
  assert.equal((await ctap(key, 0x02, new Map([[1, RP], [2, cdh()], [5, { rk: true }]]))).status, S.UNSUPPORTED_OPTION);
  // tokens are gone after a power cycle
  const t = await token(key, PIN, { permissions: 0x02 });
  key.powerCycle();
  await select(key);
  assert.equal((await run(t)).status, S.PIN_AUTH_INVALID);
});

// ---------------------------------------------------------------------------
// Counter and clones
// ---------------------------------------------------------------------------
test('counter "global" increments per makeCredential and assertion; "zero" stays 0', async () => {
  const { key, id } = await keyWithCredential();
  assert.equal(key.state.counter, 1);
  const counts = [];
  for (let i = 0; i < 3; i++) counts.push((await getAssertion(key, { pin: PIN, allow: [id] })).authData.signCount);
  assert.deepEqual(counts, [2, 3, 4]);
  const r = await makeCredential(key, { pin: PIN });
  assert.equal(parseAuthData(r.data.get(2)).signCount, 5);
  assert.equal((await getAssertion(key, { pin: PIN, allow: [id] })).authData.signCount, 6, "one counter for every credential");

  const z = await keyWithCredential({ counter: "zero" });
  assert.equal(z.key.state.counter, 0);
  assert.equal((await getAssertion(z.key, { pin: PIN, allow: [z.id] })).authData.signCount, 0);
  assert.equal((await getAssertion(z.key, { pin: PIN, allow: [z.id] })).authData.signCount, 0);
});

test("clone(): the same credentials, PRF secrets and counter, each counting on its own", async () => {
  const { key, id, publicKey } = await keyWithCredential();
  await getAssertion(key, { pin: PIN, allow: [id] });
  const twin = key.clone();
  await select(twin);
  assert.equal(twin.state.counter, key.state.counter);
  assert.deepEqual(twin.state.credentials.map((c) => toHex(c.credentialId)), [toHex(id)]);
  const a = await getAssertion(key, { pin: PIN, allow: [id], salts: [SALT] });
  const b = await getAssertion(twin, { pin: PIN, salts: [SALT] });
  assert.equal(b.status, 0, "the PIN came along");
  assert.equal(toHex(a.secret), toHex(b.secret));
  assert.equal(a.authData.signCount, b.authData.signCount, "both moved from 2 to 3: a server sees the counter fail to advance");
  assert.equal(crypto.verify("sha256", cat(b.r.get(2), b.clientDataHash), coseToKey(publicKey), b.r.get(3)), true);
  await getAssertion(twin, { pin: PIN });
  assert.equal(twin.state.counter, key.state.counter + 1);
});
