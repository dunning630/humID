// PACE (ICAO 9303 part 11, section 4.4; BSI TR-03110): password-authenticated
// key agreement. Stronger than BAC, and the only option on many newer ID
// cards. Supported here: ECDH with Generic Mapping, AES-128/192/256 or 3DES,
// on the standardized NIST and Brainpool curves. Password: the MRZ details or
// the 6-digit CAN printed on ID cards.
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { p256, p384, p521 } from "@noble/curves/nist.js";
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from "@noble/curves/misc.js";
import { tdesCbc, retailMac } from "./des.js";
import { aesCbc, cmac } from "./cmac.js";
import { kdf3des, mrzInformation } from "./bac.js";
import { concat, pad, utf8, u32be, tlv, readTlv, readTlvs, oidBytes, oidText, equal, random, wipe, ChipError } from "./util.js";

const PACE = "0.4.0.127.0.7.2.2.4";
export const PROTOCOLS = {
  [`${PACE}.2.1`]: { name: "ECDH-GM-3DES", cipher: "3des", keyLength: 16 },
  [`${PACE}.2.2`]: { name: "ECDH-GM-AES-128", cipher: "aes", keyLength: 16 },
  [`${PACE}.2.3`]: { name: "ECDH-GM-AES-192", cipher: "aes", keyLength: 24 },
  [`${PACE}.2.4`]: { name: "ECDH-GM-AES-256", cipher: "aes", keyLength: 32 },
};
/** ICAO standardized domain parameter ids → curves. */
export const CURVES = { 12: p256, 13: brainpoolP256r1, 15: p384, 16: brainpoolP384r1, 17: brainpoolP512r1, 18: p521 };

/** PACEInfo entries from EF.CardAccess (a DER SET OF SecurityInfo). */
export function parseCardAccess(bytes) {
  const out = [];
  const set = readTlv(bytes, 0);
  let p = 0;
  while (p < set.value.length) {
    const info = readTlv(set.value, p);
    p = info.end;
    let q = 0;
    const kids = [];
    while (q < info.value.length) { const k = readTlv(info.value, q); kids.push(k); q = k.end; }
    if (kids[0]?.tag !== 0x06) continue;
    const oid = oidText(kids[0].value);
    if (!oid.startsWith(PACE + ".")) continue;
    const int = (t) => (t?.tag === 0x02 ? t.value.reduce((n, b) => n * 256 + b, 0) : undefined);
    out.push({ oid, version: int(kids[1]), parameterId: int(kids[2]) });
  }
  return out;
}

/** The PACE option this reader can run, preferring the strongest. */
export function choosePace(infos) {
  const ok = infos.filter((i) => PROTOCOLS[i.oid] && CURVES[i.parameterId]);
  const rank = (i) => PROTOCOLS[i.oid].keyLength * (PROTOCOLS[i.oid].cipher === "aes" ? 2 : 1);
  return ok.sort((a, b) => rank(b) - rank(a))[0] || null;
}

export function paceKdf(k, c, proto) {
  if (proto.cipher === "3des") return kdf3des(k, c);
  if (proto.keyLength === 16) return sha1(concat(k, u32be(c))).subarray(0, 16);
  return sha256(concat(k, u32be(c))).subarray(0, proto.keyLength);
}

/** The password: SHA-1 of the MRZ information, or the CAN as text. */
export const pacePassword = (access) => (access.can ? utf8(String(access.can).replace(/\D/g, "")) : sha1(utf8(mrzInformation(access))));

export const blockCipher = (proto, key, data, decrypt) => (proto.cipher === "aes" ? aesCbc(key, data, decrypt) : tdesCbc(key, data, decrypt));
export const authMac = (proto, key, data) => (proto.cipher === "aes" ? cmac(key, data).subarray(0, 8) : retailMac(key, pad(data, 8)));
export const publicKeyDo = (oid, point) => tlv(0x7f49, concat(tlv(0x06, oidBytes(oid)), tlv(0x86, point)));
const bytesToBig = (b) => BigInt("0x" + (Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("") || "0"));
const bigToBytes = (n, len) => { const h = n.toString(16).padStart(len * 2, "0"); return Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16)); };
export const curveSizes = (curve) => Math.ceil(curve.Point.Fp.BITS / 8);
export function randomScalar(curve) {
  const n = curve.Point.Fn.ORDER;
  for (;;) { const k = bytesToBig(random(curveSizes(curve) + 8)) % n; if (k > 0n) return k; }
}
export { bytesToBig, bigToBytes };

/** GENERAL AUTHENTICATE with a dynamic authentication template (7C). */
async function generalAuthenticate(send, inner, last) {
  const r = await send({ cla: last ? 0x00 : 0x10, ins: 0x86, p1: 0, p2: 0, data: tlv(0x7c, inner), le: 256 });
  if (r.sw !== 0x9000) {
    const denied = r.sw === 0x6300 || (r.sw & 0xfff0) === 0x63c0;
    throw new ChipError(denied ? "access_denied" : "chip_refused", denied ? "These details don't open this chip. Check them and try again." : "The chip stopped the secure connection.", r.sw);
  }
  return readTlvs(readTlv(r.data, 0).value);
}

/** Run PACE. info: the chosen PACEInfo. Returns session keys and SSC for secure messaging. */
export async function pace(send, access, info) {
  const proto = PROTOCOLS[info.oid];
  const curve = CURVES[info.parameterId];
  if (!proto || !curve) throw new ChipError("unsupported", "This chip uses a PACE variant HumID can't read yet.");
  const G = curve.Point.BASE;
  const n = curve.Point.Fn.ORDER;
  const L = curveSizes(curve);

  // MSE:Set AT — protocol, password (1 = MRZ, 2 = CAN), domain parameters.
  const at = concat(tlv(0x80, oidBytes(info.oid)), tlv(0x83, Uint8Array.of(access.can ? 2 : 1)), tlv(0x84, Uint8Array.of(info.parameterId)));
  const mse = await send({ cla: 0x00, ins: 0x22, p1: 0xc1, p2: 0xa4, data: at });
  if (mse.sw !== 0x9000) throw new ChipError("chip_refused", "The chip didn't accept the PACE settings.", mse.sw);

  // 1. Encrypted nonce, opened with the password key.
  const pw = pacePassword(access);
  const kPi = paceKdf(pw, 3, proto);
  wipe(pw);
  let s;
  try {
    const z = (await generalAuthenticate(send, new Uint8Array(0))).get(0x80);
    const block = proto.cipher === "aes" ? 16 : 8;
    if (!z || !z.length || z.length % block || z.length > 64) throw new ChipError("bad_sm", "The chip sent no usable PACE nonce.");
    const plain = blockCipher(proto, kPi, z, true);
    s = bytesToBig(plain) % n;
    wipe(plain);
  } finally { wipe(kPi); }
  if (s === 0n) throw new ChipError("bad_sm", "The chip's PACE nonce is invalid.");

  // 2. Generic mapping: G' = s·G + H, H = shared point of an ephemeral exchange.
  const skMap = randomScalar(curve);
  const pkMap = G.multiply(skMap).toBytes(false);
  const pkMapIc = (await generalAuthenticate(send, tlv(0x81, pkMap))).get(0x82);
  let H;
  try { H = curve.Point.fromBytes(pkMapIc).multiply(skMap); } catch { throw new ChipError("bad_sm", "The chip's mapping key isn't on the curve."); }
  const Gm = G.multiply(s).add(H);

  // 3. Key agreement on the mapped generator.
  const sk = randomScalar(curve);
  const pk = Gm.multiply(sk).toBytes(false);
  const pkIc = (await generalAuthenticate(send, tlv(0x83, pk))).get(0x84);
  if (!pkIc || equal(pkIc, pk)) throw new ChipError("bad_sm", "The chip's PACE key is invalid.");
  let K;
  try { K = bigToBytes(curve.Point.fromBytes(pkIc).multiply(sk).toAffine().x, L); } catch { throw new ChipError("bad_sm", "The chip's PACE key isn't on the curve."); }
  const ksEnc = paceKdf(K, 1, proto), ksMac = paceKdf(K, 2, proto);
  wipe(K);

  // 4. Mutual authentication tokens over each other's public keys.
  const tIfd = authMac(proto, ksMac, publicKeyDo(info.oid, pkIc));
  const tIc = (await generalAuthenticate(send, tlv(0x85, tIfd), true)).get(0x86);
  if (!tIc || !equal(tIc, authMac(proto, ksMac, publicKeyDo(info.oid, pk)))) throw new ChipError("bad_sm", "The chip failed PACE mutual authentication.");

  return { cipher: proto.cipher, ksEnc, ksMac, ssc: new Uint8Array(proto.cipher === "aes" ? 16 : 8), protocol: proto.name, parameterId: info.parameterId };
}
