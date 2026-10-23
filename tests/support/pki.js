// Test PKI: builds X.509 chains shaped exactly like Android key attestation
// and Apple App Attest, signed by throwaway roots, so the verifiers and the
// whole stack can be tested with phones that don't exist. Tests only.
import { generateKeyPairSync, sign, createHash, randomBytes } from "node:crypto";
import { ecdsaRS, P256_N } from "@humid/attest";
import { lowS } from "../../packages/gate/src/lows.js";

/* ---------------- DER ---------------- */

const len = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255]);
const tlv = (tag, content) => Buffer.concat([Buffer.from(tag), Buffer.from(len(content.length)), Buffer.from(content)]);
const cat = (items) => Buffer.concat(items.map((i) => Buffer.from(i)));
export const seq = (...items) => tlv([0x30], cat(items));
export const set = (...items) => tlv([0x31], cat(items));
export const octet = (b) => tlv([0x04], b);
export const nul = () => Buffer.from([0x05, 0x00]);
export const bool = (v) => tlv([0x01], [v ? 0xff : 0]);
function intBytes(n) {
  let h = BigInt(n).toString(16);
  if (h.length % 2) h = "0" + h;
  let b = Buffer.from(h, "hex");
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return b;
}
export const int = (n) => tlv([0x02], intBytes(n));
export const enumerated = (n) => tlv([0x0a], intBytes(n));
const utf8s = (s) => tlv([0x0c], Buffer.from(s));
const bitString = (b) => tlv([0x03], Buffer.concat([Buffer.from([0]), b]));
const utcTime = (d) => tlv([0x17], Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
export function oid(s) {
  const p = s.split(".").map(Number);
  const out = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) {
    const b = [];
    let v = n;
    do { b.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v);
    for (let i = 0; i < b.length - 1; i++) b[i] |= 0x80;
    out.push(...b);
  }
  return tlv([0x06], out);
}
/** [n] EXPLICIT, high-tag form when n > 30. */
export function explicit(n, inner) {
  if (n < 31) return tlv([0xa0 | n], inner);
  const b = [];
  let v = n;
  do { b.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v);
  for (let i = 0; i < b.length - 1; i++) b[i] |= 0x80;
  return tlv([0xbf, ...b], inner);
}

/* ---------------- certificates ---------------- */

const SIG = { "P-256": ["1.2.840.10045.4.3.2", "sha256"], "P-384": ["1.2.840.10045.4.3.3", "sha384"] };
export const ecKeys = (curve = "P-256") => generateKeyPairSync("ec", { namedCurve: curve });
const curveOf = (k) => (k.asymmetricKeyDetails.namedCurve === "secp384r1" ? "P-384" : "P-256");
const printable = (s) => tlv([0x13], Buffer.from(s));
/** An X.509 Name: CN, with a countryName first when given ({ cn, country } or a plain CN). */
export const name = (n) => {
  const { cn, country, o, ou, uid } = typeof n === "string" ? { cn: n } : n;
  return seq(
    ...(uid ? [set(seq(oid("0.9.2342.19200300.100.1.1"), utf8s(uid)))] : []),
    ...(cn ? [set(seq(oid("2.5.4.3"), utf8s(cn)))] : []),
    ...(ou ? [set(seq(oid("2.5.4.11"), utf8s(ou)))] : []),
    ...(o ? [set(seq(oid("2.5.4.10"), utf8s(o)))] : []),
    ...(country ? [set(seq(oid("2.5.4.6"), printable(country)))] : []),
  );
};
/** keyUsage BIT STRING with the given bits set (0 = digitalSignature, 5 = keyCertSign, 6 = cRLSign). */
export const keyUsage = (...bits) => { let v = 0; for (const b of bits) v |= 0x80 >> b; return tlv([0x03], [7 - Math.max(...bits), v]); };
export const extension = (id, value, critical = false) => seq(oid(id), ...(critical ? [bool(true)] : []), octet(value));

let serial = 1000;
export function certificate({ subject, issuer, publicKey, signingKey, extensions = [], ca = false, serialNumber = serial++, notBefore = new Date(Date.now() - 86400e3), notAfter = new Date(Date.now() + 365 * 86400e3) }) {
  const [algOid, hash] = SIG[curveOf(signingKey)];
  const alg = seq(oid(algOid));
  const exts = ca ? [...extensions, extension("2.5.29.19", seq(bool(true)), true)] : extensions;
  const tbs = seq(
    explicit(0, int(2)), int(serialNumber), alg, name(issuer), seq(utcTime(notBefore), utcTime(notAfter)), name(subject),
    publicKey.export({ type: "spki", format: "der" }), ...(exts.length ? [explicit(3, seq(...exts))] : []),
  );
  return seq(tbs, alg, bitString(sign(hash, tbs, signingKey)));
}

export const pem = (der) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;

export function testRoot(cn = "HumID Test Attestation Root", curve = "P-384") {
  const k = ecKeys(curve);
  const der = certificate({ subject: cn, issuer: cn, publicKey: k.publicKey, signingKey: k.privateKey, ca: true });
  return { ...k, der, pem: pem(der), cn };
}

/* ---------------- Android key attestation ---------------- */

const authList = (entries) => seq(...entries.sort((a, b) => a[0] - b[0]).map(([t, v]) => explicit(t, v)));

/**
 * A KeyDescription like a Pixel's for a liveness key. Override any field to make a bad one.
 */
export function keyDescription({
  challenge, level = 1, userAuthType = 2, noAuthRequired = false, authTimeout, allowWhileOnBody = false,
  packageName = "app.humid.vault", deviceLocked = true, bootState = 0, curve = 1, purposes = [2], algorithm = 3,
  kmLevel = level, osPatch = 202609, signer = Buffer.alloc(32, 1), unlockedDeviceRequired = true,
}) {
  const hw = [
    [1, set(...purposes.map(int))], [2, int(algorithm)], [3, int(256)], [5, set(int(4))],
    ...(curve === null ? [] : [[10, int(curve)]]),
    ...(noAuthRequired ? [[503, nul()]] : []),
    ...(userAuthType == null ? [] : [[504, int(userAuthType)]]),
    ...(authTimeout == null ? [] : [[505, int(authTimeout)]]),
    ...(allowWhileOnBody ? [[506, nul()]] : []),
    ...(unlockedDeviceRequired ? [[509, nul()]] : []),
    ...(osPatch == null ? [] : [[706, int(osPatch)]]),
    [704, seq(octet(Buffer.alloc(32, 7)), bool(deviceLocked), enumerated(bootState), octet(Buffer.alloc(32, 9)))],
  ];
  const appId = seq(set(seq(octet(Buffer.from(packageName)), int(1))), set(octet(signer)));
  const sw = [[701, int(Date.now())], [709, octet(appId)]];
  return seq(int(200), enumerated(level), int(200), enumerated(kmLevel), octet(challenge), octet(Buffer.alloc(0)), authList(sw), authList(hw));
}

/** An Android-shaped chain for a fresh liveness key: [leaf, intermediate, root] DER. */
export function androidChain({ root, challenge, liveKey = ecKeys("P-256"), interCa = true, interNotAfter, ...kd }) {
  const inter = ecKeys("P-256");
  const interDer = certificate({ subject: "HumID Test StrongBox CA", issuer: root.cn, publicKey: inter.publicKey, signingKey: root.privateKey, ca: interCa, ...(interNotAfter ? { notAfter: interNotAfter } : {}) });
  const leafDer = certificate({
    subject: "Android Keystore Key", issuer: "HumID Test StrongBox CA", publicKey: liveKey.publicKey, signingKey: inter.privateKey,
    extensions: [extension("1.3.6.1.4.1.11129.2.1.17", keyDescription({ challenge, ...kd }))],
  });
  return { chain: [leafDer, interDer, root.der], liveKey, pub: liveKey.publicKey.export({ type: "spki", format: "der" }) };
}

/* ---------------- Apple App Attest ---------------- */

function cbor(v) {
  const head = (major, n) => (n < 24 ? Buffer.from([(major << 5) | n]) : n < 256 ? Buffer.from([(major << 5) | 24, n]) : n < 65536 ? Buffer.from([(major << 5) | 25, n >> 8, n & 255]) : Buffer.from([(major << 5) | 26, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255]));
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  const e = Object.entries(v);
  return Buffer.concat([head(5, e.length), ...e.flatMap(([k, x]) => [cbor(/^-?\d+$/.test(k) ? Number(k) : k), cbor(x)])]);
}
const sha256 = (...p) => createHash("sha256").update(Buffer.concat(p.map((x) => Buffer.from(x)))).digest();

/** An App Attest attestation object for clientDataHash, as DCAppAttestService.attestKey returns it. */
export function appAttestation({ root, clientDataHash, appId = "TEAM123456.app.humid.vault", environment = "production", counter = 0, tamperKeyId = false }) {
  const inter = ecKeys("P-384");
  const interDer = certificate({ subject: "Apple App Attestation CA 1", issuer: root.cn, publicKey: inter.publicKey, signingKey: root.privateKey, ca: true });
  const attKey = ecKeys("P-256");
  const j = attKey.publicKey.export({ format: "jwk" });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(j.x, "base64url"), Buffer.from(j.y, "base64url")]);
  const keyId = tamperKeyId ? randomBytes(32) : sha256(point);
  const aaguid = environment === "production" ? Buffer.concat([Buffer.from("appattest"), Buffer.alloc(7)]) : Buffer.from("appattestdevelop");
  const ctr = Buffer.alloc(4); ctr.writeUInt32BE(counter);
  const cl = Buffer.alloc(2); cl.writeUInt16BE(keyId.length);
  const cose = cbor({ 1: 2, 3: -7, "-1": 1, "-2": Buffer.from(j.x, "base64url"), "-3": Buffer.from(j.y, "base64url") });
  const authData = Buffer.concat([sha256(Buffer.from(appId)), Buffer.from([0x40]), ctr, aaguid, cl, keyId, cose]);
  const nonce = sha256(authData, clientDataHash);
  const leafDer = certificate({
    subject: "App Attest key", issuer: "Apple App Attestation CA 1", publicKey: attKey.publicKey, signingKey: inter.privateKey,
    extensions: [extension("1.2.840.113635.100.8.2", seq(explicit(1, octet(nonce))))],
  });
  return cbor({ fmt: "apple-appattest", attStmt: { x5c: [leafDer, interDer], receipt: Buffer.from("receipt") }, authData });
}

/**
 * A Secure Enclave-style liveness key (software here) and its signer. Like the app's
 * native gate it hands over the low-S form (servers refuse the other, ATT-01);
 * signHighS gives the other form of the same signature, for tests of that refusal.
 */
export function liveKey() {
  const k = ecKeys("P-256");
  const raw = (m) => sign("sha256", Buffer.from(m), k.privateKey);
  return { ...k, pub: k.publicKey.export({ type: "spki", format: "der" }), sign: (m) => Buffer.from(lowS(raw(m))), signHighS: (m) => Buffer.from(highS(raw(m))) };
}
/** The high-S form of a DER P-256 signature: (r, n − s) when s is low. */
export function highS(der) {
  const low = lowS(der);
  const { r, s } = ecdsaRS(low);
  const int = (x) => { let h = x.toString(16); if (h.length % 2) h = "0" + h; let b = Buffer.from(h, "hex"); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return Buffer.concat([Buffer.from([2, b.length]), b]); };
  const body = Buffer.concat([int(r), int(P256_N - s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
