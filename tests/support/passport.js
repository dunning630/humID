// Test passports: ICAO 9303-shaped chip data (DG1, DG15, EF.SOD) signed by a
// throwaway country signing CA, plus an Active Authentication "chip" that
// answers challenges. For tests and the local dev server only.
import { generateKeyPairSync, sign, createHash, privateEncrypt, constants, randomBytes } from "node:crypto";
import { seq, set, octet, int, oid, explicit, name, certificate, ecKeys, pem, extension, keyUsage } from "./pki.js";
import { checkDigit } from "../../packages/anchor/src/mrz.js";

const len = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255]);
const tlv = (tag, content) => Buffer.concat([Buffer.from(tag), Buffer.from(len(content.length)), Buffer.from(content)]);
const sha = (alg, ...p) => { const h = createHash(alg); for (const x of p) h.update(x); return h.digest(); };

const OIDS = { sha256: "2.16.840.1.101.3.4.2.1", sha1: "1.3.14.3.2.26", ecdsaSha256: "1.2.840.10045.4.3.2", rsa: "1.2.840.113549.1.1.1", sha256Rsa: "1.2.840.113549.1.1.11", pss: "1.2.840.113549.1.1.10" };

/**
 * A country signing CA (self-signed). country: the alpha-2 code in its name; "UT" is
 * ICAO's specimen country, Utopia, which test MRZs (issuer "UTO") come from.
 */
export function testCsca(cn = "HumID Test CSCA", country = "UT") {
  const k = ecKeys("P-384");
  const nm = { cn, country };
  const der = certificate({ subject: nm, issuer: nm, publicKey: k.publicKey, signingKey: k.privateKey, ca: true, extensions: [extension("2.5.29.15", keyUsage(5, 6), true)], notAfter: new Date(Date.now() + 10 * 365 * 86400e3) });
  return { ...k, der, pem: pem(der), cn, country, name: nm };
}

const pad = (s, n) => (s + "<".repeat(n)).slice(0, n);
const field = (s, n) => pad(String(s).toUpperCase().replace(/[^A-Z0-9]+/g, "<"), n);

/** A TD3 (passport) MRZ with correct check digits. Dates are YYMMDD. */
export function td3({ issuer = "UTO", surname = "ERIKSSON", given = "ANNA MARIA", number = "L898902C3", nationality = "UTO", birth = "740812", sex = "F", expiry = "341231" } = {}) {
  const l1 = pad(`P<${field(issuer, 3)}${field(surname, 39).replace(/<+$/, "")}<<${field(given, 39)}`, 44);
  const num = field(number, 9);
  const head = `${num}${checkDigit(num)}${field(nationality, 3)}${birth}${checkDigit(birth)}${sex}${expiry}${checkDigit(expiry)}`;
  const personal = "<".repeat(14);
  const composite = `${num}${checkDigit(num)}${birth}${checkDigit(birth)}${expiry}${checkDigit(expiry)}${personal}${checkDigit(personal)}`;
  const l2 = `${head}${personal}${checkDigit(personal)}${checkDigit(composite)}`;
  return l1 + l2;
}

/**
 * A chip. dsKind: "ec" | "rsa" | "pss" (how the document signer signs the SOD).
 * aaKind: "rsa" | "ec" | null (Active Authentication key in DG15, or none).
 * photo: a JPEG or JPEG 2000 image for DG2 (the holder's face), or null for none.
 * Returns { dg1, dg2, dg15, sod, mrz, answer(nonce) } — answer() is the chip signing a challenge.
 */
export function testPassport({ csca, mrz = {}, dsKind = "ec", aaKind = "rsa", tamper = null, photo = null, ds: dsOpts = {} } = {}) {
  const text = typeof mrz === "string" ? mrz : td3(mrz);
  const dg1 = tlv([0x61], tlv([0x5f, 0x1f], Buffer.from(text, "latin1")));
  const dg2 = photo ? faceGroup(photo) : null;

  let aa = null, dg15 = null;
  if (aaKind === "rsa") aa = generateKeyPairSync("rsa", { modulusLength: 1024 });
  if (aaKind === "ec") aa = ecKeys("P-256");
  if (aa) dg15 = tlv([0x6f], aa.publicKey.export({ type: "spki", format: "der" }));

  const ds = dsKind === "ec" ? ecKeys("P-256") : generateKeyPairSync("rsa", { modulusLength: 2048 });
  // The document signer: ds.country, ds.keyUsage (false = none), ds.ca, ds.sid ("ski" | "wrong") vary it for tests.
  const dsSerial = 4000 + Math.floor(Math.random() * 1e6);
  const dsName = { cn: "HumID Test Document Signer", country: dsOpts.country ?? csca.country };
  const dsExts = [
    ...(dsOpts.keyUsage === false ? [] : [extension("2.5.29.15", keyUsage(0), true)]),
    extension("2.5.29.14", octet(Buffer.from("0123456789abcdef0123", "latin1"))),
  ];
  const dsDer = certificate({ subject: dsName, issuer: csca.name || csca.cn, publicKey: ds.publicKey, signingKey: csca.privateKey, serialNumber: dsSerial, extensions: dsExts, ca: !!dsOpts.ca });

  const hashes = [[1, dg1], ...(dg2 ? [[2, dg2]] : []), ...(dg15 ? [[15, dg15]] : [])]
    .map(([n, b]) => seq(int(n), octet(sha("sha256", (tamper === "dg1" && n === 1) || (tamper === "dg2" && n === 2) ? Buffer.from("x") : b))));
  const lds = seq(int(0), seq(oid(OIDS.sha256)), seq(...hashes));
  const attrs = [
    ...(tamper === "contentType" ? [] : [seq(oid("1.2.840.113549.1.9.3"), set(oid("2.23.136.1.1.1")))]),
    seq(oid("1.2.840.113549.1.9.4"), set(octet(sha("sha256", lds)))),
  ].sort(Buffer.compare);
  const attrsSet = set(...attrs);
  let sigAlg, signature;
  if (dsKind === "ec") { sigAlg = seq(oid(OIDS.ecdsaSha256)); signature = sign("sha256", attrsSet, ds.privateKey); }
  else if (dsKind === "rsa") { sigAlg = seq(oid(OIDS.sha256Rsa), Buffer.from([0x05, 0])); signature = sign("sha256", attrsSet, ds.privateKey); }
  else {
    const params = seq(explicit(0, seq(oid(OIDS.sha256))), explicit(1, seq(oid("1.2.840.113549.1.1.8"), seq(oid(OIDS.sha256)))), explicit(2, int(32)));
    sigAlg = seq(oid(OIDS.pss), params);
    signature = sign("sha256", attrsSet, { key: ds.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
  }
  if (tamper === "signature") signature = Buffer.from(signature).fill(1, 10, 20);
  const sid = dsOpts.sid === "ski" ? explicit(0, Buffer.from("0123456789abcdef0123", "latin1")).fill(0x80, 0, 1)
    : seq(name(csca.name || csca.cn), int(dsOpts.sid === "wrong" ? dsSerial + 1 : dsSerial));
  const signerInfo = seq(int(dsOpts.sid === "ski" ? 3 : 1), sid, seq(oid(OIDS.sha256)), explicit(0, Buffer.concat(attrs)), sigAlg, octet(signature));
  const signedData = seq(int(3), set(seq(oid(OIDS.sha256))), seq(oid("2.23.136.1.1.1"), explicit(0, octet(lds))), explicit(0, dsDer), set(signerInfo));
  const sod = tlv([0x77], seq(oid("1.2.840.113549.1.7.2"), explicit(0, signedData)));

  /** The chip answers an Active Authentication challenge. */
  function answer(nonce) {
    if (!aa) return null;
    if (aaKind === "ec") return sign("sha256", Buffer.from(nonce), { key: aa.privateKey, dsaEncoding: "ieee-p1363" });
    const k = aa.publicKey.export({ format: "jwk" });
    const kLen = Buffer.from(k.n, "base64url").length;
    const m1 = randomBytes(kLen - 1 - 20 - 1);
    const f = Buffer.concat([Buffer.from([0x6a]), m1, sha("sha1", m1, Buffer.from(nonce)), Buffer.from([0xbc])]);
    return privateEncrypt({ key: aa.privateKey, padding: constants.RSA_NO_PADDING }, f);
  }

  return { dg1, dg2, dg15, sod, mrz: text, answer };
}

/** DG2: one face in a biometric information template, image in an ISO 19794-5 record. */
function faceGroup(image) {
  const img = Buffer.from(image);
  const u32 = (n) => Buffer.from([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const facial = Buffer.concat([u32(20 + 12 + img.length), Buffer.from([0, 0]), Buffer.alloc(14)]); // face block length, no landmarks, defaults
  const imageInfo = Buffer.from([1, 0, 0, 240, 0, 1, 44, 1, 0, 0, 0, 0]); // full frontal, 240 × 300 (approx), colour
  const header = Buffer.concat([Buffer.from([0x46, 0x41, 0x43, 0, 0x30, 0x31, 0x30, 0]), u32(14 + facial.length + imageInfo.length + img.length), Buffer.from([0, 1])]);
  const record = Buffer.concat([header, facial, imageInfo, img]);
  const bht = tlv([0xa1], Buffer.concat([tlv([0x80], Buffer.from([1, 1])), tlv([0x87], Buffer.from([1, 1])), tlv([0x88], Buffer.from([0, 8]))]));
  const template = tlv([0x7f, 0x61], Buffer.concat([tlv([0x02], Buffer.from([1])), tlv([0x7f, 0x60], Buffer.concat([bht, tlv([0x5f, 0x2e], record)]))]));
  return tlv([0x75], template);
}
