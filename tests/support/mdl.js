// A simulated mobile ID ecosystem for tests: an issuing authority (IACA root
// and Document Signer), the mDL it issues, and the holder's wallet answering
// a reader over an ISO 18013-5 session. The wallet's cryptography uses
// node:crypto (not @humid/mdoc's code) so the two sides check each other.
// Specimen data only: a fictional person.

import { generateKeyPairSync, createECDH, createHash, createHmac, hkdfSync, createCipheriv, createDecipheriv, sign, randomBytes } from "node:crypto";
import { encode, decode, get, Encoded, Tagged } from "@humid/mdoc";
import { seq, set, oid, int, explicit, extension, bool } from "./pki.js";

const len = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]);
const tlv = (tag, c) => Buffer.concat([Buffer.from([tag]), Buffer.from(len(c.length)), Buffer.from(c)]);
const utcTime = (d) => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
const bitString = (b) => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));

/** A distinguished name with country, state and common name. */
export const dn = ({ C, ST, CN }) => seq(
  ...(C ? [set(seq(oid("2.5.4.6"), tlv(0x13, Buffer.from(C))))] : []),
  ...(ST ? [set(seq(oid("2.5.4.8"), tlv(0x0c, Buffer.from(ST))))] : []),
  set(seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from(CN)))),
);

let serial = 5000;
function cert({ subject, issuer, publicKey, signingKey, ca = false, eku, notBefore, notAfter }) {
  const alg = seq(oid("1.2.840.10045.4.3.2"));
  const exts = [];
  if (ca) exts.push(extension("2.5.29.19", seq(bool(true)), true), extension("2.5.29.15", tlv(0x03, Buffer.from([1, 0x06])), true));
  else exts.push(extension("2.5.29.15", tlv(0x03, Buffer.from([7, 0x80])), true));
  if (eku) exts.push(extension("2.5.29.37", seq(...eku.map(oid)), true));
  const tbs = seq(explicit(0, int(2)), int(serial++), alg, dn(issuer), seq(utcTime(notBefore), utcTime(notAfter)), dn(subject),
    publicKey.export({ type: "spki", format: "der" }), explicit(3, seq(...exts)));
  return seq(tbs, alg, bitString(sign("sha256", tbs, signingKey)));
}

export const pem = (der) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
const day = 86400e3;
const ec = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
const point = (pub) => { const j = pub.export({ format: "jwk" }); return Buffer.concat([Buffer.from([4]), Buffer.from(j.x, "base64url"), Buffer.from(j.y, "base64url")]); };
const coseKey = (pub) => { const j = pub.export({ format: "jwk" }); return new Map([[1, 2], [-1, 1], [-2, Buffer.from(j.x, "base64url")], [-3, Buffer.from(j.y, "base64url")]]); };
const u8 = (b) => new Uint8Array(b);
const sha256 = (b) => createHash("sha256").update(b).digest();

/** An issuing authority: IACA root + Document Signer. */
export function issuingAuthority({ C = "US", ST = "UT", name = "Utopia DMV", dsEku = ["1.0.18013.5.1.2"], dsValidity, dsSubject } = {}) {
  const root = ec(), ds = ec();
  const now = Date.now();
  const rootSubject = { C, ST, CN: `${name} IACA Root (TEST)` };
  const rootDer = cert({ subject: rootSubject, issuer: rootSubject, publicKey: root.publicKey, signingKey: root.privateKey, ca: true, notBefore: new Date(now - 30 * day), notAfter: new Date(now + 3650 * day) });
  const dsDer = cert({
    subject: dsSubject || { C, ST, CN: `${name} Document Signer (TEST)` }, issuer: rootSubject, publicKey: ds.publicKey, signingKey: root.privateKey, eku: dsEku,
    notBefore: dsValidity?.from || new Date(now - 10 * day), notAfter: dsValidity?.until || new Date(now + 365 * day),
  });
  return { root, ds, rootDer: u8(rootDer), dsDer: u8(dsDer), rootPem: pem(rootDer), C, ST };
}

const fullDate = (s) => new Tagged(1004, s);
const tdate = (d) => new Tagged(0, d.toISOString().replace(/\.\d{3}Z$/, "Z"));

/** Specimen mDL data (fictional person) for the authority's state. */
export function specimenMdl({ C = "US", ST = "UT", portrait = Buffer.from("ffd8ffe000104a464946000101", "hex") } = {}) {
  return {
    "org.iso.18013.5.1": {
      family_name: "SPECIMEN", given_name: "JANE QUINN", birth_date: fullDate("1990-04-21"), issue_date: fullDate("2024-02-01"),
      expiry_date: fullDate("2032-04-21"), issuing_country: C, issuing_authority: `${ST} Department of Motor Vehicles`,
      issuing_jurisdiction: `${C}-${ST}`, document_number: "D1234567", portrait: u8(portrait),
      driving_privileges: [new Map([["vehicle_category_code", "C"], ["issue_date", fullDate("2024-02-01")], ["expiry_date", fullDate("2032-04-21")]])],
      sex: 2, height: 168, weight: 61, eye_colour: "brown", hair_colour: "black",
      resident_address: "123 MAIN ST", resident_city: "SPRINGFIELD", resident_state: ST, resident_postal_code: "62701", resident_country: C,
      un_distinguishing_sign: "USA", age_over_18: true, age_over_21: true,
    },
    "org.iso.18013.5.1.aamva": {
      DHS_compliance: "F", organ_donor: 1, veteran: 1, name_suffix: "JR",
      domestic_driving_privileges: [new Map([
        ["domestic_vehicle_class", new Map([["domestic_vehicle_class_code", "D"], ["domestic_vehicle_class_description", "Operator"]])],
        ["domestic_vehicle_restrictions", [new Map([["domestic_vehicle_restriction_code", "B"], ["domestic_vehicle_restriction_description", "Corrective lenses"]])]],
        ["domestic_vehicle_endorsements", [new Map([["domestic_vehicle_endorsement_code", "M"], ["domestic_vehicle_endorsement_description", "Motorcycle"]])]],
      ])],
      family_name_truncation: "N", given_name_truncation: "N",
    },
  };
}

/** COSE_Sign1 with node:crypto ECDSA P-256 / SHA-256. */
function coseSign1(payload, privateKey, { unprotected = new Map(), detached = false } = {}) {
  const prot = encode(new Map([[1, -7]]));
  const tbs = encode(["Signature1", prot, new Uint8Array(0), payload]);
  const sig = sign("sha256", tbs, { key: privateKey, dsaEncoding: "ieee-p1363" });
  return [prot, unprotected, detached ? null : payload, u8(sig)];
}

/**
 * The issuer's IssuerSigned for `data` ({ ns: { element: value } }), bound to the wallet's device key.
 * tamper: "value" (change a value after signing), "signature", "digest".
 */
export function issue(authority, data, deviceKey, { docType = "org.iso.18013.5.1.mDL", validFrom = new Date(Date.now() - day), validUntil = new Date(Date.now() + 90 * day), signed = new Date(Date.now() - day), tamper } = {}) {
  let id = 0;
  const nameSpaces = new Map();
  const valueDigests = new Map();
  for (const [ns, elements] of Object.entries(data)) {
    const items = [], digests = new Map();
    for (const [name, value] of Object.entries(elements)) {
      const item = Encoded.of(new Map([["digestID", id], ["random", u8(randomBytes(16))], ["elementIdentifier", name], ["elementValue", value]]));
      digests.set(id, u8(sha256(item.encoded)));
      items.push(item);
      id++;
    }
    nameSpaces.set(ns, items);
    valueDigests.set(ns, digests);
  }
  const mso = new Map([
    ["version", "1.0"], ["digestAlgorithm", "SHA-256"], ["valueDigests", valueDigests],
    ["deviceKeyInfo", new Map([["deviceKey", coseKey(deviceKey)]])], ["docType", docType],
    ["validityInfo", new Map([["signed", tdate(signed)], ["validFrom", tdate(validFrom)], ["validUntil", tdate(validUntil)]])],
  ]);
  const payload = Encoded.of(mso).encoded;
  const issuerAuth = coseSign1(payload, authority.ds.privateKey, { unprotected: new Map([[33, authority.dsDer]]) });
  if (tamper === "signature") issuerAuth[3][5] ^= 1;
  if (tamper === "value") {
    const [ns, items] = [...nameSpaces][0];
    const v = items[0].value;
    v.set("elementValue", "FORGED");
    items[0] = Encoded.of(v);
    nameSpaces.set(ns, items);
  }
  return new Map([["nameSpaces", nameSpaces], ["issuerAuth", issuerAuth]]);
}

const ivFor = (who, n) => { const iv = Buffer.alloc(12); if (who === "device") iv[7] = 1; iv.writeUInt32BE(n, 8); return iv; };
const gcmEnc = (key, iv, data) => { const c = createCipheriv("aes-256-gcm", key, iv); const out = Buffer.concat([c.update(data), c.final(), c.getAuthTag()]); return u8(out); };
const gcmDec = (key, iv, data) => { const d = createDecipheriv("aes-256-gcm", key, iv); d.setAuthTag(Buffer.from(data.subarray(data.length - 16))); return Buffer.concat([d.update(Buffer.from(data.subarray(0, data.length - 16))), d.final()]); };
const hkdf = (z, transcriptBytes, info) => Buffer.from(hkdfSync("sha256", z, sha256(transcriptBytes), Buffer.from(info), 32));
const ecdh = (privateKey, pubPoint) => { const e = createECDH("prime256v1"); e.setPrivateKey(Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url")); return e.computeSecret(Buffer.from(pubPoint)); };

/**
 * The holder's wallet with one document. `respond` plays the wallet's side
 * of a session: engagement QR, then the encrypted response.
 * mode: "signature" | "mac" | "none" (skip device auth) ; cloneKey: sign with a different key (copied data).
 */
export function wallet({ authority = issuingAuthority(), data, docType = "org.iso.18013.5.1.mDL", issueOptions = {} } = {}) {
  const device = ec();
  const issuerSigned = issue(authority, data || specimenMdl({ C: authority.C, ST: authority.ST }), device.publicKey, { docType, ...issueOptions });
  let session = null;

  function engagement() {
    const eDevice = ec();
    const de = encode(new Map([
      [0, "1.0"], [1, [1, Encoded.of(coseKey(eDevice.publicKey))]],
      [2, [[2, 1, new Map([[0, false], [1, true], [11, u8(randomBytes(16))]])]]],
    ]));
    session = { eDevice, deBytes: de };
    return { qr: "mdoc:" + Buffer.from(de).toString("base64url"), bytes: de };
  }

  function respond(establishment, { mode = "signature", cloneKey = false, only, omitDeviceAuth = false } = {}) {
    const m = decode(establishment);
    const eReaderKeyBytes = get(m, "eReaderKey");
    const ek = eReaderKeyBytes.value;
    const readerPoint = Buffer.concat([Buffer.from([4]), Buffer.from(get(ek, -2)), Buffer.from(get(ek, -3))]);
    const transcript = [new Encoded(session.deBytes), eReaderKeyBytes, null];
    const transcriptBytes = Encoded.of(transcript).encoded;
    const z = ecdh(session.eDevice.privateKey, readerPoint);
    const skReader = hkdf(z, transcriptBytes, "SKReader"), skDevice = hkdf(z, transcriptBytes, "SKDevice");
    const request = decode(gcmDec(skReader, ivFor("reader", 1), get(m, "data")));
    const asked = get(get(request, "docRequests")[0], "itemsRequest").value;
    const wantNs = get(asked, "nameSpaces");

    // Share only what was asked for (and, for tests, optionally less).
    const nameSpaces = new Map();
    for (const [ns, items] of get(issuerSigned, "nameSpaces")) {
      const want = get(wantNs, ns);
      if (!want) continue;
      const keep = items.filter((it) => { const n = get(it.value, "elementIdentifier"); return want.has(n) && (!only || only.includes(n)); });
      if (keep.length) nameSpaces.set(ns, keep);
    }
    const devNs = Encoded.of(new Map());
    const daBytes = Encoded.of(["DeviceAuthentication", transcript, docType, devNs]).encoded;
    const key = cloneKey ? ec().privateKey : device.privateKey;
    let deviceAuth;
    if (mode === "mac") {
      const ek2 = ecdh(key, readerPoint);
      const macKey = hkdf(ek2, transcriptBytes, "EMacKey");
      const prot = encode(new Map([[1, 5]]));
      const tag = createHmac("sha256", macKey).update(encode(["MAC0", prot, new Uint8Array(0), daBytes])).digest();
      deviceAuth = new Map([["deviceMac", [prot, new Map(), null, u8(tag)]]]);
    } else deviceAuth = new Map([["deviceSignature", coseSign1(daBytes, key, { detached: true })]]);
    const doc = new Map([
      ["docType", docType],
      ["issuerSigned", new Map([["nameSpaces", nameSpaces], ["issuerAuth", get(issuerSigned, "issuerAuth")]])],
      ["deviceSigned", new Map([["nameSpaces", devNs], ...(omitDeviceAuth ? [] : [["deviceAuth", deviceAuth]])])],
    ]);
    const response = encode(new Map([["version", "1.0"], ["documents", [doc]], ["status", 0]]));
    return encode(new Map([["data", gcmEnc(skDevice, ivFor("device", 1), response)]]));
  }

  return { device, issuerSigned, engagement, respond, authority, point: point(device.publicKey) };
}
