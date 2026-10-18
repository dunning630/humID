// What a passport or ID card chip holds, made readable: DG1 (the MRZ, as
// printed), DG2 (the holder's photo) and EF.SOD (the issuing country's signed
// list of hashes of every data group). This module checks that the data
// groups match those hashes, so the stored copy can't have been altered.
// Whether the signature itself chains to the issuing country is the server's
// job (@humid/anchor passive authentication) when the chip anchors a HumID.
import { sha1 } from "@noble/hashes/legacy.js";
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { parseMrz } from "./mrz.js";

/** One BER-TLV: { tag, start, header, length, value, end }. */
export function tlvAt(b, pos = 0) {
  let p = pos;
  let tag = b[p++];
  if ((tag & 0x1f) === 0x1f) { do { tag = (tag << 8) | b[p]; } while (b[p++] & 0x80); }
  let length = b[p++];
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n < 1 || n > 4) throw new Error("bad TLV length");
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + b[p++];
  }
  if (p + length > b.length) throw new Error("TLV runs past the end");
  return { tag: tag >>> 0, start: pos, header: p - pos, length, value: b.subarray(p, p + length), end: p + length };
}
export function tlvChildren(b) {
  const out = [];
  for (let p = 0; p < b.length;) {
    if (b[p] === 0 || b[p] === 0xff) { p++; continue; } // padding
    const t = tlvAt(b, p);
    out.push(t);
    p = t.end;
  }
  return out;
}
const child = (b, tag) => tlvChildren(b).find((t) => t.tag === tag);

/** DG1 → the MRZ text and its parse. */
export function readDg1(dg1) {
  const outer = tlvAt(dg1);
  if (outer.tag !== 0x61) throw new Error("not DG1");
  const mrz = child(outer.value, 0x5f1f);
  if (!mrz) throw new Error("DG1 has no MRZ");
  const text = new TextDecoder("latin1").decode(mrz.value);
  return { text, mrz: parseMrz(text) };
}

const startsWith = (b, i, sig) => sig.every((x, k) => b[i + k] === x);
const JPEG = [0xff, 0xd8, 0xff];
const JP2 = [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20];
const J2K = [0xff, 0x4f, 0xff, 0x51];

/**
 * DG2 → the first face image: { type: "image/jpeg" | "image/jp2", bytes }.
 * The image sits in an ISO 19794-5 record inside the biometric template; this
 * finds where the image itself starts rather than walking every header field.
 */
export function readDg2(dg2) {
  const outer = tlvAt(dg2);
  if (outer.tag !== 0x75) throw new Error("not DG2");
  let data = null;
  const walk = (b) => {
    for (const t of tlvChildren(b)) {
      if (data) return;
      if (t.tag === 0x5f2e || t.tag === 0x7f2e) { data = t.value; return; }
      if (t.tag === 0x7f61 || t.tag === 0x7f60 || t.tag === 0xa1) walk(t.value);
    }
  };
  try { walk(outer.value); } catch { /* fall back to scanning */ }
  const b = data || outer.value;
  for (let i = 0; i < b.length - 8; i++) {
    if (startsWith(b, i, JPEG)) return { type: "image/jpeg", bytes: b.slice(i) };
    if (startsWith(b, i, JP2) || startsWith(b, i, J2K)) return { type: "image/jp2", bytes: b.slice(i) };
  }
  throw new Error("DG2 has no face image");
}

const OID = {
  "1.3.14.3.2.26": ["SHA-1", sha1], "2.16.840.1.101.3.4.2.4": ["SHA-224", sha224], "2.16.840.1.101.3.4.2.1": ["SHA-256", sha256],
  "2.16.840.1.101.3.4.2.2": ["SHA-384", sha384], "2.16.840.1.101.3.4.2.3": ["SHA-512", sha512],
};
function oid(bytes) {
  const out = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) { v = v * 128 + (bytes[i] & 0x7f); if (!(bytes[i] & 0x80)) { out.push(v); v = 0; } }
  return out.join(".");
}

/** EF.SOD → { algorithm, hashes: { [dataGroup]: Uint8Array } } from its LDS security object. */
export function sodHashes(sod) {
  let b = tlvAt(sod);
  if (b.tag === 0x77) b = tlvAt(b.value);                 // EF.SOD wrapper → ContentInfo
  const contentInfo = tlvChildren(b.value);               // [ oid signedData, [0] SignedData ]
  const signedData = tlvAt(contentInfo[1].value);         // SEQUENCE
  const sd = tlvChildren(signedData.value);               // version, digestAlgorithms, encapContentInfo, …
  const encap = tlvChildren(sd[2].value);                 // [ eContentType, [0] eContent ]
  const eContent = tlvAt(encap[1].value);                 // OCTET STRING
  const lds = tlvChildren(tlvAt(eContent.value).value);   // version, hashAlgorithm, dataGroupHashValues
  const alg = oid(tlvChildren(lds[1].value)[0].value);
  const hashes = {};
  for (const g of tlvChildren(lds[2].value)) {
    const [n, h] = tlvChildren(g.value);
    hashes[n.value.reduce((x, y) => x * 256 + y, 0)] = h.value.slice();
  }
  return { algorithm: OID[alg]?.[0] || alg, hashFn: OID[alg]?.[1] || null, hashes };
}

const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Do the data groups we read match the hashes the issuing country signed?
 * groups: { 1: dg1, 2: dg2, 15: dg15, … }. Returns { ok, algorithm, groups: { n: true|false } }.
 */
export function checkIntegrity(sod, groups) {
  const { algorithm, hashFn, hashes } = sodHashes(sod);
  if (!hashFn) return { ok: false, algorithm, groups: {}, reason: "unknown hash algorithm" };
  const result = {};
  for (const [n, bytes] of Object.entries(groups)) {
    if (!bytes) continue;
    result[n] = !!hashes[n] && same(hashFn(bytes), hashes[n]);
  }
  const ok = Object.keys(result).length > 0 && Object.values(result).every(Boolean);
  return { ok, algorithm, groups: result };
}

/**
 * checkIntegrity that never throws: a malformed SOD gives { ok: false, reason: "malformed" }.
 * Callers must treat anything but ok === true as "not checked".
 */
export function safeCheckIntegrity(sod, groups) {
  try { return checkIntegrity(sod, groups); }
  catch { return { ok: false, algorithm: null, groups: {}, reason: "malformed" }; }
}

/**
 * The one fail-closed decision for chip data: true only when the integrity result is
 * exactly { ok: true }. null, undefined, thrown (null), ok:false or a truthy non-boolean
 * all mean "do not apply the chip's data, do not decode its photo".
 * Note this is a hash check against the chip's own SOD, not authenticity: the issuing
 * country's signature (CSCA chain) is not verified on the phone.
 */
export const chipIntegrityOk = (integrity) => integrity?.ok === true;
