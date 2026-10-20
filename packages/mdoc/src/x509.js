// Just enough X.509 (DER) to check an mdoc's Document Signer certificate
// against an issuing authority's IACA root, in plain JavaScript so it runs in
// the app as well as on the server. ECDSA only, which is what ISO/IEC 18013-5
// allows for IACA and Document Signer certificates.

import { p256, p384, p521 } from "@noble/curves/nist.js";
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from "@noble/curves/misc.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";

export class X509Error extends Error {}
const fail = (m) => { throw new X509Error(m); };

/* ---------------- DER ---------------- */

export function der(b, pos = 0) {
  if (pos + 2 > b.length) fail("certificate ends early");
  const first = b[pos];
  const cls = first >> 6, constructed = !!(first & 0x20);
  let tag = first & 0x1f, p = pos + 1;
  if (tag === 0x1f) { tag = 0; let c; do { c = b[p++]; tag = tag * 128 + (c & 0x7f); } while (c & 0x80); }
  let len = b[p++];
  if (len & 0x80) {
    const k = len & 0x7f;
    if (k === 0 || k > 4) fail("bad certificate length");
    len = 0;
    for (let i = 0; i < k; i++) len = len * 256 + b[p++];
  }
  if (p + len > b.length) fail("certificate ends early");
  return { cls, constructed, tag, start: pos, hdr: p - pos, len, end: p + len, value: b.subarray(p, p + len), raw: b.subarray(pos, p + len) };
}
export function children(t) {
  const out = [];
  for (let p = 0; p < t.value.length;) { const c = der(t.value, p); out.push(c); p = c.end; }
  return out;
}
export function oidString(v) {
  const parts = [Math.floor(v[0] / 40), v[0] % 40];
  let n = 0;
  for (let i = 1; i < v.length; i++) { n = n * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { parts.push(n); n = 0; } }
  return parts.join(".");
}
function time(t) {
  const s = new TextDecoder().decode(t.value);
  const m = t.tag === 23 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/.exec(s);
  if (!m) fail("bad certificate time");
  let y = +m[1];
  if (t.tag === 23) y += y < 50 ? 2000 : 1900;
  return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
}

const CURVES = {
  "1.2.840.10045.3.1.7": { name: "P-256", curve: p256 },
  "1.3.132.0.34": { name: "P-384", curve: p384 },
  "1.3.132.0.35": { name: "P-521", curve: p521 },
  "1.3.36.3.3.2.8.1.1.7": { name: "brainpoolP256r1", curve: brainpoolP256r1 },
  "1.3.36.3.3.2.8.1.1.11": { name: "brainpoolP384r1", curve: brainpoolP384r1 },
  "1.3.36.3.3.2.8.1.1.13": { name: "brainpoolP512r1", curve: brainpoolP512r1 },
};
const SIG_HASH = { "1.2.840.10045.4.3.2": sha256, "1.2.840.10045.4.3.3": sha384, "1.2.840.10045.4.3.4": sha512 };
const NAMES = { "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.7": "L" };

export const OIDS = {
  ekuMdlDs: "1.0.18013.5.1.2", // id-mdl-kp-mdlDS: may sign mdoc Mobile Security Objects
  basicConstraints: "2.5.29.19", keyUsage: "2.5.29.15", extKeyUsage: "2.5.29.37",
};

function readName(t) {
  const out = {};
  for (const rdn of children(t)) for (const atv of children(rdn)) {
    const [o, v] = children(atv);
    const k = NAMES[oidString(o.value)];
    if (k) out[k] = new TextDecoder().decode(v.value);
  }
  return out;
}

const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Parse a certificate (DER bytes or PEM text). */
export function parseCertificate(input) {
  const bytes = typeof input === "string" ? fromPem(input) : input instanceof Uint8Array ? input : new Uint8Array(input);
  try {
    const cert = der(bytes);
    const [tbs, sigAlg, sig] = children(cert);
    const f = children(tbs);
    let i = 0;
    if (f[0].cls === 2 && f[0].tag === 0) i++; // [0] version
    const serial = f[i++], alg = f[i++], issuer = f[i++], validity = f[i++], subject = f[i++], spki = f[i++];
    const [nb, na] = children(validity);
    const [keyAlg, point] = children(spki);
    const [, curveOid] = children(keyAlg);
    const ext = {};
    for (; i < f.length; i++) {
      if (f[i].cls === 2 && f[i].tag === 3) {
        for (const e of children(children(f[i])[0])) {
          const k = children(e);
          const critical = k.length === 3 && k[1].tag === 1 && k[1].value[0] !== 0;
          ext[oidString(k[0].value)] = { critical, value: k[k.length - 1].value };
        }
      }
    }
    const bc = ext[OIDS.basicConstraints];
    const isCa = !!bc && (() => { const s = der(bc.value); const c = children(s); return c.length > 0 && c[0].tag === 1 && c[0].value[0] !== 0; })();
    const eku = ext[OIDS.extKeyUsage] ? children(der(ext[OIDS.extKeyUsage].value)).map((o) => oidString(o.value)) : [];
    const ku = ext[OIDS.keyUsage] ? der(ext[OIDS.keyUsage].value).value : null;
    const keyCertSign = ku ? !!(ku.length > 1 && ku[1] & 0x04) : null;
    const curveInfo = curveOid && CURVES[oidString(curveOid.value)];
    return {
      der: bytes, tbs: tbs.raw, serial: serial.value, sigAlg: oidString(children(sigAlg)[0].value), signature: sig.value.subarray(1),
      issuerRaw: issuer.raw, subjectRaw: subject.raw, issuer: readName(issuer), subject: readName(subject),
      notBefore: time(nb), notAfter: time(na),
      curve: curveInfo?.name || null, publicKey: point.value.subarray(1), isCa, eku, keyCertSign, extensions: ext,
      _curve: curveInfo?.curve || null,
    };
  } catch (e) {
    if (e instanceof X509Error) throw e;
    fail("certificate can't be read");
  }
}

export function fromPem(text) {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(text);
  if (!m) fail("not a PEM certificate");
  let s;
  try { s = atob(m[1].replace(/\s+/g, "")); } catch { fail("not a PEM certificate"); }
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

/** All certificates in PEM text (a bundle), or one DER. */
export function readCertificates(input) {
  if (typeof input !== "string") return [parseCertificate(input)];
  return (input.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map(parseCertificate);
}

/** ECDSA-Sig-Value (DER SEQUENCE r, s) → r ‖ s. */
export function derSigToCompact(sig, size) {
  const [r, s] = children(der(sig));
  const fix = (v) => { let x = v.value; while (x.length > size && x[0] === 0) x = x.subarray(1); if (x.length > size) fail("bad signature"); const o = new Uint8Array(size); o.set(x, size - x.length); return o; };
  const out = new Uint8Array(size * 2);
  out.set(fix(r), 0); out.set(fix(s), size);
  return out;
}

/** Does `ca`'s key sign `cert`? */
export function issuedBy(cert, ca) {
  if (!same(cert.issuerRaw, ca.subjectRaw)) return false;
  const hash = SIG_HASH[cert.sigAlg];
  if (!hash || !ca._curve) return false;
  try {
    const size = ca._curve.lengths?.secretKey || Math.ceil(ca._curve.Point.Fn.BITS / 8);
    return ca._curve.verify(derSigToCompact(cert.signature, size), hash(cert.tbs), ca.publicKey, { prehash: false, lowS: false });
  } catch { return false; }
}

export const curveOf = (cert) => cert._curve;
