// X.509 certificates and signature checks (Web Crypto: the same in the app and in Node).
import { parse, kids, oid, bits, text, time, ctx, isSeq, octets, intBytes } from "./der.js";
import { WalletError } from "./zip.js";

const bad = (m) => { throw new WalletError("bad_signature", m || "A certificate in the pass can't be read."); };

const NAME_OIDS = { "2.5.4.3": "CN", "2.5.4.11": "OU", "2.5.4.10": "O", "2.5.4.6": "C", "0.9.2342.19200300.100.1.1": "UID" };
export const OID = {
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  subjectKeyId: "2.5.29.14",
  passbook: "1.2.840.113635.100.6.1.16", // Apple: "Pass Type ID" signing certificate
  rsa: "1.2.840.113549.1.1.1",
  ec: "1.2.840.10045.2.1",
};

function nameOf(t) {
  const out = {};
  for (const rdn of kids(t)) for (const atv of kids(rdn)) {
    const [k, v] = kids(atv);
    const key = NAME_OIDS[oid(k)];
    if (key && !(key in out)) { try { out[key] = text(v); } catch { /* an odd string type: not one we read */ } }
  }
  return out;
}

/** DER → the fields signature checks need. */
export function parseCert(der) {
  try {
    const cert = parse(der);
    const [tbs, sigAlg, sig] = kids(cert);
    const f = kids(tbs);
    let i = ctx(f[0], 0) ? 1 : 0;
    const serial = intBytes(f[i++]);
    i++; // signature algorithm (inside tbs)
    const issuerT = f[i++];
    const [nb, na] = kids(f[i++]);
    const subjectT = f[i++];
    const spkiT = f[i++];
    const [algSeq] = kids(spkiT);
    const [keyAlg, keyParam] = kids(algSeq);
    const ext = { ca: false, keyUsage: null, passbook: false, ski: null };
    for (; i < f.length; i++) {
      if (!ctx(f[i], 3)) continue;
      for (const e of kids(kids(f[i])[0])) {
        const parts = kids(e);
        const id = oid(parts[0]);
        const val = octets(parts[parts.length - 1]);
        if (id === OID.basicConstraints) { const bc = kids(parse(val)); ext.ca = !!bc[0] && bc[0].tag === 1 && bc[0].value[0] !== 0; }
        if (id === OID.keyUsage) ext.keyUsage = bits(parse(val));
        if (id === OID.passbook) ext.passbook = true;
        if (id === OID.subjectKeyId) ext.ski = octets(parse(val));
      }
    }
    const [sa, sp] = kids(sigAlg);
    return {
      der, tbs: tbs.raw, serial,
      issuerRaw: issuerT.raw, subjectRaw: subjectT.raw, issuer: nameOf(issuerT), subject: nameOf(subjectT),
      notBefore: time(nb), notAfter: time(na),
      spki: spkiT.raw, keyAlg: oid(keyAlg), curve: keyParam && keyParam.tag === 6 ? oid(keyParam) : null,
      sigAlg: oid(sa), sigParams: sp || null, signature: bits(sig), ext,
    };
  } catch (e) { if (e instanceof WalletError) throw e; bad(); }
}

const SIG = {
  "1.2.840.113549.1.1.5": { kind: "rsa", hash: "SHA-1" },
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },
  "1.2.840.113549.1.1.1": { kind: "rsa" },          // rsaEncryption: hash from the digest algorithm
  "1.2.840.10045.4.1": { kind: "ec", hash: "SHA-1" },
  "1.2.840.10045.4.3.2": { kind: "ec", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { kind: "ec", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { kind: "ec", hash: "SHA-512" },
  "1.2.840.10045.2.1": { kind: "ec" },              // id-ecPublicKey: hash from the digest algorithm
};
export const DIGESTS = {
  "1.3.14.3.2.26": "SHA-1", "2.16.840.1.101.3.4.2.1": "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512",
};
const CURVES = { "1.2.840.10045.3.1.7": ["P-256", 32], "1.3.132.0.34": ["P-384", 48], "1.3.132.0.35": ["P-521", 66] };

/** ECDSA's DER (r, s) → the fixed-width r ‖ s Web Crypto wants. */
function rawEcdsa(sigDer, size) {
  const [r, s] = kids(parse(sigDer)).map(intBytes);
  if (r.length > size || s.length > size) bad();
  const out = new Uint8Array(size * 2);
  out.set(r, size - r.length); out.set(s, 2 * size - s.length);
  return out;
}

/**
 * Did the holder of key `pub` (a parsed certificate) sign `data` with algorithm `alg`?
 * digest: the hash to use when the algorithm doesn't name one (CMS "rsaEncryption").
 */
export async function verifyWith(pub, alg, signature, data, digest) {
  const s = SIG[alg];
  const hash = s?.hash || digest;
  if (!s || !hash) return false;
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new WalletError("unsupported", "This device can't check signatures.");
  try {
    if (s.kind === "rsa") {
      if (pub.keyAlg !== OID.rsa) return false;
      const key = await subtle.importKey("spki", pub.spki, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
      return await subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
    }
    const curve = CURVES[pub.curve];
    if (pub.keyAlg !== OID.ec || !curve) return false;
    const key = await subtle.importKey("spki", pub.spki, { name: "ECDSA", namedCurve: curve[0] }, false, ["verify"]);
    return await subtle.verify({ name: "ECDSA", hash }, key, rawEcdsa(signature, curve[1]), data);
  } catch { return false; }
}

/** Was `cert` issued, and signed, by `issuer`? */
export async function issuedBy(cert, issuer) {
  if (cert.issuerRaw.length !== issuer.subjectRaw.length || !cert.issuerRaw.every((v, i) => v === issuer.subjectRaw[i])) return false;
  return verifyWith(issuer, cert.sigAlg, cert.signature, cert.tbs);
}

export const validAt = (cert, t) => cert.notBefore <= t && t <= cert.notAfter;
export { isSeq };
