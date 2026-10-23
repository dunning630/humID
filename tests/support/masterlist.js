// A signed ICAO-style CSCA master list for tests (CMS SignedData, eContentType
// 2.23.136.1.1.2), signed by a Master List Signer under the publisher's CSCA.
import { createHash, sign as nodeSign } from "node:crypto";
import { seq, set, octet, int, oid, explicit, certificate, ecKeys, extension, keyUsage, name as nameOf } from "./pki.js";

const utcTime = (d) => Buffer.concat([Buffer.from([0x17, 13]), Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z")]);

/** A CSCA master list (CMS SignedData, eContentType 2.23.136.1.1.2) signed by the publisher's ML signer. */
// signingTime: the signed CMS signing-time attribute (ICAO requires one); null leaves it out.
export function masterList({ publisher, cscas, tamper, eku = true, sha1 = false, signingTime = new Date() }) {
  const signer = ecKeys("P-256");
  const signerDer = certificate({ subject: { cn: "Test Master List Signer", country: publisher.country }, issuer: publisher.name, publicKey: signer.publicKey, signingKey: publisher.privateKey, serialNumber: 777, extensions: [extension("2.5.29.15", keyUsage(0), true), ...(eku ? [extension("2.5.29.37", seq(oid("2.23.136.1.1.3")))] : [])] });
  const content = seq(int(0), set(...cscas.map((c) => c.der)));
  const attrs = set(...[
    seq(oid("1.2.840.113549.1.9.3"), set(oid("2.23.136.1.1.2"))),
    seq(oid("1.2.840.113549.1.9.4"), set(octet(createHash("sha256").update(content).digest()))),
    ...(signingTime ? [seq(oid("1.2.840.113549.1.9.5"), set(utcTime(signingTime)))] : []),
  ].sort(Buffer.compare));
  const sig = nodeSign(sha1 ? "sha1" : "sha256", attrs, signer.privateKey);
  // SignerIdentifier: issuerAndSerialNumber of the signer certificate.
  const sid = seq(nameOf(publisher.name), int(777));
  const signedAttrs = Buffer.concat([Buffer.from([0xa0]), attrs.subarray(1)]);
  const si = seq(int(1), sid, seq(oid("2.16.840.1.101.3.4.2.1")), signedAttrs, seq(oid(sha1 ? "1.2.840.10045.4.1" : "1.2.840.10045.4.3.2")), octet(sig));
  const eContent = tamper ? seq(int(0), set(cscas[0].der)) : content;
  const sd = seq(int(3), set(seq(oid("2.16.840.1.101.3.4.2.1"))), seq(oid("2.23.136.1.1.2"), explicit(0, octet(eContent))), explicit(0, signerDer), set(si));
  return seq(oid("1.2.840.113549.1.7.2"), explicit(0, sd));
}

