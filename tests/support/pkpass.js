// Test Wallet passes: a throwaway root standing in for Apple's, a "WWDR" intermediate,
// a Pass Type ID signing certificate (Apple's extension, UID = pass type, OU = team),
// and .pkpass files signed with it — or broken in one particular way. Tests only.
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { deflateRawSync, crc32 } from "node:zlib";
import { seq, set, octet, int, oid, explicit, name, certificate, ecKeys, extension, keyUsage, nul } from "./pki.js";

const sha = (alg, b) => createHash(alg).update(b).digest();
const utc = (d) => { const s = d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"; return Buffer.concat([Buffer.from([0x17, s.length]), Buffer.from(s)]); };

/** A root, an intermediate, and a pass signer. signer: { passType, team, org, passbook, ca, rsa, notAfter } */
export function passChain({ passType = "pass.com.example.ticket", team = "TEAM123456", org = "Example Events", passbook = true, signerCa = false, interCa = true, rsa = true, signerNotAfter, signerNotBefore } = {}) {
  const root = ecKeys("P-384");
  const rootName = { cn: "Test Root CA", o: "Test Root", country: "US" };
  const since = new Date("2015-01-01");
  const rootDer = certificate({ subject: rootName, issuer: rootName, publicKey: root.publicKey, signingKey: root.privateKey, ca: true, notBefore: since, extensions: [extension("2.5.29.15", keyUsage(5, 6), true)], notAfter: new Date(Date.now() + 10 * 365 * 86400e3) });
  const inter = ecKeys("P-384");
  const interName = { cn: "Test Worldwide Developer Relations Certification Authority", ou: "G4", o: "Test Root", country: "US" };
  const interDer = certificate({ subject: interName, issuer: rootName, publicKey: inter.publicKey, signingKey: root.privateKey, ca: interCa, notBefore: since, extensions: [extension("2.5.29.15", keyUsage(5, 6), true)], notAfter: new Date(Date.now() + 5 * 365 * 86400e3) });
  const key = rsa ? generateKeyPairSync("rsa", { modulusLength: 2048 }) : ecKeys("P-256");
  const signerName = { uid: passType, cn: `Pass Type ID: ${passType}`, ou: team, o: org, country: "US" };
  const serialNumber = 70000 + Math.floor(Math.random() * 1e6);
  const signerDer = certificate({
    subject: signerName, issuer: interName, publicKey: key.publicKey, signingKey: inter.privateKey, serialNumber, ca: signerCa,
    extensions: [extension("2.5.29.15", keyUsage(0), true), ...(passbook ? [extension("1.2.840.113635.100.6.1.16", nul())] : [])],
    ...(signerNotAfter ? { notAfter: signerNotAfter } : {}), ...(signerNotBefore ? { notBefore: signerNotBefore } : {}),
  });
  return { root: { der: new Uint8Array(rootDer), name: "Test Root CA" }, rootDer, interDer, signerDer, key, rsa, interName, serialNumber };
}

/** A detached CMS signature over `content`, by the chain's signer. */
export function cmsSign(content, chain, { digest = "sha256", certs, signingTime = new Date(), tamperDigest = false, noAttrs = false } = {}) {
  const dOid = { sha1: "1.3.14.3.2.26", sha256: "2.16.840.1.101.3.4.2.1" }[digest];
  const md = sha(digest, content);
  if (tamperDigest) md[0] ^= 1;
  const attrs = [
    seq(oid("1.2.840.113549.1.9.3"), set(oid("1.2.840.113549.1.7.1"))),
    seq(oid("1.2.840.113549.1.9.5"), set(utc(signingTime))),
    seq(oid("1.2.840.113549.1.9.4"), set(octet(md))),
  ].sort(Buffer.compare);
  const attrsSet = set(...attrs);
  const signed = noAttrs ? Buffer.from(content) : attrsSet;
  // rsaEncryption / id-ecPublicKey: the hash is the digest algorithm's, as Apple's signpass writes it
  const sigAlg = chain.rsa ? seq(oid("1.2.840.113549.1.1.1"), nul()) : seq(oid("1.2.840.10045.2.1"));
  const signature = chain.rsa ? sign(digest, signed, chain.key.privateKey) : sign(digest, signed, chain.key.privateKey);
  const signerInfo = seq(int(1), seq(name(chain.interName), int(chain.serialNumber)), seq(oid(dOid)), ...(noAttrs ? [] : [explicit(0, Buffer.concat(attrs))]), sigAlg, octet(signature));
  const included = certs || [chain.signerDer, chain.interDer];
  const sd = seq(int(1), set(seq(oid(dOid))), seq(oid("1.2.840.113549.1.7.1")), explicit(0, Buffer.concat(included.map(Buffer.from))), set(signerInfo));
  return seq(oid("1.2.840.113549.1.7.2"), explicit(0, sd));
}

/** A zip archive; entries: [[name, bytes, { store, crc, size }]] */
export function zip(entries) {
  const locals = [], centrals = [];
  let off = 0;
  for (const [nameStr, raw, o = {}] of entries) {
    const n = Buffer.from(nameStr);
    const data = Buffer.from(raw);
    const body = o.store ? data : deflateRawSync(data);
    const crc = o.crc ?? crc32(data);
    const usize = o.size ?? data.length;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(o.flags || 0, 6); lh.writeUInt16LE(o.store ? 0 : 8, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(usize, 22); lh.writeUInt16LE(n.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(o.flags || 0, 8); ch.writeUInt16LE(o.store ? 0 : 8, 10);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(usize, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, n, body); centrals.push(ch, n);
    off += 30 + n.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return new Uint8Array(Buffer.concat([...locals, cd, end]));
}

const PNG = Buffer.from("89504e470d0a1a0a0000000d4948445200000001000000010806000000" + "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082", "hex");

export function passJson(over = {}, chain = {}) {
  return {
    formatVersion: 1, passTypeIdentifier: "pass.com.example.ticket", teamIdentifier: "TEAM123456", serialNumber: "E-1001",
    organizationName: "Example Events", description: "Concert ticket", logoText: "Example Events",
    foregroundColor: "rgb(255, 255, 255)", backgroundColor: "rgb(20, 40, 80)",
    relevantDate: "2026-12-04T19:30-06:00",
    eventTicket: {
      primaryFields: [{ key: "event", label: "EVENT", value: "The Specimen Tour" }],
      secondaryFields: [{ key: "loc", label: "VENUE", value: "Fox Valley Arena" }],
      auxiliaryFields: [{ key: "seat", label: "SEAT", value: "A-12" }],
      backFields: [{ key: "terms", label: "Terms", value: "Non-transferable. Visit https://example.com/terms" }],
    },
    barcodes: [{ format: "PKBarcodeFormatQR", message: "TICKET-E-1001-SECRET", messageEncoding: "iso-8859-1", altText: "E-1001" }],
    ...over,
  };
}

/**
 * A signed .pkpass. Options break it one way at a time:
 *   pass        pass.json (object) · files: extra { name: bytes } · digest: "sha1" | "sha256"
 *   change      { name: bytes } — swapped in after signing
 *   extra       { name: bytes } — added after signing (not in the manifest)
 *   drop        a file name to leave out after signing
 *   manifest    a function to edit the manifest before signing
 *   cms         options for cmsSign
 */
export function makePass(chain, { pass = passJson(), files = {}, digest = "sha1", change = {}, extra = {}, drop = null, manifest: editManifest, cms = {}, noSignature = false } = {}) {
  const content = { "pass.json": Buffer.from(JSON.stringify(pass)), "icon.png": PNG, "icon@2x.png": PNG, "logo.png": PNG, ...files };
  const manifest = {};
  for (const [n, b] of Object.entries(content)) manifest[n] = sha(digest, b).toString("hex");
  editManifest?.(manifest);
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const signature = cmsSign(manifestBytes, chain, { digest, ...cms });
  const all = { ...content, ...change, ...extra, "manifest.json": manifestBytes, ...(noSignature ? {} : { signature }) };
  if (drop) delete all[drop];
  return zip(Object.entries(all).map(([n, b]) => [n, b]));
}
