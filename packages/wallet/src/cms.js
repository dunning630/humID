// The pass's "signature" file: a detached CMS SignedData over manifest.json.
import { parse, kids, oid, octets, time, ctx, isSeq, isSet, intBytes } from "./der.js";
import { WalletError } from "./zip.js";
import { DIGESTS } from "./x509.js";

const bad = (m) => { throw new WalletError("bad_signature", m || "The pass's signature can't be read."); };
const OID = { signedData: "1.2.840.113549.1.7.2", data: "1.2.840.113549.1.7.1", contentType: "1.2.840.113549.1.9.3", messageDigest: "1.2.840.113549.1.9.4", signingTime: "1.2.840.113549.1.9.5" };

/** → { certs: [DER], signer: { sid, digest, signedAttrs, attrs, sigAlg, signature } } */
export function parseSignature(der) {
  try {
    const ci = kids(parse(der));
    if (oid(ci[0]) !== OID.signedData || !ctx(ci[1], 0)) bad("The pass's signature isn't a CMS signature.");
    const sd = kids(kids(ci[1])[0]);
    // SignedData: version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    const eci = kids(sd[2]);
    if (oid(eci[0]) !== OID.data) bad("The pass's signature signs something else.");
    if (eci.length > 1) bad("The pass's signature must be detached (over manifest.json).");
    let i = 3;
    const certs = [];
    if (ctx(sd[i], 0)) { for (const c of kids(sd[i])) if (isSeq(c)) certs.push(c.raw.slice()); i++; }
    if (ctx(sd[i], 1)) i++;
    if (!isSet(sd[i])) bad();
    const signers = kids(sd[i]);
    if (signers.length !== 1) bad("The pass's signature must have exactly one signer.");
    const si = kids(signers[0]);
    // SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature, [1] unsigned?
    let sid;
    if (isSeq(si[1])) { const [issuer, serial] = kids(si[1]); sid = { issuerRaw: issuer.raw, serial: intBytes(serial) }; }
    else if (ctx(si[1], 0)) sid = { ski: si[1].value };
    else bad();
    const digest = DIGESTS[oid(kids(si[2])[0])];
    if (!digest) bad("The pass's signature uses an unknown hash.");
    let j = 3, signedAttrs = null;
    const attrs = {};
    if (ctx(si[j], 0)) {
      // The signature covers the attributes encoded as a SET (tag 0x31), not as the [0] they're stored with.
      signedAttrs = si[j].raw.slice();
      signedAttrs[0] = 0x31;
      for (const a of kids(si[j])) {
        const [type, values] = kids(a);
        const id = oid(type);
        const v = kids(values);
        if (v.length !== 1) bad();
        if (id === OID.contentType) attrs.contentType = oid(v[0]);
        if (id === OID.messageDigest) attrs.messageDigest = octets(v[0]).slice();
        if (id === OID.signingTime) attrs.signingTime = time(v[0]);
      }
      j++;
    }
    const sigAlg = oid(kids(si[j])[0]);
    const signature = octets(si[j + 1]).slice();
    return { certs, signer: { sid, digest, signedAttrs, attrs, sigAlg, signature } };
  } catch (e) { if (e instanceof WalletError) throw e; bad(); }
}

export const CONTENT_DATA = OID.data;
