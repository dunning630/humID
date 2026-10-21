// Re-checking a mobile ID kept in the vault (precert finding APP-05). A vault
// record is JSON, so its `verified` flags prove nothing by themselves. This
// re-runs the issuer check over the IssuerSigned bytes the record kept, and
// confirms every field the record says came from the mobile ID still matches
// what the issuer signed. Pass the result to provenance(rec, { mdoc }).
//
// The wallet's device signature can't be repeated (that session is over), so
// "the wallet proved it holds the original" stays a statement about the read;
// what this re-proves is that the issuer signed exactly these details.

import { decode, get, parse1, Encoded, Tagged, verifyIssuerSigned, MdocError } from "@humid/mdoc";
import { mdocFields } from "@humid/idscan";

const unb64 = (s) => { const t = atob(String(s)); const o = new Uint8Array(t.length); for (let i = 0; i < t.length; i++) o[i] = t.charCodeAt(i); return o; };
const same = (a, b) => (a ?? "") === (b ?? "") || (a == null && b === "") || (a === "" && b == null);

/**
 * roots: trusted IACA roots (as for verifyCredentialResponse), or omit to check
 * only the issuer's signature and digests (chain "unchecked").
 * Returns { ok, chain: "trusted" | "unchecked", reason? }.
 */
export function recheckMdocRecord(rec, { roots, at } = {}) {
  const raw = rec?.raw?.mdoc;
  if (!raw?.issuerSigned || !raw.docType) return { ok: false, chain: "unchecked", reason: "the mobile ID's signed data isn't in this record, so it can't be re-checked" };
  let doc;
  try {
    // Checked as of when the issuer signed it: the record keeps a past read, and
    // mobile ID signatures are short-lived by design. The signature itself still
    // has to verify over these exact bytes.
    const issuerSigned = decode(unb64(raw.issuerSigned));
    const when = at || signedAt(issuerSigned);
    doc = verifyIssuerSigned(issuerSigned, { docType: raw.docType, roots, now: when });
  } catch (e) {
    return { ok: false, chain: "unchecked", reason: e instanceof MdocError ? e.message.replace(/\.$/, "").replace(/^./, (c) => c.toLowerCase()) : "the mobile ID's signed data can't be read" };
  }
  const fields = mdocFields(doc.docType, doc.values).fields;
  for (const [k, from] of Object.entries(rec.source || {})) {
    if (from !== "mdoc") continue;
    if (!same(fields[k], rec.fields?.[k])) return { ok: false, chain: doc.chain, reason: "details marked as from the mobile ID don't match what its issuer signed" };
  }
  return { ok: true, chain: doc.chain };
}

/** The MSO's own "signed" time. Only picks the clock; the signature check that follows covers these bytes. */
function signedAt(issuerSigned) {
  try {
    const s1 = parse1(get(issuerSigned, "issuerAuth"));
    let mso = decode(s1.payload); if (mso instanceof Encoded) mso = mso.value;
    const v = get(get(mso, "validityInfo"), "signed");
    const d = new Date(v instanceof Tagged ? String(v.value) : String(v));
    if (!Number.isNaN(d.getTime())) return d;
  } catch { /* falls through: verifyIssuerSigned reports what's wrong */ }
  return new Date();
}
