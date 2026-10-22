// Mobile IDs (ISO/IEC 18013-5) as an identity anchor, the counterpart of
// passive + active authentication for passport chips:
//
//   issuer data authentication   the issuing state's Document Signer signed
//                                the data, chaining to a trusted IACA root
//                                (HUMID_IACA_DIR, e.g. from AAMVA's VICAL)
//   mdoc authentication          the wallet signed THIS session's transcript
//                                with the device key the issuer bound into
//                                the document. The server is the reader, so
//                                the transcript holds its own fresh key, the
//                                way a passport answers the server's nonce.
//
// Like the passport anchor, only a keyed hash of fields that survive renewal
// is kept.

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { verifyDeviceResponse, MdocError, MDL_DOCTYPE, MDL_NS, PID_DOCTYPE } from "@humid/mdoc";

export class MdocAnchorError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/** IACA root certificates (PEM or DER) from a directory. Missing directory = none. */
export function loadIacas(dir) {
  if (!dir || !existsSync(dir)) return [];
  const out = [];
  for (const f of readdirSync(dir)) {
    if (!/\.(pem|crt|cer|der)$/i.test(f)) continue;
    const raw = readFileSync(join(dir, f));
    const text = raw.toString("latin1");
    if (text.includes("-----BEGIN CERTIFICATE-----")) out.push(...(text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []));
    else out.push(new Uint8Array(raw));
  }
  return out;
}

const txt = (v) => (v == null ? "" : typeof v === "object" && "value" in v ? String(v.value) : String(v));
const ALLOWED = [MDL_DOCTYPE, PID_DOCTYPE];

/**
 * Check a mobile ID shared in a session the server ran as the reader.
 * session: the server's ReaderSession; response: the decrypted DeviceResponse.
 * Returns the identity fields and what was proven. Throws MdocAnchorError.
 */
export function mdocAuth(response, { session, iacas, now = new Date() } = {}) {
  if (!session) throw new MdocAnchorError("no_chip_proof", "A mobile ID can only anchor from a live session.");
  if (!iacas?.length) throw new MdocAnchorError("no_trust", "This server has no issuing-authority certificates configured, so it can't check mobile IDs yet.");
  let docs;
  try { docs = verifyDeviceResponse(response, { session, roots: iacas, now }); }
  catch (e) { if (e instanceof MdocError) throw new MdocAnchorError(e.code === "untrusted_issuer" ? "untrusted_country" : e.code, e.message); throw e; }
  const d = docs.find((x) => ALLOWED.includes(x.docType));
  if (!d) throw new MdocAnchorError("unsupported", "Share a mobile driver's license, state ID or digital identity.");
  if (d.chain !== "trusted" || !d.device?.ok) throw new MdocAnchorError("bad_signature", "The mobile ID couldn't be fully checked.");
  const v = d.values[MDL_NS] || d.values[PID_DOCTYPE] || {};
  const expiry = txt(v.expiry_date);
  if (expiry && new Date(`${expiry.slice(0, 10)}T23:59:59Z`) < now) throw new MdocAnchorError("expired", "This document has expired. Use a valid license or ID.");
  const identity = {
    docType: d.docType, issuer: txt(v.issuing_country).toUpperCase(), jurisdiction: txt(v.issuing_jurisdiction).toUpperCase(),
    surname: txt(v.family_name).toUpperCase(), given: txt(v.given_name).toUpperCase(), birth: txt(v.birth_date).slice(0, 10), sex: txt(v.sex),
  };
  // A weak anchor (a surname and a birth date) would be too easy to collide with; ask for the full set.
  if (!identity.surname || !identity.given || !identity.birth || !identity.issuer) throw new MdocAnchorError("bad_chip_data", "The mobile ID didn't share the full name, date of birth and issuing country.");
  return { identity, device: d.device.method, root: d.root?.subject || null, validUntil: d.validity.validUntil };
}

/** The fields that survive renewal; a different document type from passports, so its own label. */
export const mdocStableIdentity = (i) => ["HUMID-ANCHOR-MDOC-v1", i.issuer, i.jurisdiction, i.surname, i.given, i.birth, i.sex].join("|");
export const mdocAnchorOf = (identity, key) => createHmac("sha3-256", key).update(mdocStableIdentity(identity)).digest("hex");
/** Country, state and kind only, for display. Never names or numbers. */
export const mdocAnchorSummary = (i) => ({ document: i.docType === MDL_DOCTYPE ? "mobile ID" : "digital identity", country: i.issuer, region: i.jurisdiction.split("-")[1] || "" });
