// Reading an Apple Wallet pass (.pkpass) and checking it came from its issuer, unaltered.
//
//   1. unzip, bounded (zip.js)
//   2. manifest.json lists every file with its SHA-1 (or SHA-256): every file must be
//      listed and match, and every listed file must be there
//   3. "signature" is a detached CMS signature over manifest.json: its message digest
//      must match, and the signer's key must have signed it
//   4. the signer's certificate chains, through the intermediates in the signature
//      (Apple Worldwide Developer Relations), to a pinned Apple root (roots.js); every
//      certificate valid when the pass was signed; intermediates are CAs; the signer is
//      a Pass Type ID certificate (Apple's extension) and not a CA
//   5. pass.json names the same pass type and team as the signer's certificate
//
// Anything that fails is refused with a WalletError: HumID keeps a pass only if Apple
// Wallet would trust it. The pass is never opened as a link or run; its text is shown.
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { readZip, WalletError, LIMITS } from "./zip.js";
import { parseCert, verifyWith, issuedBy, validAt, OID } from "./x509.js";
import { parseSignature, CONTENT_DATA } from "./cms.js";
import { same } from "./der.js";
import { APPLE_ROOTS } from "./roots.js";

export const MEDIA_TYPE = "application/vnd.apple.pkpass";
const fail = (code, message) => { throw new WalletError(code, message); };
const HASH = { "SHA-1": sha1, "SHA-256": sha256, "SHA-384": sha384, "SHA-512": sha512 };
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const json = (bytes, what) => {
  try { const j = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/^\uFEFF/, "")); if (j && typeof j === "object" && !Array.isArray(j)) return j; }
  catch { /* below */ }
  return fail("bad_pass", `The pass's ${what} can't be read.`);
};

/** Is this file probably a pass? (name or type; the real check is readPkpass) */
export const looksLikePass = (file) => !!file && (file.type === MEDIA_TYPE || /\.pkpass$/i.test(file.name || ""));

const STYLES = ["boardingPass", "coupon", "eventTicket", "generic", "storeCard"];
export const STYLE_LABEL = { boardingPass: "Boarding pass", coupon: "Coupon", eventTicket: "Ticket", generic: "Pass", storeCard: "Store card" };
const GROUPS = ["headerFields", "primaryFields", "secondaryFields", "auxiliaryFields", "backFields"];
const str = (v, max = 200) => (v == null ? "" : String(typeof v === "object" ? "" : v).replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max));
const color = (v) => (typeof v === "string" && /^rgb\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*\)$/.test(v) ? v.replace(/\s+/g, "") : null);
const date = (v) => (typeof v === "string" && v.length <= 40 && !Number.isNaN(Date.parse(v)) ? new Date(Date.parse(v)).toISOString() : null);

/** What HumID shows of pass.json: text only, bounded. Never a URL to open or code to run. */
export function summarizePass(p) {
  const style = STYLES.find((s) => p[s] && typeof p[s] === "object") || "generic";
  const body = p[style] || {};
  const fields = {};
  for (const g of GROUPS) {
    const list = Array.isArray(body[g]) ? body[g].slice(0, 20) : [];
    fields[g.replace("Fields", "")] = list.filter((f) => f && typeof f === "object")
      .map((f) => ({ label: str(f.label, 80), value: str(f.attributedValue ?? f.value, g === "backFields" ? 2000 : 200) }))
      .filter((f) => f.label || f.value);
  }
  const code = (Array.isArray(p.barcodes) && p.barcodes[0]) || p.barcode || null;
  const barcode = code && typeof code === "object" && typeof code.message === "string"
    ? { format: str(code.format, 40), message: code.message.slice(0, 2000), altText: str(code.altText, 120) } : null;
  return {
    style, styleLabel: STYLE_LABEL[style], transit: style === "boardingPass" ? str(body.transitType, 40) : "",
    organization: str(p.organizationName, 120), description: str(p.description, 200), logoText: str(p.logoText, 120),
    serialNumber: str(p.serialNumber, 120), passTypeIdentifier: str(p.passTypeIdentifier, 200), teamIdentifier: str(p.teamIdentifier, 40),
    relevantDate: date(p.relevantDate), expirationDate: date(p.expirationDate), voided: p.voided === true,
    colors: { foreground: color(p.foregroundColor), background: color(p.backgroundColor), label: color(p.labelColor) },
    fields, barcode,
  };
}

/** What the encrypted vault index carries (shown in the list without opening): no barcode, no back fields. */
export const passIndex = (s, issuer, checkedAt = new Date()) => ({
  style: s.style, organization: s.organization, description: s.description,
  // who signed it, from the certificate Apple issued (not the pass's own text)
  issuer: issuer.organization || "", team: issuer.team, passType: issuer.passType,
  relevant: s.relevantDate || "", expires: s.expirationDate || "", voided: s.voided || undefined,
  checkedAt: checkedAt.toISOString(),
});

// keyUsage bits (first byte of the BIT STRING): digitalSignature 0x80, keyCertSign 0x04.
const mayIssue = (c) => c.ext.ca && (!c.ext.keyUsage || (c.ext.keyUsage[0] & 0x04) !== 0);
const maySign = (c) => !c.ext.keyUsage || (c.ext.keyUsage[0] & 0x80) !== 0;

/**
 * From the signer up to a pinned root, through the intermediates the signature carries.
 * Every candidate is tried (an expired and a renewed intermediate can share a name),
 * those valid at `when` first; at most 4 links.
 */
async function chainToApple(signer, pool, roots, when) {
  const anchors = roots.map((r) => ({ ...parseCert(r.der), name: r.name }));
  async function up(cur, path) {
    for (const a of anchors) if (validAt(a, when) && (await issuedBy(cur, a))) return { path, root: a };
    if (path.length > 4) return null;
    const next = [];
    for (const c of pool) if (!path.includes(c) && mayIssue(c) && validAt(c, when) && (await issuedBy(cur, c))) next.push(c);
    for (const c of next) { const found = await up(c, [...path, c]); if (found) return found; }
    return null;
  }
  return (await up(signer, [signer])) || fail("untrusted", "The pass isn't signed through Apple's certificate chain, so Apple Wallet wouldn't trust it either.");
}

/**
 * bytes (a .pkpass) → { pass (summary), issuer, signedAt, files, manifestHash, images }.
 * roots: trust anchors (default: Apple's, pinned); now: the time to check against.
 */
export async function readPkpass(bytes, { roots = APPLE_ROOTS, now = new Date(), limits = LIMITS } = {}) {
  const files = await readZip(bytes, limits);
  const manifestBytes = files.get("manifest.json"), sigBytes = files.get("signature"), passBytes = files.get("pass.json");
  if (!passBytes || !manifestBytes) fail("bad_pass", "That isn't a Wallet pass (no pass.json or manifest.json).");
  if (!sigBytes) fail("unsigned", "That pass isn't signed.");

  // 2. every file is in the manifest, with its hash, and the manifest lists nothing extra
  const manifest = json(manifestBytes, "manifest");
  let alg = null;
  for (const [name, data] of files) {
    if (name === "manifest.json" || name === "signature") continue;
    const want = manifest[name];
    if (typeof want !== "string") fail("tampered", `The pass has a file its signature doesn't cover (${name.slice(0, 40)}).`);
    const a = want.length === 40 ? "SHA-1" : want.length === 64 ? "SHA-256" : null;
    if (!a || !/^[0-9a-f]+$/i.test(want)) fail("bad_pass", "The pass's manifest is malformed.");
    if (alg && a !== alg) fail("bad_pass", "The pass's manifest mixes hash algorithms.");
    alg ||= a;
    if (hex(HASH[a](data)) !== want.toLowerCase()) fail("tampered", `A file in the pass was changed after it was signed (${name.slice(0, 40)}).`);
  }
  for (const name of Object.keys(manifest)) if (!files.has(name)) fail("tampered", "A file the pass's signature covers is missing.");

  // 3. the signature over manifest.json
  const sig = parseSignature(sigBytes);
  const s = sig.signer;
  const pool = sig.certs.map(parseCert);
  for (const c of pool) if (c.keyAlg === OID.rsa && c.spki.length > 600) fail("bad_signature", "A key in the pass's signature is too large."); // over 4096-bit RSA
  const signer = pool.find((c) => (s.sid.ski ? c.ext.ski && same(c.ext.ski, s.sid.ski) : same(c.issuerRaw, s.sid.issuerRaw) && same(c.serial, s.sid.serial)));
  if (!signer) fail("bad_signature", "The pass's signature doesn't include its signer's certificate.");
  let signed;
  if (s.signedAttrs) {
    if (s.attrs.contentType !== CONTENT_DATA || !s.attrs.messageDigest) fail("bad_signature", "The pass's signature is malformed.");
    if (!same(HASH[s.digest](manifestBytes), s.attrs.messageDigest)) fail("tampered", "The pass's manifest was changed after it was signed.");
    signed = s.signedAttrs;
  } else signed = manifestBytes;
  if (!(await verifyWith(signer, s.sigAlg, s.signature, signed, s.digest))) fail("bad_signature", "The pass's signature doesn't verify.");

  // 4. who signed it: a Pass Type ID certificate, through Apple's chain
  // When it was signed: the time it states (no later than now), else now. A pass signed while its
  // certificate was valid stays genuine after the certificate expires (as in Wallet); that state is
  // reported (certExpired) rather than shown as plain "verified", since a signing time is the signer's word.
  const stated = s.attrs.signingTime && s.attrs.signingTime <= new Date(now.getTime() + 5 * 60_000) ? s.attrs.signingTime : null;
  const signedAt = stated || now;
  if (!signer.ext.passbook || signer.ext.ca || !maySign(signer)) fail("untrusted", "The pass wasn't signed with a Wallet pass certificate.");
  if (!validAt(signer, signedAt)) fail("untrusted", "The pass's certificate wasn't valid when it was signed.");
  const { root } = await chainToApple(signer, pool.filter((c) => c !== signer), roots, signedAt);

  // 5. the pass is the one the certificate is for
  const p = json(passBytes, "contents");
  if (p.formatVersion !== 1) fail("bad_pass", "That pass uses a format HumID doesn't know.");
  const passType = signer.subject.UID, team = signer.subject.OU;
  if (!passType || p.passTypeIdentifier !== passType) fail("untrusted", "The pass says it's a different kind of pass than its certificate allows.");
  if (!team || p.teamIdentifier !== team) fail("untrusted", "The pass names a different issuer than the one that signed it.");

  const pick = (base) => files.get(`${base}@3x.png`) || files.get(`${base}@2x.png`) || files.get(`${base}.png`) || null;
  return {
    pass: summarizePass(p),
    issuer: {
      team, passType, organization: signer.subject.O || "", name: signer.subject.CN || "", root: root.name,
      certExpires: signer.notAfter.toISOString(), certExpired: signer.notAfter < now,
    },
    signedAt: stated ? stated.toISOString() : null,
    files: files.size, manifestHash: alg,
    images: { icon: pick("icon"), logo: pick("logo"), strip: pick("strip"), thumbnail: pick("thumbnail") },
  };
}
