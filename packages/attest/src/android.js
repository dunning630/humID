// Android key attestation. The phone's Keystore (TEE or StrongBox secure
// element) signs a certificate for a key it generated, describing exactly how
// that key may be used. HumID accepts a device's liveness key only if that
// description says the key:
//   - lives in secure hardware (TEE or StrongBox), not software;
//   - signs with ECDSA P-256;
//   - can be used only after a strong (Class 3) biometric match, every time:
//     no PIN or password (userAuthType has no PASSWORD bit), no "valid for N
//     seconds" window, never without authentication;
//   - is for signing only (purpose SIGN and nothing else);
//   - belongs to the HumID app: its package name AND the release signing
//     certificate (a re-signed or rebuilt copy has a different certificate);
//   - is on a locked, verified-boot device, optionally at a minimum security patch;
//   - was made for this enrolment (attestation challenge = the HTP transcript hash
//     of a fresh session that may enrol once; see services/identity).
// The chain must end in a pinned Google root, every certificate in it must be in
// date (the leaf's dates aren't reliable on real devices and are left out, as
// Google's own verifier does), every issuer must be a CA, and no certificate may be
// on Google's revocation list.

import { X509Certificate } from "node:crypto";
import { parse, kids, int, bool, octets, certExtension, CLASS } from "./der.js";
import { GOOGLE_ATTESTATION_ROOTS, REVOKED_ANDROID_CERTS } from "./roots.js";

export const KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
export const SECURITY_LEVEL = ["software", "tee", "strongbox"];

// Keymaster / KeyMint tags (hardware/interfaces/security/keymint/aidl/.../Tag.aidl)
const T = {
  PURPOSE: 1, ALGORITHM: 2, EC_CURVE: 10, NO_AUTH_REQUIRED: 503, USER_AUTH_TYPE: 504,
  AUTH_TIMEOUT: 505, ALLOW_WHILE_ON_BODY: 506, ROOT_OF_TRUST: 704, OS_PATCHLEVEL: 706, ATTESTATION_APPLICATION_ID: 709,
  UNLOCKED_DEVICE_REQUIRED: 509,
};
/** Security levels HumID accepts: 1 TrustedEnvironment, 2 StrongBox. Anything else (0 Software, KeyMint's 100 Keystore, unknown) is refused. */
const HARDWARE = new Set([1, 2]);
const PURPOSE_SIGN = 2;
const ALGORITHM_EC = 3;
const CURVE_P256 = 1;
const AUTH_PASSWORD = 1;    // HardwareAuthenticatorType: device PIN / pattern / password
const AUTH_BIOMETRIC = 2;   // named FINGERPRINT for history; covers every Class 3 biometric
const BOOT_VERIFIED = 0;

export class AttestationError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, message) => { throw new AttestationError(code, message); };

const spki = (cert) => cert.publicKey.export({ type: "spki", format: "der" });
const same = (a, b) => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));

function authList(t) {
  const m = new Map();
  for (const c of kids(t)) if (c.cls === CLASS.context) m.set(c.tag, parse(c.value)); // EXPLICIT [tag]
  return m;
}

/** Decode the KeyDescription extension (any attestation version). */
export function parseKeyDescription(der) {
  const k = kids(parse(der));
  if (k.length < 8) fail("bad_attestation", "Key description is incomplete.");
  return {
    attestationVersion: int(k[0]),
    attestationSecurityLevel: int(k[1]),
    keymasterVersion: int(k[2]),
    keymasterSecurityLevel: int(k[3]),
    challenge: octets(k[4]),
    uniqueId: octets(k[5]),
    sw: authList(k[6]),
    hw: authList(k[7]),
  };
}

const intOf = (list, tag) => (list.has(tag) ? int(list.get(tag)) : undefined);
const intsOf = (list, tag) => (list.has(tag) ? kids(list.get(tag)).map(int) : []);
const has = (r, tag) => r.hw.has(tag) || r.sw.has(tag);

function rootOfTrust(list) {
  if (!list.has(T.ROOT_OF_TRUST)) return null;
  const k = kids(list.get(T.ROOT_OF_TRUST));
  return { deviceLocked: bool(k[1]), verifiedBootState: int(k[2]) };
}

function applicationId(r) {
  const t = r.sw.get(T.ATTESTATION_APPLICATION_ID) || r.hw.get(T.ATTESTATION_APPLICATION_ID);
  if (!t) return { packages: [], digests: [] };
  const [infos, digests] = kids(parse(octets(t)));
  return {
    packages: kids(infos).map((p) => new TextDecoder().decode(octets(kids(p)[0]))),
    digests: digests ? kids(digests).map((d) => Buffer.from(octets(d)).toString("hex")) : [],
  };
}

/** Serial numbers as Google's status list writes them: lower-case hex, no leading zeros. */
export const serialKey = (s) => String(s).toLowerCase().replace(/^0+(?=.)/, "");

/**
 * Verify the chain and decode the attestation record. No policy yet.
 * chain: leaf first, DER bytes each. roots: PEM strings (default: Google's).
 */
export function readAndroidAttestation({ chain, roots = GOOGLE_ATTESTATION_ROOTS, now = new Date(), revokedSerials = new Set() }) {
  if (!Array.isArray(chain) || chain.length < 2 || chain.length > 10) fail("bad_attestation", "Attestation chain has the wrong length.");
  let certs;
  try { certs = chain.map((c) => new X509Certificate(Buffer.from(c))); }
  catch { fail("bad_attestation", "Attestation chain has a certificate that can't be read."); }
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i].verify(certs[i + 1].publicKey)) fail("bad_attestation", "Attestation chain signature does not verify.");
  }
  const root = certs[certs.length - 1];
  if (!root.verify(root.publicKey)) fail("bad_attestation", "Attestation chain does not end in a self-signed root.");
  const pinned = roots.map((p) => spki(new X509Certificate(p)));
  if (!pinned.some((k) => same(k, spki(root)))) fail("untrusted_root", "Attestation chain does not end in a trusted root.");
  for (const c of certs.slice(1)) {
    if (now < new Date(c.validFrom) || now > new Date(c.validTo)) fail("bad_attestation", "An attestation certificate in the chain is out of date.");
    if (!c.ca) fail("bad_attestation", "A certificate that signed the attestation is not a certificate authority.");
  }
  for (const c of certs) if (revokedSerials.has(serialKey(c.serialNumber))) fail("revoked", "An attestation certificate was revoked or suspended by Google.");

  const withRecord = certs.map((c) => certExtension(c.raw, KEY_DESCRIPTION_OID));
  if (!withRecord[0] || withRecord.slice(1).some(Boolean)) fail("bad_attestation", "The attested key must be the only certificate with a key description.");
  const r = parseKeyDescription(withRecord[0]);
  return { ...r, leaf: certs[0], pub: spki(certs[0]), app: applicationId(r), root: rootOfTrust(r.hw), serials: certs.map((c) => serialKey(c.serialNumber)) };
}

/**
 * HumID's rules for a liveness key. Returns a summary; throws AttestationError.
 * opts: { challenge, packageNames, signatureDigests, allowAnySigner = false, requireLockedBoot = true, minPatchLevel }
 *   signatureDigests  SHA-256 (hex) of the release signing certificate(s). Required:
 *                     without it, a rebuilt or re-signed copy of the app would pass.
 *                     allowAnySigner: true skips it, for test builds only.
 *                     Certificates in REVOKED_ANDROID_CERTS are refused regardless.
 *   minPatchLevel     YYYYMM; phones on an older security patch are refused.
 */
export function checkAndroidPolicy(r, { challenge, packageNames, signatureDigests = [], allowAnySigner = false, requireLockedBoot = true, minPatchLevel } = {}) {
  if (!same(r.challenge, challenge)) fail("wrong_challenge", "The attestation was made for a different session.");
  if (!HARDWARE.has(r.attestationSecurityLevel) || !HARDWARE.has(r.keymasterSecurityLevel)) fail("software_key", "The key is not held in secure hardware.");
  const purposes = intsOf(r.hw, T.PURPOSE);
  if (!purposes.includes(PURPOSE_SIGN)) fail("bad_key", "The key cannot sign.");
  if (purposes.some((p) => p !== PURPOSE_SIGN)) fail("bad_key", "The key may be used for more than signing.");
  // Some StrongBox implementations omit EC_CURVE (they state KEY_SIZE 256); the leaf's own key settles it.
  const curve = intOf(r.hw, T.EC_CURVE);
  if (intOf(r.hw, T.ALGORITHM) !== ALGORITHM_EC || (curve !== undefined && curve !== CURVE_P256)) fail("bad_key", "The key is not ECDSA P-256.");
  if (r.leaf.publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") fail("bad_key", "The key is not ECDSA P-256.");
  if (has(r, T.NO_AUTH_REQUIRED)) fail("no_biometric", "The key can be used without any authentication.");
  const uat = intOf(r.hw, T.USER_AUTH_TYPE);
  if (uat === undefined) fail("no_biometric", "The key's authentication rule is not enforced by secure hardware.");
  if (uat & AUTH_PASSWORD) fail("pin_allowed", "The key also accepts a PIN or password. HumID needs a live biometric.");
  if (!(uat & AUTH_BIOMETRIC)) fail("no_biometric", "The key does not require a biometric.");
  const timeout = intOf(r.hw, T.AUTH_TIMEOUT) ?? intOf(r.sw, T.AUTH_TIMEOUT);
  if (timeout !== undefined && timeout !== 0) fail("not_per_use", "The key stays usable for a while after one check. HumID needs a check for every use.");
  if (has(r, T.ALLOW_WHILE_ON_BODY)) fail("not_per_use", "The key stays usable while the phone is on-body.");
  if (requireLockedBoot) {
    if (!r.root) fail("bad_attestation", "The attestation has no root of trust.");
    if (!r.root.deviceLocked || r.root.verifiedBootState !== BOOT_VERIFIED) fail("unlocked_device", "The phone's bootloader is unlocked or its software is not verified.");
  }
  if (minPatchLevel) {
    const patch = intOf(r.hw, T.OS_PATCHLEVEL);
    if (patch === undefined || patch < minPatchLevel) fail("old_patch", "The phone needs a newer security update before it can use HumID.");
  }
  if (!packageNames?.length) fail("not_configured", "The server doesn't know the HumID app's package name.");
  if (!r.app.packages.some((p) => packageNames.includes(p))) fail("wrong_app", "The key was not made by the HumID app.");
  // A leaked signing key is refused before any operator setting is looked at: neither
  // HUMID_ANDROID_CERT_DIGESTS nor allowAnySigner can let it back in.
  if (r.app.digests.some((d) => REVOKED_ANDROID_CERTS.includes(String(d).toLowerCase()))) fail("revoked_signer", "The app was signed with a leaked key that HumID no longer accepts. Install the official HumID app.");
  if (!signatureDigests.length && !allowAnySigner) fail("not_configured", "The server isn't set up with the HumID app's signing certificate (HUMID_ANDROID_CERT_DIGESTS), so it can't tell the real app from a copy.");
  if (signatureDigests.length && !r.app.digests.some((d) => signatureDigests.includes(d))) fail("wrong_app", "The key was not made by a HumID build signed by us.");
  return {
    proof: `android-${SECURITY_LEVEL[r.attestationSecurityLevel]}`,
    level: SECURITY_LEVEL[r.attestationSecurityLevel],
    keymasterLevel: SECURITY_LEVEL[r.keymasterSecurityLevel],
    unlockedDeviceRequired: has(r, T.UNLOCKED_DEVICE_REQUIRED),
    osPatchLevel: intOf(r.hw, T.OS_PATCHLEVEL) ?? null,
    attestationVersion: r.attestationVersion,
    keymasterVersion: r.keymasterVersion,
    packages: r.app.packages,
  };
}

export function verifyAndroidKey({ chain, roots, now, revokedSerials, ...policy }) {
  const r = readAndroidAttestation({ chain, roots, now, revokedSerials });
  return { pub: r.pub, serials: r.serials, ...checkAndroidPolicy(r, policy) };
}
