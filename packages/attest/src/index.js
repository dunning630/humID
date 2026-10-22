// @humid/attest — proof that a device's liveness key can only sign after a
// live biometric match, and checking those signatures. Server side only.
//
// A liveness key is an ECDSA P-256 key made by the phone's secure hardware.
// HumID asks the hardware to sign every sign-in and every sensitive request,
// and the hardware will only do so right after Face ID, Touch ID or a Class 3
// fingerprint/face match. No PIN, no password. See docs/SECURITY.md.

import { createHash, createPublicKey, verify } from "node:crypto";
import { verifyAndroidKey, AttestationError } from "./android.js";
import { verifyAppAttest } from "./apple.js";

export { verifyAndroidKey, readAndroidAttestation, checkAndroidPolicy, parseKeyDescription, AttestationError, KEY_DESCRIPTION_OID, serialKey } from "./android.js";
export { revocationList, parseStatusList, STATUS_URL } from "./status.js";
export { verifyAppAttest } from "./apple.js";
export { GOOGLE_ATTESTATION_ROOTS, APPLE_APP_ATTEST_ROOT, HUMID_ANDROID_RELEASE_CERT, REVOKED_ANDROID_CERTS } from "./roots.js";
export { decodeCbor } from "./cbor.js";

/** A P-256 public key as SPKI DER, or throws. */
export function p256(spkiDer) {
  let k;
  try { k = createPublicKey({ key: Buffer.from(spkiDer), format: "der", type: "spki" }); }
  catch { throw new AttestationError("bad_key", "Liveness key can't be read."); }
  if (k.asymmetricKeyType !== "ec" || k.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new AttestationError("bad_key", "Liveness key must be ECDSA P-256.");
  return k;
}

/** ECDSA P-256 / SHA-256 signature (DER) by a liveness key over `message`. */
export function verifyLiveSig(spkiDer, message, sig) {
  if (!spkiDer || !sig) return false;
  try { return verify("sha256", Buffer.from(message), p256(spkiDer), Buffer.from(sig)); }
  catch { return false; }
}

/** What an iPhone passes to App Attest: SHA-256(challenge ‖ liveness public key). */
export const appAttestClientData = (challenge, spkiDer) => createHash("sha256").update(Buffer.from(challenge)).update(Buffer.from(spkiDer)).digest();

/**
 * Check a device's liveness key at enrolment.
 * live: { pub (SPKI DER), attestation: { kind: "android-key", chain: [DER…] } | { kind: "apple-app-attest", object: CBOR } }
 * challenge: the bytes the attestation must be bound to (the HTP transcript hash).
 * config: { androidPackages, androidDigests, iosAppId, appAttestEnvironment, roots: { android, apple }, requireLockedBoot }
 * Returns { proof, detail }.
 */
export function verifyLiveKey(live, challenge, config = {}) {
  try { return verifyLiveKeyInner(live, challenge, config); }
  catch (e) {
    // anything malformed in what the phone sent (bad DER, bad CBOR) is a refusal, not a server error
    if (e instanceof AttestationError) throw e;
    throw new AttestationError("bad_attestation", "The attestation can't be read.");
  }
}

function verifyLiveKeyInner(live, challenge, config) {
  const pub = Buffer.from(live.pub);
  p256(pub);
  const a = live.attestation;
  if (!a) throw new AttestationError("no_attestation", "The device did not prove its liveness key.");
  if (a.kind === "android-key") {
    const r = verifyAndroidKey({
      chain: a.chain, challenge, roots: config.roots?.android, now: config.now,
      packageNames: config.androidPackages, signatureDigests: config.androidDigests, allowAnySigner: config.allowAnySigner === true,
      requireLockedBoot: config.requireLockedBoot ?? true, minPatchLevel: config.minPatchLevel,
      revokedSerials: typeof config.revokedSerials === "function" ? config.revokedSerials() : config.revokedSerials,
    });
    if (!r.pub.equals(pub)) throw new AttestationError("bad_attestation", "The attested key is not the liveness key.");
    const { pub: _p, proof, ...detail } = r;
    return { proof, detail };
  }
  if (a.kind === "apple-app-attest") {
    const r = verifyAppAttest({
      attestation: a.object, clientDataHash: appAttestClientData(challenge, pub),
      appId: config.iosAppId, environment: config.appAttestEnvironment, roots: config.roots?.apple, now: config.now,
    });
    const { proof, ...detail } = r;
    return { proof, detail };
  }
  throw new AttestationError("bad_attestation", "Unknown attestation kind.");
}
