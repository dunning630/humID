// Apple App Attest. iOS has no way to attest a Secure Enclave key's access
// policy to a third party, so HumID proves the next best thing: that the
// genuine, App Store-signed HumID app on a genuine Apple device created this
// liveness key during this session. The app makes its liveness key in the
// Secure Enclave with .biometryCurrentSet (Face ID / Touch ID, no passcode),
// then asks App Attest to vouch for SHA-256(th ‖ liveness public key).
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server

import { X509Certificate, createHash } from "node:crypto";
import { decodeCbor } from "./cbor.js";
import { parse, kids, octets, certExtension } from "./der.js";
import { APPLE_APP_ATTEST_ROOT } from "./roots.js";
import { AttestationError } from "./android.js";

export const APPLE_NONCE_OID = "1.2.840.113635.100.8.2";
const AAGUID = {
  production: Buffer.concat([Buffer.from("appattest"), Buffer.alloc(7)]),
  development: Buffer.from("appattestdevelop"),
};

const fail = (code, message) => { throw new AttestationError(code, message); };
const sha256 = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();

/** Uncompressed EC point (0x04 ‖ X ‖ Y) of a P-256 public key. */
function rawPoint(key) {
  const j = key.export({ format: "jwk" });
  if (j.crv !== "P-256") fail("bad_attestation", "App Attest key is not P-256.");
  return Buffer.concat([Buffer.from([4]), Buffer.from(j.x, "base64url"), Buffer.from(j.y, "base64url")]);
}

/**
 * attestation: CBOR bytes from DCAppAttestService.attestKey.
 * clientDataHash: the 32 bytes the app passed to attestKey.
 * appId: "<Team ID>.<bundle id>". environment: "production" | "development".
 */
export function verifyAppAttest({ attestation, clientDataHash, appId, environment = "production", roots = [APPLE_APP_ATTEST_ROOT], now = new Date() }) {
  if (!appId) fail("not_configured", "This server is not configured for iPhone (HUMID_IOS_APP_ID).");
  let obj;
  try { obj = decodeCbor(attestation); } catch { fail("bad_attestation", "App Attest object can't be read."); }
  if (!(obj instanceof Map) || obj.get("fmt") !== "apple-appattest") fail("bad_attestation", "Not an App Attest attestation.");
  const stmt = obj.get("attStmt");
  const authData = obj.get("authData");
  const x5c = stmt instanceof Map ? stmt.get("x5c") : null;
  if (!Array.isArray(x5c) || x5c.length < 2 || !(authData instanceof Uint8Array)) fail("bad_attestation", "App Attest object is incomplete.");

  let leaf, inter;
  try { [leaf, inter] = x5c.map((c) => new X509Certificate(Buffer.from(c))); }
  catch { fail("bad_attestation", "App Attest certificate can't be read."); }
  if (!leaf.verify(inter.publicKey)) fail("bad_attestation", "App Attest chain signature does not verify.");
  const anchors = roots.map((p) => new X509Certificate(p));
  if (!anchors.some((r) => inter.verify(r.publicKey))) fail("untrusted_root", "App Attest chain does not end in Apple's root.");
  for (const c of [leaf, inter]) {
    if (now < new Date(c.validFrom) || now > new Date(c.validTo)) fail("bad_attestation", "An App Attest certificate is expired.");
  }

  const nonce = sha256(authData, clientDataHash);
  const ext = certExtension(leaf.raw, APPLE_NONCE_OID);
  if (!ext) fail("bad_attestation", "App Attest certificate has no nonce.");
  const inner = kids(parse(ext))[0]; // [1] EXPLICIT OCTET STRING
  if (!Buffer.from(octets(parse(inner.value))).equals(nonce)) fail("wrong_challenge", "The attestation was made for a different session or key.");

  const keyId = sha256(rawPoint(leaf.publicKey));
  const ad = Buffer.from(authData);
  if (ad.length < 55) fail("bad_attestation", "App Attest authenticator data is too short.");
  if (!ad.subarray(0, 32).equals(sha256(Buffer.from(appId)))) fail("wrong_app", "The attestation is for a different app.");
  if (ad.readUInt32BE(33) !== 0) fail("bad_attestation", "App Attest counter must be zero for a new key.");
  const aaguid = ad.subarray(37, 53);
  const env = aaguid.equals(AAGUID.production) ? "production" : aaguid.equals(AAGUID.development) ? "development" : null;
  if (!env) fail("bad_attestation", "Unknown App Attest environment.");
  if (env !== environment) fail("wrong_environment", `This server accepts ${environment} builds of HumID only.`);
  const credLen = ad.readUInt16BE(53);
  if (!ad.subarray(55, 55 + credLen).equals(keyId)) fail("bad_attestation", "App Attest key id does not match its certificate.");
  return { proof: "apple-secure-enclave", keyId: keyId.toString("base64"), environment: env };
}
