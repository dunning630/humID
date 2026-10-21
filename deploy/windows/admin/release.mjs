// Who made a HumID Server for Windows release (docs/ADMIN.md, RELEASING.md).
//
// GitHub's SHA-256 digest only proves "these bytes were uploaded to a release": anyone
// who can create a server-win-v* release could upload a zip the console would install
// as SYSTEM. So every release zip also carries a signature, <zip>.sig, made with the
// maintainer's offline release key (ML-DSA-87). The console installs only a zip that
// one of the keys pinned in release-keys.mjs signed, for exactly that file name,
// version and contents.
//
// <zip>.sig is one small JSON object:
//   { format, v, name, version, size, sha256, sha3_512, key, sig }
// `sig` is ML-DSA-87 over "HUMID-SERVER-RELEASE-v1" ‖ 0x00 ‖ the canonical JSON of the
// other fields (name, version, size and both hashes), so a signature can't be reused
// for another file, another version, or anything that isn't a server release.
import { createHash } from "node:crypto";
import { ml_dsa87, b64u, unb64u, sha3_256, toHex, utf8, concat } from "@humid/htp";
import { sha3_512 } from "@noble/hashes/sha3.js";
import { canonical } from "./verify.mjs";
import { RELEASE_KEYS } from "./release-keys.mjs";

export const RELEASE_LABEL = "HUMID-SERVER-RELEASE-v1";
export const SIG_FORMAT = "humid-server-release-sig";
const PK_BYTES = 2592; // ML-DSA-87 public key
const NAME = /^HumID-Server-Windows-(\d+\.\d+\.\d+)\.zip$/;

/* global __HUMID_TEST_RELEASE_KEYS__ */
// Test builds only (build.mjs --test-release-key, used by CI to sign its own update
// packages). A release build never sets it: the release workflow checks that.
const TEST_KEYS = typeof __HUMID_TEST_RELEASE_KEYS__ !== "undefined" && Array.isArray(__HUMID_TEST_RELEASE_KEYS__) ? __HUMID_TEST_RELEASE_KEYS__ : [];

/** The keys this console trusts. */
export const pinnedKeys = () => [...RELEASE_KEYS, ...TEST_KEYS];

export class ReleaseError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/** The version a release file name carries, or null. */
export const versionOfName = (name) => NAME.exec(String(name || ""))?.[1] || null;

/** A short, readable fingerprint of a release public key. */
export const keyFingerprint = (pk) => toHex(sha3_256(pk)).slice(0, 16).toUpperCase().match(/.{4}/g).join("-");

const hashes = (bytes) => ({
  size: bytes.length,
  sha256: createHash("sha256").update(bytes).digest("hex"),
  sha3_512: toHex(sha3_512(bytes)),
});

/** The exact bytes a release signature covers. */
export function releaseMessage({ name, version, size, sha256, sha3_512: s3 }) {
  return concat(utf8(RELEASE_LABEL), new Uint8Array([0]), utf8(canonical({ label: RELEASE_LABEL, name, version, size, sha256, sha3_512: s3 })));
}

/** Sign a release zip. → the .sig object (write it as JSON). */
export function signRelease({ bytes, name, secretKey, publicKey }) {
  const version = versionOfName(name);
  if (!version) throw new ReleaseError("bad_name", `${name} isn't a HumID Server release file name (HumID-Server-Windows-X.Y.Z.zip).`);
  const fields = { name, version, ...hashes(bytes) };
  const sig = ml_dsa87.sign(releaseMessage(fields), secretKey);
  return { format: SIG_FORMAT, v: 1, ...fields, key: keyFingerprint(publicKey), sig: b64u(sig) };
}

/**
 * Check a release zip against its signature and the pinned keys, before anything else
 * is done with it.
 *   bytes    the zip, as downloaded
 *   name     its file name (HumID-Server-Windows-X.Y.Z.zip), as the release names it
 *   version  the version the release tag names
 *   sig      the .sig file's contents (string, bytes or parsed object); null if missing
 *   keys     base64url ML-DSA-87 public keys (default: the pinned ones)
 * → { key: fingerprint of the key that signed it, sha256 } or throws ReleaseError.
 */
export function verifyRelease({ bytes, name, version, sig, keys = pinnedKeys() }) {
  const no = (code, msg) => { throw new ReleaseError(code, msg); };
  const usable = (keys || []).map((k) => { try { return unb64u(String(k)); } catch { return null; } }).filter((k) => k && k.length === PK_BYTES);
  if (!usable.length) no("no_release_key", "This console has no HumID release key pinned, so it can't tell who made an update. Nothing was installed. Install a release you trust by hand (unzip it and run its installer).");
  if (sig == null) no("unsigned", `${name} has no signature (${name}.sig), so it can't be checked. Nothing was installed.`);
  let s = sig;
  try {
    if (s instanceof Uint8Array) s = Buffer.from(s).toString("utf8");
    if (typeof s === "string") s = JSON.parse(s);
  } catch { no("bad_signature", `The signature for ${name} can't be read. Nothing was installed.`); }
  if (!s || typeof s !== "object" || s.format !== SIG_FORMAT || s.v !== 1) no("bad_signature", `The signature for ${name} can't be read. Nothing was installed.`);
  if (versionOfName(name) !== version) no("wrong_version", `${name} isn't the file for version ${version}. Nothing was installed.`);
  if (s.name !== name || s.version !== version) no("wrong_version", `The signature is for ${s.name} (${s.version}), not ${name} (${version}). Nothing was installed.`);
  const got = hashes(bytes);
  if (s.size !== got.size || s.sha256 !== got.sha256 || s.sha3_512 !== got.sha3_512) no("tampered", `${name} isn't the file that was signed (SHA-256 ${got.sha256.slice(0, 16)}…). Nothing was installed.`);
  let raw;
  try { raw = unb64u(String(s.sig)); } catch { no("bad_signature", `The signature for ${name} can't be read. Nothing was installed.`); }
  const msg = releaseMessage({ name, version, ...got });
  const signer = usable.find((pk) => { try { return ml_dsa87.verify(raw, msg, pk); } catch { return false; } });
  if (!signer) no("bad_signature", `${name} isn't signed by a HumID release key this console trusts. Nothing was installed.`);
  return { key: keyFingerprint(signer), sha256: got.sha256 };
}
