// Post-quantum and curve primitives behind one swappable interface.
//
// Why swappable (security audit, "timing leaks in the crypto code", T3–T4):
// the default backend is @noble/post-quantum, which is not independently
// audited and makes no constant-time claim. Standards fix the maths, not the
// implementation (KyberSlash recovered ML-KEM keys from division timing). The
// app replaces this backend with the platform's own code where it exists
// (iOS 26 CryptoKit: ML-KEM-1024, ML-DSA-87) through `useBackend`, and a
// server would plug in a formally verified native library. Nothing else in
// @humid/msg imports a primitive directly.
//
// A replacement must be byte-for-byte compatible (same FIPS 203 / 204 / 205
// encodings and deterministic key generation from the same seeds), which
// `checkBackend` verifies against the reference before it is accepted.
//
// Note: the relay never runs any of these. Unlike the HTP gateway, nothing on
// the server side decapsulates attacker-chosen ciphertexts for messaging, so
// there is no server timing oracle to measure.

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_256f } from "@noble/post-quantum/slh-dsa.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { MsgError, equal, random } from "./util.js";

export const SIZES = Object.freeze({
  kemPk: 1568, kemCt: 1568, kemSeed: 64,
  dsaPk: 2592, dsaSig: 4627, dsaSeed: 32,
  slhPk: 64, slhSig: 49856, slhSeed: 96,
  x: 32,
});

const noble = Object.freeze({
  name: "noble",
  kem: {
    keygen: (seed) => ml_kem1024.keygen(seed),               // { publicKey, secretKey }
    encapsulate: (pk) => ml_kem1024.encapsulate(pk),         // { cipherText, sharedSecret }
    decapsulate: (ct, sk) => ml_kem1024.decapsulate(ct, sk), // sharedSecret (implicit rejection on a bad ct)
  },
  dsa: {
    keygen: (seed) => ml_dsa87.keygen(seed),
    sign: (msg, sk) => ml_dsa87.sign(msg, sk),
    verify: (sig, msg, pk) => ml_dsa87.verify(sig, msg, pk),
  },
  // SLH-DSA-SHA2-256f (FIPS 205): hash-based, so a break of lattice maths does
  // not touch it. Category 5, the same level as ML-DSA-87. Used only where a
  // signature is made rarely (a handshake), because it is 49,856 bytes.
  slh: {
    keygen: (seed) => slh_dsa_sha2_256f.keygen(seed),
    sign: (msg, sk) => slh_dsa_sha2_256f.sign(msg, sk),
    verify: (sig, msg, pk) => slh_dsa_sha2_256f.verify(sig, msg, pk),
  },
  x25519: {
    publicKey: (sk) => x25519.getPublicKey(sk),
    shared: (sk, pk) => x25519.getSharedSecret(sk, pk),
  },
});

/**
 * FIPS 203 §7.2 encapsulation-key check: every 12-bit coefficient of the
 * encoded vector must be below q = 3329. A peer's ML-KEM key is checked when
 * it arrives, so a malformed one is refused there instead of breaking a later step.
 */
export function isValidKemPk(pk) {
  if (!(pk instanceof Uint8Array) || pk.length !== SIZES.kemPk) return false;
  const end = SIZES.kemPk - 32; // 384·k bytes of coefficients, then the 32-byte seed ρ
  for (let i = 0; i < end; i += 3) {
    const a = pk[i] | ((pk[i + 1] & 0x0f) << 8);
    const b = (pk[i + 1] >> 4) | (pk[i + 2] << 4);
    if (a >= 3329 || b >= 3329) return false;
  }
  return true;
}

export function checkKemPk(pk) {
  if (!isValidKemPk(pk)) throw new MsgError("bad_key", "Malformed ML-KEM public key");
  return pk;
}

let current = noble;
export const backend = () => current;
export const REFERENCE = noble;

/** Check a candidate backend against the reference on fresh random seeds. Throws on any difference. */
export function checkBackend(b) {
  const fail = (what) => { throw new MsgError("backend_mismatch", `Backend "${b?.name}" disagrees with the reference on ${what}`); };
  const kSeed = random(SIZES.kemSeed), dSeed = random(SIZES.dsaSeed), sSeed = random(SIZES.slhSeed), xSk = random(32);
  const kA = noble.kem.keygen(kSeed), kB = b.kem.keygen(kSeed);
  if (!equal(kA.publicKey, kB.publicKey)) fail("ML-KEM key generation");
  const enc = b.kem.encapsulate(kA.publicKey);
  if (!equal(noble.kem.decapsulate(enc.cipherText, kA.secretKey), enc.sharedSecret)) fail("ML-KEM encapsulation");
  const enc2 = noble.kem.encapsulate(kA.publicKey);
  if (!equal(b.kem.decapsulate(enc2.cipherText, kB.secretKey), enc2.sharedSecret)) fail("ML-KEM decapsulation");
  const dA = noble.dsa.keygen(dSeed), dB = b.dsa.keygen(dSeed);
  if (!equal(dA.publicKey, dB.publicKey)) fail("ML-DSA key generation");
  const msg = random(48);
  if (!noble.dsa.verify(b.dsa.sign(msg, dB.secretKey), msg, dA.publicKey)) fail("ML-DSA signing");
  if (!b.dsa.verify(noble.dsa.sign(msg, dA.secretKey), msg, dB.publicKey)) fail("ML-DSA verification");
  if (b.dsa.verify(noble.dsa.sign(random(48), dA.secretKey), msg, dB.publicKey)) fail("ML-DSA rejection");
  const sA = noble.slh.keygen(sSeed), sB = b.slh.keygen(sSeed);
  if (!equal(sA.publicKey, sB.publicKey)) fail("SLH-DSA key generation");
  if (!equal(noble.x25519.publicKey(xSk), b.x25519.publicKey(xSk))) fail("X25519");
  return true;
}

/** Replace the primitives (e.g. with CryptoKit through the native bridge). Verified first. */
export function useBackend(b) {
  checkBackend(b);
  current = Object.freeze({ ...b });
  return current;
}

export const resetBackend = () => { current = noble; };
