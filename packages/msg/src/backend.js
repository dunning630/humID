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
// encodings, deterministic key generation from the same seeds, interchangeable
// signatures, ciphertexts and secret keys, the same ML-KEM implicit rejection
// and the same X25519 results, low-order points included). `checkBackend`
// tests each of these against the reference before a backend is accepted.
//
// Note: the relay never runs any of these. Unlike the HTP gateway, nothing on
// the server side decapsulates attacker-chosen ciphertexts for messaging, so
// there is no server timing oracle to measure.

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_256f } from "@noble/post-quantum/slh-dsa.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { MsgError, equal, random, label, kdf, u32, fromHex } from "./util.js";

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

/* ---------------- checkBackend: the gate on useBackend ----------------
 *
 * Audit finding PC-12: the first version compared key generation and one
 * ML-DSA rejection only, so a replacement whose SLH-DSA verify always said
 * "true", whose X25519 shared secret was a constant, or whose ML-DSA verify
 * ignored the public key was accepted, silently turning "both signatures
 * required" / "both key agreements required" into single-primitive guarantees.
 * Each primitive is now exercised in both directions and against the negative
 * cases a broken verify or decapsulate would get wrong. Keys come from fresh
 * random seeds (so a candidate can't hard-code answers); messages are fixed.
 */

/** Deterministic test messages, one per primitive. */
const testMsg = (what) => label(`backend-check ${what}`);

// RFC 7748 §6.1 Diffie-Hellman test vector (Alice and Bob). The hex is the
// published RFC text; when this was written it was cross-checked against the
// reference (noble), which reproduces both public keys and the shared secret.
const RFC7748 = Object.freeze({
  aSk: fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  aPk: fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  bSk: fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
  bPk: fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  k: fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
});

// Low-order and non-canonical u-coordinates. 0, 1 and p - 1 are computed; the
// two order-8 points are the libsodium / Libgcrypt blocklist values, the same
// numbers as noble's `lowOrderU` (cross-checked when this was written). p and
// p + 1 are non-canonical encodings of 0 and 1, and 2^255 and 2^255 + 1 set the
// top bit that RFC 7748 §5 says to ignore. The candidate must treat each one
// exactly as the reference does (the reference refuses them all).
const P25519 = (1n << 255n) - 19n;
const leU = (n) => { const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
const LOW_ORDER_U = Object.freeze([
  ...[0n, 1n, P25519 - 1n, P25519, P25519 + 1n, 1n << 255n, (1n << 255n) + 1n].map(leU),
  fromHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
  fromHex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
]);

// A second, fixed "wrong" key per signature scheme, made by the reference. The
// counters were found by searching with the reference so that each public key
// starts with a zero byte: a verify that special-cases leading key bytes (the
// PC-12 proof of concept accepted any signature when pk[0] === 0) is caught on
// every run, not one run in 256. Generated once, on first use.
const once = (f) => { let v; return () => (v ??= f()); };
const OTHER_DSA_PK = once(() => noble.dsa.keygen(kdf(u32(38), undefined, "backend-check ml-dsa-87 other key", SIZES.dsaSeed)).publicKey);
const OTHER_SLH_PK = once(() => noble.slh.keygen(kdf(u32(192), undefined, "backend-check slh-dsa other key", SIZES.slhSeed)).publicKey);

const flip = (bytes, at) => { const o = bytes.slice(); o[at] ^= 0x01; return o; };
const accepts = (f) => f() === true;
/** A verify rejects by returning a falsy value or throwing (dualVerify treats a throw as a rejection). */
const rejects = (f) => { try { return !f(); } catch { return true; } };

/** True when f() returns exactly `want`; false when it differs or throws. */
const sameOrThrows = (f, want) => { try { return equal(f(), want); } catch { return false; } };

const OURS = Symbol("checkBackend failure");

/**
 * Run one primitive's checks. Any difference, and anything the candidate
 * throws where it must not, becomes MsgError(code) naming that primitive.
 */
function section(b, code, primitive, fn) {
  const fail = (what) => {
    const e = new MsgError(code, `Backend "${b?.name}" disagrees with the reference on ${primitive} ${what}`);
    e[OURS] = true;
    throw e;
  };
  try { fn(fail); }
  catch (e) {
    if (e?.[OURS]) throw e;
    throw new MsgError(code, `Backend "${b?.name}" failed the ${primitive} check: ${e?.message ?? e}`);
  }
}

/**
 * ML-DSA-87 and SLH-DSA share one procedure: same public key from the same
 * seed; the reference's signature verifies on the candidate; the candidate's
 * signature verifies on both; and on both signatures the candidate's verify
 * rejects a flipped signature bit (first, middle and last byte), a flipped
 * message bit, two other valid public keys, and a truncated signature.
 * The reference signs first and its negatives run before the candidate signs,
 * so a broken verify is refused after one (slow, for SLH-DSA) signature.
 */
function checkSignatures(cand, fail, { seedLen, sigLen, name, otherPk }) {
  if (typeof cand?.keygen !== "function" || typeof cand.sign !== "function" || typeof cand.verify !== "function") fail("interface (keygen, sign, verify)");
  const ref = noble[name === "ML-DSA-87" ? "dsa" : "slh"];
  const seed = random(seedLen);
  const r = ref.keygen(seed), c = cand.keygen(seed);
  if (!equal(c.publicKey, r.publicKey)) fail("key generation");
  const pk = r.publicKey;
  const wrongPks = [ref.keygen(random(seedLen)).publicKey, otherPk()];
  const msg = testMsg(name);
  const negatives = (sig, whose) => {
    const cases = [
      ...[0, sig.length >> 1, sig.length - 1].map((at) => [`a signature with a bit flipped at byte ${at}`, flip(sig, at), msg, pk]),
      ["a message with a bit flipped", sig, flip(msg, msg.length >> 1), pk],
      ...wrongPks.map((other, i) => [`a different valid public key (#${i + 1})`, sig, msg, other]),
      ["a truncated signature", sig.subarray(0, sig.length - 1), msg, pk],
    ];
    for (const [what, s, m, k] of cases) if (!rejects(() => cand.verify(s, m, k))) fail(`verify: accepted ${what} (${whose} signature)`);
  };
  const rSig = ref.sign(msg, r.secretKey);
  if (!accepts(() => cand.verify(rSig, msg, pk))) fail("verify: rejected the reference's signature");
  negatives(rSig, "reference");
  const cSig = cand.sign(msg, c.secretKey);
  if (!(cSig instanceof Uint8Array) || cSig.length !== sigLen) fail("signature size");
  if (!accepts(() => ref.verify(cSig, msg, pk))) fail("signing: the reference rejects the candidate's signature");
  if (!accepts(() => cand.verify(cSig, msg, pk))) fail("verify: rejected its own signature");
  negatives(cSig, "candidate");
}

/**
 * Check a candidate backend against the reference. Throws MsgError with code
 * backend_mismatch_x25519 / _ml_kem / _ml_dsa / _slh_dsa on the first
 * difference; returns true otherwise. docs/MESSAGING.md lists every check.
 */
export function checkBackend(b) {
  section(b, "backend_mismatch_x25519", "X25519", (fail) => {
    const X = b.x25519, R = noble.x25519;
    if (typeof X?.publicKey !== "function" || typeof X.shared !== "function") fail("interface (publicKey, shared)");
    const { aSk, aPk, bSk, bPk, k } = RFC7748;
    if (!equal(X.publicKey(aSk), aPk) || !equal(X.publicKey(bSk), bPk)) fail("RFC 7748 §6.1 public keys");
    if (!equal(X.shared(aSk, bPk), k) || !equal(X.shared(bSk, aPk), k)) fail("RFC 7748 §6.1 shared secret");
    const skA = random(32), skB = random(32);
    const pkA = R.publicKey(skA), pkB = R.publicKey(skB);
    if (!equal(X.publicKey(skA), pkA) || !equal(X.publicKey(skB), pkB)) fail("public key derivation");
    const sAB = X.shared(skA, pkB);
    if (!equal(sAB, R.shared(skA, pkB))) fail("shared secret");
    if (!equal(sAB, X.shared(skB, pkA))) fail("shared secret symmetry");
    const sameAsReference = (sk, u, what) => {
      let want, refThrew = false, got, candThrew = false;
      try { want = R.shared(sk, u); } catch { refThrew = true; }
      try { got = X.shared(sk, u); } catch { candThrew = true; }
      if (refThrew !== candThrew) fail(`${what} (${refThrew ? "the reference refuses it, the candidate does not" : "the candidate refuses it, the reference does not"})`);
      if (!refThrew && !equal(got, want)) fail(what);
    };
    const pkBTop = pkB.slice(); pkBTop[31] |= 0x80;
    sameAsReference(skA, pkBTop, "a public key with the top bit set");
    LOW_ORDER_U.forEach((u, i) => sameAsReference(skA, u, `low-order or non-canonical point #${i}`));
  });

  section(b, "backend_mismatch_ml_kem", "ML-KEM-1024", (fail) => {
    const K = b.kem, R = noble.kem;
    if (typeof K?.keygen !== "function" || typeof K.encapsulate !== "function" || typeof K.decapsulate !== "function") fail("interface (keygen, encapsulate, decapsulate)");
    const seed = random(SIZES.kemSeed);
    const r = R.keygen(seed), c = K.keygen(seed);
    if (!equal(c.publicKey, r.publicKey)) fail("key generation");
    // Candidate encapsulates; the reference decapsulates, with its own secret key and with the candidate's.
    const ce = K.encapsulate(r.publicKey);
    if (ce?.cipherText?.length !== SIZES.kemCt || ce.sharedSecret?.length !== 32) fail("encapsulation sizes");
    if (!equal(R.decapsulate(ce.cipherText, r.secretKey), ce.sharedSecret)) fail("encapsulation");
    if (!sameOrThrows(() => R.decapsulate(ce.cipherText, c.secretKey), ce.sharedSecret)) fail("secret key encoding (the reference can't use the candidate's key)");
    // The reference encapsulates; the candidate decapsulates, with its own secret key and with the reference's.
    const re = R.encapsulate(r.publicKey);
    if (!equal(K.decapsulate(re.cipherText, c.secretKey), re.sharedSecret)) fail("decapsulation");
    if (!sameOrThrows(() => K.decapsulate(re.cipherText, r.secretKey), re.sharedSecret)) fail("secret key encoding (the candidate can't use the reference's key)");
    // Implicit rejection (FIPS 203 §6.3): a modified ciphertext must give J(z ‖ c), the reference's
    // value, never the real secret and never an error.
    for (const at of [0, SIZES.kemCt - 1]) {
      const bad = flip(re.cipherText, at);
      const got = K.decapsulate(bad, c.secretKey);
      if (equal(got, re.sharedSecret)) fail(`implicit rejection (a ciphertext modified at byte ${at} gave the real shared secret)`);
      if (!equal(got, R.decapsulate(bad, r.secretKey))) fail(`implicit rejection (a ciphertext modified at byte ${at} gave a different value from the reference)`);
    }
  });

  section(b, "backend_mismatch_ml_dsa", "ML-DSA-87", (fail) =>
    checkSignatures(b.dsa, fail, { seedLen: SIZES.dsaSeed, sigLen: SIZES.dsaSig, name: "ML-DSA-87", otherPk: OTHER_DSA_PK }));

  section(b, "backend_mismatch_slh_dsa", "SLH-DSA-SHA2-256f", (fail) =>
    checkSignatures(b.slh, fail, { seedLen: SIZES.slhSeed, sigLen: SIZES.slhSig, name: "SLH-DSA-SHA2-256f", otherPk: OTHER_SLH_PK }));

  return true;
}

/** Replace the primitives (e.g. with CryptoKit through the native bridge). Verified first. */
export function useBackend(b) {
  checkBackend(b);
  current = Object.freeze({ ...b });
  return current;
}

export const resetBackend = () => { current = noble; };
