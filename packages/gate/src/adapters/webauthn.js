// Browser / PWA gate: WebAuthn platform authenticator with user verification,
// key material from the PRF extension. Same flow as the original web app, so
// identities enrolled there keep working.

import { toB64, fromB64, toHex } from "@humid/codec";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { GATE_CONTRACT, ASSURANCE, interruptRecord } from "../contract.js";

const METHOD = "webauthn-platform-uv-prf";
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

function flagsOf(authData) {
  const flags = new Uint8Array(authData)[32];
  if (!(flags & 1)) throw new Error("Authenticator did not report user presence.");
  if (!(flags & 4)) throw new Error("Authenticator did not verify the user biometrically. HumID requires user verification.");
}

const signCountOf = (authData) =>
  new DataView(authData instanceof ArrayBuffer ? authData : authData.buffer).getUint32(33);

export const webauthnAdapter = {
  id: "webauthn-prf",
  contract: GATE_CONTRACT,
  assurance: ASSURANCE.HARDWARE,

  async probe() {
    const label = "Device passkey (Face ID, Touch ID, Windows Hello, Android)";
    if (!globalThis.isSecureContext) return { available: false, method: METHOD, assurance: ASSURANCE.HARDWARE, label, reason: "This page is not running in a secure context (HTTPS or localhost)." };
    if (!globalThis.PublicKeyCredential) {
      const framed = globalThis.top !== globalThis;
      return { available: false, method: METHOD, assurance: ASSURANCE.HARDWARE, label, reason: framed ? "This frame blocks WebAuthn. Run the standalone app to use the hardware gate." : "This browser does not support WebAuthn." };
    }
    let platform = false;
    try { platform = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch {}
    return platform
      ? { available: true, method: METHOD, assurance: ASSURANCE.HARDWARE, label }
      : { available: false, method: METHOD, assurance: ASSURANCE.HARDWARE, label, reason: "No built-in biometric authenticator (Face ID, Touch ID, Windows Hello, Android biometrics) was found." };
  },

  async enroll() {
    const prfSalt = random(32);
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: "HumID" },
        user: { id: random(16), name: "humid-holder", displayName: "HumID holder" },
        challenge: random(32),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
        attestation: "none",
        timeout: 120000,
        extensions: { prf: { eval: { first: prfSalt } } },
      },
    });
    const ext = cred.getClientExtensionResults();
    if (!ext.prf || ext.prf.enabled === false) {
      throw new Error("This authenticator does not support the PRF extension, so keys cannot be bound to the biometric. Use a current Safari, Chrome or Edge with Face ID, Touch ID, Windows Hello or Android biometrics.");
    }
    if (cred.response.getAuthenticatorData) flagsOf(cred.response.getAuthenticatorData());
    const handle = { credId: toB64(new Uint8Array(cred.rawId)), prfSalt: toB64(prfSalt) };
    let secret = ext.prf.results?.first ? new Uint8Array(ext.prf.results.first) : null;
    let interrupt = interruptRecord(METHOD, "enroll", ASSURANCE.HARDWARE);
    if (!secret) ({ secret, interrupt } = await this.release(handle, "enroll"));
    return { handle, bindingId: handle.credId, secret, interrupt };
  },

  async release(handle, purpose) {
    const challenge = random(32);
    const a = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ type: "public-key", id: fromB64(handle.credId) }],
        userVerification: "required",
        timeout: 120000,
        extensions: { prf: { eval: { first: fromB64(handle.prfSalt) } } },
      },
    });
    flagsOf(a.response.authenticatorData);
    const first = a.getClientExtensionResults().prf?.results?.first;
    if (!first) throw new Error("The authenticator did not release its PRF secret. The interrupt was not satisfied.");
    return {
      secret: new Uint8Array(first),
      interrupt: interruptRecord(METHOD, purpose, ASSURANCE.HARDWARE, {
        credIdHash: toHex(sha3_256(fromB64(handle.credId))).slice(0, 32),
        signCount: signCountOf(a.response.authenticatorData),
        challengeHash: toHex(sha3_256(challenge)).slice(0, 32),
      }),
    };
  },

  async forget() { /* Passkeys are removed from the OS passkey manager by the user. */ },
};
