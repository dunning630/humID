// A simulated person with a phone: an account seed (shared by all their
// devices), a device seed (one per device), and — like a real phone — a
// hardware liveness key that signs every sign-in and step-up, attested by a
// test root shaped like Google's or Apple's. The biometric is reduced to
// callbacks that sign with the right keys.
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, toHex, sha3_256, random, identityId, deviceId, sealLiveMessage, b64u } from "@humid/htp";
import { appAttestClientData } from "@humid/attest";
import { testRoot, androidChain, appAttestation, liveKey } from "../support/pki.js";

/** Test trust anchors, shared by the stack (verifier) and the simulated phones. */
export const ROOTS = { android: testRoot("HumID Test Google Root"), apple: testRoot("HumID Test App Attest Root") };
export const IOS_APP_ID = "TEAM123456.app.humid.vault";

/**
 * kind: "android" (default) | "apple" — attested phone with a liveness key
 *       "desktop" — biometric-only desktop gate, no hardware proof
 *       "demo"    — no sensor at all
 *       "rooted"  — Android key that also accepts a PIN (what a bot would try)
 */
export function makeHolder(label, { seed, kind = "android" } = {}) {
  const S = suite();
  const accountSeed = seed ?? random(64);
  const keys = S.deriveKeys(accountSeed);
  const pub = S.publicOf(keys);
  return {
    label, S, seed: accountSeed, keys, pub,
    id: identityId(pub.dsaPk),
    commit: toHex(S.identityCommit(pub, sha3_256(new TextEncoder().encode(label)))),
    indexKey: S.indexKey(accountSeed),
    ...deviceOf(S, keys, kind),
  };
}

/** Same person, another device: same account seed, new device key and liveness key. */
export function anotherDevice(h, { kind = "android" } = {}) {
  return { ...h, ...deviceOf(h.S, h.keys, kind) };
}

const GATES = {
  android: ["android-keystore-biometric", "hardware"],
  rooted: ["android-keystore-biometric", "hardware"],
  apple: ["ios-keychain-biometry", "hardware"],
  desktop: ["linux-fprintd-keyring", "os"],
  demo: ["demo-no-hardware", "none"],
};

function deviceOf(S, keys, kind) {
  const dkeys = S.deriveKeys(random(64));
  const [gateMethod, assurance] = GATES[kind];
  const lk = ["android", "apple", "rooted"].includes(kind) ? liveKey() : null;
  const interrupt = { method: gateMethod, assurance };
  const sign = (m, k) => ml_dsa87.sign(m, k.dsaSk);

  /** The liveness key and its attestation, made for session transcript `th`, signing `message`. */
  function live(message, th) {
    if (!lk) return undefined;
    let attestation;
    if (kind === "apple") attestation = { kind: "apple-app-attest", object: appAttestation({ root: ROOTS.apple, appId: IOS_APP_ID, clientDataHash: appAttestClientData(th, lk.pub) }) };
    else attestation = { kind: "android-key", chain: androidChain({ root: ROOTS.android, challenge: th, liveKey: lk, ...(kind === "rooted" ? { userAuthType: 3 } : {}) }).chain };
    return { pub: lk.pub, sig: lk.sign(message), attestation };
  }

  return {
    dkeys, interrupt, liveKey: lk, kind,
    deviceId: deviceId(dkeys.dsaPk),
    device: { dsaPk: dkeys.dsaPk, platform: kind, gateMethod, assurance },
    // register: account key signs both statements, device key proves possession, liveness key proves a live check
    registerSign: async ({ register, device, th }) => ({ registerSig: sign(register, keys), sigAccount: sign(device, keys), sigDevice: sign(device, dkeys), live: live(device, th) }),
    enrollSign: async (m, th) => ({ sigAccount: sign(m, keys), sigDevice: sign(m, dkeys), live: live(m, th) }),
    sign: async (m) => ({ sig: sign(m, dkeys), interrupt, live: lk?.sign(m) }),                      // sign-in
    stepUp: async ({ message, live: lm }) => ({ sig: sign(message, dkeys), interrupt, live: lk?.sign(lm) }),
    sealInterrupt: (ciphertextHash) => ({ ...interrupt, purpose: "seal", at: new Date().toISOString(), ...(lk ? { live: b64u(lk.sign(sealLiveMessage(ciphertextHash))) } : {}) }),
  };
}

export async function register(h, baseUrl) {
  const api = new HumidApi({ baseUrl });
  await api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign });
  return api;
}

export async function sealFor(h, name, text) {
  const bytes = new TextEncoder().encode(text);
  const p = await h.S.prepareSeal({ bytes, name, type: "text/plain" }, h.pub);
  const { envelope } = h.S.finishSeal(p, h.keys, { identityCommit: h.commit, interrupt: h.sealInterrupt(p.ciphertextHash) });
  const index = await h.S.sealIndex(h.indexKey, { name, type: "text/plain", size: bytes.length, category: "personal" });
  return { envelope, index };
}

/** Like sealFor, but split: the document also needs its own key, which the caller sends with the upload. */
export async function sealSplitFor(h, name, text) {
  const { splitWrap } = await import("@humid/crypto");
  const bytes = new TextEncoder().encode(text);
  const { file, share } = await splitWrap({ bytes, name, type: "text/plain" });
  const p = await h.S.prepareSeal(file, h.pub);
  const { envelope } = h.S.finishSeal(p, h.keys, { identityCommit: h.commit, interrupt: h.sealInterrupt(p.ciphertextHash) });
  const index = await h.S.sealIndex(h.indexKey, { name, type: "text/plain", size: bytes.length, category: "personal", split: true });
  return { envelope, index, share };
}

/** Seal raw bytes (a seed, a share) to someone's KEM keys, signed by h's account key. */
export async function sealBytes(h, bytes, to, name = "humid-key-material") {
  const { envelope } = await h.S.seal({ bytes, name, type: "application/x-humid-key" }, h.keys, to, { identityCommit: h.commit, interrupt: { ...h.interrupt, purpose: "handover", at: new Date().toISOString() } });
  return envelope;
}
