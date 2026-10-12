// A simulated person with a phone: an account seed (shared by all their
// devices) and a device seed (one per device). The biometric gate is reduced
// to callbacks that sign with the right key.
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, toHex, sha3_256, random, identityId, deviceId } from "@humid/htp";

export function makeHolder(label, { seed, assurance = "hardware" } = {}) {
  const S = suite();
  const accountSeed = seed ?? random(64);
  const keys = S.deriveKeys(accountSeed);
  const pub = S.publicOf(keys);
  return {
    label, S, seed: accountSeed, keys, pub,
    id: identityId(pub.dsaPk),
    commit: toHex(S.identityCommit(pub, sha3_256(new TextEncoder().encode(label)))),
    indexKey: S.indexKey(accountSeed),
    ...deviceOf(S, keys, assurance),
  };
}

/** Same person, another device: same account seed, new device key. */
export function anotherDevice(h, { assurance = "hardware" } = {}) {
  return { ...h, ...deviceOf(h.S, h.keys, assurance) };
}

function deviceOf(S, keys, assurance) {
  const dkeys = S.deriveKeys(random(64));
  const interrupt = { method: "test-gate", assurance };
  const sign = (m, k) => ml_dsa87.sign(m, k.dsaSk);
  return {
    dkeys, interrupt,
    deviceId: deviceId(dkeys.dsaPk),
    device: { dsaPk: dkeys.dsaPk, platform: "test", gateMethod: "test-gate", assurance },
    // register: account key signs both statements, device key proves possession
    registerSign: async ({ register, device }) => ({ registerSig: sign(register, keys), sigAccount: sign(device, keys), sigDevice: sign(device, dkeys) }),
    enrollSign: async (m) => ({ sigAccount: sign(m, keys), sigDevice: sign(m, dkeys) }),
    sign: async (m) => ({ sig: sign(m, dkeys), interrupt }),           // sign-in
    stepUp: async ({ message }) => ({ sig: sign(message, dkeys), interrupt }),
  };
}

export async function register(h, baseUrl) {
  const api = new HumidApi({ baseUrl });
  await api.register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign });
  return api;
}

export async function sealFor(h, name, text) {
  const bytes = new TextEncoder().encode(text);
  const { envelope } = await h.S.seal({ bytes, name, type: "text/plain" }, h.keys, h.pub, { identityCommit: h.commit, interrupt: { ...h.interrupt, purpose: "seal", at: new Date().toISOString() } });
  const index = await h.S.sealIndex(h.indexKey, { name, type: "text/plain", size: bytes.length, category: "personal" });
  return { envelope, index };
}

/** Seal raw bytes (a seed, a share) to someone's KEM keys, signed by h's account key. */
export async function sealBytes(h, bytes, to, name = "humid-key-material") {
  const { envelope } = await h.S.seal({ bytes, name, type: "application/x-humid-key" }, h.keys, to, { identityCommit: h.commit, interrupt: { ...h.interrupt, purpose: "handover", at: new Date().toISOString() } });
  return envelope;
}
