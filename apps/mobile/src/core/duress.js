// The duress setting on this device: whether it's on, and which unlock gesture
// (hold the Unlock button longer, or tap the mark three times) means duress.
//
// Nothing about it is on the device in the clear. The setting is sealed under a
// key derived from the account seed (@humid/crypto settingsKey), so it reads only
// after a live check. The Lock screen therefore can't know the gesture in advance:
// it always listens for both, tells unlock() which one was used, and the
// controller decides decoy-or-real AFTER the check, from the opened setting. An
// attacker with the phone's storage learns neither whether duress is set up nor
// which gesture triggers it.
//
// Pure functions, exported for tests (tests/duress.test.js).

import { toB64, fromB64 } from "@humid/codec";

export const DEFAULT = Object.freeze({ enabled: false, gesture: "taps" });
const GESTURES = new Set(["hold", "taps"]);
// Every sealed setting is the same length (the JSON is padded to this many characters
// before sealing), so the ciphertext's size says nothing about what it holds.
const SEALED_CHARS = 96;

/** A setting as the app uses it, whatever was stored. */
export const normalize = (s) => ({ enabled: !!s?.enabled, gesture: GESTURES.has(s?.gesture) ? s.gesture : "taps" });
const padded = (setting) => { const base = JSON.stringify({ ...setting, pad: "" }); return { ...setting, pad: "x".repeat(Math.max(0, SEALED_CHARS - base.length)) }; };

/**
 * The record with `setting` sealed into it (`duressSealed`), and any plaintext
 * copy from an earlier release (`duress`) removed.
 */
export async function sealDuress(Suite, key, record, setting) {
  if (!key || !Suite.sealSetting) throw Object.assign(new Error(""), { code: "locked" });
  const blob = await Suite.sealSetting(key, padded(normalize(setting)));
  const next = { ...record, duressSealed: toB64(blob), duressSealedAt: record.duressSealedAt || new Date().toISOString().slice(0, 10) };
  delete next.duress;
  return next;
}

/**
 * The setting from a record, after a live check: { setting, record, unreadable } where
 * record is non-null when the stored record should be replaced (a plaintext setting from
 * an earlier release, sealed now; or a record with no sealed setting yet, which gets "off"
 * sealed into it so that from then on a MISSING setting is tampering, not a default). A
 * sealed setting that won't open, or one that is missing from a record that should have
 * one, reads as "off" with `unreadable: true`: isDuress then treats a duress gesture as
 * duress (failing toward the decoy is the safe direction for a coercion feature).
 */
export async function openDuress(Suite, key, record) {
  if (!key || !record) return { setting: { ...DEFAULT }, record: null };
  // Written by an earlier release in the clear: seal it and drop the plaintext.
  if (record.duress && typeof record.duress === "object") {
    const setting = normalize(record.duress);
    try { return { setting, record: await sealDuress(Suite, key, record, setting) }; }
    catch { return { setting, record: null }; }
  }
  if (!record.duressSealed) {
    // Never sealed on this device: seal "off" now. A record from an earlier release has no
    // setting either; it's told apart from a deleted one by the marker the seal adds.
    let sealed = null;
    try { sealed = await sealDuress(Suite, key, record, DEFAULT); } catch { /* next unlock tries again */ }
    return { setting: { ...DEFAULT }, record: sealed, unreadable: !!record.duressSealedAt };
  }
  try { return { setting: normalize(await Suite.openSetting(key, fromB64(record.duressSealed))), record: null }; }
  catch { return { setting: { ...DEFAULT }, record: null, unreadable: true }; }
}

/**
 * Is this unlock a duress unlock? `used` is what the Lock screen saw: false (plain
 * unlock), "hold" or "taps" (that gesture was made), or true (an earlier screen, or
 * reconnecting from a decoy session: "the duress gesture, whichever it is").
 * unreadable: the sealed setting didn't open (openDuress); then any gesture counts.
 */
export function isDuress(setting, used, { unreadable = false } = {}) {
  if (unreadable) return !!used;
  const s = normalize(setting);
  if (!s.enabled || !used) return false;
  return used === true || used === s.gesture;
}
