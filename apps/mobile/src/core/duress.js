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

export const DEFAULT = Object.freeze({ enabled: false, gesture: "hold" });
const GESTURES = new Set(["hold", "taps"]);

/** A setting as the app uses it, whatever was stored. */
export const normalize = (s) => ({ enabled: !!s?.enabled, gesture: GESTURES.has(s?.gesture) ? s.gesture : "hold" });

/**
 * The record with `setting` sealed into it (`duressSealed`), and any plaintext
 * copy from an earlier release (`duress`) removed.
 */
export async function sealDuress(Suite, key, record, setting) {
  if (!key || !Suite.sealSetting) throw Object.assign(new Error(""), { code: "locked" });
  const blob = await Suite.sealSetting(key, normalize(setting));
  const next = { ...record, duressSealed: toB64(blob) };
  delete next.duress;
  return next;
}

/**
 * The setting from a record, after a live check: { setting, record } where record
 * is non-null when the stored record should be replaced (a plaintext setting from an
 * earlier release, sealed now). Anything unreadable counts as "off".
 */
export async function openDuress(Suite, key, record) {
  if (!key || !record) return { setting: { ...DEFAULT }, record: null };
  // Written by an earlier release in the clear: seal it and drop the plaintext.
  if (record.duress && typeof record.duress === "object") {
    const setting = normalize(record.duress);
    try { return { setting, record: await sealDuress(Suite, key, record, setting) }; }
    catch { return { setting, record: null }; }
  }
  if (!record.duressSealed) return { setting: { ...DEFAULT }, record: null };
  try { return { setting: normalize(await Suite.openSetting(key, fromB64(record.duressSealed))), record: null }; }
  catch { return { setting: { ...DEFAULT }, record: null }; }
}

/**
 * Is this unlock a duress unlock? `used` is what the Lock screen saw: false (plain
 * unlock), "hold" or "taps" (that gesture was made), or true (an earlier screen, or
 * reconnecting from a decoy session: "the duress gesture, whichever it is").
 */
export function isDuress(setting, used) {
  const s = normalize(setting);
  if (!s.enabled || !used) return false;
  return used === true || used === s.gesture;
}
