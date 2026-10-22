// What the relay sees: opaque objects of a few fixed sizes, posted to random
// 128-bit mailbox ids. Invites, contact requests and messages share one framing
// (a version byte, then ciphertext) and the same size classes. The size class
// still hints at the kind (invites 64 KiB, requests 128 KiB, messages usually
// 8 KiB), and a request carries its ephemeral X25519 key in the clear.

import { MsgError, u32, readU32, mac, label, toHex, dayOf, H, random } from "./util.js";

export const WIRE_VERSION = 1;

/** Every wire object is exactly one of these sizes (bytes). */
export const BUCKETS = Object.freeze([
  4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304,
]);
export const MAX_WIRE = BUCKETS[BUCKETS.length - 1];
export const isWireSize = (n) => BUCKETS.includes(n);

/**
 * Pad `bytes` so that `overhead + padded` is exactly a bucket size.
 * Layout: u32 length || bytes || zeros.
 */
export function pad(bytes, overhead) {
  const need = overhead + 4 + bytes.length;
  const size = BUCKETS.find((b) => b >= need);
  if (!size) throw new MsgError("too_large", "Message too large to send");
  const out = new Uint8Array(size - overhead);
  out.set(u32(bytes.length), 0);
  out.set(bytes, 4);
  return out;
}

export function unpad(padded) {
  if (padded.length < 4) throw new MsgError("malformed", "Padding too short");
  const n = readU32(padded, 0);
  if (n > padded.length - 4) throw new MsgError("malformed", "Padding length out of range");
  let z = 0;
  for (let i = 4 + n; i < padded.length; i++) z |= padded[i];
  if (z) throw new MsgError("malformed", "Padding is not zero");
  return padded.subarray(4, 4 + n);
}

export function checkWire(wire) {
  if (!(wire instanceof Uint8Array) || !isWireSize(wire.length)) throw new MsgError("malformed", "Not a wire object");
  if (wire[0] !== WIRE_VERSION) throw new MsgError("unsupported_version", "Made by a newer HumID");
}

/* ---------- mailbox ids ---------- */

export const BOX_RE = /^[0-9a-f]{32}$/;
export const isBox = (s) => typeof s === "string" && BOX_RE.test(s);

/**
 * A conversation direction's mailbox for one UTC day. The relay sees a fresh
 * random-looking id every day, unlinkable to yesterday's without the key.
 */
export const boxFor = (boxKey, day) => toHex(mac(boxKey, Uint8Array.of(...label("box"), ...u32(day)))).slice(0, 32);

/** Days a receiver polls: yesterday, today, tomorrow (clock skew between phones). */
export const pollDays = (now) => { const d = dayOf(now); return [d - 1, d, d + 1]; };

/* ---------- unsend tokens ----------
 * Every object a phone posts comes with a random 16-byte unsend token, kept on
 * the phone. The relay stores only SHA3(token) beside the object. Showing the
 * token later removes the object if it hasn't been fetched yet, and only the
 * sender ever has the token. The tag is random per object, so it links nothing.
 */
export const RETRACT_BYTES = 16;
export const TAG_RE = /^[0-9a-f]{64}$/;
export const retractTag = (token) => toHex(H(label("retract"), token));
export function newRetract() {
  const retract = random(RETRACT_BYTES);
  return { retract, retractTag: retractTag(retract) };
}
