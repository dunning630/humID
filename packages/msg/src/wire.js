// What the relay sees: opaque objects of a few fixed sizes, posted to random
// 128-bit mailbox ids. Invites, contact requests and messages all share one
// framing — a version byte, then bytes indistinguishable from random — and are
// padded to the same size classes, so the relay cannot tell them apart.

import { MsgError, u32, readU32, mac, label, toHex, dayOf } from "./util.js";

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
