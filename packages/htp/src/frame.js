// HTP/1 frames. Every call after the handshake is one frame each way:
//
//   header (37 bytes, authenticated as AES-GCM associated data)
//     "HTP" 0x01 | dir (0x01 request, 0x02 response) | sid (16) | seq (u64) | ts (u64 ms)
//   ciphertext = AES-256-GCM(key[dir], nonce = 0x00000000 || seq, plaintext)
//   plaintext  = u32 metaLength | meta JSON | body bytes
//
// Request meta: { m: method, p: path, h?: headers, proof?: step-up proof }
// Response meta: { s: status, h?: headers }
//
// Keys differ per direction, and the server's replay window guarantees each
// request seq is processed at most once, so a (key, nonce) pair never repeats.

import { concat, u32, u64, readU32, readU64, utf8, fromUtf8, aeadSeal, aeadOpen } from "./primitives.js";

export const MAGIC = new Uint8Array([0x48, 0x54, 0x50, 0x01]); // "HTP" v1
export const DIR = { request: 1, response: 2 };
export const HEADER_LEN = 4 + 1 + 16 + 8 + 8;
export const FRAME_SKEW_MS = 2 * 60 * 1000;
export const MEDIA_TYPE = "application/vnd.humid.htp";

const nonceFor = (seq) => concat(new Uint8Array(4), u64(seq));

export function header(dir, sid, seq, ts) {
  return concat(MAGIC, new Uint8Array([dir]), sid, u64(seq), u64(ts));
}

export function parseHeader(frame) {
  if (frame.length < HEADER_LEN + 16) throw new Error("HTP: frame too short");
  for (let i = 0; i < 4; i++) if (frame[i] !== MAGIC[i]) throw new Error("HTP: not an HTP/1 frame");
  return {
    dir: frame[4],
    sid: frame.subarray(5, 21),
    seq: readU64(frame, 21),
    ts: readU64(frame, 29),
    aad: frame.subarray(0, HEADER_LEN),
    ct: frame.subarray(HEADER_LEN),
  };
}

function pack(meta, body) {
  const m = utf8(JSON.stringify(meta));
  return concat(u32(m.length), m, body || new Uint8Array(0));
}

function unpack(plain) {
  const len = readU32(plain, 0);
  if (4 + len > plain.length) throw new Error("HTP: malformed payload");
  return { meta: JSON.parse(fromUtf8(plain.subarray(4, 4 + len))), body: plain.slice(4 + len) };
}

export async function sealFrame(key, dir, sid, seq, meta, body, ts = Date.now()) {
  const h = header(dir, sid, seq, ts);
  return concat(h, await aeadSeal(key, nonceFor(seq), pack(meta, body), h));
}

/** Decrypt a frame whose header was already checked. Throws on any tampering. */
export async function openFrame(key, parsed) {
  let plain;
  try { plain = await aeadOpen(key, nonceFor(parsed.seq), parsed.ct, parsed.aad); }
  catch { throw new Error("HTP: frame failed authentication"); }
  return unpack(plain);
}
