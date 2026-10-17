// A bounded zip reader for .pkpass files. A pass comes from outside (a share sheet,
// a download), so everything is checked before it's trusted: sizes and counts are
// capped before anything is inflated, inflating stops at the size the archive claimed,
// names that could escape a folder or hide a file are refused, and every file's CRC
// must match. Only "stored" and "deflate" entries, no encryption, no zip64.

export class WalletError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, message) => { throw new WalletError(code, message); };

// files: a pass with many languages has a folder (and strings and images) per language
export const LIMITS = Object.freeze({ archive: 20 * 1024 * 1024, files: 256, entries: 1024, file: 10 * 1024 * 1024, total: 20 * 1024 * 1024, name: 200 });

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

let CRC_TABLE = null;
export function crc32(bytes) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_TABLE[n] = c >>> 0; }
  }
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A file name that stays where it's put: no folders climbing out, no absolute paths, no odd characters. */
function safeName(name, max) {
  if (!name || name.length > max) return false;
  if (/[\u0000-\u001f\u007f\\:*?"<>|]/.test(name)) return false;
  if (name.startsWith("/")) return false;
  const parts = name.split("/");
  return parts.every((p) => p && p !== "." && p !== "..");
}

async function inflate(data, expected, cap) {
  if (typeof DecompressionStream !== "function") fail("unsupported", "This device can't unpack passes.");
  const out = new Uint8Array(expected);
  let n = 0;
  const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (n + value.length > expected || n + value.length > cap) fail("bad_zip", "A file in the pass is bigger than it says.");
      out.set(value, n); n += value.length;
    }
  } catch (e) {
    if (e instanceof WalletError) throw e;
    fail("bad_zip", "A file in the pass is damaged.");
  } finally { reader.cancel().catch(() => {}); }
  if (n !== expected) fail("bad_zip", "A file in the pass is shorter than it says.");
  return out;
}

/** bytes → Map(name → Uint8Array). Folders are skipped; every file is checked. */
export async function readZip(bytes, limits = LIMITS) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b.length > limits.archive) fail("too_big", "That pass is too big.");
  if (b.length < 22) fail("bad_zip", "That isn't a pass (not a zip archive).");
  // End of central directory: the last 22 bytes, or before a comment of up to 64 KB.
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 0xffff); i--) {
    if (u32(b, i) === 0x06054b50 && i + 22 + u16(b, i + 20) === b.length) { eocd = i; break; }
  }
  if (eocd < 0) fail("bad_zip", "That isn't a pass (not a zip archive).");
  const disk = u16(b, eocd + 4), cdDisk = u16(b, eocd + 6), here = u16(b, eocd + 8), count = u16(b, eocd + 10);
  const cdSize = u32(b, eocd + 12), cdOff = u32(b, eocd + 16);
  if (disk || cdDisk || here !== count) fail("bad_zip", "Split archives aren't passes.");
  if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) fail("bad_zip", "That archive format isn't used for passes.");
  if (count > limits.entries) fail("too_big", "That pass has too many files.");
  if (cdOff + cdSize > eocd) fail("bad_zip", "The pass's file list is damaged.");

  const entries = [];
  let p = cdOff, total = 0;
  for (let k = 0; k < count; k++) {
    if (p + 46 > cdOff + cdSize || u32(b, p) !== 0x02014b50) fail("bad_zip", "The pass's file list is damaged.");
    const flags = u16(b, p + 8), method = u16(b, p + 10), crc = u32(b, p + 16);
    const csize = u32(b, p + 20), usize = u32(b, p + 24);
    const nlen = u16(b, p + 28), xlen = u16(b, p + 30), clen = u16(b, p + 32), local = u32(b, p + 42);
    if (p + 46 + nlen + xlen + clen > cdOff + cdSize) fail("bad_zip", "The pass's file list is damaged.");
    const name = new TextDecoder("utf-8", { fatal: false }).decode(b.subarray(p + 46, p + 46 + nlen));
    p += 46 + nlen + xlen + clen;
    if (name.endsWith("/")) continue; // a folder: not counted as a file
    if (flags & 1) fail("bad_zip", "Encrypted passes aren't supported.");
    if (method !== 0 && method !== 8) fail("bad_zip", "That pass uses an unsupported compression.");
    if (!safeName(name, limits.name)) fail("bad_zip", "That pass has a file with an unsafe name.");
    if (usize > limits.file) fail("too_big", "A file in that pass is too big.");
    total += usize;
    if (total > limits.total) fail("too_big", "That pass is too big once unpacked.");
    entries.push({ name, method, crc, csize, usize, local });
    if (entries.length > limits.files) fail("too_big", "That pass has too many files.");
  }

  const files = new Map();
  for (const e of entries) {
    if (files.has(e.name)) fail("bad_zip", "That pass has the same file twice.");
    const o = e.local;
    if (o + 30 > b.length || u32(b, o) !== 0x04034b50) fail("bad_zip", "A file in the pass is damaged.");
    const ln = u16(b, o + 26), lx = u16(b, o + 28);
    const localName = new TextDecoder().decode(b.subarray(o + 30, o + 30 + ln));
    if (localName !== e.name) fail("bad_zip", "A file in the pass is damaged.");
    const start = o + 30 + ln + lx;
    if (start + e.csize > b.length) fail("bad_zip", "A file in the pass is cut short.");
    const raw = b.subarray(start, start + e.csize);
    let data;
    if (e.method === 0) {
      if (e.csize !== e.usize) fail("bad_zip", "A file in the pass is damaged.");
      data = raw.slice();
    } else data = await inflate(raw, e.usize, limits.file);
    if (crc32(data) !== e.crc) fail("bad_zip", "A file in the pass is damaged (checksum).");
    files.set(e.name, data);
  }
  return files;
}
