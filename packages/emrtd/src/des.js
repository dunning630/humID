// DES and two-key triple DES, as ICAO 9303 BAC secure messaging needs them:
// 3DES-CBC with a zero IV, and the ISO/IEC 9797-1 MAC algorithm 3 ("retail
// MAC"). Small and slow on purpose: a passport read moves a few kilobytes.
// Only used for documents that predate PACE with AES.

const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const S = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];

const bits = (bytes) => { const b = new Uint8Array(bytes.length * 8); for (let i = 0; i < b.length; i++) b[i] = (bytes[i >> 3] >> (7 - (i & 7))) & 1; return b; };
const unbits = (b) => { const out = new Uint8Array(b.length >> 3); for (let i = 0; i < b.length; i++) out[i >> 3] |= b[i] << (7 - (i & 7)); return out; };
const permute = (src, table) => Uint8Array.from(table, (p) => src[p - 1]);

function subkeys(key8) {
  const k = permute(bits(key8), PC1);
  let c = k.slice(0, 28), d = k.slice(28);
  const out = [];
  for (const s of SHIFTS) {
    c = Uint8Array.from([...c.slice(s), ...c.slice(0, s)]);
    d = Uint8Array.from([...d.slice(s), ...d.slice(0, s)]);
    out.push(permute(Uint8Array.from([...c, ...d]), PC2));
  }
  return out;
}

function f(r, k) {
  const x = permute(r, E).map((v, i) => v ^ k[i]);
  const o = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const b = x.subarray(i * 6, i * 6 + 6);
    const v = S[i][(b[0] << 5 | b[5] << 4) | (b[1] << 3 | b[2] << 2 | b[3] << 1 | b[4])];
    for (let j = 0; j < 4; j++) o[i * 4 + j] = (v >> (3 - j)) & 1;
  }
  return permute(o, P);
}

function block(keys, input8, decrypt) {
  const ip = permute(bits(input8), IP);
  let l = ip.slice(0, 32), r = ip.slice(32);
  for (let i = 0; i < 16; i++) {
    const k = keys[decrypt ? 15 - i : i];
    const nr = f(r, k).map((v, j) => v ^ l[j]);
    l = r; r = nr;
  }
  return unbits(permute(Uint8Array.from([...r, ...l]), FP));
}

const cache = new Map();
const keysFor = (k) => { const h = Array.from(k).join(","); if (!cache.has(h)) { if (cache.size > 16) cache.clear(); cache.set(h, subkeys(k)); } return cache.get(h); };

export const desEncrypt = (key8, block8) => block(keysFor(key8), block8, false);
export const desDecrypt = (key8, block8) => block(keysFor(key8), block8, true);

const xor8 = (a, b) => Uint8Array.from(a, (v, i) => v ^ b[i]);
const tdes = (key16, b, dec) => {
  const k1 = key16.subarray(0, 8), k2 = key16.subarray(8, 16);
  return dec ? desDecrypt(k1, desEncrypt(k2, desDecrypt(k1, b))) : desEncrypt(k1, desDecrypt(k2, desEncrypt(k1, b)));
};

/** Two-key 3DES in CBC mode, IV zero (ICAO 9303), no padding: input must be a multiple of 8 bytes. */
export function tdesCbc(key16, data, decrypt = false, iv = new Uint8Array(8)) {
  if (data.length % 8) throw new Error("3DES-CBC input must be a multiple of 8 bytes");
  const out = new Uint8Array(data.length);
  let prev = iv;
  for (let i = 0; i < data.length; i += 8) {
    const b = data.subarray(i, i + 8);
    if (decrypt) { out.set(xor8(tdes(key16, b, true), prev), i); prev = b; }
    else { const c = tdes(key16, xor8(b, prev), false); out.set(c, i); prev = c; }
  }
  return out;
}

/** ISO/IEC 9797-1 MAC algorithm 3 with DES ("retail MAC"). Input already padded. 8-byte MAC. */
export function retailMac(key16, data) {
  if (data.length % 8) throw new Error("MAC input must be padded");
  const ka = key16.subarray(0, 8), kb = key16.subarray(8, 16);
  let h = new Uint8Array(8);
  for (let i = 0; i < data.length; i += 8) h = desEncrypt(ka, xor8(h, data.subarray(i, i + 8)));
  return desEncrypt(ka, desDecrypt(kb, h));
}

/** Set odd parity on each DES key byte. */
export const withParity = (k) => Uint8Array.from(k, (b) => { let x = b & 0xfe, n = 0; for (let i = 1; i < 8; i++) n += (x >> i) & 1; return x | (n % 2 ? 0 : 1); });
