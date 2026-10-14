// AES and AES-CMAC (NIST SP 800-38B / RFC 4493) for PACE with AES secure messaging.
import { ecb, cbc } from "@noble/ciphers/aes.js";

export const aesEcbBlock = (key, block) => ecb(key, { disablePadding: true }).encrypt(block);
export const aesCbc = (key, data, decrypt = false, iv = new Uint8Array(16)) => {
  const c = cbc(key, iv, { disablePadding: true });
  return decrypt ? c.decrypt(data) : c.encrypt(data);
};

function dbl(b) {
  const out = new Uint8Array(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) { out[i] = ((b[i] << 1) | carry) & 255; carry = b[i] >> 7; }
  if (b[0] & 0x80) out[15] ^= 0x87;
  return out;
}

export function cmac(key, data) {
  const L = aesEcbBlock(key, new Uint8Array(16));
  const k1 = dbl(L), k2 = dbl(k1);
  const n = Math.max(1, Math.ceil(data.length / 16));
  const complete = data.length > 0 && data.length % 16 === 0;
  const last = new Uint8Array(16);
  const tail = data.subarray((n - 1) * 16);
  if (complete) for (let i = 0; i < 16; i++) last[i] = tail[i] ^ k1[i];
  else { last.set(tail); last[tail.length] = 0x80; for (let i = 0; i < 16; i++) last[i] ^= k2[i]; }
  let x = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) { const y = new Uint8Array(16); for (let j = 0; j < 16; j++) y[j] = x[j] ^ data[i * 16 + j]; x = aesEcbBlock(key, y); }
  for (let j = 0; j < 16; j++) last[j] ^= x[j];
  return aesEcbBlock(key, last);
}
