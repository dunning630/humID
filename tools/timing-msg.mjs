#!/usr/bin/env node
// Timing check for the messaging primitives (security audit: "timing leaks in
// the post-quantum code", T3–T4: "add a timing test to CI").
//
// A dudect-style test: time ML-KEM-1024 decapsulation of VALID ciphertexts
// against RANDOM (invalid) ones under the same key, interleaved in random
// order, and compare the two distributions with Welch's t-test on cropped
// samples. |t| above 4.5 means the time depends on the secret path
// (KyberSlash-class leaks show up exactly like this). The same for X25519
// with two different secret scalars.
//
//   node tools/timing-msg.mjs [samples]          (default 20000)
//   npm run test:timing
//
// Exits 1 on a detected difference. Runs against whichever backend
// @humid/msg is using; the JS reference makes no constant-time promise, which
// is why the app swaps in the platform's code (see packages/msg/src/backend.js).
// Shared CI runners are noisy: treat a pass as "no leak seen at this sample
// size", never as proof of constant time.

import { backend } from "@humid/msg";

const N = Number(process.argv[2] || 20000);
const THRESHOLD = 4.5;
const b = backend();
const ns = () => process.hrtime.bigint();

function welch(x, y) {
  const crop = (a) => { const s = [...a].sort((p, q) => p - q); return s.slice(0, Math.floor(s.length * 0.9)); };
  const [a, c] = [crop(x), crop(y)];
  const m = (v) => v.reduce((s, z) => s + z, 0) / v.length;
  const va = (v, mu) => v.reduce((s, z) => s + (z - mu) ** 2, 0) / (v.length - 1);
  const [ma, mc] = [m(a), m(c)];
  return (ma - mc) / Math.sqrt(va(a, ma) / a.length + va(c, mc) / c.length);
}

function measure(name, setup, op) {
  const classes = [[], []];
  const inputs = [setup(0), setup(1)];
  for (let i = 0; i < 200; i++) op(inputs[i & 1]); // warm up the JIT
  for (let i = 0; i < N; i++) {
    const k = Math.random() < 0.5 ? 0 : 1;
    const t0 = ns(); op(inputs[k]); const t1 = ns();
    classes[k].push(Number(t1 - t0));
  }
  const t = welch(classes[0], classes[1]);
  const ok = Math.abs(t) < THRESHOLD;
  console.log(`${ok ? "ok  " : "LEAK"}  ${name.padEnd(42)} t = ${t.toFixed(2)}  (${classes[0].length} / ${classes[1].length} samples)`);
  return ok;
}

const kp = b.kem.keygen(globalThis.crypto.getRandomValues(new Uint8Array(64)));
const valid = b.kem.encapsulate(kp.publicKey).cipherText;
const invalid = globalThis.crypto.getRandomValues(new Uint8Array(valid.length));
const xPk = b.x25519.publicKey(globalThis.crypto.getRandomValues(new Uint8Array(32)));
const sk0 = new Uint8Array(32); sk0[0] = 8;           // low-weight scalar
const sk1 = new Uint8Array(32).fill(0xff); sk1[0] = 0xf8; // high-weight scalar

console.log(`backend: ${b.name}, samples per test: ${N}`);
const results = [
  measure("ML-KEM-1024 decapsulate: valid vs random ct", (k) => (k ? invalid : valid), (ct) => b.kem.decapsulate(ct, kp.secretKey)),
  measure("X25519: low- vs high-weight secret", (k) => (k ? sk1 : sk0), (sk) => b.x25519.shared(sk, xPk)),
];
process.exit(results.every(Boolean) ? 0 : 1);
