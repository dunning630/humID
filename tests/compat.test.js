// Proves @humid/crypto is byte-compatible with the original single-file
// HumID Vault: same keys from the same seed, same identity commit, and
// envelopes/seed-wraps cross-open in both directions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { suite } from "@humid/crypto";
import { toB64, fromB64 } from "@humid/codec";

createRequire(import.meta.url)("./fixtures/original-crypto.cjs");
const O = globalThis.__orig;
const S = suite("HUMID-PQ1");
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const eq = (a, b) => assert.equal(toB64(a), toB64(b));

test("same seed derives identical key pairs", () => {
  const seed = rnd(64);
  const a = O.To(seed), b = S.deriveKeys(seed);
  for (const k of ["kemPk", "kemSk", "dsaPk", "dsaSk", "xPk", "xSk"]) eq(a[k], b[k]);
});

test("identity commit matches", () => {
  const seed = rnd(64), cred = rnd(16);
  const pub = S.publicOf(S.deriveKeys(seed));
  eq(O.es(O.ts(O.To(seed)), O.fe.sha3_256(cred)), S.identityCommit(pub, S.sha3_256(cred)));
});

test("seed wraps cross-open both ways", async () => {
  const secret = rnd(32), seed = rnd(64), aad = rnd(16);
  eq(await S.unwrapSeed(secret, await O.ns(secret, seed, aad), aad), seed);
  eq(await O.os(secret, await S.wrapSeed(secret, seed, aad), aad), seed);
});

const interrupt = { method: "test", purpose: "seal", up: true, uv: true, at: new Date().toISOString() };

test("original envelope opens with new module", async () => {
  const keys = S.deriveKeys(rnd(64));
  const file = { bytes: rnd(5000), name: "a.bin", type: "application/x-test" };
  const original = new Uint8Array(file.bytes);
  const { envelope } = await O.cs(file, keys, { kemPk: keys.kemPk, xPk: keys.xPk }, { identityCommit: "c", interrupt });
  assert.equal(S.verify(envelope).ok, true);
  const out = await S.open(envelope, keys);
  eq(out.bytes, original);
  assert.equal(out.meta.name, "a.bin");
});

test("new envelope opens with original app", async () => {
  const keys = S.deriveKeys(rnd(64));
  const bytes = rnd(5000);
  const { envelope, manifest } = await S.seal({ bytes: new Uint8Array(bytes), name: "b.txt", type: "text/plain" }, keys, keys, { identityCommit: "c", interrupt });
  assert.equal(O.Lo(envelope).ok, true);
  const out = await O.as(envelope, keys);
  eq(out.bytes, bytes);
  assert.deepEqual(out.manifest.interrupt, manifest.interrupt);
});

test("tampering is caught", async () => {
  const keys = S.deriveKeys(rnd(64));
  const { envelope } = await S.seal({ bytes: rnd(100), name: "c", type: "" }, keys, keys, { identityCommit: "c", interrupt });
  const bad = envelope.slice(); bad[bad.length - 1] ^= 1;
  assert.equal(S.verify(bad).ctOk, false);
  const other = S.deriveKeys(rnd(64));
  await assert.rejects(S.open(envelope, other), /not sealed to this identity/);
});

test("PC-03: a document sealed to you but signed by someone else doesn't open as your own", async () => {
  const me = S.deriveKeys(rnd(64));
  const server = S.deriveKeys(rnd(64)); // anyone holding my public keys
  const forged = await S.seal({ bytes: new TextEncoder().encode("I leave my entire estate to Mallory."), name: "Last will.txt", type: "text/plain" }, server, { kemPk: me.kemPk, xPk: me.xPk }, { identityCommit: "c", interrupt });
  assert.equal(S.verify(forged.envelope).ok, true, "the forgery is a valid envelope: that's the problem");
  await S.open(forged.envelope, me); // open alone can't tell
  await assert.rejects(S.openOwn(forged.envelope, me), (e) => e.code === "wrong_signer");
  const mine = await S.seal({ bytes: rnd(100), name: "ok", type: "" }, me, me, { identityCommit: "c", interrupt });
  assert.equal((await S.openOwn(mine.envelope, me)).meta.name, "ok");
  await assert.rejects(S.openOwn(mine.envelope, { ...me, dsaPk: undefined }), /signing key is needed/);
});
