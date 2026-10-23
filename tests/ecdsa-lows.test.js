// ATT-01 / LIVE-03: a liveness signature has exactly one accepted encoding.
// For any valid ECDSA signature (r, s), (r, n − s) is valid too, and anyone who
// sees one can write the other without the key. Servers accept only low-S, and
// the app's native gate hands over the low-S form whatever the chip returned.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { verifyLiveSig, isLowS, ecdsaRS, P256_N } from "@humid/attest";
import { lowS } from "../packages/gate/src/lows.js";
import { liveKey, highS } from "./support/pki.js";

const proofHash = (b) => createHash("sha3-256").update(b).digest("hex").slice(0, 32);

test("ATT-01: verifyLiveSig refuses the high-S twin of a valid liveness signature", () => {
  const k = liveKey();
  const msg = Buffer.from("HTP/1 live v2 — a step-up the holder approved");
  const sig = k.sign(msg);
  assert.equal(verifyLiveSig(k.pub, msg, sig), true, "the real signature verifies");
  const twin = highS(sig);
  assert.notDeepEqual(twin, sig, "a different byte string…");
  assert.notEqual(proofHash(twin), proofHash(sig), "…that would record as a different proof");
  assert.equal(ecdsaRS(twin).r, ecdsaRS(sig).r);
  assert.equal(verifyLiveSig(k.pub, msg, twin), false, "only the low-S form is accepted");
});

test("lowS: the native gate's normaliser turns either form into the one servers accept", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  let high = 0;
  for (let i = 0; i < 64; i++) {
    const m = Buffer.from(`challenge ${i}`);
    const raw = nodeSign("sha256", m, privateKey); // like a phone's chip: either form
    if (!isLowS(raw)) high++;
    const n = lowS(raw);
    assert.equal(isLowS(n), true);
    assert.equal(verifyLiveSig(spki, m, n), true);
    assert.deepEqual(Buffer.from(lowS(n)), Buffer.from(n), "already low: unchanged");
    assert.deepEqual(Buffer.from(lowS(highS(n))), Buffer.from(n), "high → the same low form");
  }
  assert.ok(high > 0, "the signer did produce high-S signatures to normalise");
});

test("isLowS refuses malformed DER: non-minimal integers, trailing bytes, out of range", () => {
  const k = liveKey();
  const sig = Buffer.from(k.sign(Buffer.from("x")));
  assert.equal(isLowS(sig), true);
  assert.equal(isLowS(Buffer.concat([sig, Buffer.from([0])])), false, "trailing byte");
  const { r, s } = ecdsaRS(sig);
  const int = (b) => Buffer.concat([Buffer.from([2, b.length]), b]);
  const be = (x) => { let h = x.toString(16); if (h.length % 2) h = "0" + h; return Buffer.from(h, "hex"); };
  const der = (a, b) => { const body = Buffer.concat([a, b]); return Buffer.concat([Buffer.from([0x30, body.length]), body]); };
  const padded = Buffer.concat([Buffer.from([0, 0]), be(s)]); // extra leading zeros
  assert.equal(isLowS(der(int(be(r)), int(padded))), false, "non-minimal s");
  assert.equal(isLowS(der(int(be(r)), int(Buffer.from([0])))), false, "s = 0");
  assert.equal(isLowS(der(int(Buffer.concat([Buffer.from([0]), be(P256_N)])), int(be(s)))), false, "r = n");
  assert.equal(isLowS(null), false);
  assert.equal(verifyLiveSig(k.pub, Buffer.from("x"), Buffer.concat([sig, Buffer.from([0])])), false);
});
