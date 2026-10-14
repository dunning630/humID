// Access passes: our RFC 9474 implementation against OpenSSL and against
// Cloudflare's independent implementation, in both directions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { verify as nodeVerify, createPublicKey, constants, webcrypto } from "node:crypto";
import { RSABSSA } from "@cloudflare/blindrsa-ts";
import {
  blind, finalize, verifyPass, importKey, importKeySet, spentId, unb64u, b64u,
  newAccessCode, parseAccessCode, accessCodeHash, MAX_KEYS,
} from "@humid/pass";
import { newIssuerKey, blindSign, KEY_BITS } from "@humid/pass/issuer";
import { simIssuerKey, blindSignJwk } from "@humid/pass/jwk";

const key = newIssuerKey(2048);   // fast for tests; servers use KEY_BITS
const cf = RSABSSA.SHA384.PSS.Randomized();
const cfKeys = async (k) => ({
  sk: await webcrypto.subtle.importKey("pkcs8", Buffer.from(k.pem.replace(/-----[^-]+-----|\s/g, ""), "base64"), { name: "RSA-PSS", hash: "SHA-384" }, true, ["sign"]),
  pk: await webcrypto.subtle.importKey("jwk", { kty: "RSA", n: k.pub.n64, e: k.pub.e64, alg: "PS384", ext: true }, { name: "RSA-PSS", hash: "SHA-384" }, true, ["verify"]),
});

test("issue, finalize, verify; the pass is a valid RSASSA-PSS signature for OpenSSL too", () => {
  const { blinded, draft } = blind(key.pub);
  const pass = finalize(key.pub, draft, blindSign(key, blinded));
  assert.ok(verifyPass(key.pub, pass));
  assert.ok(nodeVerify("sha384", unb64u(pass.input), { key: createPublicKey(key.sk), padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }, unb64u(pass.sig)));
  assert.equal(KEY_BITS, 4096);
});

test("cross-implementation: our client with Cloudflare's signer and verifier", async () => {
  const { sk, pk } = await cfKeys(key);
  const { blinded, draft } = blind(key.pub);
  const pass = finalize(key.pub, draft, await cf.blindSign(sk, blinded));
  assert.ok(await cf.verify(pk, unb64u(pass.sig), unb64u(pass.input)));
});

test("cross-implementation: Cloudflare's client with our signer and verifier", async () => {
  const { pk } = await cfKeys(key);
  const input = unb64u(blind(key.pub).draft.input); // a well-formed HumID pass message
  const { blindedMsg, inv } = await cf.blind(pk, input);
  const sig = await cf.finalize(pk, input, blindSign(key, blindedMsg), inv);
  assert.ok(verifyPass(key.pub, { v: 1, kid: key.id, input: b64u(input), sig: b64u(sig) }));
});

test("the simulation signer matches OpenSSL bit for bit", () => {
  const jwkKey = simIssuerKey(key.sk.export({ format: "jwk" }));
  const { blinded } = blind(key.pub);
  assert.deepEqual(blindSignJwk(jwkKey, blinded), blindSign(key, blinded));
});

test("blindness: what the server signed shares nothing with the pass it later sees", () => {
  const { blinded, draft } = blind(key.pub);
  const pass = finalize(key.pub, draft, blindSign(key, blinded));
  const seen = Buffer.from(blinded).toString("hex");
  assert.ok(!seen.includes(Buffer.from(unb64u(pass.input)).toString("hex").slice(0, 32)));
  assert.notEqual(Buffer.from(unb64u(pass.sig)).toString("hex"), Buffer.from(blindSign(key, blinded)).toString("hex"));
  // the spent id is a hash of the pass, never of the blinded request
  assert.equal(spentId(pass).length, 64);
});

test("a retried request gets the same answer, so a crash mid-payment doesn't lose the pass", () => {
  const { blinded, draft } = blind(key.pub);
  const a = finalize(key.pub, draft, blindSign(key, blinded));
  const b = finalize(key.pub, draft, blindSign(key, blinded));
  assert.deepEqual(a, b);
});

test("forgeries and tampering are refused", () => {
  const { blinded, draft } = blind(key.pub);
  const pass = finalize(key.pub, draft, blindSign(key, blinded));
  const other = newIssuerKey(2048);
  assert.equal(verifyPass(other.pub, { ...pass, kid: other.id }), false, "pass bound to its key id");
  const bad = unb64u(pass.sig); bad[10] ^= 1;
  assert.equal(verifyPass(key.pub, { ...pass, sig: b64u(bad) }), false);
  const inp = unb64u(pass.input); inp[60] ^= 1;
  assert.equal(verifyPass(key.pub, { ...pass, input: b64u(inp) }), false);
  assert.equal(verifyPass(key.pub, { ...pass, v: 2 }), false);
  // a garbage blind signature is caught by the app, not spent later
  assert.throws(() => finalize(key.pub, draft, new Uint8Array(key.pub.k).fill(7)), /did not check out|malformed/);
  // the server refuses out-of-range input
  assert.throws(() => blindSign(key, new Uint8Array(key.pub.k).fill(0xff)), /out of range/);
});

test("key set rules: id commits to the key, at most MAX_KEYS, exactly one issuing", () => {
  const k2 = newIssuerKey(2048), k3 = newIssuerKey(2048);
  const v = (k, issuing = false) => ({ ...k.publicView, issuing });
  assert.equal(importKeySet([v(key, true), v(k2)]).issuing.id, key.id);
  assert.throws(() => importKeySet([v(key, true), v(k2), v(k3)]), /more pass keys/);
  assert.equal(MAX_KEYS, 2);
  assert.throws(() => importKeySet([v(key), v(k2)]), /exactly one issuing/);
  assert.throws(() => importKey({ ...key.publicView, id: k2.id }), /does not match/);
  assert.throws(() => importKey({ n: b64u(new Uint8Array(128).fill(0xab)), e: "AQAB" }), /too small/);
});

test("access codes: format, typo detection, lookalike letters, hashing", () => {
  const code = newAccessCode();
  assert.match(code, /^HA-([0-9A-HJKMNP-TV-Z]{4}-){5}[0-9A-HJKMNP-TV-Z]{4}$/);
  const p = parseAccessCode(code);
  assert.ok(p);
  assert.equal(parseAccessCode(code.toLowerCase().replace(/-/g, " ")), p);
  assert.equal(parseAccessCode(p), p, "without the HA- prefix");
  const typo = code.slice(0, 5) + (code[5] === "0" ? "1" : "0") + code.slice(6);
  assert.equal(parseAccessCode(typo), null);
  assert.equal(parseAccessCode("HA-1234"), null);
  assert.equal(accessCodeHash(p).length, 64);
  assert.notEqual(newAccessCode(), code);
});
