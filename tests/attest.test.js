// @humid/attest: proving a liveness key needs a live biometric.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate, randomBytes, generateKeyPairSync } from "node:crypto";
import {
  readAndroidAttestation, checkAndroidPolicy, verifyAndroidKey, verifyAppAttest, verifyLiveKey, verifyLiveSig,
  appAttestClientData, decodeCbor, GOOGLE_ATTESTATION_ROOTS, APPLE_APP_ATTEST_ROOT,
} from "@humid/attest";
import { testRoot, androidChain, appAttestation, liveKey } from "./support/pki.js";

const FIX = new URL("./fixtures/android-attestation/", import.meta.url);
const chainOf = (dir) => readdirSync(new URL(dir + "/", FIX)).sort().map((f) => new X509Certificate(readFileSync(new URL(`${dir}/${f}`, FIX))).raw);

/* ---------------- real devices' format ---------------- */

test("parses Google's sample attestation chains (TEE and StrongBox) the way Google's own library does", () => {
  for (const [dir, level] of [["algorithm_EC_SecurityLevel_TEE", 1], ["algorithm_EC_SecurityLevel_StrongBox", 2], ["algorithm_RSA_SecurityLevel_TEE", 1]]) {
    const chain = chainOf(dir);
    const root = new X509Certificate(chain[chain.length - 1]).toString();
    const r = readAndroidAttestation({ chain, roots: [root], now: new Date("2019-06-01") });
    assert.equal(r.attestationVersion, 3);
    assert.equal(r.keymasterVersion, 4);
    assert.equal(r.attestationSecurityLevel, level);
    assert.equal(Buffer.from(r.challenge).toString(), "abc");
    assert.ok(r.app.packages.includes("android"));
  }
});

test("Google's sample keys don't qualify as liveness keys: they need no authentication", () => {
  const chain = chainOf("algorithm_EC_SecurityLevel_StrongBox");
  const root = new X509Certificate(chain[chain.length - 1]).toString();
  const r = readAndroidAttestation({ chain, roots: [root], now: new Date("2019-06-01") });
  assert.throws(() => checkAndroidPolicy(r, { challenge: Buffer.from("abc"), requireLockedBoot: false }), (e) => e.code === "no_biometric");
});

test("the pinned production roots are Google's two roots and Apple's App Attest root", () => {
  const g = GOOGLE_ATTESTATION_ROOTS.map((p) => new X509Certificate(p));
  assert.equal(g.length, 2);
  for (const c of g) assert.ok(c.verify(c.publicKey));
  assert.deepEqual(g.map((c) => c.publicKey.asymmetricKeyType).sort(), ["ec", "rsa"]);
  assert.match(g.find((c) => c.publicKey.asymmetricKeyType === "ec").subject, /Key Attestation CA1/);
  const a = new X509Certificate(APPLE_APP_ATTEST_ROOT);
  assert.match(a.subject, /Apple App Attestation Root CA/);
  assert.equal(a.fingerprint256, "1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32");
});

test("a chain from an unknown root is refused even if everything else is perfect", () => {
  const root = testRoot();
  const challenge = randomBytes(32);
  const { chain } = androidChain({ root, challenge });
  assert.throws(() => verifyAndroidKey({ chain, challenge, packageNames: ["app.humid.vault"] }), (e) => e.code === "untrusted_root");
});

/* ---------------- Android: HumID's rules ---------------- */

const root = testRoot();
const ok = (over = {}, policy = {}) => {
  const challenge = randomBytes(32);
  const { chain, pub } = androidChain({ root, challenge, ...over });
  return () => ({ pub, ...verifyAndroidKey({ chain, challenge: policy.challenge ?? challenge, roots: [root.pem], packageNames: ["app.humid.vault"], ...policy }) });
};

test("android: a biometric-only, per-use key in secure hardware is accepted", () => {
  const r = ok()();
  assert.equal(r.proof, "android-tee");
  assert.equal(ok({ level: 2 })().proof, "android-strongbox");
  assert.equal(ok({ curve: null })().proof, "android-tee"); // StrongBox without EC_CURVE, key itself is P-256
});

test("android: keys that also accept a PIN or password are refused", () => {
  assert.throws(ok({ userAuthType: 3 }), (e) => e.code === "pin_allowed");
  assert.throws(ok({ userAuthType: 1 }), (e) => e.code === "pin_allowed");
});

test("android: keys usable without authentication, or for a while after one, are refused", () => {
  assert.throws(ok({ noAuthRequired: true }), (e) => e.code === "no_biometric");
  assert.throws(ok({ userAuthType: null }), (e) => e.code === "no_biometric");
  assert.throws(ok({ authTimeout: 30 }), (e) => e.code === "not_per_use");
  assert.throws(ok({ allowWhileOnBody: true }), (e) => e.code === "not_per_use");
});

test("android: software keys, wrong session, wrong app and unlocked phones are refused", () => {
  assert.throws(ok({ level: 0 }), (e) => e.code === "software_key");
  assert.throws(ok({}, { challenge: randomBytes(32) }), (e) => e.code === "wrong_challenge");
  assert.throws(ok({ packageName: "com.example.bot" }), (e) => e.code === "wrong_app");
  assert.throws(ok({ deviceLocked: false }), (e) => e.code === "unlocked_device");
  assert.throws(ok({ bootState: 2 }), (e) => e.code === "unlocked_device");
  assert.throws(ok({ purposes: [3] }), (e) => e.code === "bad_key");
});

test("android: a tampered certificate breaks the chain", () => {
  const challenge = randomBytes(32);
  const { chain } = androidChain({ root, challenge });
  const leaf = Buffer.from(chain[0]);
  leaf[leaf.length - 10] ^= 1; // flip a bit in the signature
  assert.throws(() => verifyAndroidKey({ chain: [leaf, ...chain.slice(1)], challenge, roots: [root.pem] }), (e) => e.code === "bad_attestation");
});

/* ---------------- Apple App Attest ---------------- */

const apple = testRoot("HumID Test App Attest Root");
const APP = "TEAM123456.app.humid.vault";

test("apple: an App Attest attestation for this session and key is accepted", () => {
  const cdh = randomBytes(32);
  const r = verifyAppAttest({ attestation: appAttestation({ root: apple, clientDataHash: cdh }), clientDataHash: cdh, appId: APP, roots: [apple.pem] });
  assert.equal(r.proof, "apple-secure-enclave");
  assert.ok(decodeCbor(appAttestation({ root: apple, clientDataHash: cdh })) instanceof Map);
});

test("apple: wrong session, app, environment, counter, key id or root are refused", () => {
  const cdh = randomBytes(32);
  const v = (over = {}, opts = {}) => () => verifyAppAttest({ attestation: appAttestation({ root: apple, clientDataHash: cdh, ...over }), clientDataHash: cdh, appId: APP, roots: [apple.pem], ...opts });
  assert.doesNotThrow(v());
  assert.throws(v({}, { clientDataHash: randomBytes(32) }), (e) => e.code === "wrong_challenge");
  assert.throws(v({ appId: "OTHERTEAM.com.bot" }), (e) => e.code === "wrong_app");
  assert.throws(v({ environment: "development" }), (e) => e.code === "wrong_environment");
  assert.doesNotThrow(v({ environment: "development" }, { environment: "development" }));
  assert.throws(v({ counter: 1 }), (e) => e.code === "bad_attestation");
  assert.throws(v({ tamperKeyId: true }), (e) => e.code === "bad_attestation");
  assert.throws(v({}, { roots: [APPLE_APP_ATTEST_ROOT] }), (e) => e.code === "untrusted_root");
  assert.throws(v({}, { appId: undefined }), (e) => e.code === "not_configured");
});

/* ---------------- liveness keys and signatures ---------------- */

test("verifyLiveKey binds the attested key to the one the device presents", () => {
  const challenge = randomBytes(32);
  const a = androidChain({ root, challenge });
  const cfg = { roots: { android: [root.pem], apple: [apple.pem] }, androidPackages: ["app.humid.vault"], iosAppId: APP };
  assert.equal(verifyLiveKey({ pub: a.pub, attestation: { kind: "android-key", chain: a.chain } }, challenge, cfg).proof, "android-tee");
  const other = liveKey();
  assert.throws(() => verifyLiveKey({ pub: other.pub, attestation: { kind: "android-key", chain: a.chain } }, challenge, cfg), (e) => e.code === "bad_attestation");

  const se = liveKey();
  const object = appAttestation({ root: apple, clientDataHash: appAttestClientData(challenge, se.pub) });
  assert.equal(verifyLiveKey({ pub: se.pub, attestation: { kind: "apple-app-attest", object } }, challenge, cfg).proof, "apple-secure-enclave");
  assert.throws(() => verifyLiveKey({ pub: liveKey().pub, attestation: { kind: "apple-app-attest", object } }, challenge, cfg), (e) => e.code === "wrong_challenge");
  assert.throws(() => verifyLiveKey({ pub: se.pub }, challenge, cfg), (e) => e.code === "no_attestation");
});

test("liveness signatures verify only for the exact message and key", () => {
  const k = liveKey();
  const m = randomBytes(64);
  const sig = k.sign(m);
  assert.equal(verifyLiveSig(k.pub, m, sig), true);
  assert.equal(verifyLiveSig(k.pub, randomBytes(64), sig), false);
  assert.equal(verifyLiveSig(liveKey().pub, m, sig), false);
  assert.equal(verifyLiveSig(k.pub, m, null), false);
  const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey.export({ type: "spki", format: "der" });
  assert.equal(verifyLiveSig(p384, m, sig), false);
});
