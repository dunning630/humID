// @humid/attest: proving a liveness key needs a live biometric.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate, randomBytes, generateKeyPairSync } from "node:crypto";
import {
  readAndroidAttestation, checkAndroidPolicy, verifyAndroidKey, verifyAppAttest, verifyLiveKey, verifyLiveSig,
  appAttestClientData, decodeCbor, GOOGLE_ATTESTATION_ROOTS, APPLE_APP_ATTEST_ROOT, parseStatusList, revocationList, serialKey, readStatusFile, fetchStatusToFile, STATUS_MAX_AGE_MS,
  REVOKED_ANDROID_CERTS, HUMID_ANDROID_RELEASE_CERT,
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
  // they're also VERIFY keys, and need no authentication: either refusal is right
  assert.throws(() => checkAndroidPolicy(r, { challenge: Buffer.from("abc"), requireLockedBoot: false, packageNames: ["android"], allowAnySigner: true }), (e) => ["no_biometric", "bad_key"].includes(e.code));
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
const SIGNER = "01".repeat(32); // the test chains' app signing certificate digest
const ok = (over = {}, policy = {}) => {
  const challenge = randomBytes(32);
  const { chain, pub } = androidChain({ root, challenge, ...over });
  return () => ({ pub, ...verifyAndroidKey({ chain, challenge: policy.challenge ?? challenge, roots: [root.pem], packageNames: ["app.humid.vault"], signatureDigests: [SIGNER], ...policy }) });
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

test("android: only the release-signed HumID app counts; the server must know its certificate", () => {
  assert.throws(ok({ signer: Buffer.alloc(32, 9) }), (e) => e.code === "wrong_app", "a re-signed copy");
  assert.throws(ok({}, { signatureDigests: [] }), (e) => e.code === "not_configured", "no certificate configured: refuse, don't accept anyone");
  assert.throws(ok({}, { packageNames: [] }), (e) => e.code === "not_configured");
  assert.equal(ok({ signer: Buffer.alloc(32, 9) }, { signatureDigests: [], allowAnySigner: true })().proof, "android-tee", "test builds only, by explicit choice");
});

// PC-05: tools/android-test.keystore (password "android") is public, in the repository's history.
const LEAKED_TEST_CERT = "b066cd4564ac8446b02567e276992aacf64783004de81da3d3f1e51f3411928c";
test("android: the leaked test signing key is refused even if an operator allows it", () => {
  assert.ok(REVOKED_ANDROID_CERTS.includes(LEAKED_TEST_CERT));
  assert.ok(Object.isFrozen(REVOKED_ANDROID_CERTS), "the deny-list can't be changed at run time");
  assert.ok(!REVOKED_ANDROID_CERTS.includes(HUMID_ANDROID_RELEASE_CERT), "the release certificate isn't revoked");
  const leaked = { signer: Buffer.from(LEAKED_TEST_CERT, "hex") };
  // listed in HUMID_ANDROID_CERT_DIGESTS (lower or upper case, with the official one beside it)
  assert.throws(ok(leaked, { signatureDigests: [HUMID_ANDROID_RELEASE_CERT, LEAKED_TEST_CERT] }), (e) => e.code === "revoked_signer");
  assert.throws(ok(leaked, { signatureDigests: [LEAKED_TEST_CERT.toUpperCase(), LEAKED_TEST_CERT] }), (e) => e.code === "revoked_signer");
  // HUMID_ANDROID_ALLOW_ANY_SIGNER=1
  assert.throws(ok(leaked, { signatureDigests: [], allowAnySigner: true }), (e) => e.code === "revoked_signer");
  assert.throws(ok(leaked, { signatureDigests: [SIGNER], allowAnySigner: true }), (e) => e.code === "revoked_signer");
  // through verifyLiveKey, as services/identity calls it
  const challenge = randomBytes(32);
  const a = androidChain({ root, challenge, ...leaked });
  const cfg = { roots: { android: [root.pem] }, androidPackages: ["app.humid.vault"], androidDigests: [LEAKED_TEST_CERT], allowAnySigner: true };
  assert.throws(() => verifyLiveKey({ pub: a.pub, attestation: { kind: "android-key", chain: a.chain } }, challenge, cfg), (e) => e.code === "revoked_signer");
  // other signers are unaffected
  assert.equal(ok({}, { signatureDigests: [SIGNER] })().proof, "android-tee");
});

test("android: both security levels must be TEE or StrongBox; the key is for signing only", () => {
  assert.throws(ok({ kmLevel: 0 }), (e) => e.code === "software_key");
  assert.throws(ok({ level: 100, kmLevel: 100 }), (e) => e.code === "software_key", "KeyMint's KEYSTORE level isn't hardware");
  assert.throws(ok({ purposes: [2, 3] }), (e) => e.code === "bad_key", "sign and verify");
  assert.throws(ok({ purposes: [2, 7] }), (e) => e.code === "bad_key", "sign and attest-key");
  const r = ok({ level: 2, kmLevel: 2 })();
  assert.equal(r.level, "strongbox");
  assert.equal(r.keymasterLevel, "strongbox");
  assert.equal(r.unlockedDeviceRequired, true);
});

test("android: an optional minimum security patch", () => {
  assert.equal(ok({ osPatch: 202609 }, { minPatchLevel: 202601 })().osPatchLevel, 202609);
  assert.throws(ok({ osPatch: 202301 }, { minPatchLevel: 202601 }), (e) => e.code === "old_patch");
  assert.throws(ok({ osPatch: null }, { minPatchLevel: 202601 }), (e) => e.code === "old_patch");
});

test("android: an expired intermediate, or an issuer that isn't a CA, breaks the chain", () => {
  assert.throws(ok({ interNotAfter: new Date(Date.now() - 86400e3) }), (e) => e.code === "bad_attestation");
  assert.throws(ok({ interCa: false }), (e) => e.code === "bad_attestation");
});

test("android: a certificate on Google's revocation list is refused", () => {
  const challenge = randomBytes(32);
  const { chain } = androidChain({ root, challenge });
  const inter = new X509Certificate(Buffer.from(chain[1]));
  const revoked = new Set([serialKey(inter.serialNumber)]);
  assert.throws(() => verifyAndroidKey({ chain, challenge, roots: [root.pem], packageNames: ["app.humid.vault"], signatureDigests: [SIGNER], revokedSerials: revoked }), (e) => e.code === "revoked");
});

test("Google's status list: revoked and suspended count, leading zeros don't matter", async () => {
  const s = parseStatusList({ entries: { "00Ab12": { status: "REVOKED", reason: "KEY_COMPROMISE" }, "77": { status: "SUSPENDED" }, "88": { status: "VALID" } } });
  assert.deepEqual([...s].sort(), ["77", "ab12"]);
  assert.equal(serialKey("00AB12"), "ab12");
  assert.throws(() => parseStatusList({}));
  // the live copy: fetched, refreshed, and "required" refuses until there is one
  let body = { entries: { "1f": { status: "REVOKED" } } }, fail = true;
  const fetch = async () => (fail ? Promise.reject(new Error("offline")) : { ok: true, json: async () => body });
  const req = revocationList({ url: "https://example.test/status", fetch, required: true, refreshMs: 1e9 });
  await new Promise((r) => setImmediate(r));
  assert.throws(() => req.serials(), (e) => e.code === "status_unavailable");
  fail = false;
  await req.refresh();
  assert.ok(req.serials().has("1f"));
  fail = true;
  await req.refresh(); // a failed refresh keeps the last copy
  assert.ok(req.serials().has("1f"));
  req.stop();
  const opt = revocationList({ url: "https://example.test/status", fetch: async () => Promise.reject(new Error("x")), refreshMs: 1e9 });
  assert.equal(opt.serials().size, 0, "not required: an empty list until one arrives");
  opt.stop();
});

test("Google's status list: `required` also means fresh, and a file copy works like a fetched one", async () => {
  const { mkdtempSync, writeFileSync, rmSync, readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "humid-status-"));
  const file = join(dir, "s", "status.json");
  let t = Date.parse("2026-10-23T00:00:00Z");
  const now = () => t;
  try {
    // the sidecar writes it; anything that isn't a status list leaves the old copy alone
    await fetchStatusToFile({ file, now, fetch: async () => ({ ok: true, json: async () => ({ entries: { "0A": { status: "REVOKED" } } }) }) });
    await assert.rejects(fetchStatusToFile({ file, now, fetch: async () => ({ ok: true, json: async () => ({ nope: 1 }) }) }));
    await assert.rejects(fetchStatusToFile({ file, now, fetch: async () => ({ ok: false, status: 503 }) }));
    assert.ok(readStatusFile(readFileSync(file, "utf8"), now()).set.has("a"));
    const list = revocationList({ file, required: true, now, refreshMs: 1e9 });
    assert.ok(await list.refresh());
    assert.equal(list.source, "file");
    assert.ok(list.serials().has("a"));
    t += STATUS_MAX_AGE_MS - 1000;
    assert.ok(list.serials().has("a"), "just inside the maximum age");
    t += 2000;
    assert.throws(() => list.serials(), (e) => e.code === "status_stale", "required + stale: refused");
    assert.ok(list.serials({ required: false }).has("a"), "not required: the stale copy is still used");
    // a file dated in the future isn't believed
    writeFileSync(file, JSON.stringify({ fetchedAt: new Date(t + 3600_000).toISOString(), status: { entries: {} } }));
    assert.equal(await list.refresh(), false);
    assert.throws(() => list.serials(), (e) => e.code === "status_stale", "the bad file didn't refresh the age");
    list.stop();
    const missing = revocationList({ file: join(dir, "none.json"), required: true, now, refreshMs: 1e9 });
    await missing.refresh();
    assert.throws(() => missing.serials(), (e) => e.code === "status_unavailable");
    missing.stop();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("android: malformed attestation data is a refusal, never a crash", () => {
  const cfg = { roots: { android: [root.pem] }, androidPackages: ["app.humid.vault"], androidDigests: [SIGNER] };
  const k = liveKey();
  assert.throws(() => verifyLiveKey({ pub: k.pub, attestation: { kind: "android-key", chain: [Buffer.from([0x30, 0x82, 0xff]), Buffer.from([1])] } }, randomBytes(32), cfg), (e) => e.code === "bad_attestation");
  assert.throws(() => verifyLiveKey({ pub: k.pub, attestation: { kind: "apple-app-attest", object: Buffer.from([0xbf, 0xff]) } }, randomBytes(32), { ...cfg, iosAppId: APP, roots: { apple: [apple.pem] } }), (e) => typeof e.code === "string");
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
  const cfg = { roots: { android: [root.pem], apple: [apple.pem] }, androidPackages: ["app.humid.vault"], androidDigests: [SIGNER], iosAppId: APP };
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

test("servers know the official HumID Android app's signing certificate", async () => {
  const { HUMID_ANDROID_RELEASE_CERT } = await import("@humid/attest");
  assert.match(HUMID_ANDROID_RELEASE_CERT, /^[0-9a-f]{64}$/);
});
