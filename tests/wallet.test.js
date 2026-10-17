// Wallet passes (@humid/wallet): a genuine pass is read; a pass broken in any one way
// is refused with a reason. Test passes are signed under a throwaway root
// (tests/support/pkpass.js); Apple's real intermediates check against the pinned roots.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { certificate } from "./support/pki.js";
import { readPkpass, readZip, passIndex, APPLE_ROOTS, parseCert, issuedBy, looksLikePass, WalletError, LIMITS } from "@humid/wallet";
import { passChain, makePass, passJson, zip, cmsSign } from "./support/pkpass.js";

/** One DER element at `o`: { start of contents, end }. */
function tlvAt(b, o) {
  let p = o + 1, len = b[p++];
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[p++]; }
  return { start: p, end: p + len, head: b.subarray(o, p) };
}
/** The CMS wrapper (ContentInfo, [0], SignedData) re-encoded with indefinite lengths, as BER signing tools write it. */
function berWrapper(der) {
  const b = Buffer.from(der);
  const ci = tlvAt(b, 0), oidE = tlvAt(b, ci.start), ex = tlvAt(b, oidE.end), sd = tlvAt(b, ex.start);
  return Buffer.concat([Buffer.from([0x30, 0x80]), b.subarray(ci.start, oidE.end), Buffer.from([0xa0, 0x80, 0x30, 0x80]), b.subarray(sd.start, sd.end), Buffer.alloc(6)]);
}

const chain = passChain();
const opts = { roots: [chain.root] };
const refused = (code) => (e) => { assert.ok(e instanceof WalletError, `${e?.constructor?.name}: ${e?.message}`); assert.equal(e.code, code, e.message); return true; };

test("Apple's roots are pinned, and Apple's real pass-signing intermediates chain to them", async () => {
  assert.deepEqual(APPLE_ROOTS.map((r) => r.sha256), [
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024", // Apple Root CA
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179", // Apple Root CA - G3
  ]);
  const roots = APPLE_ROOTS.map((r) => parseCert(r.der));
  const wwdr = (g) => parseCert(new Uint8Array(readFileSync(new URL(`./fixtures/wallet/AppleWWDRCA${g}.cer`, import.meta.url))));
  assert.ok(await issuedBy(wwdr("G4"), roots[0]), "WWDR G4 (RSA) under Apple Root CA");
  assert.ok(await issuedBy(wwdr("G3"), roots[0]), "WWDR G3 (RSA) under Apple Root CA");
  assert.ok(await issuedBy(wwdr("G6"), roots[1]), "WWDR G6 (ECDSA P-384) under Apple Root CA - G3");
  assert.ok(!(await issuedBy(wwdr("G6"), roots[0])), "and not under the other root");
  assert.ok(wwdr("G4").ext.ca);
});

test("a genuine pass: verified, summarised, nothing to open or run", async () => {
  const r = await readPkpass(makePass(chain), opts);
  assert.equal(r.issuer.team, "TEAM123456");
  assert.equal(r.issuer.passType, "pass.com.example.ticket");
  assert.equal(r.issuer.organization, "Example Events");
  assert.equal(r.issuer.root, "Test Root CA");
  assert.equal(r.pass.style, "eventTicket");
  assert.equal(r.pass.styleLabel, "Ticket");
  assert.deepEqual(r.pass.fields.primary, [{ label: "EVENT", value: "The Specimen Tour" }]);
  assert.equal(r.pass.barcode.message, "TICKET-E-1001-SECRET");
  assert.ok(r.images.icon instanceof Uint8Array);
  assert.equal(r.manifestHash, "SHA-1");
  // SHA-256 manifests and ECDSA signers too
  assert.equal((await readPkpass(makePass(chain, { digest: "sha256" }), opts)).manifestHash, "SHA-256");
  const ec = passChain({ rsa: false });
  assert.equal((await readPkpass(makePass(ec), { roots: [ec.root] })).issuer.team, "TEAM123456");
  // the vault index carries no barcode and no back fields
  const idx = passIndex(r.pass, r.issuer);
  assert.ok(!JSON.stringify(idx).includes("SECRET") && !JSON.stringify(idx).includes("Non-transferable"));
  assert.equal(idx.organization, "Example Events");
  assert.ok(looksLikePass({ name: "Ticket.pkpass" }) && looksLikePass({ name: "x", type: "application/vnd.apple.pkpass" }) && !looksLikePass({ name: "a.pdf" }));
});

test("Apple's roots by default: a pass signed under any other root is refused", async () => {
  await assert.rejects(readPkpass(makePass(chain)), refused("untrusted"));
});

test("tampering: a changed file, an added file, a missing file, a changed manifest", async () => {
  await assert.rejects(readPkpass(makePass(chain, { change: { "pass.json": Buffer.from(JSON.stringify(passJson({ description: "Free entry" }))) } }), opts), refused("tampered"));
  await assert.rejects(readPkpass(makePass(chain, { change: { "logo.png": Buffer.from("not the logo") } }), opts), refused("tampered"));
  await assert.rejects(readPkpass(makePass(chain, { extra: { "evil.js": Buffer.from("alert(1)") } }), opts), refused("tampered"));
  await assert.rejects(readPkpass(makePass(chain, { drop: "logo.png" }), opts), refused("tampered"));
  await assert.rejects(readPkpass(makePass(chain, { cms: { tamperDigest: true } }), opts), refused("tampered"));
  await assert.rejects(readPkpass(makePass(chain, { noSignature: true }), opts), refused("unsigned"));
});

test("the signer: must be a pass certificate, through a CA, valid when signed, for this pass", async () => {
  // not a Wallet pass certificate
  const plain = passChain({ passbook: false });
  await assert.rejects(readPkpass(makePass(plain), { roots: [plain.root] }), refused("untrusted"));
  // a CA as the signer
  const ca = passChain({ signerCa: true });
  await assert.rejects(readPkpass(makePass(ca), { roots: [ca.root] }), refused("untrusted"));
  // an intermediate that isn't a CA
  const noCa = passChain({ interCa: false });
  await assert.rejects(readPkpass(makePass(noCa), { roots: [noCa.root] }), refused("untrusted"));
  // expired when the pass was signed
  const old = passChain({ signerNotBefore: new Date("2020-01-01"), signerNotAfter: new Date("2021-01-01") });
  await assert.rejects(readPkpass(makePass(old), { roots: [old.root] }), refused("untrusted"));
  // signed while valid, certificate expired since: still genuine
  const lapsed = passChain({ signerNotBefore: new Date("2024-01-01"), signerNotAfter: new Date("2025-01-01") });
  const r = await readPkpass(makePass(lapsed, { cms: { signingTime: new Date("2024-06-01") } }), { roots: [lapsed.root] });
  assert.equal(r.signedAt, "2024-06-01T00:00:00.000Z");
  // a certificate for another pass type, or another team, can't sign this one
  await assert.rejects(readPkpass(makePass(chain, { pass: passJson({ passTypeIdentifier: "pass.com.bank.card" }) }), opts), refused("untrusted"));
  await assert.rejects(readPkpass(makePass(chain, { pass: passJson({ teamIdentifier: "OTHERTEAM1" }) }), opts), refused("untrusted"));
  // the signer's certificate left out of the signature
  await assert.rejects(readPkpass(makePass(chain, { cms: { certs: [chain.interDer] } }), opts), refused("bad_signature"));
  // the intermediate left out: no chain to the root
  await assert.rejects(readPkpass(makePass(chain, { cms: { certs: [chain.signerDer] } }), opts), refused("untrusted"));
  // signed by someone else's key under the same name
  const other = passChain();
  await assert.rejects(readPkpass(makePass({ ...chain, key: other.key }), opts), refused("bad_signature"));
});

test("the archive: bounded, no escaping names, no duplicates, checksums", async () => {
  const ok = [["pass.json", Buffer.from("{}")]];
  assert.equal((await readZip(zip(ok))).size, 1);
  for (const bad of ["../pass.json", "/etc/passwd", "a/../../b", "a\\b", "x\u0000y", "./a", "a//b"]) {
    await assert.rejects(readZip(zip([[bad, Buffer.from("x")]])), refused("bad_zip"), bad);
  }
  await assert.rejects(readZip(zip([["a", Buffer.from("x")], ["a", Buffer.from("y")]])), refused("bad_zip"));
  await assert.rejects(readZip(zip([["a", Buffer.from("hello")]].map(([n, b]) => [n, b, { crc: 1 }]))), refused("bad_zip"));
  await assert.rejects(readZip(zip([["a", Buffer.from("hello"), { flags: 1 }]])), refused("bad_zip"), "encrypted");
  // a zip bomb: claims 100 bytes, inflates to 1 MB
  await assert.rejects(readZip(zip([["bomb", Buffer.alloc(1 << 20), { size: 100, crc: 0 }]])), refused("bad_zip"));
  // claims more than the limit before anything is inflated
  await assert.rejects(readZip(zip([["big", Buffer.from("x"), { size: LIMITS.file + 1 }]])), refused("too_big"));
  await assert.rejects(readZip(zip(Array.from({ length: LIMITS.files + 1 }, (_, i) => [`f${i}`, Buffer.from("x")]))), refused("too_big"));
  await assert.rejects(readZip(new Uint8Array(10)), refused("bad_zip"));
  await assert.rejects(readZip(Buffer.from("%PDF-1.4 not a zip at all, but long enough to look")), refused("bad_zip"));
  await assert.rejects(readPkpass(zip([["pass.json", Buffer.from("{}")]]), opts), refused("bad_pass"));
});

test("pass contents are shown as text, bounded and without control characters", async () => {
  const long = "x".repeat(5000);
  const r = await readPkpass(makePass(chain, { pass: passJson({ description: `Line\u0007one\nline two ${long}`, foregroundColor: "javascript:alert(1)", relevantDate: "not a date", eventTicket: { primaryFields: Array.from({ length: 50 }, (_, i) => ({ key: `k${i}`, label: "L", value: i })) } }) }), opts);
  assert.ok(r.pass.description.length <= 200 && !/[\u0000-\u001f]/.test(r.pass.description));
  assert.equal(r.pass.colors.foreground, null);
  assert.equal(r.pass.relevantDate, null);
  assert.equal(r.pass.fields.primary.length, 20);
  await assert.rejects(readPkpass(makePass(chain, { pass: { ...passJson(), formatVersion: 2 } }), opts), refused("bad_pass"));
});

test("review fixes: BER signature wrappers, one manifest hash, bounded certificates, chains with renewed intermediates", async () => {
  // a signature whose wrapper uses indefinite lengths (BouncyCastle, Apple's CMS encoder) is read
  const files = await readZip(makePass(chain));
  const manifest = files.get("manifest.json");
  const entries = [...files].map(([n, b]) => [n, n === "signature" ? berWrapper(b) : b]);
  const r = await readPkpass(zip(entries), opts);
  assert.equal(r.issuer.team, "TEAM123456");
  assert.ok(manifest.length > 0);
  // a manifest mixing SHA-1 and SHA-256 is refused
  await assert.rejects(readPkpass(makePass(chain, { manifest: (m) => { m["logo.png"] = createHash("sha256").update(files.get("logo.png")).digest("hex"); } }), opts), refused("bad_pass"));
  // a signature padded with certificates is refused before any are checked
  await assert.rejects(readPkpass(makePass(chain, { cms: { certs: [chain.signerDer, ...Array(9).fill(chain.interDer)] } }), opts), refused("bad_signature"));
  // an expired intermediate listed before its renewal (same name and key) doesn't stop the chain
  const renewed = passChain();
  const stale = certificate({ subject: renewed.interName, issuer: { cn: "Test Root CA", o: "Test Root", country: "US" }, publicKey: renewed.inter.publicKey, signingKey: renewed.rootKey.privateKey, ca: true, notBefore: new Date("2015-01-01"), notAfter: new Date("2016-01-01") });
  const ok = await readPkpass(makePass(renewed, { cms: { certs: [renewed.signerDer, stale, renewed.interDer] } }), { roots: [renewed.root] });
  assert.equal(ok.issuer.team, "TEAM123456");
});

test("review fixes: a certificate that has since expired is reported, not shown as plainly verified", async () => {
  const lapsed = passChain({ signerNotBefore: new Date("2024-01-01"), signerNotAfter: new Date("2025-01-01") });
  const r = await readPkpass(makePass(lapsed, { cms: { signingTime: new Date("2024-06-01") } }), { roots: [lapsed.root] });
  assert.equal(r.issuer.certExpired, true);
  // a signing time in the future isn't believed: it's checked (and reported) as now
  const fut = await readPkpass(makePass(chain, { cms: { signingTime: new Date("2030-01-01") } }), opts);
  assert.equal(fut.signedAt, null);
  assert.equal((await readPkpass(makePass(chain), opts)).issuer.certExpired, false);
  // the index says who signed it from the certificate, and when it was checked
  const idx = passIndex(r.pass, r.issuer, new Date("2026-10-17T00:00:00Z"));
  assert.equal(idx.issuer, "Example Events");
  assert.equal(idx.checkedAt, "2026-10-17T00:00:00.000Z");
  // the certificate's organisation, not the pass's own text
  const spoof = await readPkpass(makePass(chain, { pass: passJson({ organizationName: "Delta Air Lines" }) }), opts);
  assert.equal(spoof.issuer.organization, "Example Events");
  assert.equal(passIndex(spoof.pass, spoof.issuer).issuer, "Example Events");
  // a byte-order mark in pass.json is fine
  const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(passJson()))]);
  assert.equal((await readPkpass(makePass(chain, { files: { "pass.json": withBom } }), opts)).pass.style, "eventTicket");
});
