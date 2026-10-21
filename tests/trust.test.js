// The trust store and trust plumbing: VICALs applied only from a pinned
// provider, kept per root with the country and state the list assigns, never
// rolled back; master-list CSCAs; snapshots; the refresher; the recovery
// service reading the store.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { createTrustStore, loadTrustStore, verifyCredentialResponse, CredsError } from "@humid/creds";
import { applyMasterList, cscasFromStore, verifyPassportChip, refreshTrust, readTrustStoreFile, saveTrustStoreFile, unzipMasterList } from "@humid/creds/server";
import { ReaderSession, deviceRequest, verifyDeviceResponse, MDL_DOCTYPE } from "@humid/mdoc";
import { loadCscasFromTrustFile } from "@humid/anchor";
import { issuingAuthority, wallet, specimenMdl, signVical, fingerprint } from "./support/mdl.js";
import { testCsca, testPassport } from "./support/passport.js";
import { masterList } from "./support/masterlist.js";

const DAY = 86_400_000;
const code = (c) => (e) => { assert.ok(e instanceof CredsError || e?.code, `got ${e?.constructor?.name}: ${e?.message}`); assert.equal(e.code, c, e.message); return true; };
const read = (w, roots) => {
  const s = new ReaderSession(w.engagement().qr);
  const { response } = s.receive(w.respond(s.establish(deviceRequest([MDL_DOCTYPE]))));
  return verifyDeviceResponse(response, { session: s, roots });
};

const provider = issuingAuthority({ C: "US", ST: null, name: "Test DTS Provider" });
const PIN = fingerprint(provider.rootDer);
const il = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
const ut = issuingAuthority({ C: "US", ST: "UT", name: "Utah DLD" });
const bare = issuingAuthority({ C: "US", ST: null, name: "No-state root" });

test("VICAL: applied only from a pinned provider", () => {
  const store = createTrustStore();
  const v = signVical(provider, [{ authority: il, country: "US", state: "IL" }]);
  assert.throws(() => store.applyVical(v, {}), code("no_trust"));
  assert.throws(() => store.applyVical(v, { providerPins: ["00".repeat(32)] }), code("bad_vical"));
  const other = issuingAuthority({ name: "Impostor DTS" });
  assert.throws(() => store.applyVical(signVical(other, [{ authority: il, country: "US", state: "IL" }]), { providerPins: [PIN] }), code("bad_vical"));
  const tampered = new Uint8Array(v); tampered[tampered.length - 1] ^= 1;
  assert.throws(() => store.applyVical(tampered, { providerPins: [PIN] }), code("bad_vical"));
  assert.equal(store.applyVical(v, { providerPins: [PIN] }).added, 1);
  // Pinning the signer certificate itself works too (when the root isn't in the chain).
  assert.equal(createTrustStore().applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL" }], { includeRoot: false }), { providerPins: [fingerprint(provider.dsDer)] }).added, 1);
});

test("VICAL: each root keeps the state its list assigns, and documents are held to it", () => {
  const store = createTrustStore();
  store.applyVical(signVical(provider, [
    { authority: il, country: "US", state: "IL" },
    { authority: bare, country: "US", state: "WI" }, // the list says which state this root speaks for
    { authority: ut, country: "US", state: "NV" },   // the list and the certificate disagree: dropped
  ]), { providerPins: [PIN] });
  const { iaca } = store.forVerifier();
  assert.deepEqual(iaca.map((a) => a.state).sort(), ["IL", "WI"]);
  assert.equal(read(wallet({ authority: il }), iaca)[0].state, "IL");
  assert.equal(read(wallet({ authority: bare, data: specimenMdl({ C: "US", ST: "WI" }) }), iaca)[0].state, "WI");
  assert.throws(() => read(wallet({ authority: bare, data: specimenMdl({ C: "US", ST: "IL" }) }), iaca), (e) => e.code === "untrusted_issuer", "the WI root can't vouch for an Illinois license");
  assert.throws(() => read(wallet({ authority: ut }), iaca), (e) => e.code === "untrusted_issuer", "a dropped root isn't trusted");
  assert.deepEqual(store.status().usStates, ["IL", "WI"]);
  assert.equal(store.status().sources["vical:aamva"].count, 2);
});

test("VICAL: entries that aren't usable roots are dropped with a reason", () => {
  const store = createTrustStore();
  const r = store.applyVical(signVical(provider, [
    { der: il.dsDer, country: "US", state: "IL" },          // not a CA
    { authority: issuingAuthority({ C: "CA", ST: "ON" }), country: "US" }, // country mismatch
    { authority: issuingAuthority({ C: null, ST: null }), country: null }, // no country anywhere
    { der: new Uint8Array([1, 2, 3]), country: "US" },       // unreadable
  ]), { providerPins: [PIN] });
  assert.equal(r.added, 0);
  assert.deepEqual(r.dropped.map((d) => d.reason).sort(), ["no country", "not a certificate authority", "the list and the certificate name different countries", "unreadable certificate"]);
});

test("VICAL: no rollback, no stale or future lists", () => {
  const store = createTrustStore();
  const pins = { providerPins: [PIN] };
  store.applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL" }], { issueId: 5 }), pins);
  assert.throws(() => store.applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL" }, { authority: ut, country: "US", state: "UT" }], { issueId: 4 }), pins), code("rollback"));
  assert.throws(() => store.applyVical(signVical(provider, [{ authority: ut, country: "US", state: "UT" }], { issueId: 5 }), pins), code("rollback"), "same issue number, different contents");
  const v6 = signVical(provider, [{ authority: ut, country: "US", state: "UT" }], { issueId: 6 });
  assert.equal(store.applyVical(v6, pins).added, 1);
  assert.equal(store.applyVical(v6, pins).unchanged, true);
  assert.deepEqual(store.forVerifier().iaca.map((a) => a.state), ["UT"], "Illinois left with the list that removed it");
  assert.throws(() => createTrustStore().applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL" }], { date: new Date(Date.now() - 200 * DAY), nextUpdate: null }), pins), code("stale_vical"));
  assert.throws(() => createTrustStore().applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL" }], { date: new Date(Date.now() - 50 * DAY), nextUpdate: new Date(Date.now() - 40 * DAY) }), pins), code("stale_vical"));
  assert.throws(() => createTrustStore().applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL" }], { date: new Date(Date.now() + 3 * DAY) }), pins), code("bad_vical"));
});

test("snapshots: round trip, revision only goes up, an older copy is refused", () => {
  const store = createTrustStore();
  store.applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL" }]), { providerPins: [PIN] });
  store.addSdJwtIssuer({ iss: "https://pid.example.de", country: "DE" });
  const old = store.toJSON();
  store.pinIaca(ut.rootPem, { country: "US", state: "UT" });
  const snap = store.toJSON();
  const back = loadTrustStore(snap, { minRev: snap.rev });
  assert.deepEqual(back.toJSON(), snap);
  assert.throws(() => loadTrustStore(old, { minRev: snap.rev }), code("rollback"));
  assert.throws(() => createTrustStore({ ...snap, v: 99 }), code("bad_trust_store"));
});

test("pins and issuers: a pin must agree with its certificate; SD-JWT roots are separate from mobile ID roots", () => {
  const store = createTrustStore();
  assert.throws(() => store.pinIaca(il.rootPem, { country: "US", state: "WI" }), code("bad_certificate"));
  assert.throws(() => store.pinIaca(il.dsDer, { country: "US" }), code("bad_certificate"), "not a CA");
  assert.throws(() => store.pinIaca(issuingAuthority({ C: null, ST: null }).rootPem, {}), code("bad_certificate"), "a country is required");
  const fp = store.pinIaca(il.rootPem, { country: "US" });
  assert.equal(store.forVerifier().iaca[0].state, "IL", "taken from the certificate");
  assert.equal(store.forVerifier().sdjwt.roots.length, 0, "a DMV's mDL root isn't an SD-JWT root");
  assert.throws(() => store.addSdJwtIssuer({ iss: "http://pid.example", country: "DE" }), code("bad_issuer"));
  assert.throws(() => store.addSdJwtIssuer({ iss: "https://pid.example" }), code("bad_issuer"));
  store.addSdJwtIssuer({ iss: "https://pid.example", country: "de" });
  assert.deepEqual(store.forVerifier().sdjwt.issuers, [{ iss: "https://pid.example", country: "DE", state: null }]);
  assert.equal(store.remove({ fingerprint: fp }), true);
  assert.equal(store.forVerifier().iaca.length, 0);
  assert.equal(typeof verifyCredentialResponse, "function");
});

test("master lists: CSCAs only from a pinned publisher; a passport checks against them; services read the saved store", () => {
  const publisher = testCsca("Test Publisher CSCA", "DE");
  const uto = testCsca("Utopia CSCA", "UT");
  const ml = masterList({ publisher, cscas: [uto, testCsca("Other CSCA", "FR")] });
  const store = createTrustStore();
  const pin = fingerprint(Buffer.from(publisher.pem.replace(/-----[^-]+-----|\s/g, ""), "base64"));
  assert.throws(() => applyMasterList(store, ml, { source: "icao", publisherCscas: [publisher.pem] }), code("no_trust"));
  assert.throws(() => applyMasterList(store, ml, { source: "icao", publisherCscas: [publisher.pem], publisherPins: ["11".repeat(32)] }), code("no_trust"));
  const r = applyMasterList(store, ml, { source: "icao", publisherCscas: [publisher.pem], publisherPins: [pin] });
  assert.equal(r.added, 2);
  assert.equal(verifyPassportChip(testPassport({ csca: uto, aaKind: null }), { cscas: cscasFromStore(store) }).assurance, "issuer");
  const dir = mkdtempSync(join(tmpdir(), "humid-trust-"));
  const path = join(dir, "trust.json");
  saveTrustStoreFile(path, store);
  assert.equal(loadCscasFromTrustFile(path).length, 2, "the recovery service's loader");
  assert.equal(readTrustStoreFile(path).rev, store.rev);
  assert.equal(readFileSync(path, "utf8").includes("\"csca\""), true);
  assert.deepEqual(loadCscasFromTrustFile(join(dir, "missing.json")), []);
  // Zipped lists (as published) are unpacked, one list only.
  const zip = zipOf("ICAO_ml.ml", Buffer.from(ml));
  assert.deepEqual(Buffer.from(unzipMasterList(zip)), Buffer.from(ml));
  assert.deepEqual(Buffer.from(unzipMasterList(ml)), Buffer.from(ml));
  assert.throws(() => unzipMasterList(zipOf("readme.txt", Buffer.from("hi"))), code("bad_master_list"));
});

test("refresh: each source independent; a failing one keeps its last good data", async () => {
  const dir = mkdtempSync(join(tmpdir(), "humid-trust-"));
  const publisher = testCsca("Test Publisher CSCA", "DE");
  writeFileSync(join(dir, "publisher.pem"), publisher.pem);
  writeFileSync(join(dir, "ml.ml"), masterList({ publisher, cscas: [testCsca("Utopia CSCA", "UT")] }));
  const vicalBytes = signVical(provider, [{ authority: il, country: "US", state: "IL" }], { issueId: 2 });
  const pin = fingerprint(Buffer.from(publisher.pem.replace(/-----[^-]+-----|\s/g, ""), "base64"));
  const config = {
    vical: { id: "aamva", url: "https://vical.dts.aamva.org/vical", providerPins: [PIN] },
    masterLists: [{ source: "icao", file: "ml.ml", publisherCerts: ["publisher.pem"], publisherPins: [pin] }],
    allowHosts: ["vical.dts.aamva.org"],
  };
  let served = vicalBytes;
  const fetch = async (url, o) => { assert.deepEqual(o.allowHosts, ["vical.dts.aamva.org"]); assert.equal(url, config.vical.url); return { bytes: served }; };
  const store = createTrustStore();
  const r1 = await refreshTrust(store, config, { fetch, baseDir: dir });
  assert.equal(r1.changed, true);
  assert.equal(r1.sources["vical:aamva"].ok, true);
  assert.equal(r1.sources.icao.ok, true);
  served = signVical(provider, [], { issueId: 1 }); // an older list: refused, Illinois stays
  const r2 = await refreshTrust(store, config, { fetch, baseDir: dir });
  assert.equal(r2.sources["vical:aamva"].ok, false);
  assert.equal(r2.sources["vical:aamva"].code, "rollback");
  assert.equal(r2.sources.icao.ok, true);
  assert.equal(store.forVerifier().iaca.length, 1);
  const r3 = await refreshTrust(store, config, { fetch: async () => { throw Object.assign(new Error("down"), { code: "network" }); }, baseDir: dir });
  assert.equal(r3.sources["vical:aamva"].code, "network");
  assert.equal(store.forVerifier().iaca.length, 1);
});

/** A one-file zip (deflated), as master lists are often published. */
function zipOf(name, data) {
  const comp = deflateRawSync(data), n = Buffer.from(name);
  const h = Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(0, 6); h.writeUInt16LE(8, 8);
  h.writeUInt32LE(0, 14); h.writeUInt32LE(comp.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(n.length, 26); h.writeUInt16LE(0, 28);
  return Buffer.concat([h, n, comp]);
}
