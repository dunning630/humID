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

const provider = issuingAuthority({ C: "US", ST: null, name: "Test DTS Provider", dsEku: ["1.0.18013.5.1.8"], dsKu: [6, 0x40] });
const PIN = fingerprint(provider.rootDer);
const il = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
const ut = issuingAuthority({ C: "US", ST: "UT", name: "Utah DLD" });
const bare = issuingAuthority({ C: "US", ST: null, name: "No-state root" });

test("VICAL: applied only from a pinned provider", () => {
  const store = createTrustStore();
  const v = signVical(provider, [{ authority: il, country: "US", state: "IL" }]);
  assert.throws(() => store.applyVical(v, {}), code("no_trust"));
  assert.throws(() => store.applyVical(v, { providerPins: ["00".repeat(32)] }), code("bad_vical"));
  const other = issuingAuthority({ name: "Impostor DTS", dsEku: ["1.0.18013.5.1.8"], dsKu: [6, 0x40] });
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

test("CREDS-06: master lists only move forward; replaying an older one can't drop CSCAs", () => {
  const publisher = testCsca("Test Publisher CSCA", "DE");
  const pin = fingerprint(Buffer.from(publisher.pem.replace(/-----[^-]+-----|\s/g, ""), "base64"));
  const opts = { source: "icao", publisherCscas: [publisher.pem], publisherPins: [pin] };
  const a = testCsca("Country A", "AA"), b = testCsca("Country B", "BB");
  const der = (c) => ({ der: Buffer.from(c.pem.replace(/-----[^-]+-----|\s/g, ""), "base64") });
  const t0 = new Date(Date.now() - 30 * DAY), t1 = new Date(Date.now() - DAY);
  const older = masterList({ publisher, cscas: [der(a)], signingTime: t0 });
  const newer = masterList({ publisher, cscas: [der(a), der(b)], signingTime: t1 });
  const store = createTrustStore();
  assert.equal(applyMasterList(store, newer, opts).signedAt, new Date(Math.floor(t1 / 1000) * 1000).toISOString());
  assert.equal(store.status().cscaCountries, 2);
  const rev = store.rev;
  // The attack: last month's list, still validly signed, replayed by a hostile relay.
  assert.throws(() => applyMasterList(store, older, opts), code("rollback"));
  assert.equal(store.status().cscaCountries, 2, "country B is kept");
  assert.equal(store.rev, rev);
  // Same signing time, different contents; no signing time once one was seen; a list dated ahead.
  assert.throws(() => applyMasterList(store, masterList({ publisher, cscas: [der(a)], signingTime: t1 }), opts), code("rollback"));
  assert.throws(() => applyMasterList(store, masterList({ publisher, cscas: [der(a)], signingTime: null }), opts), code("rollback"));
  assert.throws(() => applyMasterList(store, masterList({ publisher, cscas: [der(a)], signingTime: new Date(Date.now() + 3 * DAY) }), opts), code("bad_master_list"));
  // The same list again is a no-op, a newer one replaces, and the guard survives a snapshot.
  assert.equal(applyMasterList(store, newer, opts).unchanged, true);
  assert.equal(store.rev, rev);
  applyMasterList(store, masterList({ publisher, cscas: [der(b)], signingTime: new Date() }), opts);
  assert.equal(store.status().cscaCountries, 1, "a newer list may remove a CSCA");
  assert.throws(() => applyMasterList(loadTrustStore(store.toJSON()), newer, opts), code("rollback"));
  // Sources are independent: the BSI list isn't held to ICAO's clock.
  assert.equal(applyMasterList(store, older, { ...opts, source: "bsi" }).added, 1);
});

/** A one-file zip (deflated), as master lists are often published. */
function zipOf(name, data) {
  const comp = deflateRawSync(data), n = Buffer.from(name);
  const h = Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(0, 6); h.writeUInt16LE(8, 8);
  h.writeUInt32LE(0, 14); h.writeUInt32LE(comp.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(n.length, 26); h.writeUInt16LE(0, 28);
  return Buffer.concat([h, n, comp]);
}

test("review fixes: roots need document types; same-date relists and older files are refused", () => {
  const pins = { providerPins: [PIN] };
  const r = createTrustStore().applyVical(signVical(provider, [{ authority: il, country: "US", state: "IL", docTypes: [] }]), pins);
  assert.deepEqual(r.dropped.map((d) => d.reason), ["no document types"]);
  assert.throws(() => createTrustStore().pinIaca(il.rootPem, { country: "US", docTypes: [] }), code("bad_certificate"));
  const date = new Date(Date.now() - DAY);
  const noId = (entries) => { const v = signVical(provider, entries, { date, issueId: null }); return v; };
  const store = createTrustStore();
  store.applyVical(noId([{ authority: il, country: "US", state: "IL" }]), pins);
  assert.throws(() => store.applyVical(noId([{ authority: ut, country: "US", state: "UT" }]), pins), code("rollback"));
  // The recovery service's loader refuses a trust file older than one it already used.
  const publisher = testCsca("Test Publisher CSCA", "DE");
  const pin = fingerprint(Buffer.from(publisher.pem.replace(/-----[^-]+-----|\s/g, ""), "base64"));
  const s2 = createTrustStore();
  applyMasterList(s2, masterList({ publisher, cscas: [testCsca("Utopia CSCA", "UT")] }), { source: "icao", publisherCscas: [publisher.pem], publisherPins: [pin] });
  const dir = mkdtempSync(join(tmpdir(), "humid-trust-"));
  const path = join(dir, "trust.json");
  saveTrustStoreFile(path, s2);
  assert.equal(loadCscasFromTrustFile(path).rev, s2.rev);
  assert.throws(() => loadCscasFromTrustFile(path, { minRev: s2.rev + 1 }), /older/);
});
