// The access pass at rest: before there is an account, the draft (access code and
// blinded request) and the finished pass are sealed under a per-install key that lives
// apart from them. Nothing in the stored wallet record is readable as stored.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";
import { openStore } from "@humid/store";
import { blind, finalize, newAccessCode, parseAccessCode, unb64u } from "@humid/pass";
import { newIssuerKey, blindSign } from "@humid/pass/issuer";
import { installKey, forgetInstallKey, sealedWallet, sealRecord, openRecord, isSealed, SEALED } from "@humid/pass/atrest";

const key = newIssuerKey(2048);
const code = parseAccessCode(newAccessCode());
const { blinded, draft } = blind(key.pub);
const pass = finalize(key.pub, draft, blindSign(key, blinded));
const draftRecord = { state: "draft", code, draft, savedAt: "2026-10-17" };
const readyRecord = { state: "ready", pass };

/** Every byte of what the backend holds, as text, so plaintext can be searched for. */
const storedText = (stored) => JSON.stringify(stored, (_, v) => (v instanceof Uint8Array ? Buffer.from(v).toString("latin1") : v)) + Buffer.from(stored.ct || []).toString("latin1") + Buffer.from(stored.ct || []).toString("base64");
const secrets = [code, draft.input, draft.blinded, draft.inv, pass.input, pass.sig].filter(Boolean).map(String);

const store = await openStore();
async function fresh() { await forgetInstallKey(); await store.clearPass(); return store; }

beforeEach(async () => { await forgetInstallKey(); });

test("the install key is a non-extractable AES-GCM-256 CryptoKey, the same one on every call", async () => {
  const k = await installKey();
  assert.equal(k.algorithm.name, "AES-GCM");
  assert.equal(k.algorithm.length, 256);
  assert.equal(k.extractable, false);
  const again = await installKey();
  assert.deepEqual(await openRecord(again, await sealRecord(k, readyRecord)), readyRecord, "every read is the same key");
  await assert.rejects(crypto.subtle.exportKey("raw", k), "the key's bytes are not available to JavaScript");
});

test("the stored draft holds neither the access code nor the blinded request in the clear", async () => {
  const store = await fresh();
  const w = sealedWallet(store);
  await w.put(draftRecord);
  const stored = await store.getPass();
  assert.ok(isSealed(stored));
  assert.equal(stored.sealed, SEALED);
  assert.equal(stored.iv.length, 12);
  const text = storedText(stored);
  for (const s of secrets) assert.ok(!text.includes(s), `stored record contains ${s.slice(0, 12)}…`);
  assert.ok(!text.includes("draft") && !text.includes("savedAt"), "no field names either");
  assert.deepEqual(await w.get(), draftRecord);
});

test("the stored pass holds neither the pass input nor its signature in the clear", async () => {
  const store = await fresh();
  const w = sealedWallet(store);
  await w.put(readyRecord);
  const text = storedText(await store.getPass());
  for (const s of [pass.input, pass.sig, Buffer.from(unb64u(pass.sig)).toString("latin1")]) assert.ok(!text.includes(s));
  assert.deepEqual(await w.get(), readyRecord);
});

test("a clear record from an older build is re-sealed on first read and the plaintext is gone", async () => {
  const store = await fresh();
  await store.putPass(draftRecord); // what 1.x wrote
  assert.equal((await store.getPass()).code, code);
  const w = sealedWallet(store);
  assert.deepEqual(await w.get(), draftRecord);
  const stored = await store.getPass();
  assert.ok(isSealed(stored));
  assert.ok(!storedText(stored).includes(code));
  assert.deepEqual(await w.get(), draftRecord, "and it still opens");
});

test("a record sealed under another install's key does not open and is dropped, not shown", async () => {
  const store = await fresh();
  await sealedWallet(store).put(readyRecord);
  await forgetInstallKey(); // a new install: a fresh key
  assert.equal(await sealedWallet(store).get(), null);
  assert.equal(await store.getPass(), null);
});

test("sealing binds the AAD and the IV: a flipped byte or a different label refuses", async () => {
  const k = await installKey();
  const sealed = await sealRecord(k, readyRecord);
  assert.deepEqual(await openRecord(k, sealed), readyRecord);
  const bent = { ...sealed, ct: Uint8Array.from(sealed.ct) };
  bent.ct[3] ^= 1;
  await assert.rejects(openRecord(k, bent));
  const other = await crypto.subtle.encrypt({ name: "AES-GCM", iv: sealed.iv, additionalData: new TextEncoder().encode("HUMID-OTHER-v1") }, k, new TextEncoder().encode(JSON.stringify(readyRecord)));
  await assert.rejects(openRecord(k, { ...sealed, ct: new Uint8Array(other) }));
  await assert.rejects(openRecord(k, readyRecord), /not a sealed/);
  // two seals of the same record never share an IV or ciphertext
  const again = await sealRecord(k, readyRecord);
  assert.notDeepEqual(again.iv, sealed.iv);
  assert.notDeepEqual(again.ct, sealed.ct);
});

test("the install key lives in its own database, apart from the wallet", async () => {
  await installKey();
  const names = (await indexedDB.databases()).map((d) => d.name);
  assert.ok(names.includes("humid-keys"));
  const db = await new Promise((r) => { const q = indexedDB.open("humid-keys"); q.onsuccess = () => r(q.result); });
  assert.deepEqual([...db.objectStoreNames], ["keys"]);
  db.close();
});
