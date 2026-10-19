// The phone's document scanner (apps/mobile/src/core/docscan.js, tauri-plugin-humid-docscan):
// what each answer from the plugin means, and that HumID's own camera takes over for the
// rest of the session when there is no scanner.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { outcome, createDocScanner } from "../apps/mobile/src/core/docscan.js";

const page = (bytes = [0xff, 0xd8, 0xff, 0xd9]) => ({ data: Buffer.from(bytes).toString("base64"), mime: "image/jpeg", width: 856, height: 540 });

test("plugin answers are sorted into cancelled, unavailable and failed", () => {
  assert.equal(outcome("cancelled"), "cancelled");
  assert.equal(outcome(new Error("Scan cancelled by the user")), "cancelled");
  assert.equal(outcome("unavailable: Google Play services is missing"), "unavailable");
  assert.equal(outcome("unavailable: the scanner couldn't start"), "unavailable");
  assert.equal(outcome("Command scan not found"), "unavailable");
  assert.equal(outcome("plugin:humid-docscan|scan not allowed by ACL"), "unavailable");
  assert.equal(outcome("The scanned page couldn't be read: no data"), "failed");
  assert.equal(outcome(undefined), "failed");
});

test("a scanned page comes back as JPEG bytes, and the size cap is passed on", async () => {
  const calls = [];
  const s = createDocScanner({ supported: () => true, invoke: async (cmd, args) => { calls.push([cmd, args]); return page([1, 2, 3]); } });
  assert.equal(s.available(), true);
  const r = await s.scan({ maxSide: 2400 });
  assert.deepEqual(calls, [["scan", { maxSide: 2400 }]]);
  assert.equal(r.blob.type, "image/jpeg");
  assert.deepEqual([...new Uint8Array(await r.blob.arrayBuffer())], [1, 2, 3]);
  assert.equal(r.width, 856);
  assert.equal(r.height, 540);
});

test("backing out of the scanner is not an error", async () => {
  const s = createDocScanner({ supported: () => true, invoke: async () => { throw "cancelled"; } });
  assert.equal(await s.scan(), null);
  assert.equal(s.available(), true, "still used next time");
});

test("no scanner on this phone: says so once, and the camera is used for the rest of the session", async () => {
  let n = 0;
  const s = createDocScanner({ supported: () => true, invoke: async () => { n++; throw new Error("unavailable: This device doesn't have enough memory"); } });
  await assert.rejects(s.scan(), (e) => e.kind === "unavailable" && /HumID's camera/.test(e.message));
  assert.equal(s.available(), false);
  assert.match(s.why(), /enough memory/);
  assert.equal(n, 1);
});

test("a page that couldn't be handed back can be scanned again", async () => {
  const s = createDocScanner({ supported: () => true, invoke: async () => { throw "The scanned page couldn't be read: no data"; } });
  await assert.rejects(s.scan(), (e) => e.kind === "failed");
  assert.equal(s.available(), true);
  const empty = createDocScanner({ supported: () => true, invoke: async () => ({}) });
  await assert.rejects(empty.scan(), (e) => e.kind === "failed");
});

test("outside the Android app the scanner isn't offered", () => {
  const s = createDocScanner({ invoke: async () => page() }); // node: no Tauri, no Android
  assert.equal(s.available(), false);
});

test("the Android plugin keeps the scanner to crop-and-turn, one page, no gallery, and deletes its copy", () => {
  const kt = readFileSync(new URL("../plugins/humid-docscan/android/src/main/java/app/humid/docscan/HumidDocscanPlugin.kt", import.meta.url), "utf8");
  assert.match(kt, /SCANNER_MODE_BASE\b/, "base mode: no filters or ML clean-up that could change what a document says");
  assert.doesNotMatch(kt, /SCANNER_MODE_FULL|SCANNER_MODE_BASE_WITH_FILTER/);
  assert.match(kt, /setPageLimit\(1\)/);
  assert.match(kt, /setGalleryImportAllowed\(false\)/);
  assert.match(kt, /finally \{\s*forget\(uri\)/, "the scanner's file is deleted whether or not it could be read");
  const gradle = readFileSync(new URL("../plugins/humid-docscan/android/build.gradle.kts", import.meta.url), "utf8");
  assert.match(gradle, /play-services-mlkit-document-scanner:16\./);
  const caps = JSON.parse(readFileSync(new URL("../apps/mobile/src-tauri/capabilities/default.json", import.meta.url), "utf8"));
  assert.ok(caps.permissions.includes("humid-docscan:default"));
});
