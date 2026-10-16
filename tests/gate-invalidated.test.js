// When Android (or iOS) deletes HumID's biometric key — the phone's fingerprints or
// face changed, or the app was reinstalled and its data restored — the gate says so
// with a code the app turns into "set this phone up again", not a dead end.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { nativeAdapter } from "../packages/gate/src/adapters/native.js";
import { CANCELLED } from "../packages/gate/src/contract.js";

const fake = (reject) => { globalThis.__TAURI_INTERNALS__ = { invoke: async () => { throw reject; } }; };
afterEach(() => { delete globalThis.__TAURI_INTERNALS__; });

const ANDROID = /const val INVALIDATED = "([^"]+)"/.exec(readFileSync(new URL("../plugins/humid-gate/android/src/main/java/app/humid/gate/HumidGatePlugin.kt", import.meta.url), "utf8"))[1];
const IOS = /case \.invalidated:\s*return "([^"]+)"/.exec(readFileSync(new URL("../plugins/humid-gate/ios/Sources/HumidGatePlugin/HumidGatePlugin.swift", import.meta.url), "utf8"))[1];

test("the phone's 'key is gone' message becomes key_invalidated, on Android and iOS", async () => {
  for (const msg of [ANDROID, IOS]) {
    fake(msg);
    await assert.rejects(nativeAdapter.release({ id: "x", v: 2, iv: "a", ct: "b" }, { purpose: "launch" }), (e) => e.code === "key_invalidated");
  }
});

test("a cancelled check is still a cancel, and other errors carry no code", async () => {
  fake("Biometric check cancelled.");
  await assert.rejects(nativeAdapter.release({ id: "x" }), (e) => e.message === CANCELLED);
  fake("Too many tries. Unlock your phone, then try again with your face or fingerprint.");
  await assert.rejects(nativeAdapter.release({ id: "x" }), (e) => !e.code);
});

test("Android never backs up or transfers HumID's data (its keys can't follow it)", () => {
  const manifest = readFileSync(new URL("../plugins/humid-gate/android/src/main/AndroidManifest.xml", import.meta.url), "utf8");
  assert.match(manifest, /android:allowBackup="false"/);
  assert.match(manifest, /android:dataExtractionRules="@xml\/humid_no_backup"/);
  const rules = readFileSync(new URL("../plugins/humid-gate/android/src/main/res/xml/humid_no_backup.xml", import.meta.url), "utf8");
  for (const part of ["cloud-backup", "device-transfer"]) assert.match(rules, new RegExp(`<${part}>[\\s\\S]*domain="root"[\\s\\S]*</${part}>`));
});
