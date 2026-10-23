// LIVE-01: on Android the secret that unwraps the account seed opens only inside a prompt
// HumID asked for: its key is per use and its Cipher is the prompt's CryptoObject, not
// usable for a few seconds after any biometric unlock. The Kotlin can't be built here, so
// this pins its shape; a device has to confirm the behaviour. The JS side keeps the
// handle a release hands back when an old (2.0) key is moved to a per-use one.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { nativeAdapter } from "../packages/gate/src/adapters/native.js";

const kt = readFileSync(new URL("../plugins/humid-gate/android/src/main/java/app/humid/gate/HumidGatePlugin.kt", import.meta.url), "utf8");
afterEach(() => { delete globalThis.__TAURI_INTERNALS__; });

test("Android: every Keystore key HumID makes is per use (timeout 0), the secret's included", () => {
  const params = [...kt.matchAll(/setUserAuthenticationParameters\(([^,]+),/g)].map((m) => m[1].trim());
  assert.ok(params.length >= 2, "the liveness key and the secret key both set it");
  assert.deepEqual([...new Set(params)], ["0"], "no time window on any key");
  assert.doesNotMatch(kt, /SECRET_WINDOW_S/);
});

test("Android: the secret's Cipher is a prompt's CryptoObject, and so is the liveness Signature", () => {
  assert.match(kt, /BiometricPrompt\.CryptoObject\(cipher\)/);
  assert.match(kt, /BiometricPrompt\.CryptoObject\(live\.signature\)/);
  assert.doesNotMatch(kt, /bp\.authenticate\(info\)\s*$/m, "no prompt without a CryptoObject");
  assert.match(kt, /private const val HANDLE_VERSION = 3/);
  assert.match(kt, /HANDLE_V2 -> migrateV2/, "2.0 handles move to a per-use key");
});

test("the native gate passes on a replacement handle, and only when there is one", async () => {
  const answer = { secret: Buffer.alloc(32, 1).toString("base64"), method: "android-keystore-biometric", assurance: "hardware" };
  globalThis.__TAURI_INTERNALS__ = { invoke: async () => ({ ...answer, handle: { id: "x", v: 3, iv: "aQ==", ct: "Yw==" } }) };
  assert.deepEqual((await nativeAdapter.release({ id: "x", v: 2, iv: "a", ct: "b" }, { purpose: "launch" })).handle, { id: "x", v: 3, iv: "aQ==", ct: "Yw==" });
  globalThis.__TAURI_INTERNALS__ = { invoke: async () => answer };
  assert.equal("handle" in (await nativeAdapter.release({ id: "x", v: 3, iv: "a", ct: "b" }, { purpose: "launch" })), false);
});

test("the Rust bridge carries the replacement handle through", () => {
  const rs = readFileSync(new URL("../plugins/humid-gate/src/models.rs", import.meta.url), "utf8");
  const released = rs.slice(rs.indexOf("pub struct Released"), rs.indexOf("}", rs.indexOf("pub struct Released")));
  assert.match(released, /pub handle: Option<Handle>/);
});

test("the app stores a replacement handle the moment a release returns one", () => {
  const src = readFileSync(new URL("../apps/mobile/src/core/interrupt.js", import.meta.url), "utf8");
  assert.match(src, /if \(rel\.handle\) await keepGateHandle\(id, rel\.handle\);/);
});

test("a live check gets as far as the gate (withKeys names the method in its prompt)", async () => {
  // Regression: interrupt.js passed gateLabel on without importing it, so every live check threw
  // "gateLabel is not defined" before the gate was asked.
  const S = await import("../apps/mobile/src/core/state.js");
  const { withKeys } = await import("../apps/mobile/src/core/interrupt.js");
  const asked = [];
  let shown = "";
  globalThis.__TAURI_INTERNALS__ = { invoke: async (cmd) => { asked.push(cmd); shown = S.interrupt.value?.message || ""; throw new Error("cancelled"); } };
  S.identity.value = { gate: { adapter: "native", handle: { id: "h" } }, device: { id: "d" }, method: "android-keystore-biometric", bindingId: "AA==", pub: {} };
  const e = await withKeys("launch", "Open your vault", async () => {}).catch((x) => x);
  assert.deepEqual(asked, ["plugin:humid-gate|release"], `the gate was asked (got ${e?.message})`);
  assert.match(shown, /^Confirm with /);
  S.identity.value = null;
});
