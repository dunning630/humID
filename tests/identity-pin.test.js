// V74B-03: the recovery-mode pin only goes forward. Every identity write goes through
// core/identity.js updateIdentity, which never lets a record leave with a lower pin (version or
// epoch) than the stored one, or with none; and the last writer that wrote from a snapshot,
// interrupt.js keepGateHandle (a gate that moved its secret to a new key, LIVE-01), now goes
// through it too. Before, a live check that began before a pin moved put the old pin back when
// the gate handed over a new handle, and that device would then accept the older statement.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { updateIdentity } from "../apps/mobile/src/core/identity.js";
import { pinMode } from "../apps/mobile/src/core/recmode.js";
import { withKeys } from "../apps/mobile/src/core/interrupt.js";

const pin = (version, epoch, mode = "hardened") => ({ mode, version, epoch, prev: String(version).repeat(64).slice(0, 64) });

/** An identity store in memory, as @humid/store presents it. */
function memoryStore(record) {
  let rec = structuredClone(record);
  return { getIdentity: async () => (rec ? structuredClone(rec) : null), putIdentity: async (r) => { rec = structuredClone(r); }, clearIdentity: async () => { rec = null; }, peek: () => rec };
}
const base = () => ({
  server: { id: "hid_" + "ab".repeat(20) }, gate: { adapter: "native", handle: { id: "h", v: 2 } }, bindingId: "AAAAAAAAAAAAAAAAAAAAAA==",
  wrapped: new Uint8Array(8), pub: { dsaPk: "AA==" }, device: { id: "d", dsaPk: "AA==" }, method: "android-keystore-biometric",
  recoveryMode: "hardened", modePin: pin(1, 1),
});

beforeEach(() => { R.store = memoryStore(base()); S.identity.value = { ...base(), schema: 4 }; });
afterEach(() => { delete globalThis.__TAURI_INTERNALS__; });

test("updateIdentity never lowers or drops the pin, whatever a writer hands back", async () => {
  await pinMode(pin(3, 2, "holder-only"));
  assert.deepEqual([R.store.peek().modePin.version, R.store.peek().recoveryMode], [3, "holder-only"]);
  // A writer that returns a whole record from an older copy.
  const old = base();
  await updateIdentity(() => ({ ...old, ledgerKeyFp: "f".repeat(32) }));
  assert.equal(R.store.peek().ledgerKeyFp, "f".repeat(32), "its own change is kept");
  assert.deepEqual([R.store.peek().modePin.version, R.store.peek().modePin.epoch, R.store.peek().recoveryMode], [3, 2, "holder-only"], "the pin is not");
  // One that drops it, or lowers only the epoch.
  await updateIdentity((cur) => { delete cur.modePin; });
  assert.equal(R.store.peek().modePin.version, 3);
  await updateIdentity((cur) => { cur.modePin = { ...cur.modePin, epoch: 1 }; });
  assert.equal(R.store.peek().modePin.epoch, 2);
  // Forward still works.
  await pinMode(pin(4, 3));
  assert.deepEqual([R.store.peek().modePin.version, S.identity.value.modePin.version], [4, 4]);
});

test("race: a live check that began before the pin moved can't put the old pin back (keepGateHandle)", async () => {
  // The native gate: its release waits until we let it go, then hands back a NEW handle (LIVE-01).
  let go;
  const released = new Promise((r) => { go = r; });
  let asked;
  const asking = new Promise((r) => { asked = r; });
  globalThis.__TAURI_INTERNALS__ = {
    invoke: async (cmd) => {
      if (cmd !== "plugin:humid-gate|release") throw new Error(`unexpected ${cmd}`);
      asked();
      await released;
      return { secret: Buffer.alloc(32, 7).toString("base64"), method: "android-keystore-biometric", assurance: "hardware", handle: { id: "h", v: 3 } };
    },
  };
  // The check starts with the record as it is now (pin v1)...
  const check = withKeys("launch", "Open your vault", async () => "opened").catch((e) => e);
  await asking;
  // ...meanwhile this device checks a newer statement (another device switched) and pins it.
  await pinMode(pin(2, 2, "holder-only"));
  assert.equal(R.store.peek().modePin.version, 2);
  go();
  await check; // the keys don't unwrap in this test: only what was written matters
  const rec = R.store.peek();
  assert.deepEqual(rec.gate.handle, { id: "h", v: 3 }, "the new handle is kept");
  assert.deepEqual([rec.modePin.version, rec.modePin.epoch, rec.recoveryMode], [2, 2, "holder-only"], "and so is the newer pin");
  assert.equal(S.identity.value.modePin.version, 2);
});

test("every identity write in the app goes through updateIdentity (or createIdentity/clearIdentity)", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const dir = new URL("../apps/mobile/src/core/", import.meta.url);
  const raw = [];
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".js") && n !== "identity.js")) {
    if (/\.putIdentity\(/.test(readFileSync(new URL(f, dir), "utf8"))) raw.push(f);
  }
  assert.deepEqual(raw, [], "a module writes the identity record from its own copy");
});
