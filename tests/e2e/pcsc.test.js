// Hardware in the loop, minus the hardware: the shared chip reader drives the
// native desktop transport (tauri-plugin-humid-nfc, PC/SC), through a real
// pcscd, to a simulated passport chip inserted in a virtual reader.
// Runs when pcscd with vsmartcard's vpcd is up and the bridge is built:
//   cargo build --example apdu-bridge --features pcsc-linux   (plugins/humid-nfc)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import net from "node:net";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { readDocument, util } from "@humid/emrtd";
import { passiveAuth, activeAuth } from "@humid/anchor";
import { testCsca, testPassport } from "../support/passport.js";
import { simulatedChip } from "../support/chip.js";
import { insertCard } from "../support/vicc.js";

const BRIDGE = fileURLToPath(new URL("../../plugins/humid-nfc/target/debug/examples/apdu-bridge", import.meta.url));
const vpcdUp = () => new Promise((r) => { const s = net.connect(35963, "127.0.0.1"); s.on("connect", () => { s.destroy(); r(true); }); s.on("error", () => r(false)); });
const ready = existsSync(BRIDGE) && (await vpcdUp());
if (!ready && process.env.HUMID_REQUIRE_PCSC === "1") throw new Error("pcscd with vpcd, or the apdu-bridge example, isn't available");
const skip = !ready;

function bridge() {
  const p = spawn(BRIDGE, [], { stdio: ["pipe", "pipe", "inherit"] });
  const lines = createInterface({ input: p.stdout });
  const waiting = [];
  lines.on("line", (l) => waiting.shift()?.(JSON.parse(l)));
  const ask = (cmd) => new Promise((r) => { waiting.push(r); p.stdin.write(cmd + "\n"); });
  return {
    ask,
    transport: { transceive: async (apdu) => { const r = await ask(util.hex(apdu)); if (r.error) throw new Error(r.error); return util.fromHex(r.response); } },
    close: () => p.kill(),
  };
}

test("the native PC/SC transport reads a chip (PACE, then the server verifies it and its live answer)", { skip: skip && "pcscd with vpcd, or the apdu-bridge example, isn't available" }, async () => {
  const csca = testCsca("HumID PCSC Country");
  const access = { number: "C01X00T47", birth: "750101", expiry: "350101" };
  const passport = testPassport({ csca, mrz: { ...access, surname: "TESTER" } });
  const card = await insertCard(simulatedChip({ passport, access, pace: { oid: "0.4.0.127.0.7.2.2.4.2.2", parameterId: 13 } }));
  const b = bridge();
  try {
    const probe = await b.ask("probe");
    assert.equal(probe.Ok?.available, true, JSON.stringify(probe));
    const begun = await b.ask("begin");
    assert.ok(begun.ok?.session, JSON.stringify(begun));
    const nonce = randomBytes(8);
    const r = await readDocument(b.transport, { access, nonce });
    assert.match(r.access, /^PACE/);
    assert.equal(passiveAuth(r, { cscas: [csca.pem] }).mrz.surname, "TESTER");
    assert.equal(activeAuth({ dg15: r.dg15, nonce, signature: r.aaSignature }), true);
    await b.ask("end");
  } finally { b.close(); await card.remove(); }
});
