// The simulated security key (tests/support/fido-sim.js) against Yubico's
// python-fido2, the reference CTAP2 client: tests/support/fido_crosscheck.py
// drives Ctap2, ClientPin (PIN/UV protocols 1 and 2), HmacSecretExtension,
// CredProtectExtension and Fido2Client; every CTAP message it sends crosses
// a real NFC framing here (NFCCTAP_MSG with P1 0x80 and 9100 polling, CLA 0x90
// command chaining, 61xx + GET RESPONSE) into the simulator.
//
// Python: $HUMID_PYTHON, else python3 (pip install fido2==1.2.0). Skipped, with the reason,
// when neither can import fido2 1.2+, except where HUMID_REQUIRE_FIDO2=1 (CI): there it fails.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { simulatedKey, FIDO_AID } from "./support/fido-sim.js";

const SCRIPT = fileURLToPath(new URL("./support/fido_crosscheck.py", import.meta.url));
// CI sets HUMID_REQUIRE_FIDO2=1 (and installs python-fido2), so there a missing library fails the run.
const REQUIRED = process.env.HUMID_REQUIRE_FIDO2 === "1";

function findPython() {
  const candidates = [process.env.HUMID_PYTHON, "python3"].filter(Boolean);
  const reasons = [];
  for (const py of candidates) {
    const r = spawnSync(py, ["-c", "import fido2, cryptography; print(fido2.__version__)"], { encoding: "utf8", timeout: 20_000 });
    if (r.error) {
      reasons.push(`${py}: ${r.error.code ?? r.error.message}`);
      continue;
    }
    if (r.status !== 0) {
      reasons.push(`${py}: cannot import fido2`);
      continue;
    }
    const version = r.stdout.trim();
    const [major, minor] = version.split(".").map(Number);
    if (major !== 1 || minor < 2) {
      reasons.push(`${py}: fido2 ${version} (the cross-check uses the 1.2 API)`);
      continue;
    }
    return { py, version };
  }
  return { reason: `python-fido2 not available (${reasons.join("; ")})` };
}

// ---- NFC framing, written here for the bridge (ISO 7816-4, CTAP 2.1 §11.3) ----
const swOf = (r) => (r[r.length - 2] << 8) | r[r.length - 1];
const dataOf = (r) => r.subarray(0, r.length - 2);
const cat = (...p) => Uint8Array.from(Buffer.concat(p.map((x) => Buffer.from(x))));

function nfc(key) {
  const stats = { apdus: 0, chainedCommands: 0, busyPolls: 0, getResponses: 0 };
  const tx = async (apdu) => {
    stats.apdus++;
    return key.transceive(apdu);
  };
  return {
    stats,
    async select() {
      const r = await tx(cat([0x00, 0xa4, 0x04, 0x00, FIDO_AID.length], FIDO_AID, [0x00]));
      assert.equal(swOf(r), 0x9000);
      assert.equal(Buffer.from(dataOf(r)).toString("ascii"), "FIDO_2_0");
    },
    async cbor(msg) {
      let r;
      for (let off = 0; ; off += 255) {
        const block = msg.subarray(off, off + 255);
        const last = off + 255 >= msg.length;
        r = await tx(cat([last ? 0x80 : 0x90, 0x10, 0x80, 0x00, block.length], block, [0x00]));
        if (last) break;
        stats.chainedCommands++;
        assert.equal(swOf(r), 0x9000);
      }
      while (swOf(r) === 0x9100) {
        stats.busyPolls++;
        r = await tx(Uint8Array.of(0x80, 0x11, 0x00, 0x00, 0x00));
      }
      let body = dataOf(r);
      while (swOf(r) >> 8 === 0x61) {
        stats.getResponses++;
        r = await tx(Uint8Array.of(0x00, 0xc0, 0x00, 0x00, swOf(r) & 0xff));
        body = cat(body, dataOf(r));
      }
      assert.equal(swOf(r), 0x9000, `SW ${swOf(r).toString(16)}`);
      return body;
    },
  };
}

const python = findPython();

test("python-fido2 (Yubico's reference client) against the simulated key, over NFC framing", { timeout: 120_000 }, async (t) => {
  if (python.reason) {
    assert.ok(!REQUIRED, `python-fido2 is required here (HUMID_REQUIRE_FIDO2=1): ${python.reason}`);
    t.skip(python.reason);
    return;
  }
  const key = simulatedKey({ busyPolls: 1 });
  const link = nfc(key);
  await link.select();

  const child = spawn(python.py, [SCRIPT], { stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  const exited = new Promise((resolve) => child.on("close", (code) => resolve(code)));
  const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
  const checks = [];

  const lines = createInterface({ input: child.stdout });
  for await (const line of lines) {
    const msg = JSON.parse(line);
    switch (msg.op) {
      case "cbor":
        send({ data: Buffer.from(await link.cbor(Uint8Array.from(Buffer.from(msg.data, "hex")))).toString("hex") });
        break;
      case "powerCycle":
        key.powerCycle();
        await link.select();
        send({});
        break;
      case "hmacSecret":
        send({ data: Buffer.from(key.hmacSecretForTest(Buffer.from(msg.cred, "hex"), Buffer.from(msg.salt, "hex"), { uv: msg.uv })).toString("hex") });
        break;
      case "state": {
        const s = key.state;
        send({ counter: s.counter, pinRetries: s.pinRetries, pinSet: s.pinSet, credentials: s.credentials.length });
        break;
      }
      case "check":
        checks.push(msg.name);
        break;
      case "done":
        send({});
        child.stdin.end();
        break;
      default:
        throw new Error(`unknown bridge op ${msg.op}`);
    }
  }
  const code = await exited;
  assert.equal(code, 0, `python-fido2 cross-check failed:\n${stderr}`);
  for (const c of checks) t.diagnostic(`python-fido2 ${python.version}: ${c}`);
  assert.equal(checks.length, 12, checks.join("\n"));
  // the NFC paths were really exercised
  t.diagnostic(`NFC: ${JSON.stringify(link.stats)}`);
  assert.ok(link.stats.busyPolls > 0, "9100 polling");
  assert.ok(link.stats.chainedCommands > 0 || link.stats.getResponses > 0, "chaining");
});
