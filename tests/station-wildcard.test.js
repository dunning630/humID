// VAULT-08: "*" in HUMID_STATION_ACCOUNTS makes every account a verification station, which
// can vouch any recovery onto the fastest wait. It's for the local dev server only, so the
// recovery service refuses it unless the explicit dev flag is set too, and says so loudly.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newInternalKeys } from "@humid/svc";
import { createRecovery } from "../services/recovery/src/server.js";

const keys = newInternalKeys();
const make = (opts) => {
  const dir = mkdtempSync(join(tmpdir(), "humid-station-"));
  let r = null;
  try { r = createRecovery({ port: 0, dataDir: dir, internalPk: keys.pk, corePk: keys.pk, tls: null, ...opts }); return r; }
  finally { r?.close(); rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
};

test('"*" stations are refused without the dev flag', () => {
  assert.throws(() => make({ stations: ["*"] }), /HUMID_ALLOW_ANY_STATION=dev/);
  assert.throws(() => make({ stations: ["hid_" + "a".repeat(40), "*"], allowAnyStation: false }), /local development only/);
});

test('"*" stations start only with the dev flag, and log it as an error', (t) => {
  const lines = [];
  const write = process.stdout.write;
  process.stdout.write = (chunk, ...rest) => { lines.push(String(chunk)); return true; };
  try { make({ stations: ["*"], allowAnyStation: true }); }
  finally { process.stdout.write = write; }
  const warn = lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((l) => l?.level === "error" && /EVERY ACCOUNT IS A VERIFICATION STATION/.test(l.msg));
  assert.ok(warn, "a loud startup line");
});

test("named stations need no flag", () => {
  assert.doesNotThrow(() => make({ stations: ["hid_" + "a".repeat(40)] }));
});
