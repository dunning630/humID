// The key that protects HumID Server for Windows at rest (server 3.0, docs/DEPLOY-VMS.md):
//
//   seal key     <root>\keys\seal.dpapi           opens the server's sealed secrets (packages/svc/src/seal.js).
//                                                 Read by the server (LOCAL SERVICE) at every start.
//
// 32 random bytes kept as a DPAPI machine blob: only this Windows installation can open it,
// and with BitLocker's TPM protector on the system drive, only on this machine. A copy of the
// data folder, a stolen data disk or a VM's data volume opens nothing.
//
// Backups are NOT encrypted with a key kept here (server 3.1, PC-10): they are encrypted to a
// backup key whose private half the administrator keeps off this computer (admin/backups.mjs),
// so this server can't open its own backups. An encrypted backup carries the raw seal key
// inside, so a restore on a new machine can seal it again under that machine's DPAPI
// (storeSealKey).
//
// HUMID_SEAL chooses: dpapi (default on Windows) · file (HUMID_SEAL_KEY_FILE, for tests and
// other hosts) · off (no sealing; secrets kept as before 3.0).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { sealer, parseKeyText, writeAtomic } from "@humid/svc";

const PS = () => join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
// The bytes go through the environment, never the command line (which other users can list).
const DPAPI = `$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$in=[Convert]::FromBase64String($env:HUMID_DPAPI_IN)
$e=[Text.Encoding]::UTF8.GetBytes($env:HUMID_DPAPI_PURPOSE)
$s=[Security.Cryptography.DataProtectionScope]::LocalMachine
if ($env:HUMID_DPAPI_OP -eq 'protect') { $o=[Security.Cryptography.ProtectedData]::Protect($in,$e,$s) } else { $o=[Security.Cryptography.ProtectedData]::Unprotect($in,$e,$s) }
[Console]::Out.Write([Convert]::ToBase64String($o))`;

/** DPAPI (machine scope) through Windows PowerShell 5.1, which every Windows has. */
export function dpapi(op, bytes, purpose) {
  if (process.platform !== "win32") throw Object.assign(new Error("DPAPI exists only on Windows (set HUMID_SEAL=file or off elsewhere)"), { code: "no_dpapi" });
  const r = spawnSync(PS(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", DPAPI], {
    env: { ...process.env, HUMID_DPAPI_OP: op, HUMID_DPAPI_IN: Buffer.from(bytes).toString("base64"), HUMID_DPAPI_PURPOSE: purpose },
    encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 1 << 20,
  });
  if (r.status !== 0 || !r.stdout) throw Object.assign(new Error(`DPAPI ${op} failed: ${(r.stderr || r.error?.message || "no output").trim().split(/\r?\n/)[0]}`), { code: "dpapi_failed" });
  return new Uint8Array(Buffer.from(r.stdout.trim(), "base64"));
}

const SEAL_PURPOSE = "HumID seal key v1";
export const sealKeyFile = (root) => join(root, "keys", "seal.dpapi");

export const sealMode = (env = process.env) => (env.HUMID_SEAL || (process.platform === "win32" ? "dpapi" : "off")).toLowerCase();

/**
 * This server's seal key (32 bytes), or null when sealing is off. With create, a missing key
 * is made (first start of 3.0, or a fresh install). Never replaced once it exists: a seal key
 * that can't be opened is an error, because new keys would orphan every sealed secret.
 */
export function loadSealKey(root, { create = true, env = process.env } = {}) {
  const mode = sealMode(env);
  if (mode === "off") return null;
  if (mode === "file") {
    if (!env.HUMID_SEAL_KEY_FILE) throw new Error("HUMID_SEAL=file needs HUMID_SEAL_KEY_FILE");
    return parseKeyText(readFileSync(env.HUMID_SEAL_KEY_FILE));
  }
  if (mode !== "dpapi") throw new Error("HUMID_SEAL must be dpapi, file or off");
  return guarded(sealKeyFile(root), SEAL_PURPOSE, create);
}

function guarded(file, purpose, create) {
  if (existsSync(file)) return dpapi("unprotect", Buffer.from(readFileSync(file, "utf8").trim(), "base64"), purpose);
  if (!create) return null;
  const key = new Uint8Array(randomBytes(32));
  mkdirSync(join(file, ".."), { recursive: true });
  writeAtomic(file, Buffer.from(dpapi("protect", key, purpose)).toString("base64"));
  return key;
}

/**
 * Keep a raw seal key (restored from a backup) under `root` as this machine's own DPAPI blob.
 * With HUMID_SEAL=file the key file is the operator's, and with off there is none: nothing is
 * written then. Returns whether it was stored.
 */
export function storeSealKey(root, key, env = process.env) {
  if (sealMode(env) !== "dpapi") return false;
  const file = sealKeyFile(root);
  mkdirSync(join(file, ".."), { recursive: true });
  writeAtomic(file, Buffer.from(dpapi("protect", key, SEAL_PURPOSE)).toString("base64"));
  return true;
}

/** The sealer this server uses: a pass-through when sealing is off. */
export const serverSealer = (root, opts) => sealer(loadSealKey(root, opts));
