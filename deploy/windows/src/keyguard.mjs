// The keys that protect HumID Server for Windows at rest (server 3.0, docs/DEPLOY-VMS.md):
//
//   seal key     <root>\keys\seal.dpapi           opens the server's sealed secrets (packages/svc/src/seal.js).
//                                                 Read by the server (LOCAL SERVICE) at every start.
//   backup key   <root>\backup-key\backup.dpapi   encrypts backups (backup.mjs). Read only by
//                                                 administrators and SYSTEM (the folder's ACL).
//
// Each is 32 random bytes kept as a DPAPI machine blob: only this Windows installation can
// open it, and with BitLocker's TPM protector on the system drive, only on this machine. A
// copy of the data folder, a stolen data disk or a VM's data volume opens nothing. The
// backup key is also shown once to the administrator (humid backup-key) to keep offline,
// because a backup must be restorable on a new machine.
//
// HUMID_SEAL chooses: dpapi (default on Windows) · file (HUMID_SEAL_KEY_FILE, for tests and
// other hosts) · off (no sealing; secrets kept as before 3.0).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes, createHash } from "node:crypto";
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
const BACKUP_PURPOSE = "HumID backup key v1";
export const sealKeyFile = (root) => join(root, "keys", "seal.dpapi");
export const backupKeyFile = (root) => join(root, "backup-key", "backup.dpapi");

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

/** The backup key (32 bytes). Administrators and SYSTEM only. */
export function loadBackupKey(root, { create = true, env = process.env } = {}) {
  if (env.HUMID_BACKUP_KEY_FILE) return parseKeyText(readFileSync(env.HUMID_BACKUP_KEY_FILE)); // tests, and hosts without DPAPI
  if (process.platform !== "win32") {
    // elsewhere: a key file in the private folder (owner-only), for development and the Linux test suite
    const f = join(root, "backup-key", "backup.key");
    if (existsSync(f)) return parseKeyText(readFileSync(f));
    if (!create) return null;
    const k = new Uint8Array(randomBytes(32));
    writeAtomic(f, Buffer.from(k).toString("hex"));
    return k;
  }
  return guarded(backupKeyFile(root), BACKUP_PURPOSE, create);
}

function guarded(file, purpose, create) {
  if (existsSync(file)) return dpapi("unprotect", Buffer.from(readFileSync(file, "utf8").trim(), "base64"), purpose);
  if (!create) return null;
  const key = new Uint8Array(randomBytes(32));
  mkdirSync(join(file, ".."), { recursive: true });
  writeAtomic(file, Buffer.from(dpapi("protect", key, purpose)).toString("base64"));
  return key;
}

/** Keep a raw key (restored from a backup) as this machine's own DPAPI blob. */
export function storeKey(root, which, key) {
  if (process.platform !== "win32" || sealMode() === "file") {
    if (which === "backup") writeAtomic(join(root, "backup-key", "backup.key"), Buffer.from(key).toString("hex"));
    return; // the seal key file is the operator's on other hosts
  }
  const [file, purpose] = which === "seal" ? [sealKeyFile(root), SEAL_PURPOSE] : [backupKeyFile(root), BACKUP_PURPOSE];
  writeAtomic(file, Buffer.from(dpapi("protect", key, purpose)).toString("base64"));
}

/** The sealer this server uses: a pass-through when sealing is off. */
export const serverSealer = (root, opts) => sealer(loadSealKey(root, opts));

/* ---------------- the backup key, as a person writes it down ---------------- */

const B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I, O, 0, 1
/** 32 bytes -> "HBK-XXXX-XXXX-…" (52 characters in 13 groups) + a 4-character check. */
export function formatBackupKey(key) {
  const bytes = Buffer.concat([Buffer.from(key), createHash("sha256").update(key).digest().subarray(0, 2)]);
  let bitsBuf = 0, n = 0, out = "";
  for (const b of bytes) { bitsBuf = (bitsBuf << 8) | b; n += 8; while (n >= 5) { out += B32[(bitsBuf >>> (n - 5)) & 31]; n -= 5; } }
  if (n) out += B32[(bitsBuf << (5 - n)) & 31];
  return "HBK-" + out.match(/.{1,4}/g).join("-");
}
/** The reverse; throws on a typo (the check doesn't match). Case and spacing don't matter. */
export function parseBackupKey(text) {
  const s = String(text).toUpperCase().replace(/^\s*HBK/, "").replace(/[^A-Z0-9]/g, "");
  let bitsBuf = 0, n = 0;
  const out = [];
  for (const ch of s) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new Error(`"${ch}" isn't in a backup key`);
    bitsBuf = ((bitsBuf << 5) | v) & 0xffff; n += 5;
    if (n >= 8) { out.push((bitsBuf >>> (n - 8)) & 0xff); n -= 8; }
  }
  if (out.length < 34) throw new Error("That backup key is too short");
  const key = Buffer.from(out.slice(0, 32)), check = Buffer.from(out.slice(32, 34));
  if (!createHash("sha256").update(key).digest().subarray(0, 2).equals(check)) throw new Error("That backup key has a typo (its check doesn't match)");
  return new Uint8Array(key);
}
