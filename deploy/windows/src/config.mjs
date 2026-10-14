// humid.env: one KEY=VALUE per line, # for comments. The installer and the
// `set` command edit it through these functions, so comments and the order of
// existing lines survive every change.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/** Settings a fresh install gets, with what each one means. */
export const DEFAULTS = [
  ["HUMID_PORT", "8480", "Local port the tunnel (Tailscale Funnel or Cloudflare Tunnel) forwards to."],
  ["HUMID_BIND_HOST", "127.0.0.1", "Keep 127.0.0.1: nothing on your network can reach the server directly; only the tunnel can."],
  ["HUMID_PUBLIC_URL", "", "The https address phones use. Set by `humid.ps1 expose`."],
  ["HUMID_DEVICE_POLICY", "attested", "attested = phones whose secure chip proves every live face or fingerprint check · biometric = also biometric-only desktops · demo = testing only."],
  ["HUMID_IOS_APP_ID", "", "<Apple Team ID>.app.humid.vault — needed to accept iPhones."],
  ["HUMID_APP_ATTEST_ENV", "production", "development only for Xcode debug builds."],
  ["HUMID_ANDROID_PACKAGES", "app.humid.vault", "Android package names accepted in key attestation."],
  ["HUMID_ANDROID_CERT_DIGESTS", "", "SHA-256 of your Android release signing certificate; empty accepts any signer."],
  ["HUMID_REQUIRE_LOCKED_BOOT", "1", "1 refuses rooted / unlocked-bootloader Android phones."],
  ["RECOVERY_DELAY_MS", "259200000", "Base recovery wait (72 hours). Two-proof recoveries wait a third of it with a station, the whole of it with witnesses, 7/3 of it with a card and an ID chip alone; twice that after a duress signal."],
  ["HUMID_CSCA_DIR", "", "Folder of country signing certificates (CSCA, PEM or DER) for ID chips. Empty = the csca folder next to data."],
  ["HUMID_STATION_ACCOUNTS", "", "HumID account ids (hid_…, comma-separated) allowed to act as in-person verification stations."],
  ["HUMID_TLOG_COSIGNERS", "", "name=base64url ML-DSA-87 public key, comma-separated: independent cosigners of the public log."],
  ["HUMID_DURESS_COOLOFF_MS", "86400000", "After a duress signal, how long it must stay calm before the owner can lift the lockdown (24 hours)."],
  ["VAULT_QUOTA_BYTES", "262144000", "Storage per account (250 MB)."],
];

const LINE = /^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/;
const unquote = (v) => (/^(["']).*\1$/.test(v) ? v.slice(1, -1) : v);

export function readEnvFile(file) {
  const out = {};
  if (!existsSync(file)) return out;
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue;
    const m = LINE.exec(line);
    if (m) out[m[1]] = unquote(m[2]);
  }
  return out;
}

/** Set (or add) keys in the file, keeping everything else as it is. */
export function updateEnvFile(file, changes) {
  mkdirSync(dirname(file), { recursive: true });
  const lines = existsSync(file) ? readFileSync(file, "utf8").split(/\r?\n/) : [];
  const pending = new Map(Object.entries(changes));
  const next = lines.map((line) => {
    const m = LINE.exec(line);
    if (!m || /^\s*#/.test(line) || !pending.has(m[1])) return line;
    const v = pending.get(m[1]);
    pending.delete(m[1]);
    return `${m[1]}=${v}`;
  });
  while (next.length && next[next.length - 1] === "") next.pop();
  for (const [k, v] of pending) next.push(`${k}=${v}`);
  writeFileSync(file, next.join("\r\n") + "\r\n", { mode: 0o600 });
}

/** A new humid.env: the internal key pair, then every default with its explanation. */
export function initialEnvText(keys) {
  const lines = [
    "# HumID Server settings. Change with:  humid set KEY=VALUE   (in Terminal (Admin); it restarts the server)",
    "# Keep this file private: the internal key below lets a program impersonate the gateway to the other services.",
    `HUMID_INTERNAL_SK=${keys.sk}`,
    `HUMID_INTERNAL_PK=${keys.pk}`,
    "",
  ];
  for (const [k, v, help] of DEFAULTS) lines.push(`# ${help}`, `${k}=${v}`, "");
  return lines.join("\r\n");
}

export const VALID_POLICIES = ["attested", "biometric", "demo"];

/** Throw a readable error for settings the services would reject later. */
export function validate(cfg) {
  const problems = [];
  if (!cfg.HUMID_INTERNAL_SK || !cfg.HUMID_INTERNAL_PK) problems.push("HUMID_INTERNAL_SK / HUMID_INTERNAL_PK are missing (run `init`).");
  if (cfg.HUMID_DEVICE_POLICY && !VALID_POLICIES.includes(cfg.HUMID_DEVICE_POLICY)) problems.push(`HUMID_DEVICE_POLICY must be one of ${VALID_POLICIES.join(", ")}.`);
  const port = Number(cfg.HUMID_PORT || 8480);
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push("HUMID_PORT must be a port number.");
  if (cfg.HUMID_IOS_APP_ID && !/^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$/.test(cfg.HUMID_IOS_APP_ID)) problems.push("HUMID_IOS_APP_ID must look like ABCDE12345.app.humid.vault (10-character Team ID, a dot, the bundle id).");
  if (cfg.HUMID_PUBLIC_URL && !/^https:\/\/[^/\s]+$/.test(cfg.HUMID_PUBLIC_URL)) problems.push("HUMID_PUBLIC_URL must be https://host with no path.");
  if (problems.length) throw Object.assign(new Error(problems.join("\n")), { code: "bad_config" });
}
