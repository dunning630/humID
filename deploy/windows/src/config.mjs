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
  ["HUMID_REGISTRATION", "pass", "pass = a new HumID needs an access pass, bought with an access code and signed blind so the payment can't be linked to the account (mint codes with `mint`) · open = anyone can create one."],
  ["HUMID_PASS_BUY_URL", "", "https address where people buy access codes; the app links to it. Empty = no link."],
  ["HUMID_IOS_APP_ID", "", "<Apple Team ID>.app.humid.vault — needed to accept iPhones."],
  ["HUMID_APP_ATTEST_ENV", "production", "development only for Xcode debug builds."],
  ["HUMID_ANDROID_PACKAGES", "app.humid.vault", "Android package names accepted in key attestation."],
  ["HUMID_ANDROID_CERT_DIGESTS", "", "The official HumID Android app is always accepted. Add the SHA-256 of your own signing certificate here only if you build and sign the app yourself."],
  ["HUMID_REQUIRE_LOCKED_BOOT", "1", "1 refuses rooted / unlocked-bootloader Android phones."],
  ["HUMID_ANDROID_MIN_PATCH", "", "Optional minimum Android security patch, YYYYMM (e.g. 202501). Empty = any."],
  ["HUMID_ATTESTATION_STATUS_REQUIRED", "0", "1 refuses Android phones until Google's revoked-key list has been fetched (it's fetched every 6 hours either way)."],
  ["RECOVERY_DELAY_MS", "259200000", "Base recovery wait (72 hours). Two-proof recoveries wait a third of it with a station, the whole of it with witnesses, 7/3 of it with a card and an ID chip alone; twice that after a duress signal."],
  ["HUMID_CSCA_DIR", "", "Folder of country signing certificates (CSCA, PEM or DER) for ID chips. Empty = the csca folder next to data."],
  ["HUMID_STATION_ACCOUNTS", "", "HumID account ids (hid_…, comma-separated) allowed to act as in-person verification stations."],
  ["HUMID_TLOG_COSIGNERS", "", "name=base64url ML-DSA-87 public key, comma-separated: independent cosigners of the public log."],
  ["HUMID_DURESS_COOLOFF_MS", "86400000", "After a duress signal, how long it must stay calm before the owner can lift the lockdown (24 hours)."],
  ["VAULT_QUOTA_BYTES", "262144000", "Storage per account (250 MB)."],
  ["HUMID_SHARE_RELEASES_PER_HOUR", "120", "Split keys: how many documents one account can open per hour, so a hijacked phone can't drain the vault."],
  ["HUMID_CHECKIN", "off", "on = holders can arm Check-in: their vault is erased for good unless they check in every hour or two (docs/CHECKIN.md). While anyone is armed, stopping the server (a restart, an update, a backup, restarting Windows) erases their vault too: its keys live in memory only. off until push reminders exist."],
  ["HUMID_UPDATE_PRERELEASES", "off", "on = the admin console also offers HumID Server releases marked pre-release on GitHub (still only ones signed with a HumID release key). off for anything holding real data."],
  ["HUMID_ADMIN_PORT", "8490", "Local port of the admin console (HumID Admin). Only this computer can open it; the tunnel never forwards it. Open it with `humid console`."],
  ["HUMID_SEAL", process.platform === "win32" ? "dpapi" : "off", "dpapi = the server's secrets are sealed under a key only this Windows installation can open (with BitLocker's TPM protector, only this machine) · off = kept in plain files as before 3.0 (not recommended)."],
  ["HUMID_ROLES", "front,core,keys", "What this machine runs (docs/DEPLOY-VMS.md): front = the edge and gateway · core = identity, vault, ledger, recovery, access · keys = the key-share service. All three on one machine by default."],
  ["HUMID_CORE_HOST", "", "When this machine runs front but not core: the address of the machine that runs core."],
  ["HUMID_KEYS_HOST", "", "When this machine runs front but not keys: the address of the machine that runs keys."],
  ["HUMID_INTERNAL_BIND", "127.0.0.1", "When this machine runs core or keys for a gateway elsewhere: the address it listens on for that gateway (mutual TLS only)."],
  ["HUMID_INTERNAL_PORT_BASE", "8500", "Internal ports for a gateway on another machine: base+1 identity, +2 vault, +3 ledger, +4 recovery, +5 access, +6 keyshare."],
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
  const roles = String(cfg.HUMID_ROLES || "front,core,keys").split(",").map((r) => r.trim().toLowerCase()).filter(Boolean);
  if (!roles.length || roles.some((r) => !["front", "core", "keys"].includes(r))) problems.push("HUMID_ROLES must be some of front, core, keys (comma-separated).");
  if (!cfg.HUMID_INTERNAL_PK) problems.push("HUMID_INTERNAL_PK is missing (run `init`, or `pki import` on a core or keys machine).");
  if (roles.includes("front") && !cfg.HUMID_INTERNAL_SK) problems.push("HUMID_INTERNAL_SK is missing: the front role signs internal requests with it (run `init`).");
  if (roles.includes("front") && !roles.includes("core") && !cfg.HUMID_CORE_HOST) problems.push("HUMID_CORE_HOST must name the machine that runs core.");
  if (roles.includes("front") && !roles.includes("keys") && !cfg.HUMID_KEYS_HOST) problems.push("HUMID_KEYS_HOST must name the machine that runs keys.");
  if (cfg.HUMID_SEAL && !["dpapi", "file", "off"].includes(String(cfg.HUMID_SEAL).toLowerCase())) problems.push("HUMID_SEAL must be dpapi, file or off.");
  const ib = Number(cfg.HUMID_INTERNAL_PORT_BASE || 8500);
  if (!Number.isInteger(ib) || ib < 1024 || ib > 65000) problems.push("HUMID_INTERNAL_PORT_BASE must be a port number from 1024 to 65000.");
  if (cfg.HUMID_DEVICE_POLICY && !VALID_POLICIES.includes(cfg.HUMID_DEVICE_POLICY)) problems.push(`HUMID_DEVICE_POLICY must be one of ${VALID_POLICIES.join(", ")}.`);
  if (cfg.HUMID_REGISTRATION && !["pass", "open"].includes(cfg.HUMID_REGISTRATION)) problems.push("HUMID_REGISTRATION must be pass or open.");
  if (cfg.HUMID_CHECKIN && !["on", "off"].includes(cfg.HUMID_CHECKIN)) problems.push("HUMID_CHECKIN must be on or off.");
  if (cfg.HUMID_UPDATE_PRERELEASES && !["on", "off"].includes(cfg.HUMID_UPDATE_PRERELEASES)) problems.push("HUMID_UPDATE_PRERELEASES must be on or off.");
  if (cfg.HUMID_PASS_BUY_URL && !/^https:\/\//.test(cfg.HUMID_PASS_BUY_URL)) problems.push("HUMID_PASS_BUY_URL must start with https://.");
  const port = Number(cfg.HUMID_PORT || 8480);
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push("HUMID_PORT must be a port number.");
  const adminPort = Number(cfg.HUMID_ADMIN_PORT || 8490);
  if (!Number.isInteger(adminPort) || adminPort < 1 || adminPort > 65535) problems.push("HUMID_ADMIN_PORT must be a port number.");
  else if (adminPort === port) problems.push("HUMID_ADMIN_PORT must differ from HUMID_PORT: the tunnel forwards HUMID_PORT, and the console must never be reachable through it.");
  if (cfg.HUMID_IOS_APP_ID && !/^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$/.test(cfg.HUMID_IOS_APP_ID)) problems.push("HUMID_IOS_APP_ID must look like ABCDE12345.app.humid.vault (10-character Team ID, a dot, the bundle id).");
  if (cfg.HUMID_PUBLIC_URL && !/^https:\/\/[^/\s]+$/.test(cfg.HUMID_PUBLIC_URL)) problems.push("HUMID_PUBLIC_URL must be https://host with no path.");
  if (problems.length) throw Object.assign(new Error(problems.join("\n")), { code: "bad_config" });
}
