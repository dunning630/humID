// HumID Admin for Windows: the admin console program (docs/ADMIN.md).
//
//   node humid-admin.mjs run   [--root DIR] [--service]   run the console (the "HumID Admin" task does this)
//   node humid-admin.mjs reset-admins [--root DIR]        forget every administrator phone (break-glass,
//                                                         for `humid admin reset` in an admin terminal)
//   node humid-admin.mjs verify-release --zip FILE --version X.Y.Z [--sig FILE]
//                                                         check a release zip's signature against the
//                                                         release keys this console pins (the update
//                                                         job runs it right before unpacking)
//   node humid-admin.mjs backup-key-new --out FILE [--replace]  a new backup key: the private key to FILE
//                                                         (never inside the data or program folders), the
//                                                         public key into admin\admin.env
//   node humid-admin.mjs backup-key-show                 the backup key and where keyshare's half goes
//   node humid-admin.mjs backup-keyshare-dir --dir DIR|default   where the console puts keyshare's half
//   node humid-admin.mjs backup [--out F --keyshare-out K] [--local L] [--console | --console-if-key] [--check]
//                                                         write backups (the server must be stopped):
//                                                         F and K encrypted to the backup key; L the local
//                                                         rollback copy; --console into backups\ and the
//                                                         keyshare folder, newest 10 kept; --check only
//                                                         says whether it could (before the server stops)
//   node humid-admin.mjs restore --into DIR [--in F] [--keyshare K] [--key KEYFILE]
//                                                         unpack a backup into the new folder DIR (keyshare's
//                                                         half alone: --keyshare without --in); the seal key it
//                                                         carries is sealed again under this machine's DPAPI
//   node humid-admin.mjs version
//
// DIR defaults to %ProgramData%\HumID, as for the server.
import { readFileSync, existsSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname, basename, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readEnvFile, updateEnvFile } from "../src/config.mjs";
import { teeToFile } from "../src/logfile.mjs";
import { loadSealKey, storeSealKey } from "../src/keyguard.mjs";
import { createConsole } from "./console.mjs";
import { windowsPlatform } from "./platform.mjs";
import { openStore } from "./store.mjs";
import { verifyRelease } from "./release.mjs";
import { newBackupKey, publicKeyOf, writeBackup, restoreBackup, backupNames, prune, isInside, sameDisk } from "./backups.mjs";
import { assertNoLinks } from "./nolinks.mjs";
import { random } from "@humid/crypto";
import { toHex } from "@humid/htp";

/* global __HUMID_SERVER_VERSION__ */
const VERSION = typeof __HUMID_SERVER_VERSION__ === "string" ? __HUMID_SERVER_VERSION__ : "dev";
const here = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
const command = argv[0] && !argv[0].startsWith("--") ? argv.shift() : "run";
const flag = (name) => { const i = argv.indexOf(name); if (i < 0) return undefined; const v = argv[i + 1]; argv.splice(i, 2); return v; };
const has = (name) => { const i = argv.indexOf(name); if (i < 0) return false; argv.splice(i, 1); return true; };
const root = flag("--root") || process.env.HUMID_HOME || join(process.env.ProgramData || "C:\\ProgramData", "HumID");

function fail(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }
// For the commands humid.ps1 runs and shows: plain lines on stdout ("Warning: …" for warnings),
// and on failure one line saying why, then exit 1.
const say = (line) => process.stdout.write(`${line}\n`);
async function step(fn) {
  try { await fn(); } catch (e) { say(e.message); process.exit(1); }
}
const adminEnvFile = () => join(root, "admin", "admin.env");
// The server's settings (HUMID_SEAL) as the server reads them: humid.env, then the environment.
const serverEnv = () => ({ ...readEnvFile(join(root, "humid.env")), ...process.env });
const keyshareDir = (env) => env.HUMID_BACKUP_KEYSHARE_DIR || join(root, "backups", "keyshare");
const sameDiskWarning = (a, b) => `Warning: keyshare's half (${b}) is on the same disk as the rest (${a}). Together they hold both halves of every split key: keep them on different disks.`;

switch (command) {
  case "version": process.stdout.write(`${VERSION}\n`); break;
  case "reset-admins": {
    const store = openStore(root);
    const n = store.admins().length;
    store.saveAdmins([]);
    store.audit("admin.reset", { removed: n, by: "admin terminal" });
    process.stdout.write(`Removed ${n} administrator phone${n === 1 ? "" : "s"}. Add yours again from the console.\n`);
    break;
  }
  case "verify-release": {
    // One line on stdout either way, for the job's step list; exit 1 when it doesn't check out.
    const zip = flag("--zip"), version = flag("--version");
    const sigFile = flag("--sig") || `${zip}.sig`;
    if (!zip || !version) fail("Usage: verify-release --zip FILE --version X.Y.Z [--sig FILE]", 2);
    try {
      const v = verifyRelease({ bytes: readFileSync(zip), name: basename(zip), version, sig: existsSync(sigFile) ? readFileSync(sigFile) : null });
      process.stdout.write(`Signed by HumID release key ${v.key}\n`);
    } catch (e) { process.stdout.write(`${e.message}\n`); process.exit(1); }
    break;
  }
  case "backup-key-new": {
    const out = flag("--out"), replace = has("--replace");
    if (!out) fail("Usage: backup-key-new --out FILE [--replace]", 2);
    await step(() => {
      const env = readEnvFile(adminEnvFile());
      if (env.HUMID_BACKUP_KEY && !replace) throw new Error(`A backup key is already set (${publicKeyOf(env.HUMID_BACKUP_KEY).fingerprint}). To replace it: humid backup-key new -Path <file> -Replace. Backups made before then still need the old key file.`);
      for (const [dir, what] of [[root, "the server's data folder"], [here, "the program folder"], [`${here}.previous`, "the program folder"], [`${here}.rollback`, "the program folder"]]) {
        if (isInside(out, dir)) throw new Error(`${out} is inside ${what} (${dir}). The backup key must be kept off this computer (a USB drive), never beside what it opens. Nothing was written.`);
      }
      const k = newBackupKey();
      try { writeFileSync(out, k.file, { mode: 0o600, flag: "wx" }); }
      catch (e) { throw new Error(e.code === "EEXIST" ? `${out} already exists. Nothing was written: choose another file name.` : `Couldn't write ${out}: ${e.message}`); }
      updateEnvFile(adminEnvFile(), { HUMID_BACKUP_KEY: k.publicKey });
      say(`Backup key ${k.fingerprint} is set: every backup from now on is encrypted to it.`);
      say(`Its private key is in ${out}. Restoring any backup needs that file: keep it, and a second copy, off this computer.`);
      if (sameDisk(out, root)) say(`Warning: ${out} is on the same disk as the server. Copy it to a USB drive or somewhere else off this computer, then delete it here: a key beside the backups opens them.`);
      if (env.HUMID_BACKUP_KEY) say("Warning: backups made before now are still encrypted to the old key; keep its file until you no longer need them.");
    });
    break;
  }
  case "backup-key-show": {
    await step(() => {
      const env = readEnvFile(adminEnvFile());
      if (env.HUMID_BACKUP_KEY) say(`Backup key        ${publicKeyOf(env.HUMID_BACKUP_KEY).fingerprint} (its private key is kept off this computer)`);
      else say("Backup key        none yet: backups wait until there is one (humid backup-key new -Path E:\\humid-backup.key)");
      say(`Backups           ${join(root, "backups")} (newest 10 kept)`);
      say(`Keyshare's half   ${keyshareDir(env)}${env.HUMID_BACKUP_KEYSHARE_DIR ? "" : " (change it with: humid backup-key keyshare D:\\HumID-keyshare)"}`);
      if (sameDisk(join(root, "backups"), keyshareDir(env))) say(sameDiskWarning(join(root, "backups"), keyshareDir(env)));
    });
    break;
  }
  case "backup-keyshare-dir": {
    const dir = flag("--dir");
    if (!dir) fail("Usage: backup-keyshare-dir --dir DIR|default", 2);
    await step(() => {
      if (dir === "default") { updateEnvFile(adminEnvFile(), { HUMID_BACKUP_KEYSHARE_DIR: "" }); say(`Keyshare's half goes to ${keyshareDir({})} again.`); }
      else {
        if (!isAbsolute(dir)) throw new Error("Give the whole path of a folder, e.g. D:\\HumID-keyshare.");
        // Under the data root the server's account could reach it; the console's backups\ is the one exception (the default).
        if (isInside(dir, root) && !isInside(dir, join(root, "backups"))) throw new Error(`${dir} is inside the server's data folder. Choose a folder on another disk that only administrators can change.`);
        updateEnvFile(adminEnvFile(), { HUMID_BACKUP_KEYSHARE_DIR: dir });
        say(`The console now writes keyshare's half of each backup to ${dir}. Choose a folder only administrators can change.`);
      }
      const now = keyshareDir(readEnvFile(adminEnvFile()));
      if (sameDisk(join(root, "backups"), now)) say(sameDiskWarning(join(root, "backups"), now));
    });
    break;
  }
  case "backup": {
    const out = flag("--out"), ksOut = flag("--keyshare-out"), local = flag("--local");
    const toConsole = has("--console"), ifKey = has("--console-if-key"), check = has("--check");
    if ((out && !ksOut) || (!out && ksOut) || (!out && !local && !toConsole && !ifKey)) fail("Usage: backup [--out F --keyshare-out K] [--local L] [--console | --console-if-key]", 2);
    await step(async () => {
      const env = readEnvFile(adminEnvFile());
      const key = env.HUMID_BACKUP_KEY || null;
      if ((out || toConsole) && !key) throw new Error("No backup key is set, so nothing was backed up: backups are always encrypted. In Terminal (Admin): humid backup-key new -Path E:\\humid-backup.key (a USB drive), then keep that file off this computer.");
      if (key) publicKeyOf(key);
      for (const f of [out, ksOut, local]) if (f && existsSync(f)) throw new Error(`${f} already exists. Nothing was written.`);
      if (out && resolve(out) === resolve(ksOut)) throw new Error("The backup and keyshare's half need two different files.");
      if (check) { say("Ready to back up."); return; }
      const set = toHex(random(8));
      const created = new Date().toISOString();
      // The seal key (server 3.0) travels inside the encrypted files, so they restore on a new
      // machine; never in the local copy, which keeps keys\ as this machine's own DPAPI blob.
      const sealKey = (out || toConsole || (ifKey && key)) ? loadSealKey(root, { create: false, env: serverEnv() }) : null;
      if (local) {
        const r = await writeBackup({ root, out: local, kind: "local", set, created });
        say(`Local rollback copy written to ${r.file}.`);
      }
      const pair = async (dataFile, ksFile) => {
        const a = await writeBackup({ root, out: dataFile, kind: "data", publicKey: key, set, created, sealKey });
        const b = await writeBackup({ root, out: ksFile, kind: "keyshare", publicKey: key, set, created, sealKey });
        say(`Backup written to ${a.file}, encrypted to backup key ${publicKeyOf(key).fingerprint}.`);
        say(`Keyshare's half written to ${b.file}.`);
        if (sameDisk(a.file, b.file)) say(sameDiskWarning(a.file, b.file));
        return { a, b };
      };
      if (out) await pair(out, ksOut);
      if (toConsole || (ifKey && key)) {
        const names = backupNames(new Date(created));
        const dataDir = join(root, "backups"), ksDir = keyshareDir(env);
        assertNoLinks(root, dataDir);
        if (isInside(ksDir, root)) assertNoLinks(root, ksDir);
        const { a, b } = await pair(join(dataDir, names.data), join(ksDir, names.keyshare));
        prune(dataDir, "HumID-backup-", 10);
        prune(ksDir, "HumID-keyshare-", 10);
        say(JSON.stringify({ file: names.data, bytes: a.bytes, keyshare: b.file, keyshareBytes: b.bytes, key: publicKeyOf(key).fingerprint }));
      } else if (ifKey) say("No backup key is set, so no lasting backup was kept, only the local rollback copy. Set one up: humid backup-key new.");
    });
    break;
  }
  case "restore": {
    const into = flag("--into"), file = flag("--in"), keyshareFile = flag("--keyshare"), keyFile = flag("--key");
    if (!into || (!file && !keyshareFile)) fail("Usage: restore --into DIR [--in F] [--keyshare K] [--key KEYFILE]", 2);
    await step(async () => {
      let keyText = null;
      if (keyFile) { try { keyText = readFileSync(keyFile, "utf8"); } catch (e) { throw new Error(`Can't read the backup key file ${keyFile}: ${e.message}`); } }
      const r = await restoreBackup({ file, keyshareFile, keyText, into });
      // The seal key the backup carried, sealed again under this machine's own DPAPI (it stays
      // inside `into`, the folder only SYSTEM and Administrators can open, until it's swapped in).
      let sealed = false;
      if (r.sealKey) {
        try { sealed = storeSealKey(into, r.sealKey, serverEnv()); }
        catch (e) { rmSync(into, { recursive: true, force: true }); throw new Error(`The backup checks out, but its seal key couldn't be kept on this machine (${e.message}). Nothing was restored.`); }
      }
      const what = r.kind === "local" ? "local rollback copy" : r.kind === "keyshare" ? "keyshare's half of the backup" : "backup";
      say(`Unpacked ${r.files} files (${Math.round(r.bytes / 1048576)} MB) from the ${what} made ${r.created}.`);
      say(JSON.stringify({ kind: r.kind, files: r.files, bytes: r.bytes, sealKey: !!r.sealKey, sealed }));
    });
    break;
  }
  case "run": {
    const service = has("--service");
    // In admin\logs, not logs\: the server's account writes there, and SYSTEM must never
    // append to a file it could have swapped for a link.
    teeToFile(join(root, "admin", "logs", "humid-admin.log"), { quiet: service });
    const log = (level, msg, extra = {}) => process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level, service: "admin", msg, ...extra }) + "\n");
    process.on("uncaughtException", (e) => { log("error", "uncaught", { err: e.stack }); process.exit(1); });
    process.on("unhandledRejection", (e) => { log("error", "unhandled rejection", { err: e?.stack || String(e) }); process.exit(1); });
    const port = Number(readEnvFile(join(root, "humid.env")).HUMID_ADMIN_PORT || 8490);
    const c = createConsole({ root, installDir: here, port, platform: windowsPlatform({ installDir: here }), version: VERSION, log });
    try { await c.start(); }
    catch (e) { log("error", e.code === "EADDRINUSE" ? `Port ${port} is already in use. Pick another with: humid set HUMID_ADMIN_PORT=8491` : "console failed to start", { err: e.message }); process.exit(1); }
    if (!service) process.stdout.write(`\nHumID Admin ${VERSION} at http://127.0.0.1:${port}\nOpen it with: humid console\n\n`);
    break;
  }
  default: fail(`Unknown command "${command}". Use run, reset-admins, verify-release, backup-key-new, backup-key-show, backup-keyshare-dir, backup, restore or version.`, 2);
}
