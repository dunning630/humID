// HumID Admin for Windows: the admin console program (docs/ADMIN.md).
//
//   node humid-admin.mjs run   [--root DIR] [--service]   run the console (the "HumID Admin" task does this)
//   node humid-admin.mjs reset-admins [--root DIR]        forget every administrator phone (break-glass,
//                                                         for `humid admin reset` in an admin terminal)
//   node humid-admin.mjs verify-release --zip FILE --version X.Y.Z [--sig FILE]
//                                                         check a release zip's signature against the
//                                                         release keys this console pins (the update
//                                                         job runs it right before unpacking)
//   node humid-admin.mjs version
//
// DIR defaults to %ProgramData%\HumID, as for the server.
import { readFileSync, existsSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { readEnvFile } from "../src/config.mjs";
import { teeToFile } from "../src/logfile.mjs";
import { createConsole } from "./console.mjs";
import { windowsPlatform } from "./platform.mjs";
import { openStore } from "./store.mjs";
import { verifyRelease } from "./release.mjs";

/* global __HUMID_SERVER_VERSION__ */
const VERSION = typeof __HUMID_SERVER_VERSION__ === "string" ? __HUMID_SERVER_VERSION__ : "dev";
const here = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
const command = argv[0] && !argv[0].startsWith("--") ? argv.shift() : "run";
const flag = (name) => { const i = argv.indexOf(name); if (i < 0) return undefined; const v = argv[i + 1]; argv.splice(i, 2); return v; };
const has = (name) => { const i = argv.indexOf(name); if (i < 0) return false; argv.splice(i, 1); return true; };
const root = flag("--root") || process.env.HUMID_HOME || join(process.env.ProgramData || "C:\\ProgramData", "HumID");

function fail(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }

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
  default: fail(`Unknown command "${command}". Use run, reset-admins, verify-release or version.`, 2);
}
