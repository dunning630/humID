// HumID Server for Windows: the five HumID services and a local edge in one
// Node process, so a single background task runs the whole vault.
//
//   node humid-server.mjs run   [--root DIR] [--service]   run the server
//   node humid-server.mjs init  [--root DIR] [--set K=V …]  create humid.env (keys + defaults), or update it
//   node humid-server.mjs set   [--root DIR]  K=V …          change settings
//   node humid-server.mjs show  [--root DIR]                 print settings (keys hidden) and server.json
//   node humid-server.mjs version
//
// DIR defaults to %ProgramData%\HumID (HUMID_HOME overrides). Inside it:
//   humid.env      settings and the internal key pair
//   data\<service> each service's own database and keys
//   logs\          humid-server.log, rotated at 10 MB
//   server.json    written at start: local and public address, key id, fingerprint
//
// Same code as the Docker images; here every service listens on 127.0.0.1 on a
// random port and only the edge has a fixed one (HUMID_PORT, default 8480),
// which the tunnel forwards to.

import "./embedded.mjs"; // must stay the first import
import { existsSync, writeFileSync, mkdirSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { newInternalKeys } from "@humid/svc";
import { createIdentity } from "../../../services/identity/src/server.js";
import { createVault } from "../../../services/vault/src/server.js";
import { createLedger } from "../../../services/ledger/src/server.js";
import { createRecovery } from "../../../services/recovery/src/server.js";
import { createGateway } from "../../../services/gateway/src/server.js";
import { readEnvFile, updateEnvFile, initialEnvText, validate, DEFAULTS } from "./config.mjs";
import { teeToFile } from "./logfile.mjs";
import { createEdge } from "./edge.mjs";

/* global __HUMID_SERVER_VERSION__ */
const VERSION = typeof __HUMID_SERVER_VERSION__ === "string" ? __HUMID_SERVER_VERSION__ : "dev";
const here = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
const command = argv[0] && !argv[0].startsWith("--") ? argv.shift() : "run";
const flag = (name) => { const i = argv.indexOf(name); if (i < 0) return undefined; const v = argv[i + 1]; argv.splice(i, 2); return v; };
const has = (name) => { const i = argv.indexOf(name); if (i < 0) return false; argv.splice(i, 1); return true; };

const root = flag("--root") || process.env.HUMID_HOME || join(process.env.ProgramData || "C:\\ProgramData", "HumID");
const envFile = join(root, "humid.env");
const sets = [];
for (let v; (v = flag("--set")) !== undefined;) sets.push(v);

const parsePairs = (pairs) => Object.fromEntries(pairs.map((p) => {
  const i = p.indexOf("=");
  if (i < 1) throw new Error(`Expected KEY=VALUE, got "${p}"`);
  return [p.slice(0, i).trim(), p.slice(i + 1).trim()];
}));

function fail(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }

async function main() {
  switch (command) {
    case "version": process.stdout.write(`${VERSION}\n`); return;
    case "init": return init(parsePairs(sets));
    case "set": return set(parsePairs([...sets, ...argv]));
    case "show": return show();
    case "run": return run({ service: has("--service") });
    default: fail(`Unknown command "${command}". Use run, init, set, show or version.`, 2);
  }
}

function init(changes) {
  mkdirSync(root, { recursive: true });
  for (const d of ["data", "logs"]) mkdirSync(join(root, d), { recursive: true });
  if (!existsSync(envFile)) {
    writeFileSync(envFile, initialEnvText(newInternalKeys()), { mode: 0o600 });
    process.stdout.write(`Created ${envFile} with a new internal key pair.\n`);
  } else {
    // Older installs may lack newer settings: add any that are missing, keep the rest.
    const cur = readEnvFile(envFile);
    const missing = Object.fromEntries(DEFAULTS.filter(([k]) => !(k in cur)).map(([k, v]) => [k, v]));
    if (!cur.HUMID_INTERNAL_SK || !cur.HUMID_INTERNAL_PK) Object.assign(missing, (({ sk, pk }) => ({ HUMID_INTERNAL_SK: sk, HUMID_INTERNAL_PK: pk }))(newInternalKeys()));
    if (Object.keys(missing).length) updateEnvFile(envFile, missing);
  }
  if (Object.keys(changes).length) set(changes);
  else validate(readEnvFile(envFile));
}

function set(changes) {
  if (!existsSync(envFile)) fail(`${envFile} doesn't exist yet. Run init first.`);
  for (const k of Object.keys(changes)) if (!/^[A-Z][A-Z0-9_]*$/.test(k)) fail(`"${k}" is not a setting name.`);
  validate({ ...readEnvFile(envFile), ...changes });
  updateEnvFile(envFile, changes);
  for (const [k, v] of Object.entries(changes)) process.stdout.write(`${k}=${/_SK$/.test(k) ? "(hidden)" : v}\n`);
}

function show() {
  const cfg = readEnvFile(envFile);
  for (const [k, v] of Object.entries(cfg)) process.stdout.write(`${k}=${/_SK$/.test(k) ? "(hidden)" : v}\n`);
}

async function run({ service }) {
  if (!existsSync(envFile)) fail(`${envFile} doesn't exist. Run: humid-server.mjs init`);
  teeToFile(join(root, "logs", "humid-server.log"), { quiet: service });
  const log = (level, msg, extra = {}) => process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level, service: "windows-host", msg, ...extra }) + "\n");
  process.on("uncaughtException", (e) => { log("error", "uncaught", { err: e.stack }); process.exit(1); });
  process.on("unhandledRejection", (e) => { log("error", "unhandled rejection", { err: e?.stack || String(e) }); process.exit(1); });

  // Settings: humid.env, unless the environment already sets a value (handy for tests).
  const cfg = readEnvFile(envFile);
  for (const [k, v] of Object.entries(cfg)) if (process.env[k] === undefined) process.env[k] = v;
  const S = (k, d) => process.env[k] || d;
  try { validate(process.env); } catch (e) { log("error", "bad settings", { err: e.message }); process.exit(1); }
  const host = S("HUMID_BIND_HOST", "127.0.0.1");
  process.env.HUMID_BIND_HOST = host;
  const data = (svc) => join(root, "data", svc);
  log("info", "starting", { version: VERSION, root, node: process.version, policy: S("HUMID_DEVICE_POLICY", "attested") });

  const pk = process.env.HUMID_INTERNAL_PK;
  const identity = createIdentity({ port: 0, dataDir: data("identity"), internalPk: pk });
  const vault = createVault({ port: 0, dataDir: data("vault"), internalPk: pk });
  const ledger = createLedger({ port: 0, dataDir: data("ledger"), internalPk: pk });
  const recovery = createRecovery({ port: 0, dataDir: data("recovery"), internalPk: pk });
  await Promise.all([identity.start(), vault.start(), ledger.start(), recovery.start()]);
  const url = (s) => `http://${host.includes(":") ? `[${host}]` : host}:${s.server.address().port}`;
  const local = (s) => `http://127.0.0.1:${s.server.address().port}`;
  const gateway = createGateway({
    port: 0, dataDir: data("gateway"), internalSk: process.env.HUMID_INTERNAL_SK,
    upstreams: { identity: local(identity), vault: local(vault), ledger: local(ledger), recovery: local(recovery) },
    trustProxy: true, // only the edge talks to it, and the edge sets X-Forwarded-For
  });
  await gateway.start();

  const port = Number(S("HUMID_PORT", "8480"));
  const edge = createEdge({
    port, host, appDir: join(here, "app"), gatewayUrl: local(gateway),
    log: { error: (msg, extra) => log("error", msg, extra) },
  });
  try { await edge.start(); }
  catch (e) {
    log("error", e.code === "EADDRINUSE" ? `Port ${port} is already in use. Pick another with: humid.ps1 set HUMID_PORT=8481` : "edge failed to start", { err: e.message });
    process.exit(1);
  }

  const info = {
    version: VERSION,
    localUrl: url(edge),
    publicUrl: S("HUMID_PUBLIC_URL", "") || null,
    kid: gateway.htp.kid,
    fingerprint: gateway.htp.fingerprint,
    devicePolicy: S("HUMID_DEVICE_POLICY", "attested"),
    iphones: Boolean(S("HUMID_IOS_APP_ID", "")),
    startedAt: new Date().toISOString(),
    pid: process.pid,
  };
  const tmp = join(root, "server.json.tmp");
  writeFileSync(tmp, JSON.stringify(info, null, 2));
  renameSync(tmp, join(root, "server.json"));
  log("info", "ready", info);
  if (!service) process.stdout.write(`\nHumID Server ${VERSION} is running at ${info.localUrl}\nServer fingerprint ${info.fingerprint}\nPress Ctrl+C to stop.\n\n`);
}

main().catch((e) => fail(e.code === "bad_config" ? e.message : e.stack || String(e)));
