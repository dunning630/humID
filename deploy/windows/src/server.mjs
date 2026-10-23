// HumID Server for Windows: the seven HumID services and a local edge in one
// Node process, so a single background task runs the whole vault.
//
//   node humid-server.mjs run   [--root DIR] [--service]   run the server
//   node humid-server.mjs init  [--root DIR] [--set K=V …]  create humid.env (keys + defaults), or update it
//   node humid-server.mjs set   [--root DIR]  K=V …          change settings
//   node humid-server.mjs show  [--root DIR]                 print settings (keys hidden) and server.json
//   node humid-server.mjs mint  [--root DIR] COUNT [BATCH]   print COUNT new access codes to sell (docs/ANONYMITY.md)
//   node humid-server.mjs pki init|status|issue ROLE --out DIR|import --from DIR [--root DIR]   mutual TLS between roles
//   node humid-server.mjs seal-status [--root DIR]           which secrets are sealed (JSON)
//   node humid-server.mjs cells run|once|status|check [--root DIR]   holder cells (docs/CELLS.md; run as SYSTEM)
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
//
// Server 3.0 (docs/DEPLOY-VMS.md):
//   roles     HUMID_ROLES picks what this machine runs: front (edge + gateway), core (identity,
//             vault, ledger, recovery, access), keys (keyshare). Default all three. A role whose
//             gateway is on another machine listens on HUMID_INTERNAL_BIND at fixed ports
//             (HUMID_INTERNAL_PORT_BASE + 1…6) with mutual TLS (<root>\pki); the gateway reaches
//             roles elsewhere at HUMID_CORE_HOST / HUMID_KEYS_HOST.
//   sealing   every server secret is sealed under the seal key (keyguard.mjs: DPAPI on Windows).
//   backups   written by the admin program (admin/admin.mjs backup, restore; admin/backups.mjs):
//             encrypted to a backup key the administrator keeps off this computer (server 3.1,
//             PC-10), keyshare's data in its own file. This program holds no backup key.

import "./embedded.mjs"; // must stay the first import
import { existsSync, writeFileSync, mkdirSync, renameSync, readFileSync, readdirSync } from "node:fs";
import http from "node:http";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { newInternalKeys, newStatementKeys, isSealedText, isSealedFile, makeCa, issueRoleCert, serverTls, roleOf, daysLeft, ROLES } from "@humid/svc";
import { loadSealKey, serverSealer, sealMode } from "./keyguard.mjs";
import { sealer as makeSealer, writeAtomic } from "@humid/svc";
import { createIdentity } from "../../../services/identity/src/server.js";
import { createVault } from "../../../services/vault/src/server.js";
import { createLedger } from "../../../services/ledger/src/server.js";
import { createRecovery } from "../../../services/recovery/src/server.js";
import { createGateway } from "../../../services/gateway/src/server.js";
import { createAccess } from "../../../services/access/src/server.js";
import { createKeyshare } from "../../../services/keyshare/src/server.js";
import { createRelay } from "../../../services/relay/src/server.js";
import { readEnvFile, updateEnvFile, initialEnvText, validate, DEFAULTS } from "./config.mjs";

/** The statement key pairs (SRV-30), private halves sealed: what the gateway's key alone can't do. */
const newStatements = (seal) => {
  const core = newStatementKeys(), keys = newStatementKeys();
  return { core: { sk: seal.sealText("humid.env/HUMID_CORE_STATEMENT_SK", core.sk), pk: core.pk }, keys: { sk: seal.sealText("humid.env/HUMID_KEYS_STATEMENT_SK", keys.sk), pk: keys.pk } };
};
import { teeToFile } from "./logfile.mjs";
import { createEdge } from "./edge.mjs";
import { createAdminBridge } from "./adminbridge.mjs";
import { createCells } from "../../../services/gateway/src/cells.js";
import { createController } from "./cells.mjs";
import { hyperV } from "./hyperv.mjs";
import { startStatus, watchLog } from "./status.mjs";

/* global __HUMID_SERVER_VERSION__, __HUMID_APP_VERSION__ */
const VERSION = typeof __HUMID_SERVER_VERSION__ === "string" ? __HUMID_SERVER_VERSION__ : "dev";
const APP_VERSION = typeof __HUMID_APP_VERSION__ === "string" ? __HUMID_APP_VERSION__ : "dev";
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
    case "mint": return mint(argv[0], argv[1]);
    case "pki": return pki(argv.shift(), argv);
    case "seal-status": return sealStatus();
    case "cells": return cells(argv.shift());
    default: fail(`Unknown command "${command}". Use run, init, set, show, mint, pki, seal-status, cells or version. (Backups: humid-admin.mjs backup and restore.)`, 2);
  }
}

function init(changes) {
  mkdirSync(root, { recursive: true });
  for (const d of ["data", "logs"]) mkdirSync(join(root, d), { recursive: true });
  // the seal key first (made once, never replaced), then the internal key sealed under it
  const envNow = { ...readEnvFile(envFile), ...process.env, ...changes };
  const seal = makeSealer(loadSealKey(root, { create: true, env: envNow }));
  if (!existsSync(envFile)) {
    const k = newInternalKeys();
    writeFileSync(envFile, initialEnvText({ sk: seal.sealText("humid.env/HUMID_INTERNAL_SK", k.sk), pk: k.pk }, newStatements(seal)), { mode: 0o600 });
    process.stdout.write(`Created ${envFile} with a new internal key pair${seal.on ? " (the private half sealed)" : ""}.\n`);
  } else {
    // Older installs may lack newer settings: add any that are missing, keep the rest.
    const cur = readEnvFile(envFile);
    const missing = Object.fromEntries(DEFAULTS.filter(([k]) => !(k in cur)).map(([k, v]) => [k, v]));
    if (!cur.HUMID_INTERNAL_PK) Object.assign(missing, (({ sk, pk }) => ({ HUMID_INTERNAL_SK: seal.sealText("humid.env/HUMID_INTERNAL_SK", sk), HUMID_INTERNAL_PK: pk }))(newInternalKeys()));
    else if (cur.HUMID_INTERNAL_SK && seal.on && !isSealedText(cur.HUMID_INTERNAL_SK)) missing.HUMID_INTERNAL_SK = seal.sealText("humid.env/HUMID_INTERNAL_SK", cur.HUMID_INTERNAL_SK); // seal an older install's key in place
    // An install from before SRV-30 gets its statement keys (a core or keys machine gets them from its pki bundle).
    if (!cur.HUMID_CORE_STATEMENT_PK && cur.HUMID_INTERNAL_SK !== "") {
      const st = newStatements(seal);
      Object.assign(missing, { HUMID_CORE_STATEMENT_SK: st.core.sk, HUMID_CORE_STATEMENT_PK: st.core.pk, HUMID_KEYS_STATEMENT_SK: st.keys.sk, HUMID_KEYS_STATEMENT_PK: st.keys.pk });
    }
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

/** Access codes to sell. Safe while the server runs: the database allows one writer at a time and waits. */
function mint(count, batch) {
  if (!existsSync(envFile)) fail(`${envFile} doesn't exist yet. Run init first.`);
  const n = Number(count);
  if (!Number.isInteger(n) || n < 1 || n > 10000) fail("Usage: mint COUNT [BATCH]   (COUNT from 1 to 10000)");
  const a = createAccess({ port: 0, dataDir: join(root, "data", "access"), internalPk: readEnvFile(envFile).HUMID_INTERNAL_PK, seal: serverSealer(root, { create: false, env: { ...readEnvFile(envFile), ...process.env } }), tls: null });
  process.stdout.write(a.mint(n, batch).join("\n") + "\n");
  a.close();
}

function show() {
  const cfg = readEnvFile(envFile);
  for (const [k, v] of Object.entries(cfg)) process.stdout.write(`${k}=${/_SK$/.test(k) ? "(hidden)" : v}\n`);
}

/* ---------------- roles ---------------- */

/** Each service, the role it belongs to, and its fixed internal port offset when another machine calls it. */
const SERVICES = [["identity", "core", 1], ["vault", "core", 2], ["ledger", "core", 3], ["recovery", "core", 4], ["access", "core", 5], ["keyshare", "keys", 6], ["relay", "core", 7]];
/** Services that run only when a setting turns them on: the messaging relay (HUMID_MESSAGING=on). */
const OPTIONAL = new Set(["relay"]);

export function parseRoles(text = "front,core,keys") {
  const roles = [...new Set(String(text).split(",").map((r) => r.trim().toLowerCase()).filter(Boolean))];
  const bad = roles.filter((r) => !ROLES.includes(r));
  if (bad.length || !roles.length) throw Object.assign(new Error(`HUMID_ROLES must be some of ${ROLES.join(", ")} (got "${text}")`), { code: "bad_config" });
  return roles;
}

const pkiDir = () => join(root, "pki");
/** This machine's certificate for a role (its key opened with the seal key). */
function roleCert(role, seal) {
  const d = pkiDir();
  const need = ["ca.crt", `${role}.crt`, `${role}.key`].map((f) => join(d, f));
  const missing = need.filter((f) => !existsSync(f));
  if (missing.length) throw Object.assign(new Error(`The ${role} role needs its certificate: ${missing.join(", ")} is missing. Run: humid pki init (on the front machine), then humid pki issue/import (docs/DEPLOY-VMS.md).`), { code: "bad_config" });
  return { ca: readFileSync(need[0], "utf8"), cert: readFileSync(need[1], "utf8"), key: seal.open(`pki/${role}.key`, readFileSync(need[2])).toString("utf8") };
}

async function run({ service }) {
  if (!existsSync(envFile)) fail(`${envFile} doesn't exist. Run: humid-server.mjs init`);
  teeToFile(join(root, "logs", "humid-server.log"), { quiet: service });
  const logWatch = watchLog(); // errors and warnings of the last hour, for the admin console
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

  // The seal key opens every sealed secret; secrets kept in plain by an older version are sealed in place.
  let seal;
  try { seal = makeSealer(loadSealKey(root, { create: true })); }
  catch (e) { log("error", "the seal key couldn't be opened, so the server can't start", { err: e.message, mode: sealMode() }); process.exit(1); }
  globalThis.__HUMID_SEALER__ = seal;
  if (!seal.on) log("warn", "secrets are not sealed (HUMID_SEAL=off): a copy of the data folder holds the server's keys");

  const roles = parseRoles(S("HUMID_ROLES", "front,core,keys"));
  const here3 = (r) => roles.includes(r);
  const base = Number(S("HUMID_INTERNAL_PORT_BASE", "8500"));
  const internalBind = S("HUMID_INTERNAL_BIND", "127.0.0.1");
  log("info", "starting", { version: VERSION, root, node: process.version, policy: S("HUMID_DEVICE_POLICY", "attested"), roles, sealed: seal.on ? sealMode() : "off" });

  // The internal assertion key: the private half only where the gateway runs.
  let internalSk = null;
  if (here3("front")) {
    if (!process.env.HUMID_INTERNAL_SK) fail("This machine runs the front role but has no HUMID_INTERNAL_SK (run init).");
    internalSk = seal.openText("humid.env/HUMID_INTERNAL_SK", process.env.HUMID_INTERNAL_SK);
    if (seal.on && !isSealedText(cfg.HUMID_INTERNAL_SK)) {
      // On Windows the server's account can't change humid.env (PC-09): humid install (init, as an administrator) seals it there.
      try { updateEnvFile(envFile, { HUMID_INTERNAL_SK: seal.sealText("humid.env/HUMID_INTERNAL_SK", internalSk) }); log("info", "sealed the internal key in humid.env"); }
      catch (e) { log("warn", "the internal key in humid.env is still in plain; humid install seals it", { err: e.code || e.message }); }
    }
  }
  const pk = process.env.HUMID_INTERNAL_PK;

  // A service listens for another machine (fixed port, mutual TLS) when the gateway isn't here.
  const remote = !here3("front");
  const tlsFor = {};
  for (const r of ["core", "keys"]) if (here3(r) && remote) tlsFor[r] = serverTls(roleCert(r, seal));
  const opts = (name, role, offset) => remote
    ? { port: base + offset, tls: tlsFor[role], dataDir: data(name), internalPk: pk }
    : { port: 0, tls: null, dataDir: data(name), internalPk: pk };
  // A machine that no longer runs core or keys shouldn't keep their signing keys (after a split, they live there).
  if (!here3("core") && process.env.HUMID_CORE_STATEMENT_SK) log("warn", "this machine doesn't run core but humid.env still holds HUMID_CORE_STATEMENT_SK: clear it (humid set HUMID_CORE_STATEMENT_SK=)");
  if (!here3("keys") && process.env.HUMID_KEYS_STATEMENT_SK) log("warn", "this machine doesn't run keys but humid.env still holds HUMID_KEYS_STATEMENT_SK: clear it (humid set HUMID_KEYS_STATEMENT_SK=) once the keys machine is running");
  // SRV-30: statement keys. Private halves only on the role that signs with them; never the gateway's to use.
  const st = {
    coreSk: here3("core") ? seal.openText("humid.env/HUMID_CORE_STATEMENT_SK", S("HUMID_CORE_STATEMENT_SK", "")) : "",
    corePk: S("HUMID_CORE_STATEMENT_PK", ""),
    keysSk: here3("keys") ? seal.openText("humid.env/HUMID_KEYS_STATEMENT_SK", S("HUMID_KEYS_STATEMENT_SK", "")) : "",
    keysPk: S("HUMID_KEYS_STATEMENT_PK", ""),
  };
  if (remote) process.env.HUMID_BIND_HOST = internalBind; // createService reads it when it listens

  const svcs = {};
  if (here3("core")) {
    svcs.identity = createIdentity({ ...opts("identity", "core", 1), statementSk: st.coreSk });
    svcs.vault = createVault({ ...opts("vault", "core", 2), corePk: st.corePk, keysPk: st.keysPk });
    svcs.ledger = createLedger({ ...opts("ledger", "core", 3), seal, statementSk: st.coreSk });
    // Country signing certificates for ID chips: drop PEM or DER files in <root>\csca (or point HUMID_CSCA_DIR elsewhere).
    svcs.recovery = createRecovery({ ...opts("recovery", "core", 4), seal, corePk: st.corePk, cscaDir: S("HUMID_CSCA_DIR", join(root, "csca")) });
    svcs.access = createAccess({ ...opts("access", "core", 5), seal });
    // Person to person (4.1 preview): mailboxes of fixed-size ciphertext, no accounts, no addresses.
    if (S("HUMID_MESSAGING", "off") === "on") svcs.relay = createRelay(opts("relay", "core", 7));
  }
  // Split keys. On one PC the keyshare data sits beside the vault's, sealed under the same
  // machine key; on VMs the keys role runs on its own machine and storage (docs/DEPLOY-VMS.md).
  if (here3("keys")) svcs.keyshare = createKeyshare({ ...opts("keyshare", "keys", 6), secretSeal: seal, corePk: st.corePk, statementSk: st.keysSk });
  await Promise.all(Object.values(svcs).map((x) => x.start()));
  process.env.HUMID_BIND_HOST = host;
  const url = (srv) => `http://${host.includes(":") ? `[${host}]` : host}:${srv.server.address().port}`;
  const local = (srv) => `http://127.0.0.1:${srv.server.address().port}`;

  let gateway = null, edge = null;
  const port = Number(S("HUMID_PORT", "8480"));
  if (here3("front")) {
    const where = { core: S("HUMID_CORE_HOST", ""), keys: S("HUMID_KEYS_HOST", "") };
    const upstreams = {};
    const messaging = S("HUMID_MESSAGING", "off") === "on";
    for (const [name, role, offset] of SERVICES) {
      if (OPTIONAL.has(name) && !messaging) continue; // off: no relay upstream, so the gateway offers no messaging
      if (svcs[name]) upstreams[name] = local(svcs[name]);
      else if (where[role]) upstreams[name] = `https://${where[role].includes(":") && !where[role].startsWith("[") ? `[${where[role]}]` : where[role]}:${base + offset}`;
      else fail(`HUMID_ROLES=${roles.join(",")} leaves out ${role}, so set HUMID_${role.toUpperCase()}_HOST to the machine that runs it.`);
    }
    const internalTls = Object.values(upstreams).some((u) => u.startsWith("https:")) ? roleCert("front", seal) : null;
    // Holder cells (docs/CELLS.md): the pool the controller writes, read here; claims kept in the gateway's data.
    let cellRouter = null;
    if (S("HUMID_CELLS", "off") === "hyperv") {
      cellRouter = createCells({ poolFile: join(root, "cells", "pool.json"), dataDir: data("gateway"), tls: roleCert("front", seal), log: { warn: (msg, extra) => log("warn", msg, extra) } });
      log("info", "holder cells on", cellRouter.stats());
    }
    gateway = createGateway({
      port: 0, dataDir: data("gateway"), internalSk, seal, internalTls, cells: cellRouter,
      upstreams,
      trustProxy: true, // only the edge talks to it, and the edge sets X-Forwarded-For
      admin: createAdminBridge(root), // approvals from administrators' phones, checked again by the admin console
      checkin: S("HUMID_CHECKIN", "off"), // docs/CHECKIN.md
      sharedHelloPerMin: Number(S("HUMID_SHARED_HELLO_PER_MIN", "600")), // V76-03: the tunnel's visitors can't be told apart
    });
    await gateway.start();
    edge = createEdge({
      port, host, appDir: join(here, "app"), gatewayUrl: local(gateway),
      trustForwarded: S("HUMID_TRUST_FORWARDED", "off"), // SRV-31: which tunnel header names the visitor, if any
      log: { error: (msg, extra) => log("error", msg, extra) },
    });
  } else {
    // no edge here: a local health answer on HUMID_PORT, so humid.ps1 can tell this role is up
    edge = healthOnly({ port, host, svcs, roles });
  }
  try { await edge.start(); }
  catch (e) {
    log("error", e.code === "EADDRINUSE" ? `Port ${port} is already in use. Pick another with: humid.ps1 set HUMID_PORT=8481` : "edge failed to start", { err: e.message });
    process.exit(1);
  }

  const info = {
    version: VERSION,
    appVersion: APP_VERSION,
    roles,
    sealed: seal.on ? sealMode() : "off",
    localUrl: url(edge),
    publicUrl: S("HUMID_PUBLIC_URL", "") || null,
    kid: gateway?.htp.kid ?? null,
    fingerprint: gateway?.htp.fingerprint ?? null,
    devicePolicy: S("HUMID_DEVICE_POLICY", "attested"),
    registration: S("HUMID_REGISTRATION", "pass"),
    messaging: S("HUMID_MESSAGING", "off") === "on",
    iphones: Boolean(S("HUMID_IOS_APP_ID", "")),
    internal: remote ? Object.fromEntries(Object.entries(svcs).map(([n, x]) => [n, `${internalBind}:${x.server.address().port}`])) : undefined,
    startedAt: new Date().toISOString(),
    pid: process.pid,
  };
  startStatus({
    root, version: VERSION, appVersion: APP_VERSION, log: logWatch, edgePort: port,
    services: { ...svcs, ...(gateway ? { gateway } : {}) },
    sessions: () => gateway?.htp.sessions.size ?? 0,
    checkinArmed: () => svcs.keyshare?.armedCount() ?? 0, // the console warns before anything that stops the server
    info: { kid: info.kid, fingerprint: info.fingerprint, publicUrl: info.publicUrl, devicePolicy: info.devicePolicy, registration: info.registration, roles, sealed: info.sealed },
  });
  const tmp = join(root, "server.json.tmp");
  writeFileSync(tmp, JSON.stringify(info, null, 2));
  renameSync(tmp, join(root, "server.json"));
  log("info", "ready", info);
  if (!service) process.stdout.write(`\nHumID Server ${VERSION} (${roles.join(", ")}) is running at ${info.localUrl}\n${info.fingerprint ? `Server fingerprint ${info.fingerprint}\n` : ""}Press Ctrl+C to stop.\n\n`);
}

/** A machine without the front role still answers GET /healthz on 127.0.0.1:HUMID_PORT (nothing else). */
function healthOnly({ port, host, svcs, roles }) {
  const server = http.createServer((req, res) => {
    const ok = req.method === "GET" && req.url === "/healthz" && Object.values(svcs).every((x) => x.server.listening);
    res.writeHead(req.url === "/healthz" ? (ok ? 200 : 503) : 404, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(req.url === "/healthz" ? { ok, roles } : { error: "not_found" }));
  });
  return { server, start: () => new Promise((r, j) => { server.once("error", j); server.listen(port, host, () => r(server)); }) };
}

/* ---------------- PKI for split roles ---------------- */

function pki(sub, args) {
  const d = pkiDir();
  const env = { ...readEnvFile(envFile), ...process.env };
  const seal = makeSealer(loadSealKey(root, { create: true, env }));
  const sealIt = (role, pem) => (seal.on ? seal.seal(`pki/${role}.key`, Buffer.from(pem)) : Buffer.from(pem));
  if (sub === "init") {
    if (existsSync(join(d, "ca.crt")) && !args.includes("--force")) fail(`${d} already has a CA. Use --force to replace it (every role's certificate must then be issued again).`);
    mkdirSync(d, { recursive: true });
    const ca = makeCa();
    writeAtomic(join(d, "ca.crt"), ca.certPem, 0o644);
    writeAtomic(join(d, "ca.key"), sealIt("ca", ca.keyPem));
    for (const r of ROLES) { const c = issueRoleCert(ca, r); writeAtomic(join(d, `${r}.crt`), c.certPem, 0o644); writeAtomic(join(d, `${r}.key`), sealIt(r, c.keyPem)); }
    process.stdout.write(`Made a CA and certificates for ${ROLES.join(", ")} in ${d}.\n`);
    return;
  }
  if (sub === "status") {
    const out = {};
    for (const f of existsSync(d) ? readdirSync(d) : []) if (f.endsWith(".crt")) { const pem = readFileSync(join(d, f), "utf8"); out[f] = { role: roleOf(pem), daysLeft: Math.floor(daysLeft(pem)), keySealed: isSealedFile(join(d, f.replace(/\.crt$/, ".key"))) }; }
    process.stdout.write(JSON.stringify(out, null, 2) + "\n");
    return;
  }
  if (sub === "issue") {
    const role = args.find((a) => ROLES.includes(a));
    const i = args.indexOf("--out"), out = i >= 0 ? args[i + 1] : null;
    if (!role || role === "front" || !out) fail("Usage: pki issue core|keys --out DIR   (a bundle to carry to the machine that runs that role)");
    if (!existsSync(join(d, "ca.key"))) fail("No CA on this machine: run pki init on the front machine first.");
    const ca = { certPem: readFileSync(join(d, "ca.crt"), "utf8"), keyPem: seal.open("pki/ca.key", readFileSync(join(d, "ca.key"))).toString("utf8") };
    const c = issueRoleCert(ca, role);
    writeAtomic(join(d, `${role}.crt`), c.certPem, 0o644);
    writeAtomic(join(d, `${role}.key`), sealIt(role, c.keyPem));
    mkdirSync(out, { recursive: true });
    writeAtomic(join(out, "ca.crt"), ca.certPem, 0o644);
    writeAtomic(join(out, `${role}.crt`), c.certPem, 0o644);
    writeAtomic(join(out, `${role}.key`), c.keyPem); // plain only for the trip: import seals it and you delete this folder
    writeAtomic(join(out, "internal.pub"), `${env.HUMID_INTERNAL_PK}\n`, 0o644);
    // SRV-30: the statement keys this role checks, and (core or keys) the one it signs with. Plain only for the trip, like the TLS key.
    const stOut = { HUMID_CORE_STATEMENT_PK: env.HUMID_CORE_STATEMENT_PK, HUMID_KEYS_STATEMENT_PK: env.HUMID_KEYS_STATEMENT_PK };
    if (role === "core") stOut.HUMID_CORE_STATEMENT_SK = seal.openText("humid.env/HUMID_CORE_STATEMENT_SK", env.HUMID_CORE_STATEMENT_SK || "");
    if (role === "keys") stOut.HUMID_KEYS_STATEMENT_SK = seal.openText("humid.env/HUMID_KEYS_STATEMENT_SK", env.HUMID_KEYS_STATEMENT_SK || "");
    writeAtomic(join(out, "statements.env"), Object.entries(stOut).map(([k, v]) => `${k}=${v || ""}`).join("\n") + "\n");
    writeAtomic(join(out, "README.txt"), `HumID ${role} role bundle. On the ${role} machine (Terminal, Admin):\r\n  humid pki import -Path "<this folder>"\r\nthen delete this folder: it holds the role's private key until it is imported.\r\n`, 0o644);
    process.stdout.write(`Wrote the ${role} bundle to ${out}. Carry it to the ${role} machine, import it, then delete it.\n`);
    return;
  }
  if (sub === "import") {
    const i = args.indexOf("--from"), from = i >= 0 ? args[i + 1] : null;
    if (!from) fail("Usage: pki import --from DIR");
    const role = ["core", "keys"].find((r) => existsSync(join(from, `${r}.crt`)) && existsSync(join(from, `${r}.key`)));
    if (!role) fail(`${from} holds no core or keys bundle.`);
    const crt = readFileSync(join(from, `${role}.crt`), "utf8");
    if (roleOf(crt) !== role) fail(`${role}.crt in ${from} isn't a ${role} certificate.`);
    mkdirSync(d, { recursive: true });
    writeAtomic(join(d, "ca.crt"), readFileSync(join(from, "ca.crt"), "utf8"), 0o644);
    writeAtomic(join(d, `${role}.crt`), crt, 0o644);
    writeAtomic(join(d, `${role}.key`), sealIt(role, readFileSync(join(from, `${role}.key`), "utf8")));
    // the gateway's public key, so this machine checks its assertions; this machine needs no private half
    const pub = readFileSync(join(from, "internal.pub"), "utf8").trim();
    // the statement keys for this role (SRV-30): its own private one sealed, the others' public halves; no others' private ones
    const stIn = existsSync(join(from, "statements.env")) ? readEnvFile(join(from, "statements.env")) : {};
    const stSet = { HUMID_CORE_STATEMENT_PK: stIn.HUMID_CORE_STATEMENT_PK || "", HUMID_KEYS_STATEMENT_PK: stIn.HUMID_KEYS_STATEMENT_PK || "", HUMID_CORE_STATEMENT_SK: "", HUMID_KEYS_STATEMENT_SK: "" };
    if (role === "core" && stIn.HUMID_CORE_STATEMENT_SK) stSet.HUMID_CORE_STATEMENT_SK = seal.sealText("humid.env/HUMID_CORE_STATEMENT_SK", stIn.HUMID_CORE_STATEMENT_SK);
    if (role === "keys" && stIn.HUMID_KEYS_STATEMENT_SK) stSet.HUMID_KEYS_STATEMENT_SK = seal.sealText("humid.env/HUMID_KEYS_STATEMENT_SK", stIn.HUMID_KEYS_STATEMENT_SK);
    updateEnvFile(envFile, { HUMID_INTERNAL_PK: pub, HUMID_INTERNAL_SK: "", ...stSet });
    process.stdout.write(`Imported the ${role} certificate${seal.on ? " (its key sealed)" : ""} and the gateway's public key. Delete ${from} now.\n`);
    return;
  }
  fail("Usage: pki init | status | issue core|keys --out DIR | import --from DIR");
}

/* ---------------- holder cells (docs/CELLS.md) ---------------- */

/** The cell controller's settings and keys, from humid.env and the PKI. Runs as SYSTEM: it opens the seal key. */
function cellController({ hv } = {}) {
  if (!existsSync(envFile)) fail(`${envFile} doesn't exist. Run: humid-server.mjs init`);
  const cfg = { ...readEnvFile(envFile), ...process.env };
  const n = (k, d) => Number(cfg[k] || d);
  const seal = makeSealer(loadSealKey(root, { create: false, env: cfg }));
  const d = pkiDir();
  if (!existsSync(join(d, "ca.key"))) fail("Holder cells need this server's CA: run  humid pki init  first.");
  const front = roleCert("front", seal);
  return createController({
    root,
    settings: {
      warm: n("HUMID_CELLS_WARM", 2), max: n("HUMID_CELLS_MAX", 25), reserveMb: n("HUMID_CELLS_RESERVE_MB", 4096), diskMb: n("HUMID_CELLS_DISK_MB", 1024),
      image: cfg.HUMID_CELLS_IMAGE || join(root, "cells", "base", "humid-cell.vhdx"), quotaBytes: n("VAULT_QUOTA_BYTES", 262144000),
    },
    keys: { internalSk: seal.openText("humid.env/HUMID_INTERNAL_SK", cfg.HUMID_INTERNAL_SK || ""), internalPk: cfg.HUMID_INTERNAL_PK, corePk: cfg.HUMID_CORE_STATEMENT_PK, keysPk: cfg.HUMID_KEYS_STATEMENT_PK },
    ca: { certPem: readFileSync(join(d, "ca.crt"), "utf8"), keyPem: seal.open("pki/ca.key", readFileSync(join(d, "ca.key"))).toString("utf8") },
    front: { cert: front.cert, key: front.key },
    hv: hv || hyperV({ root }),
    log: (level, msg, extra = {}) => process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level, service: "cells", msg, ...extra }) + "\n"),
  });
}

async function cells(sub) {
  if (sub === "check") { process.stdout.write(JSON.stringify(await hyperV({ root }).check()) + "\n"); return; }
  if (sub === "switch") { process.stdout.write(JSON.stringify(await hyperV({ root }).ensureSwitch()) + "\n"); return; }
  if (!["run", "once", "status"].includes(sub)) fail("Usage: cells run | once | status | check | switch");
  const c = cellController();
  if (sub === "status") { process.stdout.write(JSON.stringify(c.summary(), null, 2) + "\n"); return; }
  const on = () => (readEnvFile(envFile).HUMID_CELLS || "off") === "hyperv";
  const pass = async () => {
    if (!on()) return;
    try { const r = await c.reconcile(); if (Object.values(r).some((x) => x.length)) process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level: "info", service: "cells", msg: "pass", ...r }) + "\n"); }
    catch (e) { process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level: "error", service: "cells", msg: "pass failed", err: e.message }) + "\n"); }
  };
  if (sub === "once") { if (!on()) fail("HUMID_CELLS is off (humid set HUMID_CELLS=hyperv)."); await pass(); process.stdout.write(JSON.stringify(c.summary()) + "\n"); return; }
  teeToFile(join(root, "logs", "humid-cells.log"), { quiet: true });
  for (;;) { await pass(); await new Promise((r) => setTimeout(r, 15_000)); }
}

/** Which secrets are sealed: for humid status and the CI. */
function sealStatus() {
  const files = {
    "gateway/htp-keys.json": join(root, "data", "gateway", "htp-keys.json"),
    "ledger/ledger-key.json": join(root, "data", "ledger", "ledger-key.json"),
    "recovery/anchor-secret.bin": join(root, "data", "recovery", "anchor-secret.bin"),
    "keyshare/share-key.bin": join(root, "data", "keyshare", "share-key.bin"),
  };
  const out = { mode: sealMode({ ...readEnvFile(envFile), ...process.env }), sealed: [], plain: [], internalKey: null };
  for (const [n, f] of Object.entries(files)) if (existsSync(f)) (isSealedFile(f) ? out.sealed : out.plain).push(n);
  const sk = readEnvFile(envFile).HUMID_INTERNAL_SK;
  out.internalKey = !sk ? "none here" : isSealedText(sk) ? "sealed" : "plain";
  process.stdout.write(JSON.stringify(out) + "\n");
}

main().catch((e) => fail(e.code === "bad_config" ? e.message : e.stack || String(e)));
