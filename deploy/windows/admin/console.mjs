// HumID Admin: the server's admin console (docs/ADMIN.md).
//
// A second program beside the HumID server, run by Windows as SYSTEM so it can install
// Windows updates and new HumID versions. It listens on 127.0.0.1 only, on its own port
// (HUMID_ADMIN_PORT, 8490); the tunnel forwards the server's port, never this one.
//
//   Seeing      a one-time sign-in link from `humid console` in an admin terminal
//   Changing    every change waits for an administrator's phone: a 12-character code,
//               a live face or fingerprint check in HumID, and a signature this console
//               checks itself against the keys it pinned for that phone
//   Break-glass while the HumID server is down (so no phone can reach it), restarting it
//               is the one change that doesn't wait; it's logged as break-glass
import http from "node:http";
import tls from "node:tls";
import os from "node:os";
import { randomBytes } from "node:crypto";
import { readFileSync, readdirSync, rmSync, statSync, mkdirSync } from "node:fs";
import { join, basename } from "node:path";
import qrcode from "qrcode-generator";
import { qrPayload } from "@humid/recovery";
import { readEnvFile } from "../src/config.mjs";
import { adminPaths } from "../src/adminbridge.mjs";
import { STATUS_FILE } from "../src/status.mjs";
import { openStore, readJson, writeJsonAtomic } from "./store.mjs";
import { newCode, formatCode, requestDigest, digestCheck, verifyApproval, ApprovalError, REQUEST_TTL_MS, CODE_RE } from "./verify.mjs";
import { latestRelease, download, compareVersions, DEFAULT_REPO } from "./updates.mjs";
import { pinnedKeys } from "./release.mjs";

const MIN = 60_000, HOUR = 60 * MIN;
const SESSION_IDLE_MS = 30 * MIN, SESSION_MAX_MS = 12 * HOUR;
const STALE_MS = 45_000;            // the server writes its status every 15 s
const BREAK_GLASS_AFTER_MS = 30_000; // down this long before break-glass restart is offered
const CHECK_EVERY_MS = 6 * HOUR;    // HumID releases and Windows Update
const JOB_TYPES = new Set(["restart-server", "backup", "update-humid", "rollback-humid", "os-install", "reboot", "defender-update", "os-scan"]);
const MAINTENANCE = new Set(["restart-server", "backup", "update-humid", "rollback-humid", "reboot"]);

/* global __HUMID_ADMIN_PAGE__ */
const PAGE = typeof __HUMID_ADMIN_PAGE__ === "string" ? __HUMID_ADMIN_PAGE__ : readFileSync(new URL("./page.html", import.meta.url), "utf8");

const pct = (a, b) => (b > 0 ? Math.round((a / b) * 1000) / 10 : null);
const fmtBytes = (n) => (n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GB` : `${Math.round(n / (1 << 20))} MB`);

/** What each change does, in the words both the console and the phone show. */
const DESCRIBE = {
  "restart-server": () => ({ title: "Restart the HumID server", lines: ["Phones are disconnected for about a minute and sign in again with a live check."] }),
  "backup": () => ({ title: "Back up the HumID server now", lines: ["Stops the server for a few seconds for a consistent copy.", "The backup holds the server keys and every sealed document; it stays on this computer, readable only by administrators."] }),
  "update-humid": (a) => ({ title: `Update HumID Server ${a.from} → ${a.version}`, lines: [`File ${a.file}, SHA-256 ${a.sha256.slice(0, 16)}…, signed by HumID release key ${a.signer}`, "Backs up first, keeps the current version, and rolls back by itself if the new one doesn't come up healthy with the same server identity."] }),
  "rollback-humid": (a) => ({ title: `Roll back HumID Server ${a.from} → ${a.to}`, lines: ["Backs up first. Phones on newer app versions may need the server they had."] }),
  "os-install": (a) => ({ title: `Install ${a.updates.length} Windows update${a.updates.length === 1 ? "" : "s"}`, lines: a.updates.slice(0, 10).map((u) => u.title).concat(a.updates.length > 10 ? [`and ${a.updates.length - 10} more`] : []) }),
  "reboot": () => ({ title: "Restart this computer", lines: ["Starts 60 seconds after approval. HumID is unavailable for a few minutes and starts again by itself."] }),
  "defender-update": () => ({ title: "Update Microsoft Defender definitions", lines: [] }),
  "remove-admin": (a) => ({ title: `Remove administrator phone ${a.platform}`, lines: [`Device ${a.device}. It can no longer approve changes on this server.`] }),
  "enrol": () => ({ title: "Make this phone an administrator of this server", lines: ["After you approve, compare the admin check on your phone with the one on the console."] }),
};

export function createConsole({
  root, installDir, port = 8490, host = "127.0.0.1", platform, fetchImpl = fetch, version = "dev",
  now = () => Date.now(), timers = true, log = (level, msg, extra = {}) => process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level, service: "admin", msg, ...extra }) + "\n"),
}) {
  const store = openStore(root);
  const shared = adminPaths(root);
  for (const d of [shared.dir, shared.requests, shared.approvals]) mkdirSync(d, { recursive: true });
  const jobsDir = join(store.dir, "jobs");
  const backupsDir = join(root, "backups");
  const settings = () => readEnvFile(join(root, "humid.env"));
  const adminEnv = () => readEnvFile(join(store.dir, "admin.env"));

  const S = {
    status: null, edge: { ok: null, ms: null, at: 0, downSince: null }, probe: { data: null, at: 0, error: null },
    publicUrl: { at: 0 }, cpu: { pct: null, last: null }, humid: { checkedAt: 0, latest: null, error: null, checking: false },
    requests: new Map(), lastOsScanStart: 0,
  };
  const sessions = new Map();

  /* ---------------------------------------------------------------- collectors */

  function readStatus() {
    S.status = readJson(join(root, STATUS_FILE));
    S.serverInfo = readJson(join(root, "server.json"));
  }

  function edgeProbe() {
    const p = Number(settings().HUMID_PORT || 8480);
    const started = performance.now();
    return new Promise((resolve) => {
      const r = http.get({ host: "127.0.0.1", port: p, path: "/healthz", timeout: 4000 }, (res) => {
        res.resume();
        res.on("end", () => done(res.statusCode === 200));
      });
      r.on("timeout", () => r.destroy(new Error("timeout")));
      r.on("error", () => done(false));
      function done(ok) {
        const t = now();
        S.edge = { ok, ms: Math.round(performance.now() - started), at: t, downSince: ok ? null : S.edge.downSince ?? t, port: p };
        resolve(ok);
      }
    });
  }

  function cpuSample() {
    const c = os.cpus().reduce((a, x) => { const t = x.times; a.idle += t.idle; a.total += t.user + t.nice + t.sys + t.irq + t.idle; return a; }, { idle: 0, total: 0 });
    if (S.cpu.last) {
      const total = c.total - S.cpu.last.total, idle = c.idle - S.cpu.last.idle;
      S.cpu.pct = total > 0 ? Math.round((1 - idle / total) * 1000) / 10 : S.cpu.pct;
    }
    S.cpu.last = c;
  }

  async function probeWindows() {
    try { S.probe = { data: await platform.probe(), at: now(), error: null }; }
    catch (e) { S.probe = { ...S.probe, at: now(), error: e.message.slice(0, 300) }; log("warn", "probe failed", { err: e.message.slice(0, 300) }); }
  }

  async function checkPublic() {
    const url = settings().HUMID_PUBLIC_URL;
    if (!url) { S.publicUrl = { at: now(), url: null }; return; }
    const out = { at: now(), url };
    const started = performance.now();
    try {
      const res = await fetchImpl(`${url}/healthz`, { signal: AbortSignal.timeout(10_000) });
      out.ok = res.ok; out.status = res.status; out.ms = Math.round(performance.now() - started);
    } catch (e) { out.ok = false; out.error = e.cause?.code || e.name || "unreachable"; }
    try { out.certExpires = await certExpiry(new URL(url).hostname); } catch {}
    S.publicUrl = out;
  }

  function certExpiry(hostname) {
    return new Promise((resolve, reject) => {
      const sock = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: 8000 }, () => {
        const c = sock.getPeerCertificate();
        sock.end();
        resolve(c?.valid_to ? new Date(c.valid_to).toISOString() : null);
      });
      sock.on("timeout", () => { sock.destroy(); reject(new Error("timeout")); });
      sock.on("error", reject);
    });
  }

  async function checkHumid({ force = false } = {}) {
    if (S.humid.checking) return;
    if (!force && now() - S.humid.checkedAt < CHECK_EVERY_MS) return;
    S.humid.checking = true;
    const env = adminEnv();
    try {
      const current = installedVersion();
      const allowPrerelease = settings().HUMID_UPDATE_PRERELEASES === "on";
      const latest = await latestRelease({ repo: env.HUMID_UPDATE_REPO || DEFAULT_REPO, token: env.HUMID_UPDATE_TOKEN || "", current, allowPrerelease, fetchImpl });
      S.humid = { checkedAt: now(), latest, error: null, checking: false, current };
    } catch (e) {
      S.humid = { ...S.humid, checkedAt: now(), error: e.message, checking: false };
    }
  }

  function osUpdates() { return readJson(join(store.dir, "os-updates.json")); }

  function startOsScan({ force = false } = {}) {
    if (runningJob()) return null;
    const last = osUpdates()?.checkedAt ? Date.parse(osUpdates().checkedAt) : 0;
    if (!force && (now() - Math.max(last || 0, S.lastOsScanStart) < CHECK_EVERY_MS)) return null;
    S.lastOsScanStart = now();
    return queueJob("os-scan", {}, { by: "schedule" });
  }

  function backups() {
    let out = [];
    try {
      out = readdirSync(backupsDir).filter((f) => f.endsWith(".zip")).map((f) => {
        const st = statSync(join(backupsDir, f));
        return { name: f, bytes: st.size, at: st.mtime.toISOString() };
      }).sort((a, b) => (a.at < b.at ? 1 : -1));
    } catch {}
    return out;
  }

  const installedVersion = () => S.probe.data?.installed?.version || S.status?.version || S.serverInfo?.version || "0.0.0";

  /* ---------------------------------------------------------------- jobs */

  function jobs() {
    let files = [];
    try { files = readdirSync(jobsDir).filter((f) => f.endsWith(".request.json")); } catch {}
    return files.map((f) => {
      const id = f.slice(0, -".request.json".length);
      const req = readJson(join(jobsDir, f)) || {};
      const st = readJson(join(jobsDir, `${id}.json`));
      return { id, type: req.type, title: req.title, requestedAt: req.requestedAt, by: req.by, state: st?.state || "queued", steps: st?.steps || [], result: st?.result || null, finishedAt: st?.finishedAt || null, error: st?.error || null };
    }).sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : -1));
  }
  // A job the job task never picked up (10 minutes) or that never finished (4 hours, the
  // task's own limit) doesn't block everything else.
  const runningJob = () => jobs().find((j) => {
    const age = now() - Date.parse(j.requestedAt || 0);
    return (j.state === "queued" && age < 10 * MIN) || (j.state === "running" && age < 4 * HOUR);
  }) || null;

  function queueJob(type, args, { title, code = null, by = null } = {}) {
    if (!JOB_TYPES.has(type)) throw new Error(`unknown job ${type}`);
    const stamp = new Date(now()).toISOString().replace(/[-:]/g, "").replace(/\..*/, "").replace("T", "-");
    const id = `${stamp}-${type}-${randomBytes(3).toString("hex")}`;
    writeJsonAtomic(join(jobsDir, `${id}.request.json`), { id, type, args, title: title || DESCRIBE[type]?.(args)?.title || type, code, by, requestedAt: new Date(now()).toISOString() });
    // keep the last 40 jobs
    const all = jobs();
    for (const j of all.slice(40)) for (const f of [`${j.id}.request.json`, `${j.id}.json`]) rmSync(join(jobsDir, f), { force: true });
    platform.startJob().catch((e) => log("error", "couldn't start the job task", { err: e.message }));
    if (type !== "os-scan") store.audit("job.queued", { job: id, action: type, code });
    return id;
  }

  /* ---------------------------------------------------------------- requests and approvals */

  const kid = () => S.serverInfo?.kid || S.status?.kid || "unknown";

  function newRequest(kind, type, args = {}) {
    const code = newCode();
    const createdAt = now();
    const digest = requestDigest({ kid: kid(), code, kind, type, args, createdAt });
    const { title, lines: described } = DESCRIBE[kind === "enrol" ? "enrol" : type](args);
    // Check-in keeps armed vaults' keys in memory only: anything that stops the server erases them.
    const armed = MAINTENANCE.has(type) ? Number(S.status?.checkin?.armed || 0) : 0;
    const lines = armed ? [...described, `Check-in: ${armed} armed vault${armed === 1 ? "" : "s"} will be erased for good when the server stops (their keys live in memory only). Ask ${armed === 1 ? "its holder" : "their holders"} to turn Check-in off first.`] : described;
    const r = { code, kind, type, args, title, lines, digest, check: digestCheck(digest), createdAt, expiresAt: createdAt + REQUEST_TTL_MS, state: "waiting" };
    S.requests.set(code, r);
    publishRequest(r);
    store.audit("request.created", { code, kind, action: type, title, digest });
    return r;
  }

  function publishRequest(r) {
    const approvers = r.kind === "enrol" ? [] : store.admins().map((a) => a.account);
    writeJsonAtomic(join(shared.requests, `${r.code}.json`), { code: r.code, kind: r.kind, title: r.title, lines: r.lines, digest: r.digest, check: r.check, expiresAt: r.expiresAt, approvers });
  }
  const unpublish = (code) => rmSync(join(shared.requests, `${code}.json`), { force: true });

  function finish(r, state, extra = {}) {
    Object.assign(r, { state, ...extra, finishedAt: now() });
    unpublish(r.code);
  }

  /** Approvals the server handed over: each is checked here before anything happens. */
  function takeApprovals() {
    let files = [];
    try { files = readdirSync(shared.approvals).filter((f) => f.endsWith(".json")); } catch { return; }
    for (const f of files) {
      const code = basename(f, ".json");
      const file = join(shared.approvals, f);
      const rec = readJson(file);
      rmSync(file, { force: true });
      const r = CODE_RE.test(code) ? S.requests.get(code) : null;
      if (!r || r.state !== "waiting") { if (r) store.audit("approval.ignored", { code, reason: `request is ${r.state}` }); continue; }
      let v;
      try { v = verifyApproval(rec, r, store.admins(), now()); }
      catch (e) {
        const reason = e instanceof ApprovalError ? e.code : "error";
        store.audit("approval.rejected", { code, reason, message: e.message, device: rec?.device, platform: rec?.platform });
        log("warn", "approval rejected", { code, reason });
        finish(r, "rejected", { error: e.message });
        continue;
      }
      const by = { device: v.admin.device, platform: v.admin.platform, proof: v.proof };
      store.audit("approval.verified", { code, kind: r.kind, action: r.type, title: r.title, digest: r.digest, ...by });
      if (r.kind === "enrol") {
        if (store.admins().some((a) => a.device === v.admin.device)) { finish(r, "done", { by, note: "Already an administrator." }); continue; }
        Object.assign(r, { state: "matching", by, candidate: { ...v.admin, check: v.enrolCheck } });
        unpublish(r.code);
        continue;
      }
      approvedAction(r, by);
    }
  }

  function approvedAction(r, by) {
    r.by = by;
    if (r.type === "remove-admin") {
      const list = store.admins();
      const gone = list.find((a) => a.device === r.args.device);
      store.saveAdmins(list.filter((a) => a.device !== r.args.device));
      store.audit("admin.removed", { device: r.args.device, platform: gone?.platform, by: by.device });
      finish(r, "done");
      return;
    }
    try {
      r.jobId = queueJob(r.type, r.args, { title: r.title, code: r.code, by });
      finish(r, "running");
    } catch (e) { finish(r, "failed", { error: e.message }); }
  }

  function expireRequests() {
    const t = now();
    for (const r of S.requests.values()) {
      if (r.state === "waiting" && r.expiresAt <= t) { finish(r, "expired"); store.audit("request.expired", { code: r.code }); }
      if (r.state === "matching" && t - r.createdAt > 15 * MIN) { finish(r, "expired"); store.audit("request.expired", { code: r.code }); }
      if (["done", "failed", "expired", "cancelled", "rejected", "running"].includes(r.state) && t - (r.finishedAt || r.createdAt) > HOUR) S.requests.delete(r.code);
    }
    // anything left in the shared folder that this console doesn't know about (after a restart)
    try { for (const f of readdirSync(shared.requests)) if (!S.requests.has(basename(f, ".json"))) rmSync(join(shared.requests, f), { force: true }); } catch {}
  }

  /* ---------------------------------------------------------------- health and alerts */

  function serverHealth() {
    const st = S.status;
    const stale = !st || now() - Date.parse(st.at) > STALE_MS;
    const down = S.edge.ok === false;
    const services = st?.services || [];
    const bad = services.filter((s) => !s.ok);
    return { up: S.edge.ok === true && !stale, stale, down, downFor: S.edge.downSince ? now() - S.edge.downSince : 0, badServices: bad.map((s) => s.name) };
  }

  function breakGlass() {
    const h = serverHealth();
    return h.down && h.downFor >= BREAK_GLASS_AFTER_MS && !runningJob();
  }

  function alerts() {
    const out = [];
    const add = (level, area, title, detail = "") => out.push({ level, area, title, detail });
    const h = serverHealth();
    const job = runningJob();
    const maint = job && MAINTENANCE.has(job.type);
    if (maint) add("info", "server", `Maintenance: ${job.title}`, "Health alerts are paused until it finishes.");
    else if (h.down) add("bad", "server", "The HumID server isn't answering", `Not answering on 127.0.0.1:${S.edge.port || "?"} for ${Math.round(h.downFor / 1000)} s. Windows restarts it by itself within a minute; if it stays down, restart it here.`);
    else if (h.stale && S.edge.ok) add("warn", "server", "The server stopped reporting its status", "It answers, but hasn't written server-status.json lately.");
    for (const s of h.badServices) if (!maint) add("bad", "server", `Service ${s} isn't healthy`, "Its health check failed on the last status report.");
    const st = S.status;
    if (st?.log?.errorsLastHour >= 5) add("warn", "server", `${st.log.errorsLastHour} errors in the last hour`, st.log.recent?.find((x) => x)?.msg || "");
    if (st?.process?.loopLagP99Ms > 500) add("warn", "server", "The server is slow to respond", `Event-loop delay ${st.process.loopLagP99Ms} ms (p99).`);
    const pub = S.publicUrl;
    if (pub.url && pub.ok === false && !maint) add("bad", "network", "Phones can't reach the public address", `${pub.url}/healthz: ${pub.status ? `HTTP ${pub.status}` : pub.error}. Check the tunnel (Tailscale or Cloudflare).`);
    if (pub.certExpires) {
      const days = (Date.parse(pub.certExpires) - now()) / (24 * HOUR);
      if (days < 7) add("bad", "network", "The HTTPS certificate is about to expire", `${Math.max(0, Math.floor(days))} days left.`);
      else if (days < 14) add("warn", "network", "The HTTPS certificate expires soon", `${Math.floor(days)} days left; the tunnel normally renews it.`);
    }
    if (!settings().HUMID_PUBLIC_URL) add("info", "network", "No public address yet", "Phones can't reach this server until you run: humid expose tailscale");
    const mem = os.totalmem() ? 1 - os.freemem() / os.totalmem() : 0;
    if (mem > 0.92) add("warn", "machine", "Memory is almost full", `${Math.round(mem * 100)}% used.`);
    for (const d of S.probe.data?.disks || []) {
      const free = d.freeBytes / d.sizeBytes;
      if (d.freeBytes < 2 * 2 ** 30 || free < 0.05) add("bad", "machine", `Drive ${d.drive} is almost full`, `${fmtBytes(d.freeBytes)} free.`);
      else if (d.freeBytes < 10 * 2 ** 30 || free < 0.1) add("warn", "machine", `Drive ${d.drive} is getting full`, `${fmtBytes(d.freeBytes)} free.`);
    }
    const p = S.probe.data;
    if (p?.defender && p.defender.available !== false) {
      if (!p.defender.antivirus || !p.defender.realtime) add("bad", "security", "Microsoft Defender protection is off", "Real-time protection should be on.");
      else if (p.defender.signatureAgeDays > 3) add("warn", "security", "Defender definitions are out of date", `${p.defender.signatureAgeDays} days old.`);
    }
    for (const f of p?.firewall || []) if (!f.enabled) add("bad", "security", `Windows Firewall is off (${f.profile})`, "Turn it on in Windows Security.");
    if (p?.bitlocker && p.bitlocker.status !== "on") add("warn", "security", "The system drive isn't encrypted (BitLocker)", "A stolen disk would hold the vault and the split keys together.");
    if (p?.pendingReboot) add("warn", "updates", "Windows needs a restart to finish updates", (p.pendingRebootReasons || []).join(", "));
    const osu = osUpdates();
    const sec = (osu?.updates || []).filter((u) => u.security);
    if (sec.length) add(Date.parse(osu.checkedAt) - Math.min(...sec.map((u) => Date.parse(u.published) || now())) > 7 * 24 * HOUR ? "bad" : "warn", "updates", `${sec.length} Windows security update${sec.length === 1 ? "" : "s"} waiting`, "");
    else if (osu?.updates?.length) add("info", "updates", `${osu.updates.length} Windows update${osu.updates.length === 1 ? "" : "s"} available`, "");
    if (osu?.error) add("warn", "updates", "Windows Update couldn't be checked", osu.error);
    if (S.humid.latest) add("warn", "updates", `HumID Server ${S.humid.latest.version} is available`, `Installed: ${installedVersion()}.`);
    if (S.humid.error) add("info", "updates", "Couldn't check for HumID updates", S.humid.error);
    if (!pinnedKeys().length) add("warn", "updates", "HumID updates can't be installed from the console", "This build has no HumID release key pinned, so it can't tell who made an update and refuses them all. Install the next release by hand (unzip it and run its installer).");
    const b = backups()[0];
    if (!b) add("warn", "backups", "No backups on this computer yet", "Back up now, then copy the file somewhere safe and offline.");
    else if (now() - Date.parse(b.at) > 7 * 24 * HOUR) add("warn", "backups", "The last backup is more than a week old", b.name);
    if (!store.admins().length) add("warn", "console", "No administrator phone yet", "Changes need a phone's live check. Add yours under Administrators.");
    const a = store.auditState();
    if (a.broken) add("bad", "console", "The admin audit log was altered", a.broken);
    if (S.probe.error) add("info", "console", "Couldn't read Windows details", S.probe.error);
    const order = { bad: 0, warn: 1, info: 2 };
    return out.sort((x, y) => order[x.level] - order[y.level]);
  }

  function summaryForPhones() {
    const al = alerts();
    const osu = osUpdates();
    writeJsonAtomic(shared.summary, {
      at: new Date(now()).toISOString(),
      health: al.some((a) => a.level === "bad") ? "bad" : al.some((a) => a.level === "warn") ? "warn" : "ok",
      alerts: al.filter((a) => a.level !== "info").slice(0, 5).map((a) => a.title),
      updates: { humid: S.humid.latest?.version || null, os: osu?.updates?.length || 0, security: (osu?.updates || []).filter((u) => u.security).length },
      version: installedVersion(),
      approvers: store.admins().map((a) => a.account),
    });
  }

  function takeSample() {
    const st = S.status;
    const c = (S.probe.data?.disks || []).find((d) => /^C/i.test(d.drive)) || S.probe.data?.disks?.[0];
    store.sample({
      cpu: S.cpu.pct, mem: pct(os.totalmem() - os.freemem(), os.totalmem()), disk: c ? pct(c.sizeBytes - c.freeBytes, c.sizeBytes) : null,
      rss: st?.process?.rssMB ?? null, ok: serverHealth().up ? 1 : 0, ms: st?.services?.find((s) => s.name === "gateway")?.ms ?? null,
      errs: st?.log?.errorsLastHour ?? null, sessions: st?.sessions ?? null,
    }, now());
  }

  /* ---------------------------------------------------------------- the state the page shows */

  function state() {
    const p = S.probe.data;
    const h = serverHealth();
    return {
      console: { version, port, now: now(), audit: store.auditState() },
      server: { ...h, status: S.status, info: S.serverInfo, edge: S.edge, public: S.publicUrl },
      machine: {
        computer: p?.computer || os.hostname(), os: p?.os || { caption: os.type(), version: os.release() }, lastBoot: p?.lastBoot || null,
        uptimeS: Math.round(os.uptime()), cpu: { pct: S.cpu.pct, cores: os.cpus().length, model: os.cpus()[0]?.model || "" },
        memory: { total: os.totalmem(), free: os.freemem() }, disks: p?.disks || [], tasks: p?.tasks || [], tunnel: p?.tunnel || null,
      },
      security: { defender: p?.defender || null, firewall: p?.firewall || [], bitlocker: p?.bitlocker || null, pendingReboot: !!p?.pendingReboot, pendingRebootReasons: p?.pendingRebootReasons || [], probedAt: S.probe.at, probeError: S.probe.error },
      updates: {
        humid: { installed: installedVersion(), previous: p?.previous?.version || null, ...S.humid, tokenSet: !!adminEnv().HUMID_UPDATE_TOKEN, repo: adminEnv().HUMID_UPDATE_REPO || DEFAULT_REPO, releaseKeys: pinnedKeys().length, prereleases: settings().HUMID_UPDATE_PRERELEASES === "on" },
        os: osUpdates(),
      },
      backups: backups(),
      alerts: alerts(),
      history: store.history().filter((_, i, a) => a.length <= 360 || i % Math.ceil(a.length / 360) === 0 || i === a.length - 1),
      admins: store.admins().map(({ account, device, platform, proofLevel, assurance, addedAt, check }) => ({ account, device, platform, proofLevel, assurance, addedAt, check })),
      requests: [...S.requests.values()].sort((a, b) => b.createdAt - a.createdAt).map(viewRequest),
      jobs: jobs().slice(0, 15),
      audit: store.recentAudit(60),
      breakGlass: breakGlass(),
    };
  }

  function viewRequest(r) {
    const view = { code: r.code, display: formatCode(r.code), kind: r.kind, type: r.type, title: r.title, lines: r.lines, check: r.check, createdAt: r.createdAt, expiresAt: r.expiresAt, state: r.state, by: r.by || null, jobId: r.jobId || null, error: r.error || null, note: r.note || null };
    if (r.state === "waiting") view.qr = qrSvg(r.code, r.expiresAt);
    if (r.state === "matching") view.candidate = { platform: r.candidate.platform, proofLevel: r.candidate.proofLevel, assurance: r.candidate.assurance, check: r.candidate.check, account: r.candidate.account };
    return view;
  }

  function qrSvg(code, expiresAt) {
    try {
      const q = qrcode(0, "M");
      q.addData(qrPayload("admin", code, expiresAt));
      q.make();
      return q.createSvgTag({ cellSize: 5, margin: 2, scalable: true, alt: "Approval code for the HumID app" });
    } catch { return null; }
  }

  /* ---------------------------------------------------------------- actions from the page */

  async function requestAction(type, input = {}) {
    if (!store.admins().length) throw httpError(409, "no_admin", "Add an administrator phone first: every change needs one to approve it.");
    const busy = runningJob();
    if (busy && type !== "remove-admin") throw httpError(409, "busy", `Wait for "${busy.title}" to finish.`);
    if ([...S.requests.values()].some((r) => r.state === "waiting" && r.type === type)) throw httpError(409, "pending", "There's already a request for that waiting for a phone.");
    let args = {};
    switch (type) {
      case "restart-server": case "backup": case "reboot": case "defender-update": break;
      case "update-humid": {
        const latest = S.humid.latest;
        if (!latest) throw httpError(409, "no_update", "No newer HumID Server release was found. Check again first.");
        const env = adminEnv();
        let got;
        try { got = await download({ repo: env.HUMID_UPDATE_REPO || DEFAULT_REPO, token: env.HUMID_UPDATE_TOKEN || "", release: latest, dir: join(store.dir, "downloads"), fetchImpl }); }
        catch (e) { throw httpError(502, "download_failed", e.message); }
        args = { version: latest.version, from: installedVersion(), file: basename(got.file), sha256: got.sha256, signer: got.signer };
        break;
      }
      case "rollback-humid": {
        const prev = S.probe.data?.previous?.version;
        if (!prev) throw httpError(409, "no_previous", "There's no previous version kept on this computer.");
        if (compareVersions(prev, "2.0.0") < 0) throw httpError(409, "too_old", `${prev} has no admin console, so rolling back to it can't be done from here. In Terminal (Admin), run its installer from the release zip.`);
        args = { from: installedVersion(), to: prev };
        break;
      }
      case "os-install": {
        const known = osUpdates()?.updates || [];
        const ids = Array.isArray(input.ids) ? input.ids.map(String) : [];
        const picked = known.filter((u) => ids.includes(u.id));
        if (!picked.length) throw httpError(400, "no_updates", "Choose at least one update from the last scan.");
        args = { updates: picked.map((u) => ({ id: u.id, title: String(u.title).slice(0, 160), kb: u.kb || [] })) };
        break;
      }
      case "remove-admin": {
        const a = store.admins().find((x) => x.device === String(input.device));
        if (!a) throw httpError(404, "unknown_admin", "No such administrator phone.");
        args = { device: a.device, platform: a.platform };
        break;
      }
      default: throw httpError(400, "unknown_action", "Unknown action.");
    }
    return viewRequest(newRequest("action", type, args));
  }

  function requestEnrol() {
    if ([...S.requests.values()].some((r) => r.kind === "enrol" && (r.state === "waiting" || r.state === "matching"))) throw httpError(409, "pending", "An enrolment is already in progress.");
    return viewRequest(newRequest("enrol", "enrol", {}));
  }

  function confirmEnrol(code, match) {
    const r = S.requests.get(code);
    if (!r || r.kind !== "enrol" || r.state !== "matching") throw httpError(404, "unknown_request", "No enrolment is waiting for that.");
    if (!match) {
      finish(r, "rejected", { error: "The check codes didn't match." });
      store.audit("admin.enrol_mismatch", { code, device: r.candidate.device, platform: r.candidate.platform });
      return viewRequest(r);
    }
    const { check, ...pin } = r.candidate;
    store.saveAdmins([...store.admins().filter((a) => a.device !== pin.device), { ...pin, check, addedAt: new Date(now()).toISOString() }]);
    store.audit("admin.enrolled", { code, account: pin.account, device: pin.device, platform: pin.platform, proofLevel: pin.proofLevel, check });
    finish(r, "done");
    summaryForPhones();
    return viewRequest(r);
  }

  function cancel(code) {
    const r = S.requests.get(code);
    if (!r || !["waiting", "matching"].includes(r.state)) throw httpError(404, "unknown_request", "Nothing to cancel.");
    finish(r, "cancelled");
    store.audit("request.cancelled", { code });
    return viewRequest(r);
  }

  function breakGlassRestart() {
    if (!breakGlass()) throw httpError(409, "not_down", "The server is answering: restarting it needs a phone's approval.");
    store.audit("breakglass.restart", { downForMs: serverHealth().downFor });
    return { job: queueJob("restart-server", {}, { title: "Restart the HumID server (break-glass)", by: { breakGlass: true } }) };
  }

  /* ---------------------------------------------------------------- HTTP */

  const httpError = (status, code, message) => Object.assign(new Error(message), { status, code });
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const allowedOrigins = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
  const BASE = {
    "cache-control": "no-store", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin", "permissions-policy": "camera=(), microphone=(), geolocation=()",
  };

  const cookieOf = (req) => /(?:^|;\s*)humid_admin=([A-Za-z0-9_-]{43})/.exec(req.headers.cookie || "")?.[1];
  function session(req) {
    const id = cookieOf(req);
    const s = id && sessions.get(id);
    const t = now();
    if (!s) return null;
    if (t - s.last > SESSION_IDLE_MS || t - s.created > SESSION_MAX_MS) { sessions.delete(id); return null; }
    s.last = t;
    return { id, ...s };
  }

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { ...BASE, "content-type": "application/json; charset=utf-8", ...headers });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let n = 0; const chunks = [];
      req.on("data", (c) => { n += c.length; if (n > 64 * 1024) { reject(httpError(413, "too_large", "Too large")); req.destroy(); } else chunks.push(c); });
      req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch { reject(httpError(400, "bad_json", "Bad JSON")); } });
      req.on("error", reject);
    });
  }

  let loginFails = 0, loginWindow = 0;

  async function handle(req, res) {
    // Only this computer, by name: a web page elsewhere can't reach in through DNS tricks.
    if (!allowedHosts.has(String(req.headers.host || ""))) return send(res, 421, { error: "wrong_host", message: "Open the console at http://127.0.0.1:" + port });
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      const nonce = randomBytes(18).toString("base64");
      res.writeHead(200, {
        ...BASE, "content-type": "text/html; charset=utf-8",
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src-elem 'nonce-${nonce}'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      });
      return res.end(PAGE.replaceAll("__NONCE__", nonce).replaceAll("__VERSION__", version));
    }
    if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, { ok: true });
    if (!url.pathname.startsWith("/api/")) return send(res, 404, { error: "not_found" });

    // Changes come only from this page: a custom header (no other site can send one without
    // asking first), a matching Origin when the browser sends one, and the session cookie.
    if (req.method !== "GET") {
      if (req.headers["x-humid-console"] !== "1") return send(res, 403, { error: "forbidden", message: "Missing console header." });
      if (req.headers.origin && !allowedOrigins.has(req.headers.origin)) return send(res, 403, { error: "forbidden", message: "Wrong origin." });
    }
    if (url.pathname === "/api/login" && req.method === "POST") {
      const t = now();
      if (t - loginWindow > MIN) { loginWindow = t; loginFails = 0; }
      if (loginFails > 20) return send(res, 429, { error: "rate_limited", message: "Too many tries. Wait a minute." });
      const b = await readBody(req);
      if (!store.useLogin(b.token, t)) { loginFails++; return send(res, 401, { error: "bad_link", message: "That sign-in link was already used or has expired. Run `humid console` again in Terminal (Admin)." }); }
      const id = randomBytes(32).toString("base64url");
      sessions.set(id, { created: t, last: t });
      store.audit("console.signed_in", {});
      return send(res, 200, { ok: true }, { "set-cookie": `humid_admin=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_MS / 1000}` });
    }
    const s = session(req);
    if (!s) return send(res, 401, { error: "signed_out", message: "Run `humid console` in Terminal (Admin) to open the console." });

    const route = `${req.method} ${url.pathname}`;
    try {
      if (route === "GET /api/state") return send(res, 200, state());
      if (route === "POST /api/logout") { sessions.delete(s.id); store.audit("console.signed_out", {}); return send(res, 200, { ok: true }, { "set-cookie": "humid_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" }); }
      if (route === "POST /api/check") {
        const b = await readBody(req);
        if (b.what === "humid") await checkHumid({ force: true });
        else if (b.what === "os") { if (!startOsScan({ force: true })) throw httpError(409, "busy", "Another job is running; check again when it's done."); }
        else if (b.what === "probe") await probeWindows();
        else throw httpError(400, "bad_check", "Unknown check.");
        return send(res, 200, state());
      }
      if (route === "POST /api/requests") { const b = await readBody(req); return send(res, 200, await requestAction(String(b.type || ""), b)); }
      if (route === "POST /api/enrol") return send(res, 200, requestEnrol());
      if (route === "POST /api/breakglass/restart") return send(res, 200, breakGlassRestart());
      let m;
      if (req.method === "POST" && (m = /^\/api\/requests\/([0-9A-Z]{12})\/cancel$/.exec(url.pathname))) return send(res, 200, cancel(m[1]));
      if (req.method === "POST" && (m = /^\/api\/enrol\/([0-9A-Z]{12})\/confirm$/.exec(url.pathname))) { const b = await readBody(req); return send(res, 200, confirmEnrol(m[1], b.match === true)); }
      return send(res, 404, { error: "not_found" });
    } catch (e) {
      if (!e.status) log("error", "console request failed", { err: e.stack });
      return send(res, e.status || 500, { error: e.code || "internal", message: e.status ? e.message : "Something went wrong. See the console log." });
    }
  }

  const server = http.createServer((req, res) => { handle(req, res).catch((e) => { log("error", "unhandled", { err: e.stack }); if (!res.headersSent) send(res, 500, { error: "internal" }); }); });
  server.requestTimeout = 600_000; // downloading an update can take a while
  server.headersTimeout = 15_000;

  /* ---------------------------------------------------------------- the loop */

  const intervals = [];
  async function tick({ slow = false } = {}) {
    readStatus();
    cpuSample();
    await edgeProbe();
    takeApprovals();
    expireRequests();
    if (slow) { try { summaryForPhones(); } catch (e) { log("warn", "summary failed", { err: e.message }); } }
  }

  return {
    server, store, state, alerts, tick, probeWindows, checkPublic, checkHumid, startOsScan, takeApprovals, takeSample, summaryForPhones,
    requestAction, requestEnrol, confirmEnrol, cancel, breakGlassRestart, sessions, S,
    async start() {
      await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => { server.off("error", reject); resolve(); }); });
      await tick({ slow: true });
      if (timers) {
        const every = (ms, fn) => { const t = setInterval(() => { Promise.resolve().then(fn).catch((e) => log("warn", "loop", { err: e.message })); }, ms); t.unref?.(); intervals.push(t); };
        every(1000, async () => { takeApprovals(); });
        every(5000, () => tick());
        every(30_000, () => tick({ slow: true }));
        every(MIN, async () => { takeSample(); store.sweepLogins(now()); });
        every(MIN, () => probeWindows());
        every(5 * MIN, () => checkPublic());
        // HUMID_AUTO_CHECKS=0 in admin.env turns off the scheduled update checks (tests do this)
        const auto = () => adminEnv().HUMID_AUTO_CHECKS !== "0";
        every(HOUR, async () => { if (auto()) { await checkHumid(); startOsScan(); } });
        // The first check waits ten minutes, so a restart or an install isn't followed by a
        // Windows Update scan straight away.
        probeWindows().then(() => takeSample());
        const first = setTimeout(() => { if (auto()) { checkHumid(); startOsScan(); } }, 10 * MIN);
        first.unref?.(); intervals.push(first);
        checkPublic();
      }
      store.audit("console.started", { version });
      log("info", "listening", { host, port, version });
      return server;
    },
    stop: () => new Promise((resolve) => { for (const t of intervals) { clearInterval(t); clearTimeout(t); } server.close(() => resolve()); }),
  };
}
