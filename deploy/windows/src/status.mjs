// How the server is doing, written to <root>\server-status.json every 15 seconds for
// the admin console (docs/ADMIN.md). A file rather than an endpoint: nothing new
// listens on the network, and only administrators and the server can read <root>.
//
// It holds health and counts only: each service's answer and response time, memory,
// CPU, event-loop delay, open sessions, data sizes, and the last errors from the log
// (which already records routes, never codes or ids). No account, document or key.
import http from "node:http";
import { writeFileSync, renameSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { monitorEventLoopDelay } from "node:perf_hooks";

export const STATUS_FILE = "server-status.json";
export const STATUS_EVERY_MS = 15_000;
const HOUR = 3_600_000;

/** Bytes under a folder (one level of sub-folders is plenty for a service's data). */
export function folderBytes(dir, depth = 3) {
  let n = 0;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const p = join(dir, e.name);
    try {
      if (e.isFile()) n += statSync(p).size;
      else if (e.isDirectory() && depth > 0) n += folderBytes(p, depth - 1);
    } catch {}
  }
  return n;
}

/** Answer and response time of GET /healthz on a local port. */
export function probe(port, path = "/healthz", timeoutMs = 3000) {
  const started = performance.now();
  return new Promise((resolve) => {
    const r = http.get({ host: "127.0.0.1", port, path, timeout: timeoutMs }, (res) => {
      res.resume();
      res.on("end", () => resolve({ ok: res.statusCode === 200, status: res.statusCode, ms: Math.round(performance.now() - started) }));
    });
    r.on("timeout", () => r.destroy(new Error("timeout")));
    r.on("error", (e) => resolve({ ok: false, error: e.message === "timeout" ? "timeout" : "unreachable", ms: Math.round(performance.now() - started) }));
  });
}

/**
 * Watch the log lines this process writes (one JSON object per line) and keep the
 * errors and warnings of the last hour.
 */
export function watchLog() {
  const errors = [], warnings = [];
  let partial = "";
  const take = (chunk) => {
    const text = partial + (typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
    const lines = text.split("\n");
    partial = lines.pop().slice(-8192);
    for (const line of lines) {
      if (!line.includes('"level":"error"') && !line.includes('"level":"warn"')) continue;
      let o;
      try { o = JSON.parse(line); } catch { continue; }
      const item = { t: Date.parse(o.t) || Date.now(), service: String(o.service || "?").slice(0, 32), msg: String(o.msg || "").slice(0, 160), ...(o.err ? { err: String(o.err).split("\n")[0].slice(0, 200) } : {}) };
      (o.level === "error" ? errors : warnings).push(item);
      for (const a of [errors, warnings]) while (a.length > 500) a.shift();
    }
  };
  for (const stream of [process.stdout, process.stderr]) {
    const original = stream.write.bind(stream);
    stream.write = (chunk, encoding, cb) => { try { take(chunk); } catch {} return original(chunk, encoding, cb); };
  }
  const recent = (a, now) => a.filter((x) => now - x.t < HOUR);
  return {
    take,
    snapshot(now = Date.now()) {
      const e = recent(errors, now), w = recent(warnings, now);
      return { errorsLastHour: e.length, warningsLastHour: w.length, recent: [...e, ...w].sort((a, b) => b.t - a.t).slice(0, 20) };
    },
  };
}

/**
 * start({ root, version, appVersion, services: { name: server }, edgePort, sessions: () => n, checkinArmed: () => n })
 * Writes the status file now and every STATUS_EVERY_MS. Returns { stop, write }.
 */
export function startStatus({ root, version, appVersion, services, edgePort, sessions, checkinArmed, info = {}, log = watchLog(), everyMs = STATUS_EVERY_MS }) {
  const lag = monitorEventLoopDelay({ resolution: 20 });
  lag.enable();
  const startedAt = new Date().toISOString();
  let lastCpu = process.cpuUsage(), lastAt = performance.now();
  let dataSizes = [], sizesAt = 0;

  async function snapshot() {
    const now = Date.now();
    const cpu = process.cpuUsage(lastCpu), t = performance.now();
    const cpuPct = Math.round(((cpu.user + cpu.system) / 1000 / Math.max(1, t - lastAt)) * 1000) / 10;
    lastCpu = process.cpuUsage(); lastAt = t;
    const checks = await Promise.all(Object.entries(services).map(async ([name, s]) => {
      const port = s.server?.address?.()?.port;
      // a role that serves another machine speaks mutual TLS only: listening is what can be seen from here
      if (s.tls) return { name, port, ok: !!s.server?.listening, tls: true };
      return { name, port, ...(port ? await probe(port) : { ok: false, error: "not listening" }) };
    }));
    const edge = edgePort ? await probe(edgePort) : null;
    if (now - sizesAt > 5 * 60_000) { // sizes change slowly; walking folders isn't free
      dataSizes = Object.keys(services).filter((n) => n !== "gateway").concat("gateway").map((name) => ({ name, bytes: folderBytes(join(root, "data", name)) }));
      sizesAt = now;
    }
    const mem = process.memoryUsage();
    const out = {
      at: new Date(now).toISOString(), version, appVersion, pid: process.pid, startedAt, ...info,
      uptimeS: Math.round(process.uptime()),
      process: { rssMB: Math.round(mem.rss / 1048576), heapMB: Math.round(mem.heapUsed / 1048576), cpuPct, loopLagP99Ms: Math.round(lag.percentile(99) / 1e6), node: process.version },
      services: checks, edge, sessions: sessions?.() ?? null, data: dataSizes,
      // Check-in: how many vaults are armed (a count, nothing more). Stopping the server erases them.
      checkin: { armed: checkinArmed?.() ?? null },
      log: log.snapshot(now),
    };
    lag.reset();
    return out;
  }

  async function write() {
    try {
      const s = await snapshot();
      const file = join(root, STATUS_FILE), tmp = `${file}.tmp`;
      writeFileSync(tmp, JSON.stringify(s, null, 1));
      renameSync(tmp, file);
      return s;
    } catch { return null; } // a status file must never take the server down
  }

  write();
  const timer = setInterval(write, everyMs);
  timer.unref();
  return { write, snapshot, stop: () => { clearInterval(timer); lag.disable(); } };
}
