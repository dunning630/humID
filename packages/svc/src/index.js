// @humid/svc — the whole "framework" for HumID services, on purpose small
// enough to read in one sitting. Node built-ins only (http, node:sqlite),
// plus noble for Ed25519 internal assertions.

import http from "node:http";
import { mkdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { ed25519 } from "@noble/curves/ed25519.js";

/* ---------------- config & logging ---------------- */

export function env(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === "") {
    if (fallback === undefined) throw new Error(`Missing required environment variable ${name}`);
    return fallback;
  }
  return v;
}

/**
 * True when the module at `url` is the program being run: not imported by a
 * test, and not bundled into a host that runs several services in one process
 * (the Windows server sets globalThis.__HUMID_EMBEDDED__ before loading them).
 */
export const isMain = (url) =>
  !globalThis.__HUMID_EMBEDDED__ && typeof process.argv[1] === "string" && url === pathToFileURL(process.argv[1]).href;

export function logger(service) {
  const write = (level, msg, extra) =>
    process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level, service, msg, ...extra }) + "\n");
  return {
    info: (msg, extra) => write("info", msg, extra),
    warn: (msg, extra) => write("warn", msg, extra),
    error: (msg, extra) => write("error", msg, extra),
  };
}

/* ---------------- base64url ---------------- */

export const b64u = (b) => Buffer.from(b).toString("base64url");
export const unb64u = (s) => {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new HttpError(400, "bad_encoding", "Expected base64url");
  return new Uint8Array(Buffer.from(s, "base64url"));
};

/* ---------------- internal assertions ---------------- */
// The gateway is the only service that talks to the outside. It tells the
// others who is calling with a short-lived Ed25519-signed assertion, so a
// service never trusts a bare header and an attacker inside the network
// cannot impersonate a user without the gateway's key.

const ASSERT_PREFIX = "HUMID-ASSERT-v1.";
export const ASSERTION_HEADER = "x-humid-assertion";

export function newInternalKeys() {
  const sk = ed25519.utils.randomSecretKey();
  return { sk: b64u(sk), pk: b64u(ed25519.getPublicKey(sk)) };
}

export function signAssertion(skB64, claims, ttlMs = 30_000) {
  const now = Date.now();
  const payload = b64u(Buffer.from(JSON.stringify({ iat: now, exp: now + ttlMs, ...claims })));
  const sig = ed25519.sign(new TextEncoder().encode(ASSERT_PREFIX + payload), unb64u(skB64));
  return `${payload}.${b64u(sig)}`;
}

export function verifyAssertion(pkB64, token, audience) {
  if (!token) throw new HttpError(401, "unauthenticated", "Missing assertion");
  const [payload, sig] = String(token).split(".");
  let ok = false;
  try { ok = ed25519.verify(unb64u(sig), new TextEncoder().encode(ASSERT_PREFIX + payload), unb64u(pkB64)); } catch {}
  if (!ok) throw new HttpError(401, "unauthenticated", "Bad assertion signature");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
  if (claims.aud !== audience) throw new HttpError(401, "unauthenticated", "Assertion not for this service");
  if (Date.now() > claims.exp) throw new HttpError(401, "unauthenticated", "Assertion expired");
  return claims;
}

/* ---------------- HTTP ---------------- */

export class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

export async function readBody(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw new HttpError(413, "too_large", `Body exceeds ${limit} bytes`);
    chunks.push(c);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

export const json = (status, obj, headers = {}) => ({ status, headers: { "content-type": "application/json", ...headers }, body: Buffer.from(JSON.stringify(obj)) });
export const bytes = (status, buf, type = "application/octet-stream", headers = {}) => ({ status, headers: { "content-type": type, ...headers }, body: buf });
export const parseJson = (buf) => {
  try { return JSON.parse(Buffer.from(buf).toString() || "null"); } catch { throw new HttpError(400, "bad_json", "Body is not valid JSON"); }
};

/**
 * Minimal router. Routes: [["GET", "/objects/:id", handler], ...].
 * Handler receives ({ req, params, query, body, claims }) and returns json()/bytes().
 */
export const logPath = (route, pathname) => route ? route.pattern : `/${String(pathname).split("/")[1] || ""}/…`.replace(/[^\w/…-]/g, "");

export function createService({ name, port, routes, bodyLimit = 1 << 20, verify, onError, extraHeaders }) {
  const log = logger(name);
  const compiled = routes.map(([method, pattern, handler, opts = {}]) => {
    const keys = [];
    const re = new RegExp("^" + pattern.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return "([^/]+)"; }) + "$");
    return { method, pattern, re, keys, handler, opts };
  });

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    const url = new URL(req.url, "http://internal");
    let out, route = null;
    try {
      if (req.method === "GET" && url.pathname === "/healthz") {
        out = json(200, { ok: true, service: name });
      } else {
        route = compiled.find((r) => r.method === req.method && r.re.test(url.pathname)) || null;
        if (!route) throw new HttpError(404, "not_found", "No such route");
        const m = url.pathname.match(route.re);
        const params = Object.fromEntries(route.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
        const claims = route.opts.public ? null : verify?.(req.headers[ASSERTION_HEADER]);
        const body = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method) ? await readBody(req, route.opts.bodyLimit || bodyLimit) : new Uint8Array(0);
        out = await route.handler({ req, params, query: url.searchParams, body, claims, headers: req.headers });
      }
    } catch (e) {
      if (!(e instanceof HttpError)) log.error("unhandled", { err: e.stack });
      out = onError?.(e) || json(e.status || 500, { error: e.code || "internal", message: e instanceof HttpError ? e.message : "Internal error" });
    }
    res.writeHead(out.status, { "cache-control": "no-store", "x-content-type-options": "nosniff", ...(extraHeaders?.(req) || {}), ...out.headers });
    res.end(out.body);
    // The route's pattern ("/links/:code"), never the path: paths carry recovery codes,
    // request and object ids. An unmatched path logs only its first segment.
    if (url.pathname !== "/healthz") log.info("req", { m: req.method, p: logPath(route, url.pathname), s: out.status, ms: Date.now() - started });
  });
  server.requestTimeout = 120_000;
  server.headersTimeout = 15_000;

  // HUMID_BIND_HOST=127.0.0.1 keeps a service off the network (the Windows server does this).
  const start = () => new Promise((resolve, reject) => {
    const host = process.env.HUMID_BIND_HOST || undefined;
    server.once("error", reject);
    server.listen(port, host, () => { server.off("error", reject); log.info("listening", { port: server.address().port, ...(host ? { host } : {}) }); resolve(server); });
  });
  const stop = () => new Promise((resolve) => server.close(() => resolve()));
  for (const sig of ["SIGTERM", "SIGINT"]) process.once(sig, () => { log.info("shutdown", { sig }); stop().then(() => process.exit(0)); });
  return { server, start, stop, log };
}

/* ---------------- storage ---------------- */

/** Open the service's own SQLite database and apply numbered migrations once. */
export function openDb(dir, file, migrations) {
  mkdirSync(dir, { recursive: true });
  const db = new DatabaseSync(`${dir}/${file}`);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS _migrations (n INTEGER PRIMARY KEY, at TEXT NOT NULL)");
  const done = new Set(db.prepare("SELECT n FROM _migrations").all().map((r) => r.n));
  migrations.forEach((sql, i) => {
    if (done.has(i + 1)) return;
    db.exec("BEGIN");
    db.exec(sql);
    db.prepare("INSERT INTO _migrations (n, at) VALUES (?, ?)").run(i + 1, new Date().toISOString());
    db.exec("COMMIT");
  });
  return db;
}
