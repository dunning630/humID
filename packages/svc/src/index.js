// @humid/svc — the whole "framework" for HumID services, on purpose small
// enough to read in one sitting. Node built-ins only (http, node:sqlite),
// plus noble for Ed25519 internal assertions.

import http from "node:http";
import https from "node:https";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { ed25519 } from "@noble/curves/ed25519.js";
import { roleOf, serverTls } from "./pki.js";
import { sealerFromEnv } from "./seal.js";

export { makeCa, issueRoleCert, serverTls, clientTls, roleOf, roleName, daysLeft, ROLES } from "./pki.js";
export { sealer, sealerFromEnv, secretFile, writeAtomic, isSealedFile, isSealedText, parseKeyText } from "./seal.js";

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
//
// Version 2 (server 3.0, SEC-S-01): an assertion is bound to ONE request. It names the
// service (aud), the method (m), the exact path and query (p) and the SHA-256 of the body
// (bh), carries a random id (rid), and a service accepts each id once. One captured
// assertion (from a download, say) therefore authorises nothing else: not another route,
// not another body, not the same request again. A service also refuses assertions minted
// before it started, so a restart doesn't reopen the window its memory of ids covered.

const ASSERT_PREFIX = "HUMID-ASSERT-v1.";
export const ASSERTION_HEADER = "x-humid-assertion";
export const ASSERTION_VERSION = 2;
const ASSERT_TTL_MS = 30_000;
const CLOCK_SKEW_MS = 5_000;    // between the gateway's clock and a service's on another machine
const RESTART_GRACE_MS = 2_000; // assertions minted this long before a service started are still taken

export function newInternalKeys() {
  const sk = ed25519.utils.randomSecretKey();
  return { sk: b64u(sk), pk: b64u(ed25519.getPublicKey(sk)) };
}

/** SHA-256 of a request body (empty for none), base64url: what an assertion's `bh` must equal. */
export const bodyHash = (body) => createHash("sha256").update(body && body.length ? body : new Uint8Array(0)).digest("base64url");

/** Low level: sign arbitrary claims. Services refuse anything not made by signRequest (below). */
export function signAssertion(skB64, claims, ttlMs = ASSERT_TTL_MS) {
  const now = Date.now();
  const payload = b64u(Buffer.from(JSON.stringify({ iat: now, exp: now + ttlMs, ...claims })));
  const sig = ed25519.sign(new TextEncoder().encode(ASSERT_PREFIX + payload), unb64u(skB64));
  return `${payload}.${b64u(sig)}`;
}

/**
 * The assertion for one internal request. `path` is the origin-form target exactly as it
 * is sent (path and query, already percent-encoded); `body` the exact bytes (or none).
 */
export function signRequest(skB64, { aud, method, path, body, claims = {}, ttlMs = ASSERT_TTL_MS }) {
  return signAssertion(skB64, { iss: "gateway", ...claims, v: ASSERTION_VERSION, aud, m: String(method).toUpperCase(), p: path, bh: bodyHash(body), rid: randomUUID() }, ttlMs);
}

/** Check an assertion's signature, audience and time. The binding to the request is checked by createService once the body is in. */
export function verifyAssertion(pkB64, token, audience) {
  if (!token) throw new HttpError(401, "unauthenticated", "Missing assertion");
  const [payload, sig] = String(token).split(".");
  let ok = false;
  try { ok = ed25519.verify(unb64u(sig), new TextEncoder().encode(ASSERT_PREFIX + payload), unb64u(pkB64)); } catch {}
  if (!ok) throw new HttpError(401, "unauthenticated", "Bad assertion signature");
  let claims;
  try { claims = JSON.parse(Buffer.from(payload, "base64url").toString()); } catch { throw new HttpError(401, "unauthenticated", "Bad assertion"); }
  if (!claims || typeof claims !== "object") throw new HttpError(401, "unauthenticated", "Bad assertion");
  if (claims.aud !== audience) throw new HttpError(401, "unauthenticated", "Assertion not for this service");
  const now = Date.now();
  if (!(now <= claims.exp)) throw new HttpError(401, "unauthenticated", "Assertion expired");
  if (!(claims.iat <= now + CLOCK_SKEW_MS) || !(claims.exp - claims.iat <= 5 * 60_000)) throw new HttpError(401, "unauthenticated", "Assertion times out of range");
  return claims;
}

/**
 * Each service's memory of the assertion ids it has accepted, until they expire. Bounded: if
 * it ever fills with live ids the service refuses (503) rather than forget one, because
 * forgetting would let that one be replayed.
 */
export function replayGuard({ max = 200_000, now = () => Date.now() } = {}) {
  const startedAt = now();
  const seen = new Map(); // rid -> exp
  const prune = () => { const t = now(); for (const [k, exp] of seen) if (exp < t) seen.delete(k); };
  return {
    startedAt,
    get size() { return seen.size; },
    /** Bind `claims` to this request and spend its id. Throws 401 on any mismatch or reuse. */
    check(claims, { method, url, body }) {
      const bad = (why) => new HttpError(401, "unauthenticated", why);
      if (claims.v !== ASSERTION_VERSION) throw bad("Assertion not bound to a request");
      if (claims.m !== method) throw bad("Assertion is for another method");
      if (claims.p !== url) throw bad("Assertion is for another path");
      if (claims.bh !== bodyHash(body)) throw bad("Assertion is for another body");
      if (typeof claims.rid !== "string" || claims.rid.length < 16 || claims.rid.length > 64) throw bad("Assertion has no id");
      if (claims.iat < startedAt - RESTART_GRACE_MS) throw bad("Assertion is older than this service");
      if (seen.has(claims.rid)) throw bad("Assertion already used");
      if (seen.size >= max) { prune(); if (seen.size >= max) throw new HttpError(503, "busy", "Too many requests in flight"); }
      seen.set(claims.rid, claims.exp);
      if (seen.size % 1024 === 0) prune();
    },
  };
}

/* ---------------- HTTP ---------------- */

export class HttpError extends Error {
  /** detail: extra fields for the JSON body, for internal callers (the gateway strips what the app mustn't see). */
  constructor(status, code, message, detail) {
    super(message || code);
    this.status = status;
    this.code = code;
    if (detail && typeof detail === "object") this.detail = detail;
  }
}

/**
 * Read a request body with a hard cap. `limit` is a number, or { max, peek, decide }: once the
 * first `peek` bytes have arrived `decide(prefix)` returns the limit that applies from then on
 * (or throws an HttpError), so a route can pick its cap from a frame header before the rest is
 * buffered. A declared Content-Length over the cap is refused without reading anything, and a
 * streamed body is abandoned the moment it passes the cap (nothing past the cap is buffered).
 * The request is not destroyed here, so the 413 can still be sent; the caller closes the socket.
 */
export function readBody(req, limit) {
  const opts = typeof limit === "number" ? { max: limit } : limit;
  let max = opts.max;
  const tooLarge = () => new HttpError(413, "too_large", `Body exceeds ${max} bytes`);
  const declared = req.headers["content-length"];
  if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > opts.max)) return Promise.reject(/^\d+$/.test(declared) ? tooLarge() : new HttpError(400, "bad_request", "Bad Content-Length"));
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0, decided = !opts.decide;
    const done = (fn, v) => { req.off("data", onData); req.off("end", onEnd); req.off("error", onErr); req.off("aborted", onErr); req.pause(); fn(v); };
    const onData = (c) => {
      size += c.length;
      if (size > max) return done(reject, tooLarge());
      chunks.push(c);
      if (!decided && size >= opts.peek) {
        decided = true;
        try {
          max = Math.min(opts.max, opts.decide(Buffer.concat(chunks)));
          if (declared !== undefined && Number(declared) > max) throw tooLarge();
          if (size > max) throw tooLarge();
        } catch (e) { done(reject, e); }
      }
    };
    const onEnd = () => {
      if (!decided) { try { max = Math.min(opts.max, opts.decide(Buffer.concat(chunks))); if (size > max) throw tooLarge(); } catch (e) { return done(reject, e); } }
      done(resolve, new Uint8Array(Buffer.concat(chunks)));
    };
    const onErr = () => done(reject, new HttpError(400, "bad_request", "Request aborted"));
    req.on("data", onData); req.on("end", onEnd); req.on("error", onErr); req.on("aborted", onErr);
  });
}

export const json = (status, obj, headers = {}) => ({ status, headers: { "content-type": "application/json", ...headers }, body: Buffer.from(JSON.stringify(obj)) });
export const bytes = (status, buf, type = "application/octet-stream", headers = {}) => ({ status, headers: { "content-type": type, ...headers }, body: buf });
export const parseJson = (buf) => {
  try { return JSON.parse(Buffer.from(buf).toString() || "null"); } catch { throw new HttpError(400, "bad_json", "Body is not valid JSON"); }
};

/** Like parseJson, but the body must be a JSON object: null, arrays and scalars are a 400, never a TypeError later. */
export const parseObject = (buf) => {
  const v = parseJson(buf);
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new HttpError(400, "bad_json", "Body must be a JSON object");
  return v;
};

/**
 * Minimal router. Routes: [["GET", "/objects/:id", handler], ...].
 * Handler receives ({ req, params, query, body, claims }) and returns json()/bytes().
 */
export const logPath = (route, pathname) => route ? route.pattern : `/${String(pathname).split("/")[1] || ""}/…`.replace(/[^\w/…-]/g, "");

/**
 * quiet: no per-request log lines (the relay and the stamp issuer, whose request times, side by
 * side, would line up stamp requests with deposits; security review MSG-13). Errors still log.
 */
export function createService({ name, port, routes, bodyLimit = 1 << 20, verify, onError, extraHeaders, tls = null, quiet = false }) {
  const log = logger(name);
  const replay = replayGuard();
  const compiled = routes.map(([method, pattern, handler, opts = {}]) => {
    const keys = [];
    const re = new RegExp("^" + pattern.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return "([^/]+)"; }) + "$");
    return { method, pattern, re, keys, handler, opts };
  });

  // One request must never be able to take the process down: this process may hold keys that
  // exist only in memory (keyshare). Every step, including parsing the request target and
  // writing the reply, is inside a try; the outer catch is the last resort.
  async function handle(req, res) {
    const started = Date.now();
    let out, route = null, pathname = "/";
    let closeAfter = false;
    try {
      // Origin-form only. "//x", "http://[" and absolute-form targets are not routes; "//host/p"
      // must not be read as a host + path by the URL parser either.
      if (typeof req.url !== "string" || req.url[0] !== "/" || req.url[1] === "/") throw new HttpError(400, "bad_request", "Bad request target");
      let url;
      try { url = new URL(req.url, "http://internal"); } catch { throw new HttpError(400, "bad_request", "Bad request target"); }
      pathname = url.pathname;
      if (req.method === "GET" && pathname === "/healthz") {
        out = json(200, { ok: true, service: name });
      } else {
        route = compiled.find((r) => r.method === req.method && r.re.test(pathname)) || null;
        if (!route) throw new HttpError(404, "not_found", "No such route");
        const m = pathname.match(route.re);
        let params;
        try { params = Object.fromEntries(route.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])); }
        catch { throw new HttpError(400, "bad_request", "Bad path encoding"); }
        const claims = route.opts.public ? null : verify?.(req.headers[ASSERTION_HEADER]);
        let body = new Uint8Array(0);
        if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
          // admit() may refuse (429) before a byte is read; its release runs when the body is in or abandoned.
          let release;
          try { release = route.opts.admit?.(req); body = await readBody(req, route.opts.readLimit || route.opts.bodyLimit || bodyLimit); }
          catch (e) { closeAfter = true; throw e; }
          finally { release?.(); }
        }
        // SEC-S-01: the assertion must be for exactly this request, and unused
        if (claims) replay.check(claims, { method: req.method, url: req.url, body });
        out = await route.handler({ req, params, query: url.searchParams, body, claims, headers: req.headers });
      }
    } catch (e) {
      try {
        if (!(e instanceof HttpError)) log.error("unhandled", { err: e?.stack });
        out = onError?.(e) || json(e?.status || 500, { ...(e instanceof HttpError && e.detail ? e.detail : {}), error: e?.code || "internal", message: e instanceof HttpError ? e.message : "Internal error" });
      } catch (e2) {
        log.error("unhandled", { err: e2?.stack });
        out = json(500, { error: "internal", message: "Internal error" });
      }
    }
    // A refused or broken upload may still be streaming in: answer, then drop the connection.
    if (closeAfter) { res.once("finish", () => setTimeout(() => req.socket?.destroy(), 200).unref()); }
    res.writeHead(out.status, { "cache-control": "no-store", "x-content-type-options": "nosniff", ...(closeAfter ? { connection: "close" } : {}), ...(extraHeaders?.(req) || {}), ...out.headers });
    res.end(out.body);
    // The route's pattern ("/links/:code"), never the path: paths carry recovery codes,
    // request and object ids. An unmatched path logs only its first segment.
    if (pathname !== "/healthz" && !quiet) log.info("req", { m: req.method, p: logPath(route, pathname), s: out.status, ms: Date.now() - started });
  }

  const onRequest = (req, res) => {
    handle(req, res).catch((e) => {
      try { log.error("unhandled", { err: e?.stack }); } catch {}
      try { if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" }); res.end(res.headersSent ? undefined : '{"error":"internal","message":"Internal error"}'); } catch { try { res.destroy(); } catch {} }
    });
  };
  // Calls from another machine (server 3.0, split roles): mutual TLS with the server's own CA
  // (pki.js), and only the roles in tls.allow (the gateway's humid-front) may connect at all.
  const server = tls ? https.createServer(tls, onRequest) : http.createServer(onRequest);
  if (tls) {
    const allow = tls.allow || ["front"];
    server.on("secureConnection", (sock) => {
      const role = roleOf(sock.getPeerCertificate?.());
      if (!sock.authorized || !allow.includes(role)) { log.warn("refused a connection", { role: role || "none" }); sock.destroy(); }
    });
    server.on("tlsClientError", () => {}); // a handshake that fails is the client's problem, not a crash
  }
  server.on("clientError", (err, socket) => { try { if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"); else socket.destroy(); } catch {} });
  server.requestTimeout = 120_000;
  server.headersTimeout = 15_000;

  // HUMID_BIND_HOST=127.0.0.1 keeps a service off the network (the Windows server does this).
  const start = () => new Promise((resolve, reject) => {
    const host = process.env.HUMID_BIND_HOST || undefined;
    server.once("error", reject);
    server.listen(port, host, () => { server.off("error", reject); log.info("listening", { port: server.address().port, ...(host ? { host } : {}), ...(tls ? { tls: "mutual" } : {}) }); resolve(server); });
  });
  const stop = () => new Promise((resolve) => server.close(() => resolve()));
  for (const sig of ["SIGTERM", "SIGINT"]) process.once(sig, () => { log.info("shutdown", { sig }); stop().then(() => process.exit(0)); });
  return { server, start, stop, log, tls: !!tls };
}

/* ---------------- calls between services ---------------- */

/**
 * One HTTP(S) request to another service: { status, headers: Map-like get(), body: Uint8Array }.
 * `agent` carries the TLS settings for a role on another machine (an https.Agent made with
 * clientTls()); without one, plain HTTP on this machine's loopback.
 */
export function internalRequest(url, { method = "GET", headers = {}, body, agent, timeoutMs = 120_000 } = {}) {
  const u = new URL(url);
  const lib = u.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request({
      method, hostname: u.hostname.replace(/^\[|\]$/g, ""), port: u.port, path: u.pathname + u.search, agent,
      headers: { ...headers, ...(body && body.length ? { "content-length": body.length } : {}) },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: { get: (h) => { const v = res.headers[h.toLowerCase()]; return Array.isArray(v) ? v.join(", ") : v ?? null; } }, body: new Uint8Array(Buffer.concat(chunks)) }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    if (body && body.length) req.end(Buffer.from(body)); else req.end();
  });
}

/**
 * A service's TLS when it takes calls from another machine: HUMID_TLS_CA, HUMID_TLS_CERT and
 * HUMID_TLS_KEY (files; the key may be sealed). null = plain HTTP (one machine, loopback only).
 */
export function serviceTlsFromEnv(env = process.env) {
  const { HUMID_TLS_CA: ca, HUMID_TLS_CERT: cert, HUMID_TLS_KEY: key } = env;
  if (!ca && !cert && !key) return null;
  if (!ca || !cert || !key) throw new Error("Internal TLS needs all of HUMID_TLS_CA, HUMID_TLS_CERT and HUMID_TLS_KEY");
  const seal = sealerFromEnv(env);
  return serverTls({ ca: readFileSync(ca, "utf8"), cert: readFileSync(cert, "utf8"), key: seal.open("tls/key", readFileSync(key)).toString("utf8") });
}

/** An https.Agent for calls to `role` on another machine, from pki.js clientTls() settings. */
export const roleAgent = (tlsOpts) => new https.Agent({ keepAlive: true, maxSockets: 64, ...tlsOpts });

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
