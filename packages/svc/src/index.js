// @humid/svc — the whole "framework" for HumID services, on purpose small
// enough to read in one sitting. Node built-ins only (http, node:sqlite),
// plus noble for Ed25519 internal assertions.

import http from "node:http";
import { mkdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
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

const sha256hex = (b) => createHash("sha256").update(b || new Uint8Array(0)).digest("hex");

/**
 * An assertion for exactly one request (PC-08): its method, its target (path and query) and
 * a hash of its body are signed in with the claims, and createService refuses the assertion
 * on any other request. Each also carries a fresh `rid` and is accepted once. So one captured
 * on the internal network can't be replayed, or turned from a read into a delete.
 */
export function signRequestAssertion(skB64, claims, { method, path, body }, ttlMs) {
  return signAssertion(skB64, { ...claims, m: String(method).toUpperCase(), p: String(path), bh: sha256hex(body) }, ttlMs);
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

export function createService({ name, port, routes, bodyLimit = 1 << 20, verify, onError, extraHeaders }) {
  const log = logger(name);
  // Assertions already used, until they expire (PC-08): each is good for one request.
  const usedRids = new Map();
  function bound(claims, req, body) {
    if (claims.m !== req.method || claims.p !== req.url || claims.bh !== sha256hex(body)) {
      throw new HttpError(401, "unauthenticated", "Assertion is for a different request");
    }
    const rid = typeof claims.rid === "string" ? claims.rid : "";
    const t = Date.now();
    if (usedRids.size > 50_000) for (const [k, exp] of usedRids) if (exp < t) usedRids.delete(k);
    if (!rid || usedRids.has(rid)) throw new HttpError(401, "unauthenticated", "Assertion already used");
    if (usedRids.size > 200_000) throw new HttpError(503, "busy", "Too many requests in flight");
    usedRids.set(rid, Number(claims.exp) || t);
  }
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
        if (claims) bound(claims, req, body);
        out = await route.handler({ req, params, query: url.searchParams, body, claims, headers: req.headers });
      }
    } catch (e) {
      try {
        if (!(e instanceof HttpError)) log.error("unhandled", { err: e?.stack });
        out = onError?.(e) || json(e?.status || 500, { error: e?.code || "internal", message: e instanceof HttpError ? e.message : "Internal error" });
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
    if (pathname !== "/healthz") log.info("req", { m: req.method, p: logPath(route, pathname), s: out.status, ms: Date.now() - started });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      try { log.error("unhandled", { err: e?.stack }); } catch {}
      try { if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" }); res.end(res.headersSent ? undefined : '{"error":"internal","message":"Internal error"}'); } catch { try { res.destroy(); } catch {} }
    });
  });
  server.on("clientError", (err, socket) => { try { if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"); else socket.destroy(); } catch {} });
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
