// The local edge: what Caddy does in the Docker deployment, minus TLS (the
// tunnel provides HTTPS). Listens on 127.0.0.1 only.
//   /htp/*     streamed to the gateway (bodies capped at 64 MB)
//   /tlog/*    the public transparency log, at the gateway
//   /healthz   ok when the gateway answers
//   anything   the web app, with the same security headers as the Docker edge
import http from "node:http";
import { createReadStream, statSync } from "node:fs";
import { join, normalize, extname, sep } from "node:path";

const SECURITY = {
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(self), geolocation=(), microphone=(), payment=()",
};
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'self' blob:; worker-src 'self'; connect-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json", ".webmanifest": "application/manifest+json", ".png": "image/png", ".svg": "image/svg+xml",
  ".ico": "image/x-icon", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8",
};
const HOP = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer", "proxy-authorization"]);
const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

/**
 * The visitor's address. Only the tunnel (a local program) can reach this
 * port, so its headers are trusted: Cloudflare's CF-Connecting-IP, else the
 * last X-Forwarded-For entry (the one the tunnel added; earlier ones come
 * from the visitor and could be made up).
 */
export function clientIp(req) {
  const peer = req.socket.remoteAddress || "";
  if (!LOOPBACK.has(peer)) return peer;
  const cf = req.headers["cf-connecting-ip"];
  if (typeof cf === "string" && cf.trim()) return cf.trim();
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) return xff.split(",").map((s) => s.trim()).filter(Boolean).pop();
  return peer;
}

export function createEdge({ port, host = "127.0.0.1", appDir, gatewayUrl, maxBodyBytes = 64 * 1024 * 1024, log = console }) {
  const gw = new URL(gatewayUrl);
  const root = normalize(appDir + sep);

  const send = (res, status, headers, body) => {
    res.writeHead(status, { ...SECURITY, ...headers });
    res.end(body);
  };

  function proxy(req, res) {
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && !k.startsWith("x-forwarded-") && k !== "cf-connecting-ip") headers[k] = v;
    headers.host = gw.host;
    headers["x-forwarded-for"] = clientIp(req); // the gateway rate-limits per address
    headers["x-forwarded-proto"] = req.headers["x-forwarded-proto"] === "https" ? "https" : "http";

    const declared = Number(req.headers["content-length"] || 0);
    if (declared > maxBodyBytes) return send(res, 413, { "content-type": "text/plain" }, "Too large");

    const up = http.request({ host: gw.hostname, port: gw.port, method: req.method, path: req.url, headers }, (r) => {
      const out = {};
      for (const [k, v] of Object.entries(r.headers)) if (!HOP.has(k)) out[k] = v;
      res.writeHead(r.statusCode, { ...SECURITY, ...out });
      r.pipe(res);
    });
    up.setTimeout(130_000, () => up.destroy(new Error("gateway timeout")));
    let tooBig = false;
    up.on("error", (e) => {
      if (tooBig) return; // we cut it off ourselves
      log.error?.("edge proxy error", { err: e.message });
      if (!res.headersSent) send(res, 502, { "content-type": "text/plain" }, "Gateway unavailable");
      else res.destroy();
    });

    let seen = 0;
    req.on("data", (c) => {
      seen += c.length;
      if (seen > maxBodyBytes && !tooBig) {
        tooBig = true;
        up.destroy();
        if (!res.headersSent) send(res, 413, { "content-type": "text/plain", connection: "close" }, "Too large");
        req.destroy();
      }
    });
    req.pipe(up);
  }

  function health(res) {
    const r = http.get({ host: gw.hostname, port: gw.port, path: "/healthz", timeout: 2000 }, (g) => {
      g.resume();
      send(res, g.statusCode === 200 ? 200 : 503, { "content-type": "text/plain", "cache-control": "no-store" }, g.statusCode === 200 ? "ok" : "gateway unhealthy");
    });
    r.on("timeout", () => r.destroy(new Error("timeout")));
    r.on("error", () => send(res, 503, { "content-type": "text/plain", "cache-control": "no-store" }, "gateway unavailable"));
  }

  function file(req, res, url) {
    if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, { allow: "GET, HEAD", "content-type": "text/plain" }, "Method not allowed");
    let rel;
    try { rel = decodeURIComponent(url.pathname); } catch { return send(res, 400, { "content-type": "text/plain" }, "Bad path"); }
    if (rel.includes("\0")) return send(res, 400, { "content-type": "text/plain" }, "Bad path");
    let path = normalize(join(root, rel));
    if (!path.startsWith(root)) return send(res, 400, { "content-type": "text/plain" }, "Bad path");
    let st;
    try { st = statSync(path); if (st.isDirectory()) { path = join(path, "index.html"); st = statSync(path); } }
    catch { path = join(root, "index.html"); try { st = statSync(path); } catch { return send(res, 404, { "content-type": "text/plain" }, "Not found"); } }

    const name = url.pathname;
    const cache = name.startsWith("/assets/") ? "public, max-age=31536000, immutable"
      : name === "/sw.js" || name === "/manifest.webmanifest" || path.endsWith("index.html") ? "no-cache" : "public, max-age=3600";
    const headers = { "content-type": TYPES[extname(path).toLowerCase()] || "application/octet-stream", "content-length": st.size, "cache-control": cache, "content-security-policy": CSP };
    res.writeHead(200, { ...SECURITY, ...headers });
    if (req.method === "HEAD") return res.end();
    createReadStream(path).on("error", () => res.destroy()).pipe(res);
  }

  const server = http.createServer((req, res) => {
    let url;
    try { url = new URL(req.url, "http://edge"); } catch { return send(res, 400, { "content-type": "text/plain" }, "Bad request"); }
    if (url.pathname.startsWith("/htp/") || url.pathname.startsWith("/tlog/")) return proxy(req, res);
    if (url.pathname === "/healthz") return health(res);
    return file(req, res, url);
  });
  server.requestTimeout = 130_000;
  server.headersTimeout = 15_000;

  return {
    server,
    start: () => new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => { server.off("error", reject); resolve(server); });
    }),
    stop: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
