// Local development: the whole HumID stack on your machine, no Docker.
//   npm run dev        → http://localhost:5173  (demo mode on: policy "demo")
// Runs identity, vault, ledger, recovery and gateway in-process (fresh data each run
// unless HUMID_DEV_DATA is set), serves the built app, and proxies /htp/* to
// the gateway exactly as the Caddy edge does in production.
import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { startStack } from "../tests/e2e/stack.js";

// Local development build: includes demo mode (no sensor) so you can try HumID on a
// laptop. Release builds never contain it, and real servers refuse it.
execFileSync(process.execPath, [fileURLToPath(new URL("../apps/mobile/build.mjs", import.meta.url))], { stdio: "inherit", env: { ...process.env, HUMID_ALLOW_DEMO: "1" } });

const PORT = Number(process.env.PORT || 5173);
const dist = fileURLToPath(new URL("../apps/mobile/dist/", import.meta.url));
// Recovery normally waits 72 hours; locally it's 2 minutes so you can try it (RECOVERY_DELAY_MS to change).
const stack = await startStack({ recoveryDelayMs: Number(process.env.RECOVERY_DELAY_MS || 120_000), devicePolicy: process.env.HUMID_DEVICE_POLICY || "demo" });
const gw = new URL(stack.baseUrl);

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".png": "image/png", ".json": "application/json", ".webmanifest": "application/manifest+json" };

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname.startsWith("/htp/")) {
    const p = http.request({ host: gw.hostname, port: gw.port, path: req.url, method: req.method, headers: { ...req.headers, "x-forwarded-for": req.socket.remoteAddress } }, (r) => {
      res.writeHead(r.statusCode, r.headers);
      r.pipe(res);
    });
    p.on("error", () => { res.writeHead(502); res.end(); });
    return req.pipe(p);
  }
  let file = join(dist, decodeURIComponent(url.pathname));
  try { if ((await stat(file)).isDirectory()) file = join(file, "index.html"); }
  catch { file = join(dist, "index.html"); }
  try {
    const body = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream", "cache-control": "no-store" });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
}).listen(PORT, () => {
  console.log(`HumID dev: http://localhost:${PORT}  (gateway ${stack.baseUrl}, server fingerprint ${stack.gateway.htp.fingerprint})`);
});

for (const s of ["SIGINT", "SIGTERM"]) process.on(s, async () => { await stack.stop(); process.exit(0); });
