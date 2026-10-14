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
import { testCsca, testPassport } from "../tests/support/passport.js";
import { simulatedChip } from "../tests/support/chip.js";
import { randomBytes } from "node:crypto";

// Local development build: includes demo mode (no sensor) so you can try HumID on a
// laptop. Release builds never contain it, and real servers refuse it.
execFileSync(process.execPath, [fileURLToPath(new URL("../apps/mobile/build.mjs", import.meta.url))], { stdio: "inherit", env: { ...process.env, HUMID_ALLOW_DEMO: "1" } });

const PORT = Number(process.env.PORT || 5173);
const dist = fileURLToPath(new URL("../apps/mobile/dist/", import.meta.url));
// Recovery normally waits 72 hours; locally it's 2 minutes so you can try it (RECOVERY_DELAY_MS to change).
// Demo passports: a throwaway country signing CA the dev server trusts, and one chip per holder name,
// so "Use a demo passport" works for anchoring, recovering and station checks. Every account can act
// as a verification station here, so you can try the operator side too.
const devCsca = testCsca("HumID Dev Country");
const passports = new Map();
const chips = new Map();
const passportFor = (name) => {
  const key = String(name || "Demo Person").toUpperCase().replace(/[^A-Z ]/g, "").trim().slice(0, 30) || "DEMO PERSON";
  if (!passports.has(key)) {
    const [given, ...rest] = key.split(" ");
    const number = `D${String(passports.size + 1).padStart(8, "0")}`;
    const p = testPassport({ csca: devCsca, mrz: { issuer: "UTO", nationality: "UTO", surname: rest.join(" ") || "PERSON", given, number } });
    p.access = { number, birth: "740812", expiry: "341231" };
    passports.set(key, p);
  }
  return passports.get(key);
};
const stack = await startStack({
  recoveryDelayMs: Number(process.env.RECOVERY_DELAY_MS || 120_000), devicePolicy: process.env.HUMID_DEVICE_POLICY || "demo",
  cscas: [devCsca.pem], stations: ["*"], duressCoolOffMs: Number(process.env.HUMID_DURESS_COOLOFF_MS || 60_000),
});
const gw = new URL(stack.baseUrl);

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".png": "image/png", ".json": "application/json", ".webmanifest": "application/manifest+json" };

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/dev/passport" && req.method === "POST") {
    const p = passportFor(url.searchParams.get("name"));
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify({ dg1: p.dg1.toString("base64"), sod: p.sod.toString("base64"), dg15: p.dg15?.toString("base64") }));
  }
  if (url.pathname === "/dev/passport/answer" && req.method === "POST") {
    const p = passportFor(url.searchParams.get("name"));
    const nonce = Buffer.from(String(url.searchParams.get("nonce") || ""), "hex");
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify({ signature: p.answer(nonce).toString("base64") }));
  }
  // A simulated chip for the demo passport, so the chip reader runs for real in a dev browser.
  // Alternates BAC and PACE so both get exercised.
  if (url.pathname === "/dev/chip/begin" && req.method === "POST") {
    const p = passportFor(url.searchParams.get("name"));
    const id = randomBytes(8).toString("hex");
    const pace = chips.size % 2 ? null : { oid: "0.4.0.127.0.7.2.2.4.2.2", parameterId: 13 };
    chips.set(id, simulatedChip({ passport: p, access: p.access, pace }));
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify({ session: id, hint: p.access }));
  }
  if (url.pathname === "/dev/chip/transceive" && req.method === "POST") {
    const chip = chips.get(url.searchParams.get("session") || "");
    const apdu = Buffer.from(String(url.searchParams.get("apdu") || ""), "hex");
    const r = chip ? Buffer.from(await chip.transceive(Uint8Array.from(apdu))) : Buffer.from([0x6f, 0x00]);
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify({ response: r.toString("hex") }));
  }
  if (url.pathname === "/dev/chip/hint" && req.method === "POST") {
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify(passportFor(url.searchParams.get("name")).access));
  }
  if (url.pathname.startsWith("/htp/") || url.pathname.startsWith("/tlog/")) {
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
