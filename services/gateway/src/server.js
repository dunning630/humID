// gateway — the only HumID service reachable from the internet (behind the
// TLS edge). It terminates HTP/1, binds sessions to identities with
// biometric-signed proofs, checks step-up proofs, and forwards whitelisted
// calls to internal services with a short-lived signed assertion.
//
// Invariant: no document ciphertext leaves the vault without a matching
// ledger record. If the ledger cannot record the access, the gateway refuses.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { createService, env, json, bytes, parseJson, signAssertion, HttpError, b64u, unb64u, logger } from "@humid/svc";
import { HtpServer, HtpServerError, createStatics, exportStatics, importStatics } from "@humid/htp/server";
import { MEDIA_TYPE, loginMessage, stepUpMessage, verify, proofHash, STEP_UP_MAX_AGE_MS, random, utf8 } from "@humid/htp";

const ID_RE = "hid_[0-9a-f]{40}";
const OBJ_RE = "[0-9a-f-]{36}";

/** Inner routes the app may call. Anything else is a 404 — internal routes are unreachable from outside. */
const ROUTES = [
  { m: "POST", p: /^\/auth\/register$/, h: "register" },
  { m: "POST", p: /^\/auth\/challenge$/, h: "challenge" },
  { m: "POST", p: /^\/auth\/login$/, h: "login" },
  { m: "POST", p: /^\/auth\/logout$/, h: "logout" },
  { m: "GET", p: /^\/identity\/me$/, to: "identity", path: "/me", auth: true },
  { m: "DELETE", p: /^\/identity\/me$/, h: "closeIdentity", auth: true },
  { m: "GET", p: /^\/vault\/objects$/, to: "vault", path: "/objects", auth: true },
  { m: "POST", p: /^\/vault\/objects$/, to: "vault", path: "/objects", auth: true, event: "object.sealed" },
  { m: "GET", p: new RegExp(`^/vault/objects/(${OBJ_RE})$`), to: "vault", path: "/objects/$1", auth: true, event: "object.opened", audited: true },
  { m: "PATCH", p: new RegExp(`^/vault/objects/(${OBJ_RE})$`), to: "vault", path: "/objects/$1", auth: true, event: "object.updated" },
  { m: "DELETE", p: new RegExp(`^/vault/objects/(${OBJ_RE})$`), to: "vault", path: "/objects/$1", auth: true, event: "object.deleted", audited: true },
  { m: "GET", p: /^\/ledger\/events$/, to: "ledger", path: "/events", auth: true },
];

const FORWARD_REQ_HEADERS = ["content-type", "x-humid-index"];
const FORWARD_RES_HEADERS = ["content-type", "x-humid-size"];

class Buckets {
  constructor(capacity, perMs) { this.capacity = capacity; this.perMs = perMs; this.m = new Map(); }
  take(key, now = Date.now()) {
    const b = this.m.get(key) || { tokens: this.capacity, at: now };
    b.tokens = Math.min(this.capacity, b.tokens + ((now - b.at) / this.perMs) * this.capacity);
    b.at = now;
    if (b.tokens < 1) { this.m.set(key, b); return false; }
    b.tokens -= 1;
    this.m.set(key, b);
    if (this.m.size > 100_000) this.m.clear();
    return true;
  }
}

export function createGateway({
  port = Number(env("PORT", "8080")),
  dataDir = env("DATA_DIR", "/data"),
  internalSk = env("HUMID_INTERNAL_SK"),
  upstreams = {
    identity: env("IDENTITY_URL", "http://identity:8081"),
    vault: env("VAULT_URL", "http://vault:8082"),
    ledger: env("LEDGER_URL", "http://ledger:8083"),
  },
  allowedOrigins = env("HUMID_ALLOWED_ORIGINS", "tauri://localhost,http://tauri.localhost,https://tauri.localhost").split(",").map((s) => s.trim()).filter(Boolean),
  trustProxy = env("TRUST_PROXY", "0") === "1",
  maxCallBytes = Number(env("GATEWAY_MAX_CALL_BYTES", String(64 * 1024 * 1024))),
} = {}) {
  const log = logger("gateway");

  // Long-term HTP keys. Losing this file changes the server's identity, and apps that pinned it will refuse to connect.
  mkdirSync(dataDir, { recursive: true });
  const keyFile = `${dataDir}/htp-keys.json`;
  let statics;
  if (existsSync(keyFile)) statics = importStatics(JSON.parse(readFileSync(keyFile, "utf8")));
  else { statics = createStatics(); writeFileSync(keyFile, JSON.stringify(exportStatics(statics)), { mode: 0o600 }); }
  const htp = new HtpServer(statics);
  log.info("server identity", { kid: htp.kid, fingerprint: htp.fingerprint });
  setInterval(() => htp.sweep(), 60_000).unref();

  const helloLimit = new Buckets(30, 60_000);   // per client IP
  const callLimit = new Buckets(600, 60_000);   // per session
  const loginLimit = new Buckets(10, 300_000);  // per identity

  const clientIp = (req) => (trustProxy && req.headers["x-forwarded-for"]?.split(",")[0].trim()) || req.socket.remoteAddress;

  /* ---------- internal calls ---------- */

  async function internal(service, method, path, { claims = {}, body, headers = {} } = {}) {
    const assertion = signAssertion(internalSk, { iss: "gateway", aud: service, rid: randomUUID(), ...claims });
    let res;
    try {
      res = await fetch(`${upstreams[service]}${path}`, {
        method,
        headers: { "x-humid-assertion": assertion, ...headers },
        body: body && body.length ? body : undefined,
      });
    } catch (e) {
      throw new HttpError(503, `${service}_unavailable`, `${service} service is unavailable`);
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    const out = { status: res.status, headers: {}, body: buf };
    for (const h of FORWARD_RES_HEADERS) { const v = res.headers.get(h); if (v) out.headers[h] = v; }
    return out;
  }
  const internalJson = async (service, method, path, opts = {}) => {
    const r = await internal(service, method, path, { ...opts, body: opts.json ? utf8(JSON.stringify(opts.json)) : opts.body, headers: { "content-type": "application/json", ...(opts.headers || {}) } });
    return { status: r.status, data: r.body.length ? JSON.parse(Buffer.from(r.body).toString()) : null };
  };

  async function record(sub, type, detail) {
    let r;
    try { r = await internalJson("ledger", "POST", "/internal/events", { json: { sub, type, detail } }); }
    catch { r = { status: 503 }; }
    if (r.status !== 201) throw new HttpError(503, "audit_unavailable", "Access log is unavailable, so access is refused.");
    return r.data;
  }
  const recordQuietly = (sub, type, detail) => record(sub, type, detail).catch((e) => log.warn("ledger write failed", { type, err: e.message }));

  const claimsFor = (s, extra = {}) => ({ sub: s.subject, sid: s.sidText.slice(0, 8), dsaFp: s.dsaFp, kemFp: s.kemFp, assurance: s.assurance, ...extra });

  function bindSession(s, identity, interrupt, platform) {
    s.subject = identity.id;
    s.dsaPk = unb64u(identity.dsaPk);
    s.dsaFp = identity.dsaFp;
    s.kemFp = identity.kemFp;
    s.assurance = ["hardware", "os", "none"].includes(interrupt?.assurance) ? interrupt.assurance : "none";
    s.gateMethod = String(interrupt?.method || "unknown").slice(0, 64);
    s.platform = String(platform || "unknown").slice(0, 32);
    s.authAt = Date.now();
  }
  const sessionView = (s) => ({ id: s.subject, assurance: s.assurance, gateMethod: s.gateMethod, expiresAt: s.expiresAt, idleTimeoutMs: htp.idleMs });

  /* ---------- auth handlers (run inside the encrypted channel) ---------- */

  const handlers = {
    async register(s, body) {
      const r = parseJson(body);
      const reg = await internalJson("identity", "POST", "/internal/register", {
        json: { kemPk: r.kemPk, dsaPk: r.dsaPk, xPk: r.xPk, commit: r.commit, sig: r.sig, th: b64u(s.th), device: r.device },
      });
      if (reg.status >= 300) return { status: reg.status, json: reg.data };
      bindSession(s, reg.data, { method: r.device?.gateMethod, assurance: r.device?.assurance }, r.device?.platform);
      if (reg.status === 201) await recordQuietly(s.subject, "identity.created", { platform: s.platform, method: s.gateMethod, assurance: s.assurance });
      await recordQuietly(s.subject, "session.opened", { platform: s.platform, method: s.gateMethod, assurance: s.assurance, proof: proofHash(unb64u(r.sig)) });
      return { status: reg.status, json: { ...sessionView(s), created: reg.status === 201 } };
    },

    async challenge(s, body) {
      const { id } = parseJson(body) || {};
      if (!new RegExp(`^${ID_RE}$`).test(String(id))) throw new HttpError(400, "bad_identity", "Unknown identity format");
      s.challenge = { id, nonce: random(32), exp: Date.now() + 120_000 };
      return { status: 200, json: { challenge: b64u(s.challenge.nonce), expiresAt: s.challenge.exp } };
    },

    async login(s, body) {
      const r = parseJson(body) || {};
      const c = s.challenge;
      s.challenge = null; // one attempt per challenge
      if (!c || c.id !== r.id || Date.now() > c.exp) throw new HttpError(400, "challenge_invalid", "Request a new challenge");
      if (!loginLimit.take(r.id)) throw new HttpError(429, "rate_limited", "Too many sign-in attempts. Wait a few minutes.");
      const v = await internalJson("identity", "POST", "/internal/verify", {
        json: { id: r.id, sig: r.sig, message: b64u(loginMessage(s.th, r.id, c.nonce)) },
      });
      if (v.status !== 200 || !v.data?.ok) {
        if (v.status === 401) await recordQuietly(r.id, "access.denied", { reason: "bad_login_proof" });
        throw new HttpError(v.status === 404 ? 404 : 401, v.status === 404 ? "unknown_identity" : "bad_proof", v.status === 404 ? "This identity is not registered on this server." : "Sign-in proof was rejected.");
      }
      bindSession(s, v.data, r.interrupt, r.device?.platform);
      await recordQuietly(s.subject, "session.opened", { platform: s.platform, method: s.gateMethod, assurance: s.assurance, proof: proofHash(unb64u(r.sig)) });
      return { status: 200, json: sessionView(s) };
    },

    async logout(s) {
      if (s.subject) await recordQuietly(s.subject, "session.closed", {});
      s.closeAfterReply = true;
      return { status: 200, json: { closed: true } };
    },

    async closeIdentity(s, body, stepUp) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Closing your identity needs a fresh biometric check.");
      const claims = claimsFor(s, { stepUp });
      const wiped = await internalJson("vault", "DELETE", "/objects", { claims });
      if (wiped.status !== 200) return { status: wiped.status, json: wiped.data };
      await recordQuietly(s.subject, "vault.erased", { count: wiped.data.deleted, proof: stepUp.proof });
      const closed = await internalJson("identity", "DELETE", "/me", { claims });
      if (closed.status === 200) await recordQuietly(s.subject, "identity.closed", { proof: stepUp.proof });
      s.closeAfterReply = true;
      return { status: closed.status, json: { closed: closed.status === 200, erasedItems: wiped.data.deleted } };
    },
  };

  /* ---------- the encrypted call ---------- */

  async function dispatch(s, seq, meta, body) {
    const url = new URL(String(meta.p || "/"), "http://inner");
    const route = ROUTES.find((r) => r.m === meta.m && r.p.test(url.pathname));
    if (!route) throw new HttpError(404, "not_found", "No such endpoint");
    if (route.auth && !s.subject) throw new HttpError(401, "sign_in_required", "Sign in first");

    // Step-up: a fresh biometric signature over exactly this request.
    let stepUp = null;
    if (meta.proof) {
      if (!s.subject) throw new HttpError(401, "sign_in_required", "Sign in first");
      const at = Number(meta.proof.at);
      if (!Number.isSafeInteger(at) || Math.abs(Date.now() - at) > STEP_UP_MAX_AGE_MS) throw new HttpError(403, "step_up_stale", "Biometric check is too old. Try again.");
      const sig = unb64u(String(meta.proof.sig));
      if (!verify(sig, stepUpMessage(s.th, seq, meta.m, meta.p, body, at), s.dsaPk)) {
        await recordQuietly(s.subject, "access.denied", { path: url.pathname.replace(/[0-9a-f-]{36}/, ":id"), reason: "bad_step_up" });
        throw new HttpError(401, "bad_proof", "Biometric proof was rejected.");
      }
      const i = meta.proof.interrupt || {};
      stepUp = { at, proof: proofHash(sig), method: String(i.method || s.gateMethod).slice(0, 64), assurance: ["hardware", "os", "none"].includes(i.assurance) ? i.assurance : s.assurance };
    }

    if (route.h) return handlers[route.h](s, body, stepUp);

    const headers = {};
    for (const k of FORWARD_REQ_HEADERS) if (meta.h?.[k]) headers[k] = String(meta.h[k]);
    const path = url.pathname.replace(route.p, route.path) + url.search;
    const res = await internal(route.to, meta.m, path, { claims: claimsFor(s, stepUp ? { stepUp } : {}), body, headers });

    if (route.event) {
      const objectId = url.pathname.match(new RegExp(OBJ_RE))?.[0];
      if (res.status >= 200 && res.status < 300) {
        const detail = { id: objectId || safeJson(res.body)?.id, size: route.event === "object.sealed" ? body.length : undefined, ...(stepUp ? { proof: stepUp.proof, method: stepUp.method, assurance: stepUp.assurance } : {}) };
        if (route.audited) await record(s.subject, route.event, detail); // fail closed: no record, no release
        else await recordQuietly(s.subject, route.event, detail);
      } else if (res.status === 403) {
        await recordQuietly(s.subject, "access.denied", { path: url.pathname.replace(/[0-9a-f-]{36}/, ":id"), reason: safeJson(res.body)?.error || "forbidden" });
      }
    }
    return res;
  }

  const safeJson = (b) => { try { return JSON.parse(Buffer.from(b).toString()); } catch { return null; } };

  async function call({ req, body }) {
    let opened;
    try { opened = await htp.open(body); }
    catch (e) {
      if (e instanceof HtpServerError) return json(e.status, { error: e.code, message: e.message });
      throw e;
    }
    const { session: s, seq, meta, body: inner } = opened;
    if (!callLimit.take(s.sidText)) return json(429, { error: "rate_limited", message: "Slow down" });
    let out;
    try {
      const r = await dispatch(s, seq, meta, inner);
      out = r.json !== undefined
        ? { status: r.status, headers: { "content-type": "application/json" }, body: utf8(JSON.stringify(r.json)) }
        : r;
    } catch (e) {
      if (!(e instanceof HttpError)) log.error("dispatch failed", { err: e.stack });
      out = { status: e.status || 500, headers: { "content-type": "application/json" }, body: utf8(JSON.stringify({ error: e.code || "internal", message: e instanceof HttpError ? e.message : "Internal error" })) };
    }
    const frame = await htp.seal(s, seq, out.status, out.headers, out.body);
    if (s.closeAfterReply) htp.drop(s); // logout / close: reply first, then destroy the keys
    return bytes(200, frame, MEDIA_TYPE);
  }

  const cors = (req) => {
    const o = req.headers.origin;
    if (!o || !allowedOrigins.includes(o)) return {};
    return { "access-control-allow-origin": o, vary: "origin", "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type", "access-control-max-age": "600" };
  };

  const routes = [
    ["GET", "/htp/v1/keys", () => json(200, htp.publicKeys()), { public: true }], // never cached: a stale key bundle would hide a server change
    ["POST", "/htp/v1/hello", ({ req, body }) => {
      if (!helloLimit.take(clientIp(req))) return json(429, { error: "rate_limited", message: "Too many handshakes" });
      try { return json(200, htp.hello(parseJson(body))); }
      catch (e) { if (e instanceof HtpServerError) return json(e.status, { error: e.code, message: e.message }); throw e; }
    }, { public: true, bodyLimit: 16 * 1024 }],
    ["POST", "/htp/v1/call", call, { public: true, bodyLimit: maxCallBytes }],
    ["OPTIONS", "/htp/v1/keys", () => ({ status: 204, headers: {}, body: "" }), { public: true }],
    ["OPTIONS", "/htp/v1/hello", () => ({ status: 204, headers: {}, body: "" }), { public: true }],
    ["OPTIONS", "/htp/v1/call", () => ({ status: 204, headers: {}, body: "" }), { public: true }],
  ];

  const svc = createService({ name: "gateway", port, routes, extraHeaders: cors });
  return { ...svc, htp };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes("keygen")) {
    // `docker compose run --rm gateway server.mjs keygen` -> lines for deploy/.env
    const { newInternalKeys } = await import("@humid/svc");
    const k = newInternalKeys();
    process.stdout.write(`HUMID_INTERNAL_SK=${k.sk}\nHUMID_INTERNAL_PK=${k.pk}\n`);
  } else createGateway().start();
}
