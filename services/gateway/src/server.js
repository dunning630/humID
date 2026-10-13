// gateway — the only HumID service reachable from the internet (behind the
// TLS edge). It terminates HTP/1, binds sessions to an account and one of its
// devices with biometric-signed proofs, checks step-up proofs, and forwards
// whitelisted calls to internal services with a short-lived signed assertion.
//
// Invariant: no document ciphertext leaves the vault without a matching
// ledger record. If the ledger cannot record the access, the gateway refuses.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { createService, env, json, bytes, parseJson, signAssertion, HttpError, b64u, unb64u, logger } from "@humid/svc";
import { HtpServer, HtpServerError, createStatics, exportStatics, importStatics } from "@humid/htp/server";
import { MEDIA_TYPE, loginMessage, stepUpMessage, liveMessage, verify, proofHash, STEP_UP_MAX_AGE_MS, random, utf8 } from "@humid/htp";
import { verifyLiveSig } from "@humid/attest";

const ID_RE = "hid_[0-9a-f]{40}";
const DEV_RE = "dev_[0-9a-f]{24}";
const OBJ_RE = "[0-9a-f-]{36}";
const CODE_RE = "[0-9A-HJKMNP-TV-Z]{12}";
const REQ_RE = "[A-Za-z0-9_-]{22}";
const REF_RE = "[0-9a-f]{16}";
/**
 * Which devices may sign in (HUMID_DEVICE_POLICY):
 *   attested   only phones whose secure chip proves every check is a live biometric
 *              (Android key attestation / Apple App Attest). Default.
 *   biometric  also desktop gates that accept only a biometric, enforced by the OS
 *              (Touch ID, Windows fingerprint, Linux fingerprint), without hardware proof.
 *   demo       anything, including demo mode with no sensor. Local development only.
 */
const POLICIES = ["attested", "biometric", "demo"];
const re = (s) => new RegExp(`^${s}$`);

/**
 * Inner routes the app may call. Anything else is a 404, so internal routes
 * are unreachable from outside. auth = needs a signed-in session; anon = open
 * to a session that has not signed in (a new device that has no keys yet).
 */
const ROUTES = [
  { m: "POST", p: re("/auth/register"), h: "register" },
  { m: "POST", p: re("/auth/device"), h: "enrollDevice" },
  { m: "POST", p: re("/auth/challenge"), h: "challenge" },
  { m: "POST", p: re("/auth/login"), h: "login" },
  { m: "POST", p: re("/auth/logout"), h: "logout" },

  { m: "GET", p: re("/identity/me"), to: "identity", path: "/me", auth: true },
  { m: "DELETE", p: re("/identity/me"), h: "closeIdentity", auth: true },
  { m: "DELETE", p: re(`/identity/devices/(${DEV_RE})`), h: "removeDevice", auth: true },

  { m: "GET", p: re("/vault/objects"), to: "vault", path: "/objects", auth: true },
  { m: "POST", p: re("/vault/objects"), to: "vault", path: "/objects", auth: true, event: "object.sealed" },
  { m: "GET", p: re(`/vault/objects/(${OBJ_RE})`), to: "vault", path: "/objects/$1", auth: true, event: "object.opened", audited: true },
  { m: "PATCH", p: re(`/vault/objects/(${OBJ_RE})`), to: "vault", path: "/objects/$1", auth: true, event: "object.updated" },
  { m: "DELETE", p: re(`/vault/objects/(${OBJ_RE})`), to: "vault", path: "/objects/$1", auth: true, event: "object.deleted", audited: true },

  { m: "GET", p: re("/ledger/events"), to: "ledger", path: "/events", auth: true },

  // add a device you still have
  { m: "POST", p: re("/recovery/links"), to: "recovery", path: "/links", anon: true },
  { m: "GET", p: re(`/recovery/links/(${CODE_RE})`), to: "recovery", path: "/links/$1", auth: true },
  { m: "POST", p: re(`/recovery/links/(${CODE_RE})/approve`), to: "recovery", path: "/links/$1/approve", auth: true, event: "device.link_approved", audited: true, detail: (r, su) => ({ platform: r?.platform, proof: su?.proof }) },
  { m: "GET", p: re(`/recovery/links/(${CODE_RE})/result`), to: "recovery", path: "/links/$1/result", anon: true },
  // recovery card
  { m: "GET", p: re("/recovery/card"), to: "recovery", path: "/card", auth: true },
  { m: "PUT", p: re("/recovery/card"), to: "recovery", path: "/card", auth: true, event: "recovery.card_set", detail: (r, su) => ({ proof: su?.proof }) },
  { m: "DELETE", p: re("/recovery/card"), to: "recovery", path: "/card", auth: true, event: "recovery.card_removed", detail: (r, su) => ({ proof: su?.proof }) },
  // recovery contacts
  { m: "POST", p: re("/recovery/offers"), to: "recovery", path: "/offers", auth: true },
  { m: "GET", p: re(`/recovery/offers/(${CODE_RE})`), to: "recovery", path: "/offers/$1", auth: true },
  { m: "GET", p: re("/recovery/contacts"), to: "recovery", path: "/contacts", auth: true },
  { m: "PUT", p: re("/recovery/contacts"), to: "recovery", path: "/contacts", auth: true, event: "recovery.contacts_set", detail: (r, su) => ({ n: r?.n, threshold: r?.threshold, proof: su?.proof }) },
  { m: "DELETE", p: re("/recovery/contacts"), to: "recovery", path: "/contacts", auth: true, event: "recovery.contacts_removed", detail: (r, su) => ({ proof: su?.proof }) },
  { m: "GET", p: re("/recovery/protecting"), to: "recovery", path: "/protecting", auth: true },
  // recovering on a new device
  { m: "POST", p: re("/recovery/requests"), h: "startRecovery", anon: true },
  { m: "GET", p: re(`/recovery/requests/(${REQ_RE})`), to: "recovery", path: "/requests/$1", anon: true },
  { m: "GET", p: re(`/recovery/help/(${CODE_RE})`), to: "recovery", path: "/help/$1", auth: true },
  { m: "POST", p: re(`/recovery/help/(${CODE_RE})`), h: "helpRecover", auth: true },
  { m: "GET", p: re("/recovery/alerts"), to: "recovery", path: "/alerts", auth: true },
  { m: "POST", p: re(`/recovery/alerts/(${REF_RE})/cancel`), to: "recovery", path: "/alerts/$1/cancel", auth: true, event: "recovery.cancelled", detail: (r, su) => ({ ref: r?.ref, method: r?.method, platform: r?.platform, proof: su?.proof }) },
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
    recovery: env("RECOVERY_URL", "http://recovery:8084"),
  },
  allowedOrigins = env("HUMID_ALLOWED_ORIGINS", "tauri://localhost,http://tauri.localhost,https://tauri.localhost").split(",").map((s) => s.trim()).filter(Boolean),
  trustProxy = env("TRUST_PROXY", "0") === "1",
  maxCallBytes = Number(env("GATEWAY_MAX_CALL_BYTES", String(64 * 1024 * 1024))),
  devicePolicy = env("HUMID_DEVICE_POLICY", "attested"),
} = {}) {
  const log = logger("gateway");
  if (!POLICIES.includes(devicePolicy)) throw new Error(`HUMID_DEVICE_POLICY must be one of ${POLICIES.join(", ")}`);

  // Long-term HTP keys. Losing this file changes the server's identity, and apps that pinned it will refuse to connect.
  mkdirSync(dataDir, { recursive: true });
  const keyFile = `${dataDir}/htp-keys.json`;
  let statics;
  if (existsSync(keyFile)) statics = importStatics(JSON.parse(readFileSync(keyFile, "utf8")));
  else { statics = createStatics(); writeFileSync(keyFile, JSON.stringify(exportStatics(statics)), { mode: 0o600 }); }
  const htp = new HtpServer(statics);
  log.info("server identity", { kid: htp.kid, fingerprint: htp.fingerprint, devicePolicy });
  setInterval(() => htp.sweep(), 60_000).unref();

  const helloLimit = new Buckets(30, 60_000);   // per client IP
  const callLimit = new Buckets(600, 60_000);   // per session
  const loginLimit = new Buckets(10, 300_000);  // per identity
  const anonLimit = new Buckets(20, 60_000);    // per session, for calls before sign-in

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
    } catch {
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
  const fail = (r) => { throw new HttpError(r.status, r.data?.error || "error", r.data?.message || "Request failed"); };

  async function record(sub, type, detail) {
    let r;
    try { r = await internalJson("ledger", "POST", "/internal/events", { json: { sub, type, detail } }); }
    catch { r = { status: 503 }; }
    if (r.status !== 201) throw new HttpError(503, "audit_unavailable", "Access log is unavailable, so access is refused.");
    return r.data;
  }
  const recordQuietly = (sub, type, detail) => record(sub, type, detail).catch((e) => log.warn("ledger write failed", { type, err: e.message }));

  const claimsFor = (s, extra = {}) => ({
    sub: s.subject, device: s.deviceId, sid: s.sidText.slice(0, 8), dsaFp: s.dsaFp, kemFp: s.kemFp, assurance: s.assurance,
    ...(s.livePub ? { livePub: b64u(s.livePub) } : {}), ...extra,
  });

  /** Bind a session to an account and the device that proved itself. */
  function bindSession(s, view, interrupt) {
    s.subject = view.id;
    s.deviceId = view.device.id;
    s.dsaPk = unb64u(view.deviceDsaPk); // device key: verifies step-up proofs
    s.dsaFp = view.dsaFp;               // account key: signs envelopes
    s.kemFp = view.kemFp;
    s.livePub = view.deviceLivePub ? unb64u(view.deviceLivePub) : null; // hardware liveness key: checks every step-up
    s.proof = view.device.proof || "none";
    s.assurance = view.device.assurance; // derived by the server from the proof, never the device's own claim
    s.gateMethod = String(interrupt?.method || view.device.gateMethod || "unknown").slice(0, 64);
    s.platform = String(view.device.platform || "unknown").slice(0, 40);
    s.authAt = Date.now();
  }
  const sessionView = (s, extra = {}) => ({ id: s.subject, device: s.deviceId, assurance: s.assurance, proof: s.proof, gateMethod: s.gateMethod, expiresAt: s.expiresAt, idleTimeoutMs: htp.idleMs, ...extra });
  const dropWhere = (pred) => { for (const x of [...htp.sessions.values()]) if (pred(x)) htp.drop(x); };

  /* ---------- handlers (run inside the encrypted channel) ---------- */

  const handlers = {
    // First device: create the account and enrol this device.
    async register(s, body) {
      const r = parseJson(body) || {};
      const reg = await internalJson("identity", "POST", "/internal/register", {
        json: { kemPk: r.kemPk, dsaPk: r.dsaPk, xPk: r.xPk, commit: r.commit, sig: r.sig, th: b64u(s.th), device: r.device, policy: devicePolicy },
      });
      if (reg.status >= 300) fail(reg);
      bindSession(s, reg.data, { method: r.device?.gateMethod, assurance: r.device?.assurance });
      if (reg.status === 201) await recordQuietly(s.subject, "identity.created", { platform: s.platform, method: s.gateMethod, assurance: s.assurance });
      await recordQuietly(s.subject, "device.added", { device: s.deviceId, platform: s.platform, via: "register", method: s.gateMethod, assurance: s.assurance, level: s.proof });
      await recordQuietly(s.subject, "session.opened", { device: s.deviceId, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(r.sig)) });
      // A recovery card made with the account: the registration itself was the live check.
      let cardSet = false;
      if (reg.status === 201 && r.card) {
        const stepUp = { at: Date.now(), proof: proofHash(unb64u(r.sig)), method: s.gateMethod, assurance: s.assurance, live: !!s.livePub };
        const c = await internalJson("recovery", "PUT", "/card", { claims: claimsFor(s, { stepUp }), json: r.card }).catch(() => ({ status: 503 }));
        cardSet = c.status === 200;
        if (cardSet) await recordQuietly(s.subject, "recovery.card_set", { proof: stepUp.proof, at: "setup" });
      }
      return { status: reg.status, json: sessionView(s, { created: reg.status === 201, cardSet }) };
    },

    // Another device joins an account it now holds the seed of (device link or recovery).
    async enrollDevice(s, body) {
      const r = parseJson(body) || {};
      if (!re(ID_RE).test(String(r.account))) throw new HttpError(400, "bad_identity", "Unknown identity format");
      const add = await internalJson("identity", "POST", "/internal/devices", { json: { account: r.account, th: b64u(s.th), via: r.via, device: r.device, policy: devicePolicy } });
      if (add.status >= 300) fail(add);
      bindSession(s, add.data, { method: r.device?.gateMethod, assurance: r.device?.assurance });
      await recordQuietly(s.subject, "device.added", { device: s.deviceId, platform: s.platform, via: String(r.via), method: s.gateMethod, assurance: s.assurance, level: s.proof });
      await recordQuietly(s.subject, "session.opened", { device: s.deviceId, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(String(r.device?.sigDevice || ""))) });
      if (r.recoveryId && re(REQ_RE).test(String(r.recoveryId))) {
        const done = await internalJson("recovery", "POST", `/requests/${r.recoveryId}/complete`, { json: { account: s.subject } });
        if (done.status === 200) await recordQuietly(s.subject, "recovery.completed", { method: done.data.method, ref: done.data.ref, device: s.deviceId, platform: s.platform });
      }
      return { status: 201, json: sessionView(s, { created: add.status === 201 }) };
    },

    async challenge(s, body) {
      const { id, device } = parseJson(body) || {};
      if (!re(ID_RE).test(String(id)) || !re(DEV_RE).test(String(device))) throw new HttpError(400, "bad_identity", "Unknown identity format");
      s.challenge = { id, device, nonce: random(32), exp: Date.now() + 120_000 };
      return { status: 200, json: { challenge: b64u(s.challenge.nonce), expiresAt: s.challenge.exp } };
    },

    async login(s, body) {
      const r = parseJson(body) || {};
      const c = s.challenge;
      s.challenge = null; // one attempt per challenge
      if (!c || c.id !== r.id || c.device !== r.device || Date.now() > c.exp) throw new HttpError(400, "challenge_invalid", "Request a new challenge");
      if (!loginLimit.take(r.id)) throw new HttpError(429, "rate_limited", "Too many sign-in attempts. Wait a few minutes.");
      const v = await internalJson("identity", "POST", "/internal/verify", {
        json: { account: r.id, device: r.device, sig: r.sig, live: r.live, policy: devicePolicy, message: b64u(loginMessage(s.th, `${r.id}/${r.device}`, c.nonce)) },
      });
      if (v.status === 401) {
        const live = v.data?.error === "bad_live_proof";
        await recordQuietly(r.id, "access.denied", { reason: live ? "no_live_biometric" : "bad_login_proof", device: r.device });
        throw new HttpError(401, live ? "bad_live_proof" : "bad_proof", live ? "Sign-in needs a live face or fingerprint check on this device." : "Sign-in proof was rejected.");
      }
      if (v.status === 403 && ["device_removed", "device_not_proven"].includes(v.data?.error)) {
        await recordQuietly(r.id, "access.denied", { reason: v.data.error, device: r.device });
      }
      if (v.status !== 200) fail(v);
      bindSession(s, v.data, r.interrupt);
      await recordQuietly(s.subject, "session.opened", { device: s.deviceId, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(r.sig)) });
      return { status: 200, json: sessionView(s) };
    },

    async logout(s) {
      if (s.subject) await recordQuietly(s.subject, "session.closed", { device: s.deviceId });
      s.closeAfterReply = true;
      return { status: 200, json: { closed: true } };
    },

    async removeDevice(s, body, stepUp, m) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Removing a device needs a fresh biometric check.");
      const id = m[1];
      const r = await internalJson("identity", "DELETE", `/devices/${id}`, { claims: claimsFor(s, { stepUp }) });
      if (r.status !== 200) fail(r);
      dropWhere((x) => x.subject === s.subject && x.deviceId === id); // its open sessions end now
      await recordQuietly(s.subject, "device.removed", { device: id, platform: r.data.device?.platform, proof: stepUp.proof });
      return { status: 200, json: r.data };
    },

    async closeIdentity(s, body, stepUp) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Closing your identity needs a fresh biometric check.");
      const claims = claimsFor(s, { stepUp });
      const wiped = await internalJson("vault", "DELETE", "/objects", { claims });
      if (wiped.status !== 200) return { status: wiped.status, json: wiped.data };
      await recordQuietly(s.subject, "vault.erased", { count: wiped.data.deleted, proof: stepUp.proof });
      await internalJson("recovery", "DELETE", "/card", { claims }).catch(() => {});
      await internalJson("recovery", "DELETE", "/contacts", { claims }).catch(() => {});
      const closed = await internalJson("identity", "DELETE", "/me", { claims });
      if (closed.status === 200) await recordQuietly(s.subject, "identity.closed", { proof: stepUp.proof });
      const subject = s.subject;
      s.closeAfterReply = true;
      dropWhere((x) => x !== s && x.subject === subject);
      return { status: closed.status, json: { closed: closed.status === 200, erasedItems: wiped.data.deleted } };
    },

    // A new device asks to recover. For a card the account is known now, so its devices are alerted now.
    async startRecovery(s, body) {
      const r = await internalJson("recovery", "POST", "/requests", { body });
      if (r.status >= 300) fail(r);
      if (r.data.account) {
        await recordQuietly(r.data.account, "recovery.requested", { method: r.data.method, ref: r.data.ref, platform: r.data.platform, releaseAt: r.data.releaseAt });
      }
      return { status: 201, json: r.data };
    },

    // A recovery contact releases their share. Recorded in both people's ledgers.
    async helpRecover(s, body, stepUp, m) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Releasing your piece needs a fresh biometric check.");
      const r = await internalJson("recovery", "POST", `/help/${m[1]}`, { claims: claimsFor(s, { stepUp }), body });
      if (r.status !== 200) fail(r);
      const d = r.data;
      if (d.first) await recordQuietly(d.owner, "recovery.requested", { method: "contacts", ref: d.ref, platform: d.platform });
      await recordQuietly(d.owner, "recovery.approved", { ref: d.ref, contact: s.subject, approvals: d.approvals, threshold: d.threshold, releaseAt: d.releaseAt });
      await recordQuietly(s.subject, "recovery.helped", { owner: d.owner, ref: d.ref, proof: stepUp.proof });
      return { status: 200, json: { approvals: d.approvals, threshold: d.threshold, releaseAt: d.releaseAt } };
    },
  };

  /* ---------- the encrypted call ---------- */

  async function dispatch(s, seq, meta, body) {
    const url = new URL(String(meta.p || "/"), "http://inner");
    const route = ROUTES.find((r) => r.m === meta.m && r.p.test(url.pathname));
    if (!route) throw new HttpError(404, "not_found", "No such endpoint");
    if (route.auth && !s.subject) throw new HttpError(401, "sign_in_required", "Sign in first");
    if (!s.subject && meta.m !== "GET" && !anonLimit.take(s.sidText)) throw new HttpError(429, "rate_limited", "Slow down");

    // Step-up: a fresh biometric signature over exactly this request, by this session's device key.
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
      // The device's secure chip must have signed this request slot during a live biometric check.
      if (s.livePub) {
        let live = null;
        try { live = meta.proof.live ? unb64u(String(meta.proof.live)) : null; } catch {}
        if (!verifyLiveSig(s.livePub, liveMessage(s.th, seq, meta.m, meta.p, at), live)) {
          await recordQuietly(s.subject, "access.denied", { path: url.pathname.replace(/[0-9a-f-]{36}/, ":id"), reason: "no_live_biometric" });
          throw new HttpError(401, "bad_live_proof", "This needs a live face or fingerprint check on this device.");
        }
      }
      const i = meta.proof.interrupt || {};
      stepUp = { at, proof: proofHash(sig), method: String(i.method || s.gateMethod).slice(0, 64), assurance: s.assurance, live: !!s.livePub };
    }

    if (route.h) return handlers[route.h](s, body, stepUp, url.pathname.match(route.p));

    const headers = {};
    for (const k of FORWARD_REQ_HEADERS) if (meta.h?.[k]) headers[k] = String(meta.h[k]);
    const path = url.pathname.replace(route.p, route.path) + url.search;
    const claims = s.subject ? claimsFor(s, stepUp ? { stepUp } : {}) : { sid: s.sidText.slice(0, 8) };
    const res = await internal(route.to, meta.m, path, { claims, body, headers });

    if (route.event) {
      const objectId = url.pathname.match(new RegExp(OBJ_RE))?.[0];
      if (res.status >= 200 && res.status < 300) {
        const out = safeJson(res.body);
        const detail = route.detail
          ? route.detail(out, stepUp)
          : { id: objectId || out?.id, size: route.event === "object.sealed" ? body.length : undefined, ...(stepUp ? { proof: stepUp.proof, method: stepUp.method, assurance: stepUp.assurance } : {}) };
        if (route.audited) await record(s.subject, route.event, detail); // fail closed: no record, no release
        else await recordQuietly(s.subject, route.event, detail);
      } else if (res.status === 403) {
        await recordQuietly(s.subject, "access.denied", { path: url.pathname.replace(/[0-9a-f-]{36}/, ":id"), reason: safeJson(res.body)?.error || "forbidden" });
      }
    }
    return res;
  }

  const safeJson = (b) => { try { return JSON.parse(Buffer.from(b).toString()); } catch { return null; } };

  async function call({ body }) {
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
    // Never cached: a stale key bundle would hide a server change. `policy` is a hint for the app's
    // UI; the gateway enforces it on every sign-in and step-up.
    ["GET", "/htp/v1/keys", () => json(200, { ...htp.publicKeys(), policy: { devicePolicy } }), { public: true }],
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
