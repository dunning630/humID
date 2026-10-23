// gateway — the only HumID service reachable from the internet (behind the
// TLS edge). It terminates HTP/1, binds sessions to an account and one of its
// devices with biometric-signed proofs, checks step-up proofs, and forwards
// whitelisted calls to internal services with a short-lived signed assertion.
//
// Invariant: no document ciphertext leaves the vault without a matching
// ledger record. If the ledger cannot record the access, the gateway refuses.

import { mkdirSync, readFileSync } from "node:fs";
import { createService, env, json, bytes, parseJson, signRequest, internalRequest, roleAgent, clientTls, sealerFromEnv, secretFile, HttpError, b64u, unb64u, logger, isMain } from "@humid/svc";
import { HtpServer, HtpServerError, createStatics, exportStatics, importStatics } from "@humid/htp/server";
import { MEDIA_TYPE, HEADER_LEN, DIR, parseHeader, concat, deviceId, identityId, loginMessage, loginPresenceMessage, stepUpMessage, liveMessage, actionBytes, verify, proofHash, STEP_UP_MAX_AGE_MS, STEP_UP_NONCE_MS, CLOCK_SKEW_MS, random, utf8 } from "@humid/htp";
import { verifyLiveSig } from "@humid/attest";
import { rateKey, isBox, TAG_RE } from "@humid/msg/relay-rules";

const ID_RE = "hid_[0-9a-f]{40}";
const DEV_RE = "dev_[0-9a-f]{24}";
const OBJ_RE = "[0-9a-f-]{36}";
const CODE_RE = "[0-9A-HJKMNP-TV-Z]{12}";
/** A recovery request's code: 16 characters, it lives up to a week (CRYPTO-08). Older 12-character ones still work. */
const RCODE_RE = "[0-9A-HJKMNP-TV-Z]{12}(?:[0-9A-HJKMNP-TV-Z]{4})?";
const REQ_RE = "[A-Za-z0-9_-]{22}";
const REF_RE = "[0-9a-f]{16}";
const KEY_RE = "[0-9a-f]{32}";
/**
 * Which devices may sign in (HUMID_DEVICE_POLICY):
 *   attested   only phones whose secure chip proves every check is a live biometric
 *              (Android key attestation / Apple App Attest). Default.
 *   biometric  also desktop gates that accept only a biometric, enforced by the OS
 *              (Touch ID, Windows fingerprint, Linux fingerprint), without hardware proof.
 *   demo       anything, including demo mode with no sensor. Local development only.
 */
const POLICIES = ["attested", "biometric", "demo"];
/**
 * Who may create an account (HUMID_REGISTRATION):
 *   pass  only with an access pass: paid for with an access code, signed blind,
 *         so the payment can't be linked to the account. Default.
 *   open  anyone (testing, private deployments).
 */
const REGISTRATION = ["pass", "open"];
const re = (s) => new RegExp(`^${s}$`);
/** How a device may join an existing account: an approved link, or a released recovery (never "register"). */
const ENROL_VIA = new Set(["link", "card", "contacts", "quorum"]);
/** The account id a registration's ML-DSA-87 key will have (base64url key → hid_…). */
const identityOf = (dsaPkB64) => { try { return identityId(unb64u(String(dsaPkB64 || ""))); } catch { return ""; } };

/**
 * Inner routes the app may call. Anything else is a 404, so internal routes
 * are unreachable from outside. auth = needs a signed-in session; anon = open
 * to a session that has not signed in (a new device that has no keys yet).
 */
const ROUTES = [
  // Anonymous payment (docs/ANONYMITY.md): swap an access code for a blind-signed pass.
  // The app does this in a session of its own that never signs in.
  { m: "GET", p: re("/pass/keys"), h: "passKeys", anon: true },
  { m: "POST", p: re("/pass/issue"), h: "passIssue", anon: true },

  { m: "POST", p: re("/auth/register"), h: "register" },
  { m: "POST", p: re("/auth/device"), h: "enrollDevice" },
  { m: "POST", p: re("/auth/challenge"), h: "challenge" },
  { m: "POST", p: re("/auth/login"), h: "login" },
  { m: "POST", p: re("/auth/logout"), h: "logout" },
  // a device whose biometric keys Android or iOS destroyed says so (LIVE-06); no sign-in possible
  { m: "POST", p: re("/auth/key-invalidated"), h: "keyInvalidated" },
  // duress: every unlock reports presence the same way; only the flag inside differs
  { m: "POST", p: re("/auth/presence"), h: "presence", auth: true },
  // a step-up approval for one action: the device signs it during the live check
  { m: "POST", p: re("/auth/step-up"), h: "stepUpNonce", auth: true },
  { m: "GET", p: re("/auth/duress"), h: "duressStatus", auth: true },
  { m: "POST", p: re("/auth/duress/clear"), h: "clearDuress", auth: true },

  { m: "GET", p: re("/identity/me"), to: "identity", path: "/me", auth: true },
  { m: "DELETE", p: re("/identity/me"), h: "closeIdentity", auth: true, guard: true },
  { m: "DELETE", p: re(`/identity/devices/(${DEV_RE})`), h: "removeDevice", auth: true, guard: true },

  { m: "GET", p: re("/vault/objects"), to: "vault", path: "/objects", auth: true },
  // Split keys: upload takes the document key off the request before the vault sees it;
  // download adds it back from the keyshare service, after the access is in the ledger.
  { m: "POST", p: re("/vault/objects"), h: "upload", auth: true },
  { m: "GET", p: re(`/vault/objects/(${OBJ_RE})`), h: "download", auth: true },
  { m: "PATCH", p: re(`/vault/objects/(${OBJ_RE})`), to: "vault", path: "/objects/$1", auth: true, event: "object.updated" },
  { m: "DELETE", p: re(`/vault/objects/(${OBJ_RE})`), h: "removeObject", auth: true },

  { m: "GET", p: re("/ledger/events"), to: "ledger", path: "/events", auth: true },
  // the public transparency log, as the holder's phone checks it
  { m: "GET", p: re("/ledger/tlog/checkpoint"), to: "ledger", path: "/tlog/checkpoint", auth: true },
  { m: "GET", p: re("/ledger/tlog/inclusion"), to: "ledger", path: "/tlog/inclusion", auth: true },
  { m: "GET", p: re("/ledger/tlog/consistency"), to: "ledger", path: "/tlog/consistency", auth: true },

  // add a device you still have
  { m: "POST", p: re("/recovery/links"), to: "recovery", path: "/links", anon: true },
  { m: "GET", p: re(`/recovery/links/(${CODE_RE})`), to: "recovery", path: "/links/$1", auth: true },
  { m: "POST", p: re(`/recovery/links/(${CODE_RE})/approve`), to: "recovery", path: "/links/$1/approve", auth: true, guard: true, event: "device.link_approved", audited: true, detail: (r, su) => ({ platform: r?.platform, proof: su?.proof }) },
  { m: "GET", p: re(`/recovery/links/(${CODE_RE})/result`), to: "recovery", path: "/links/$1/result", anon: true },
  // recovery card
  { m: "GET", p: re("/recovery/card"), to: "recovery", path: "/card", auth: true },
  { m: "PUT", p: re("/recovery/card"), to: "recovery", path: "/card", auth: true, guard: true, event: "recovery.card_set", detail: (r, su) => ({ scheme: r?.scheme, proof: su?.proof }) },
  { m: "DELETE", p: re("/recovery/card"), to: "recovery", path: "/card", auth: true, guard: true, event: "recovery.card_removed", detail: (r, su) => ({ proof: su?.proof }) },
  // recovery contacts
  { m: "POST", p: re("/recovery/offers"), to: "recovery", path: "/offers", auth: true },
  { m: "GET", p: re(`/recovery/offers/(${CODE_RE})`), to: "recovery", path: "/offers/$1", auth: true },
  { m: "GET", p: re("/recovery/contacts"), to: "recovery", path: "/contacts", auth: true },
  { m: "PUT", p: re("/recovery/contacts"), to: "recovery", path: "/contacts", auth: true, guard: true, event: "recovery.contacts_set", detail: (r, su) => ({ n: r?.n, threshold: r?.threshold, scheme: r?.scheme, proof: su?.proof }) },
  { m: "DELETE", p: re("/recovery/contacts"), to: "recovery", path: "/contacts", auth: true, guard: true, event: "recovery.contacts_removed", detail: (r, su) => ({ proof: su?.proof }) },
  { m: "GET", p: re("/recovery/protecting"), to: "recovery", path: "/protecting", auth: true },
  { m: "GET", p: re("/recovery/protecting/alerts"), to: "recovery", path: "/protecting/alerts", auth: true },
  // identity anchor (passport or ID chip) and recovery settings
  { m: "GET", p: re("/recovery/anchor"), to: "recovery", path: "/anchor", auth: true },
  { m: "POST", p: re("/recovery/anchor/challenge"), to: "recovery", path: "/anchor/challenge", auth: true },
  { m: "PUT", p: re("/recovery/anchor"), to: "recovery", path: "/anchor", auth: true, guard: true, event: "recovery.anchor_set", detail: (r, su) => ({ document: r?.document, country: r?.country, version: r?.version, proof: su?.proof }) },
  { m: "DELETE", p: re("/recovery/anchor"), to: "recovery", path: "/anchor", auth: true, guard: true, event: "recovery.anchor_removed", detail: (r, su) => ({ proof: su?.proof }) },
  // security keys (4.0, docs/SECURITY-KEY.md): adding or removing one is a guarded change
  { m: "GET", p: re("/recovery/keys"), to: "recovery", path: "/keys", auth: true },
  { m: "POST", p: re("/recovery/keys/challenge"), to: "recovery", path: "/keys/challenge", auth: true },
  { m: "POST", p: re("/recovery/keys"), to: "recovery", path: "/keys", auth: true, guard: true, event: "recovery.key_added", detail: (r, su) => ({ count: r?.count, proof: su?.proof }) },
  { m: "DELETE", p: re(`/recovery/keys/(${KEY_RE})`), to: "recovery", path: "/keys/$1", auth: true, guard: true, event: "recovery.key_removed", detail: (r, su) => ({ count: r?.count, proof: su?.proof }) },
  { m: "DELETE", p: re("/recovery/keys"), to: "recovery", path: "/keys", auth: true, guard: true, event: "recovery.key_removed", detail: (r, su) => ({ count: 0, removed: r?.removed, proof: su?.proof }) },
  // Recovery mode (docs/RECOVERY.md#two-recovery-modes): holder-only or hardened, signed by the account key.
  { m: "GET", p: re("/recovery/mode"), to: "recovery", path: "/mode", auth: true },
  { m: "POST", p: re("/recovery/mode"), h: "setRecoveryMode", auth: true, guard: true },
  { m: "GET", p: re("/recovery/settings"), to: "recovery", path: "/settings", auth: true },
  { m: "PUT", p: re("/recovery/settings"), to: "recovery", path: "/settings", auth: true, guard: true, event: "settings.changed", detail: (r, su) => ({ duressAlert: r?.duressAlert, proof: su?.proof }) },
  // verification stations
  { m: "GET", p: re("/recovery/station"), to: "recovery", path: "/station", auth: true },
  { m: "GET", p: re(`/recovery/station/requests/(${RCODE_RE})`), to: "recovery", path: "/station/requests/$1", auth: true },
  { m: "POST", p: re(`/recovery/station/requests/(${RCODE_RE})/challenge`), to: "recovery", path: "/station/requests/$1/challenge", auth: true },
  { m: "POST", p: re(`/recovery/station/requests/(${RCODE_RE})/verify`), h: "stationVerify", auth: true, guard: true },
  // recovering on a new device
  { m: "POST", p: re("/recovery/requests"), h: "startRecovery", anon: true },
  { m: "GET", p: re(`/recovery/requests/(${REQ_RE})`), to: "recovery", path: "/requests/$1", anon: true },
  { m: "POST", p: re(`/recovery/requests/(${REQ_RE})/card`), h: "addEvidence", kind: "card", anon: true },
  { m: "POST", p: re(`/recovery/requests/(${REQ_RE})/challenge`), to: "recovery", path: "/requests/$1/challenge", anon: true },
  { m: "POST", p: re(`/recovery/requests/(${REQ_RE})/anchor`), h: "addEvidence", kind: "anchor", anon: true },
  { m: "POST", p: re(`/recovery/requests/(${REQ_RE})/key/challenge`), to: "recovery", path: "/requests/$1/key/challenge", anon: true },
  { m: "POST", p: re(`/recovery/requests/(${REQ_RE})/key`), h: "addEvidence", kind: "key", anon: true },
  { m: "GET", p: re(`/recovery/help/(${RCODE_RE})`), to: "recovery", path: "/help/$1", auth: true },
  { m: "POST", p: re(`/recovery/help/(${RCODE_RE})`), h: "helpRecover", auth: true, guard: true },
  { m: "GET", p: re("/recovery/alerts"), to: "recovery", path: "/alerts", auth: true },
  { m: "POST", p: re(`/recovery/alerts/(${REF_RE})/cancel`), to: "recovery", path: "/alerts/$1/cancel", auth: true, event: "recovery.cancelled", detail: (r, su) => ({ ref: r?.ref, method: r?.method, platform: r?.platform, proof: su?.proof }) },

  // Server administration (docs/ADMIN.md), only where the host gives the gateway an admin
  // console to talk to (HumID Server for Windows). The console asks; an administrator's
  // phone approves one exact change with a live check; the console checks that proof itself.
  { m: "GET", p: re("/admin/summary"), h: "adminSummary", auth: true },
  { m: "GET", p: re(`/admin/requests/(${CODE_RE})`), h: "adminRequest", auth: true },
  { m: "POST", p: re(`/admin/requests/(${CODE_RE})/approve`), h: "adminApprove", auth: true, guard: true },

  // Check-in (docs/CHECKIN.md), when HUMID_CHECKIN=on: a timer the holder arms before a
  // high-stakes situation. Check in with a live check before each deadline, or the vault's
  // document keys are destroyed. Not guarded by lockdown: in a duress session these must
  // look ordinary (handled inside), and arming or checking in is never a risk to the holder.
  { m: "GET", p: re("/checkin"), h: "checkinStatus", auth: true },
  { m: "POST", p: re("/checkin/arm"), h: "checkinArm", auth: true },
  { m: "POST", p: re("/checkin/check"), h: "checkinCheck", auth: true },
  { m: "POST", p: re("/checkin/disarm"), h: "checkinDisarm", auth: true },

  // Person to person (HumID 4.0, docs/MESSAGING.md), when the server runs a relay.
  // Stamp keys and the network-wide daily totals: public.
  { m: "GET", p: re("/msg/keys"), h: "msgKeys", msg: true },
  { m: "GET", p: re("/msg/stats"), h: "msgStats", msg: true },
  // A live stamp: blind values, signed only inside a live step-up over exactly these values
  // (one message, or one action that is two: deleting a conversation for both is a delete and the end).
  // Not guarded by lockdown: a duress session must look like any other.
  { m: "POST", p: re("/msg/stamp"), h: "msgStamp", auth: true, msg: true },
  // The relay: ONLY from a session that never signs in, so nothing here links an account to a
  // mailbox. Its own per-network limits apply instead of the anonymous-session limit.
  { m: "POST", p: re("/msg/relay/put"), h: "relayPut", relay: true, msg: true },
  { m: "POST", p: re("/msg/relay/take"), h: "relayTake", relay: true, msg: true },
  { m: "POST", p: re("/msg/relay/retract"), h: "relayRetract", relay: true, msg: true },
];

/**
 * Largest inner body each route takes (SRV-32). The frame cap is chosen from the session before
 * the route is known (it's inside the encryption), so a signed-in session's frame may be as big
 * as a vault upload; this is checked as soon as the frame is open, before anything parses the
 * body. Every route not listed takes CALL_CAP_DEFAULT: JSON and control bodies are a few KiB.
 * Keyed by handler, or by upstream service and path.
 */
const CALL_CAP_DEFAULT = 64 * 1024;
const RECOVERY_ENVELOPE_CAP = 96 * 1024;  // one sealed envelope (recovery: 64 KiB), as bytes or base64 in JSON
const RECOVERY_CHIP_CAP = 256 * 1024;     // up to three ID-chip reads (recovery: 3 × 48 KiB), base64 in JSON
const CALL_CAPS = {
  "h:upload": "max",                       // POST /vault/objects: the vault-sized cap (GATEWAY_MAX_CALL_BYTES)
  "recovery:/links/$1/approve": RECOVERY_ENVELOPE_CAP,
  "h:helpRecover": RECOVERY_ENVELOPE_CAP,
  "recovery:/contacts": 6 * RECOVERY_ENVELOPE_CAP, // up to five contacts' envelopes
  "recovery:/anchor": RECOVERY_CHIP_CAP,
  "h:addEvidence": RECOVERY_CHIP_CAP,
  "h:stationVerify": RECOVERY_CHIP_CAP,
};
const capKey = (route) => (route.h ? `h:${route.h}` : `${route.to}:${route.path}`);

/** Check-in settings, as keyshare accepts them (CHECKIN_WINDOWS_MS, CHECKIN_GRACE_MS). Published in the policy hint. */
const CHECKIN_POLICY = { windowsH: [1, 2, 4, 8, 24], graceMin: [0, 15, 30, 60] };
const CHECKIN_WINDOWS = CHECKIN_POLICY.windowsH.map((h) => h * 3_600_000);
const CHECKIN_GRACES = CHECKIN_POLICY.graceMin.map((m) => m * 60_000);

/** What a locked-down account sees for a sensitive change: an ordinary, temporary failure. */
const busy = () => new HttpError(503, "busy", "HumID is busy right now. Try again in a few minutes.");

const FORWARD_REQ_HEADERS = ["content-type", "x-humid-index", "x-humid-object-id"];
const FORWARD_RES_HEADERS = ["content-type", "x-humid-size"];
const SHARE_HEADER = "x-humid-share"; // a split document's key: app ⇄ gateway ⇄ keyshare only, never the vault

/**
 * Token buckets per key. At `max` keys the least recently used one is forgotten, never the
 * whole table: clearing everything (as before, CRYPTO-04) let anyone with 100k addresses
 * reset every limit, failed sign-in counts included. A key that's forgotten is one nobody
 * has used for longer than any other, so it was close to full again anyway.
 */
export class Buckets {
  constructor(capacity, perMs, { max = 100_000 } = {}) { this.capacity = capacity; this.perMs = perMs; this.max = max; this.m = new Map(); }
  take(key, now = Date.now()) {
    const b = this.m.get(key) || { tokens: this.capacity, at: now };
    this.m.delete(key); // re-inserted below, so the Map's order is least recently used first
    b.tokens = Math.min(this.capacity, b.tokens + ((now - b.at) / this.perMs) * this.capacity);
    b.at = now;
    const ok = b.tokens >= 1;
    if (ok) b.tokens -= 1;
    this.m.set(key, b);
    while (this.m.size > this.max) this.m.delete(this.m.keys().next().value);
    return ok;
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
    access: env("ACCESS_URL", "http://access:8085"),
    keyshare: env("KEYSHARE_URL", "http://keyshare:8086"),
    // the messaging relay (services/relay); without one, messaging is off on this server
    ...(env("RELAY_URL", "") ? { relay: env("RELAY_URL", "") } : {}),
  },
  allowedOrigins = env("HUMID_ALLOWED_ORIGINS", "tauri://localhost,http://tauri.localhost,https://tauri.localhost").split(",").map((s) => s.trim()).filter(Boolean),
  trustProxy = env("TRUST_PROXY", "0") === "1",
  maxCallBytes = Number(env("GATEWAY_MAX_CALL_BYTES", String(64 * 1024 * 1024))),
  /** Largest frame accepted from a session that has not signed in (recovery requests carry up to three ID-chip reads). */
  maxAnonCallBytes = Number(env("GATEWAY_MAX_ANON_CALL_BYTES", String(512 * 1024))),
  /** New recovery requests per source network (IPv4 address or IPv6 /64) per hour (SRV-34). */
  recoveryStartsPerHour = Number(env("HUMID_RECOVERY_STARTS_PER_HOUR", "20")),
  devicePolicy = env("HUMID_DEVICE_POLICY", "attested"),
  registration = env("HUMID_REGISTRATION", "pass"),
  passBuyUrl = env("HUMID_PASS_BUY_URL", ""),
  /**
   * Optional bridge to a local admin console (HumID Server for Windows):
   *   summary()              -> { approvers: [account ids], … } | null
   *   request(code)          -> { kind: "enrol" | "action", title, lines, digest, check, expiresAt, approvers } | null
   *   approved(code, record) -> hands the console everything it needs to verify the proof itself
   * Without it the /admin routes answer "not on this server".
   */
  admin = null,
  /** Check-in (docs/CHECKIN.md): on | off. Off until push reminders exist, so nobody loses a vault to a missed notification by surprise. */
  checkin = env("HUMID_CHECKIN", "off"),
  /** How often the gateway tidies up after a Check-in erase: the vault's envelopes, and the ledger entry. */
  checkinSweepMs = 10_000,
  /** Server secrets sealed at rest (packages/svc/src/seal.js): HUMID_SEAL_KEY_FILE, or the host's sealer. */
  seal = sealerFromEnv(),
  /**
   * Mutual TLS to roles on other machines (server 3.0, docs/DEPLOY-VMS.md): this gateway's
   * humid-front certificate, its key and the server's CA (PEM). Used for every https:// upstream.
   * Default: HUMID_TLS_CA / HUMID_TLS_CERT / HUMID_TLS_KEY files, if set.
   */
  internalTls = tlsFromEnv(),
  /**
   * Development only: let a `demo` server stamp without a hardware liveness key, so the dev
   * server's messaging can be tried in a browser. Not read from the environment, and ignored
   * under any other policy, so no deployed server can turn it on.
   */
  demoStamps = false,
  /** /msg/stats shows only days with at least this many live checks, rounded to 100 (MSG-13). */
  msgStatsMin = Number(env("HUMID_MSG_STATS_MIN", "1000")),
  /** Signed-in sessions one account may hold at once (CRYPTO-04): its own oldest makes room. */
  sessionsPerAccount = Number(env("HUMID_SESSIONS_PER_ACCOUNT", "16")),
} = {}) {
  const log = logger("gateway");
  const DEMO_STAMPS = demoStamps === true && devicePolicy === "demo";
  const STATS_MIN = Number.isFinite(msgStatsMin) && msgStatsMin >= 100 ? msgStatsMin : 1000;
  if (!["on", "off"].includes(checkin)) throw new Error("HUMID_CHECKIN must be on or off");
  const CHECKIN = checkin === "on";
  if (!POLICIES.includes(devicePolicy)) throw new Error(`HUMID_DEVICE_POLICY must be one of ${POLICIES.join(", ")}`);
  if (!REGISTRATION.includes(registration)) throw new Error(`HUMID_REGISTRATION must be one of ${REGISTRATION.join(", ")}`);
  if (passBuyUrl && !/^https:\/\//.test(passBuyUrl)) throw new Error("HUMID_PASS_BUY_URL must be an https:// URL");

  // Long-term HTP keys. Losing this file changes the server's identity, and apps that pinned it will refuse to connect.
  mkdirSync(dataDir, { recursive: true });
  // Sealed under the server's seal key when it has one; a plain file from before 3.0 is sealed in place (same keys, same kid).
  const keyFile = `${dataDir}/htp-keys.json`;
  const statics = importStatics(JSON.parse(secretFile(keyFile, { seal, name: "gateway/htp-keys", make: () => JSON.stringify(exportStatics(createStatics())), log }).toString("utf8")));
  const htp = new HtpServer(statics, { perSubject: sessionsPerAccount });
  log.info("server identity", { kid: htp.kid, fingerprint: htp.fingerprint, devicePolicy, registration });
  setInterval(() => htp.sweep(), 60_000).unref();

  const helloLimit = new Buckets(30, 60_000);   // per client network: an IPv4 address or an IPv6 /64 (rateKey)
  const callLimit = new Buckets(600, 60_000);   // per session
  // Sign-in throttles count FAILED proofs only and never refuse a request before its proof has been
  // checked. See the note at `login` and docs/CHECKIN.md: a lockout must never keep the holder from
  // checking in, because a missed Check-in erases the vault.
  const loginFailId = new Buckets(10, 300_000);     // failed proofs per identity
  const loginFailIp = new Buckets(20, 300_000);     // failed proofs per source network (IPv4 address or IPv6 /64)
  const loginFailAll = new Buckets(200, 300_000);   // failed proofs, whole server (ledger-write budget)
  const loginNote = new Buckets(1, 300_000);        // one "sign-in throttled" ledger note per identity per window
  const keyRefusedNote = new Buckets(1, 3_600_000); // one "security key answer refused" note per account and reason per hour
  const anonLimit = new Buckets(20, 60_000);    // per session, for calls before sign-in
  const keysGoneNote = new Buckets(1, 24 * 3_600_000); // one "keys gone" report per device a day
  // SRV-34: new recovery requests per source network (IPv4 address or IPv6 /64). Anonymous and
  // kept by the recovery service, so a session's own limit isn't enough: one person recovering
  // starts one or two. The recovery service also caps how many unproven requests exist at all.
  const recoveryStartLimit = new Buckets(recoveryStartsPerHour, 3_600_000);

  // Bodies still being uploaded before the frame is authenticated: per source address and in total.
  const inflight = new Map();
  let inflightAll = 0;
  const admitBody = (perIp = 16, all = 1024) => (req) => {
    const ip = clientIp(req);
    const n = inflight.get(ip) || 0;
    if (n >= perIp || inflightAll >= all) throw new HttpError(429, "rate_limited", "Too many requests in flight");
    inflight.set(ip, n + 1); inflightAll++;
    let released = false;
    return () => { if (released) return; released = true; inflightAll--; const k = (inflight.get(ip) || 1) - 1; if (k > 0) inflight.set(ip, k); else inflight.delete(ip); };
  };

  const clientIp = (req) => (trustProxy && req.headers["x-forwarded-for"]?.split(",")[0].trim()) || req.socket.remoteAddress;

  /* ---------- internal calls ---------- */

  // Which role each service belongs to, for the certificate the gateway expects when it's on another machine.
  const ROLE_OF = { identity: "core", vault: "core", ledger: "core", recovery: "core", access: "core", keyshare: "keys", relay: "core" };
  const MESSAGING = !!upstreams.relay;
  const agents = {};
  for (const [svcName, base] of Object.entries(upstreams)) {
    if (!/^https:/.test(base)) continue;
    if (!internalTls) throw new Error(`${svcName} is at ${base}, but this gateway has no internal TLS certificate (HUMID_TLS_CA / HUMID_TLS_CERT / HUMID_TLS_KEY)`);
    const role = ROLE_OF[svcName];
    agents[role] ||= roleAgent(clientTls({ ...internalTls, expect: role }));
  }

  async function internal(service, method, path, { claims = {}, body, headers = {} } = {}) {
    // SEC-S-01: the assertion names this exact request (service, method, path and query as sent, body), once.
    const target = new URL(path, "http://internal");
    const sent = target.pathname + target.search;
    const payload = body && body.length ? body : undefined;
    const assertion = signRequest(internalSk, { aud: service, method, path: sent, body: payload, claims });
    let res;
    try {
      res = await internalRequest(`${upstreams[service]}${sent}`, { method, headers: { "x-humid-assertion": assertion, ...headers }, body: payload, agent: agents[ROLE_OF[service]] });
    } catch {
      throw new HttpError(503, `${service}_unavailable`, `${service} service is unavailable`);
    }
    const buf = res.body;
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

  const claimsFor = (s, extra = {}) => {
    const out = {
      sub: s.subject, device: s.deviceId, sid: s.sidText.slice(0, 8), dsaFp: s.dsaFp, kemFp: s.kemFp, assurance: s.assurance,
      ...(s.livePub ? { livePub: b64u(s.livePub) } : {}), ...extra,
    };
    // SRV-30: the holder's own step-up proof goes with it, so the service that releases or
    // destroys a secret checks it itself; the gateway's word (stepUp) is a hint, not the proof.
    // The proof travels in the assertion header, so a large signed body (an envelope) stays out;
    // no service that checks proofs needs one, and a caller that does sends it in the request body.
    if (extra.stepUp?.holder) {
      const { body, ...h } = extra.stepUp.holder;
      out.holder = body.length <= 8 * 1024 ? { ...h, body } : h;
    }
    return out;
  };

  /**
   * SRV-30: everything a back-end service needs to check this step-up itself: the request as the
   * holder's device signed it, its signatures, and identity's statement that this device key
   * belongs to the account (vault and keyshare hold no device keys).
   */
  async function holderProof(s, seq, meta, body, proof, nonce, exp) {
    const v = await internalJson("identity", "POST", "/internal/vouch", { json: { account: s.subject, device: s.deviceId } }).catch(() => ({ status: 503 }));
    if (v.status !== 200) throw new HttpError(503, "identity_unavailable", "identity service is unavailable");
    return { th: b64u(s.th), seq, at: Number(proof.at), m: meta.m, p: meta.p, body: b64u(body || new Uint8Array(0)), nonce, exp, device: s.deviceId, sig: String(proof.sig), ...(proof.live ? { live: String(proof.live) } : {}), vouch: v.data.vouch };
  }
  /** The holder proof with its body left out, for a caller that sends the body in the request instead (Check-in's settings). */
  const withoutBody = (stepUp) => ({ ...stepUp, holder: { ...stepUp.holder, body: "" } });

  /** Bind a session to an account and the device that proved itself. */
  function bindSession(s, view, interrupt) {
    s.subject = view.id;
    htp.signedIn(s); // at most sessionsPerAccount signed-in sessions per account: its own oldest makes room
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

  const denied = (s, path, res) => recordQuietly(s.subject, "access.denied", { path: path.replace(/[0-9a-f-]{36}/, ":id"), reason: safeJson(res.body)?.error || "forbidden" });

  /**
   * After every live sign-in. d = the duress flag the device key signed into it: this session
   * becomes a decoy, the account is locked down, recoveries slow down, and an armed Check-in
   * erases the vault. Every sign-in asks keyshare where Check-in stands, so a duress sign-in
   * takes the same time, and the work happens after the reply, so the answer looks the same.
   */
  async function presence(s, duress, signIn) {
    const ck = CHECKIN ? await internalJson("keyshare", "GET", "/internal/checkin", { claims: claimsFor(s) }).catch(() => null) : null;
    if (!duress || s.duress) return;
    s.duress = true;
    // The duress sign-in as the device signed it: keyshare erases an armed vault only on this.
    const vouch = CHECKIN ? await internalJson("identity", "POST", "/internal/vouch", { json: { account: s.subject, device: s.deviceId } }).catch(() => null) : null;
    s.duressProof = vouch?.status === 200 ? { ...signIn, device: s.deviceId, vouch: vouch.data.vouch } : null;
    const duressProof = s.duressProof;
    const st = ck?.status === 200 ? ck.data : null;
    s.decoyCheckin = st && (st.state === "armed" || st.state === "locked")
      ? decoyFrom({ ...st, deadline: st.state === "armed" ? st.deadline : Date.now() + st.windowMs })
      : null;
    const account = s.subject, device = s.deviceId, platform = s.platform;
    setImmediate(async () => {
      // Check-in first: a duress signal while it's armed erases the vault now (decoys stay).
      if (CHECKIN) await eraseNow(account, duressProof);
      await internalJson("identity", "POST", "/internal/duress", { json: { account } }).catch((e) => log.warn("duress: identity", { err: e.message }));
      await internalJson("recovery", "POST", "/internal/duress", { json: { account } }).catch((e) => log.warn("duress: recovery", { err: e.message }));
      await recordQuietly(account, "duress.signaled", { device, platform });
    });
  }

  const handlers = {
    // Seal: the envelope goes to the vault, its document key (if split) to keyshare. If the
    // key can't be stored, the upload is undone: a document must never exist without its key.
    async upload(s, body, stepUp, m, route, meta) {
      const h = meta.h || {};
      let share = null;
      if (h[SHARE_HEADER]) {
        try { share = unb64u(String(h[SHARE_HEADER])); } catch {}
        if (!share || share.length !== 32) throw new HttpError(400, "bad_share", "A document key is 32 bytes.");
      }
      const claims = claimsFor(s, stepUp ? { stepUp } : {});
      const headers = {};
      for (const k of FORWARD_REQ_HEADERS) if (h[k]) headers[k] = String(h[k]);
      const res = await internal("vault", "POST", "/objects", { claims, body, headers });
      if (res.status !== 201) {
        if (res.status === 403) await denied(s, "/vault/objects", res);
        return res;
      }
      const out = safeJson(res.body);
      if (share) {
        const put = await internalJson("keyshare", "PUT", `/internal/shares/${out.id}`, { claims, json: { share: b64u(share) } }).catch(() => ({ status: 503 }));
        share.fill(0);
        if (put.status !== 201) {
          await internalJson("vault", "DELETE", `/internal/objects/${out.id}`, { claims }).catch((e) => log.warn("upload rollback failed", { err: e.message }));
          if (put.status === 423) throw new HttpError(423, put.data.error, put.data.message); // a missed check-in
          throw new HttpError(503, "keyshare_unavailable", "Your document's key couldn't be stored, so it wasn't saved. Try again.");
        }
      }
      await recordQuietly(s.subject, "object.sealed", { id: out.id, size: body.length, split: !!share, ...(stepUp ? { proof: stepUp.proof, method: stepUp.method, assurance: stepUp.assurance } : {}) });
      return res;
    },

    // Open: the envelope from the vault and, for a split document, its key from keyshare,
    // both under this one live step-up. Recorded in the ledger before either is released.
    // SRV-30: the open is written to the ledger FIRST, and the vault releases the envelope only
    // against the ledger's signed receipt for it, so an open can't happen without its entry.
    // The document key leaves keyshare sealed to a one-time key in the body the holder signed
    // (CRYPTO-03), so this gateway forwards it without being able to read it.
    async download(s, body, stepUp, m) {
      const id = m[1], path = `/vault/objects/${id}`;
      if (!stepUp) {
        const e = new HttpError(403, "step_up_required", "This needs a fresh biometric check on your device.");
        await denied(s, path, { body: utf8(JSON.stringify({ error: e.code })) });
        throw e;
      }
      const own = await internalJson("vault", "GET", `/objects/${id}/meta`, { claims: claimsFor(s) });
      if (own.status !== 200) fail(own);
      // The document key is asked for only when the signed body names a one-time key to seal it
      // to (downloadWithShare); a plain download (exporting the sealed copy) gets the envelope alone.
      const wantShare = !!safeJson(body)?.to;
      // Would keyshare release this document's key now (and is it split)? Releases nothing.
      const keyshareRefused = async (ks) => {
        // 423: a missed check-in locks the vault; 410: Check-in erased this document's key
        if ([403, 410, 423].includes(ks.status)) await denied(s, path, { body: utf8(JSON.stringify(ks.data || {})) });
        throw new HttpError([403, 410, 423, 426, 429].includes(ks.status) ? ks.status : 503, ks.data?.error || "keyshare_unavailable", ks.data?.message || "Your document's key is unavailable right now. Try again.");
      };
      let split = false;
      if (wantShare) {
        const pre = await internalJson("keyshare", "GET", `/internal/shares/${id}/state`, { claims: claimsFor(s) }).catch(() => ({ status: 503 }));
        if (pre.status !== 200) await keyshareRefused(pre);
        split = !!pre.data.split;
      }
      const opened = await record(s.subject, "object.opened", { id, split, proof: stepUp.proof, method: stepUp.method, assurance: stepUp.assurance });
      if (!opened?.receipt) throw new HttpError(503, "audit_unavailable", "Access log is unavailable, so access is refused.");
      const claims = claimsFor(s, { stepUp, receipt: opened.receipt });
      const res = await internal("vault", "GET", `/objects/${id}`, { claims });
      if (res.status !== 200) {
        if (res.status === 403) await denied(s, path, res);
        return res;
      }
      if (split) {
        const ks = await internalJson("keyshare", "GET", `/shares/${id}`, { claims }).catch(() => ({ status: 503 }));
        if (ks.status !== 200) await keyshareRefused(ks);
        res.headers[SHARE_HEADER] = ks.data.sealed;
      }
      return res;
    },

    // Delete: the envelope, then its key, under the same step-up.
    async removeObject(s, body, stepUp, m) {
      const id = m[1], path = `/vault/objects/${id}`;
      const claims = claimsFor(s, stepUp ? { stepUp } : {});
      const res = await internal("vault", "DELETE", `/objects/${id}`, { claims });
      if (res.status !== 200) {
        if (res.status === 403) await denied(s, path, res);
        return res;
      }
      await record(s.subject, "object.deleted", { id, ...(stepUp ? { proof: stepUp.proof, method: stepUp.method, assurance: stepUp.assurance } : {}) });
      const ks = await internalJson("keyshare", "DELETE", `/shares/${id}`, { claims }).catch(() => ({ status: 503 }));
      if (ks.status !== 200 && ks.status !== 404) log.warn("keyshare delete failed; the key is useless without its envelope", { status: ks.status });
      return res;
    },

    // The access service's published pass keys (at most two; the app checks).
    async passKeys() {
      const r = await internalJson("access", "GET", "/internal/keys");
      if (r.status !== 200) fail(r);
      return { status: 200, json: r.data };
    },

    // Access code → blind signature. Nothing about this session is kept, and it never signs in.
    async passIssue(s, body) {
      if (s.subject) throw new HttpError(400, "signed_in", "Get access passes from a session that isn't signed in.");
      const r = parseJson(body) || {};
      const out = await internalJson("access", "POST", "/internal/issue", { json: { code: r.code, kid: r.kid, blinded: r.blinded } });
      if (out.status !== 200) fail(out);
      s.closeAfterReply = true; // one code per session: nothing to carry over to a registration
      return { status: 200, json: out.data };
    },

    // First device: create the account and enrol this device.
    // With HUMID_REGISTRATION=pass, an access pass is spent first. The access service gets
    // only the pass; identity gets only the keys. Neither learns the other's half.
    async register(s, body) {
      const r = parseJson(body) || {};
      let spent = null;
      if (registration === "pass") {
        if (!r.pass || typeof r.pass !== "object") throw new HttpError(402, "pass_required", "Creating a HumID needs an access pass.");
        const sp = await internalJson("access", "POST", "/internal/spend", { json: { pass: r.pass } }).catch(() => ({ status: 503, data: { error: "access_unavailable", message: "Payments are unavailable right now. Your pass wasn't used." } }));
        if (sp.status !== 200) fail(sp);
        spent = sp.data.spent;
      }
      const refund = () => spent && internalJson("access", "POST", "/internal/refund", { json: { spent } }).catch((e) => log.warn("pass refund failed", { err: e.message }));
      // The recovery mode chosen at setup, signed by the account key. The recovery service learns
      // it first: if it can't, nothing is created, so a holder-only account is never one it would
      // store recovery material for.
      const mode = r.recoveryMode && typeof r.recoveryMode === "object" ? { mode: r.recoveryMode.mode, version: r.recoveryMode.version, epoch: r.recoveryMode.epoch, prev: r.recoveryMode.prev, sig: r.recoveryMode.sig } : null;
      if (mode) {
        const m = await internalJson("recovery", "POST", "/internal/recovery-mode", { json: { account: identityOf(r.dsaPk), dsaPk: r.dsaPk, ...mode } }).catch(() => ({ status: 503, data: { error: "recovery_unavailable", message: "recovery service is unavailable" } }));
        if (m.status !== 200) { await refund(); fail(m); }
      }
      let reg;
      try {
        reg = await internalJson("identity", "POST", "/internal/register", {
          json: { kemPk: r.kemPk, dsaPk: r.dsaPk, xPk: r.xPk, commit: r.commit, sig: r.sig, th: b64u(s.th), sessionAgeMs: Date.now() - s.createdAt, device: r.device, policy: devicePolicy, ...(mode ? { recoveryMode: mode } : {}) },
        });
      } catch (e) { await refund(); throw e; }
      if (reg.status !== 201) await refund(); // failed, or these keys already had an account: the pass stays unspent
      if (reg.status >= 300) fail(reg);
      bindSession(s, reg.data, { method: r.device?.gateMethod, assurance: r.device?.assurance });
      if (reg.status === 201) await recordQuietly(s.subject, "identity.created", { platform: s.platform, method: s.gateMethod, assurance: s.assurance });
      await recordQuietly(s.subject, "device.added", { device: s.deviceId, platform: s.platform, via: "register", method: s.gateMethod, assurance: s.assurance, level: s.proof, soleBiometric: r.soleBiometric === true });
      await recordQuietly(s.subject, "session.opened", { device: s.deviceId, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(r.sig)) });
      if (reg.status === 201 && mode) await recordQuietly(s.subject, "recovery.mode_set", { mode: mode.mode, version: mode.version, epoch: mode.epoch, at: "setup", proof: proofHash(unb64u(r.sig)) });
      // A recovery card made with the account: the registration itself was the live check.
      let cardSet = false;
      if (reg.status === 201 && r.card) {
        const stepUp = { at: Date.now(), proof: proofHash(unb64u(r.sig)), method: s.gateMethod, assurance: s.assurance, live: !!s.livePub };
        const c = await internalJson("recovery", "PUT", "/card", { claims: claimsFor(s, { stepUp }), json: r.card }).catch(() => ({ status: 503 }));
        cardSet = c.status === 200;
        if (cardSet) await recordQuietly(s.subject, "recovery.card_set", { proof: stepUp.proof, at: "setup", scheme: c.data?.scheme });
      }
      return { status: reg.status, json: sessionView(s, { created: reg.status === 201, cardSet }) };
    },

    // Another device joins an account (device link or recovery). Holding the account seed is
    // not enough (PC-02): a seed copied once off a phone would otherwise let anyone add a phone
    // of their own, silently, and open everything. A link must have been approved, with a live
    // check, by one of the account's devices, for exactly this device key; a recovery must be
    // released: its proofs in, its wait over, not cancelled by any of the account's devices.
    async enrollDevice(s, body) {
      const r = parseJson(body) || {};
      if (!re(ID_RE).test(String(r.account))) throw new HttpError(400, "bad_identity", "Unknown identity format");
      const via = String(r.via);
      if (!ENROL_VIA.has(via)) throw new HttpError(400, "bad_via", "Unknown enrolment route");
      let dsaPk;
      try { dsaPk = unb64u(String(r.device?.dsaPk || "")); } catch { dsaPk = null; }
      if (!dsaPk?.length) throw new HttpError(400, "bad_key", "Missing device key");
      // A device that already joined this account (its reply was lost, say) finishes joining again.
      const known = await internalJson("identity", "GET", `/internal/devices/${deviceId(dsaPk)}`).catch(() => ({ status: 503 }));
      if (known.status !== 200 && known.status !== 404) throw new HttpError(503, "identity_unavailable", "identity service is unavailable");
      const rejoin = known.status === 200 && known.data.account === r.account && !known.data.revoked;
      // Noted in the account's ledger (once per window, like refused sign-ins), then refused.
      const refuse = async (e) => {
        if (loginNote.take(`enrol:${r.account}`)) await recordQuietly(r.account, "access.denied", { reason: "enrol_without_evidence", via, device: deviceId(dsaPk) });
        throw e;
      };
      let linkCode = null;
      if (!rejoin && via === "link") {
        linkCode = String(r.linkCode || "");
        if (!re(CODE_RE).test(linkCode)) await refuse(new HttpError(403, "not_approved", "Approve this device from a device you already use."));
        const c = await internalJson("recovery", "POST", `/internal/links/${linkCode}/consume`, { json: { account: r.account, devicePk: b64u(dsaPk) } }).catch(() => ({ status: 503 }));
        if (c.status === 403) await refuse(new HttpError(403, "not_approved", c.data?.message || "Approve this device from a device you already use."));
        if (c.status !== 200) throw new HttpError(503, "recovery_unavailable", "recovery service is unavailable");
      } else if (!rejoin) {
        if (!re(REQ_RE).test(String(r.recoveryId || ""))) await refuse(new HttpError(403, "not_released", "This device can join only through a released recovery."));
        await syncMode(r.account); // the release check below then sees the account's newest mode
        const c = await internalJson("recovery", "POST", `/internal/requests/${r.recoveryId}/check`, { json: { account: r.account, method: via } }).catch(() => ({ status: 503 }));
        if (c.status === 403) await refuse(new HttpError(403, "not_released", c.data?.message || "That recovery isn't released yet."));
        if (c.status !== 200) throw new HttpError(503, "recovery_unavailable", "recovery service is unavailable");
      }
      const giveBack = () => linkCode && internalJson("recovery", "POST", `/internal/links/${linkCode}/restore`, { json: { account: r.account } }).catch(() => {});
      let add;
      try { add = await internalJson("identity", "POST", "/internal/devices", { json: { account: r.account, th: b64u(s.th), sessionAgeMs: Date.now() - s.createdAt, via, device: r.device, policy: devicePolicy } }); }
      catch (e) { await giveBack(); throw e; }
      if (add.status >= 300) { await giveBack(); fail(add); }
      bindSession(s, add.data, { method: r.device?.gateMethod, assurance: r.device?.assurance });
      // Continuity: every device carries the evidence that let it in.
      let evidence = { via };
      if (!rejoin && via !== "link") {
        const done = await internalJson("recovery", "POST", `/requests/${r.recoveryId}/complete`, { json: { account: s.subject } }).catch(() => ({ status: 503 }));
        if (done.status !== 200) {
          // Cancelled or spent between the check and now: this device doesn't stay.
          await internalJson("identity", "POST", `/internal/devices/${s.deviceId}/revoke`, { json: { account: s.subject } }).catch((e) => log.warn("enrol rollback failed", { err: e.message }));
          s.subject = null; s.deviceId = null; s.closeAfterReply = true;
          throw new HttpError(409, "not_released", "That recovery was cancelled or already used. Nothing was added.");
        }
        const d = done.data;
        evidence = { via, kinds: d.kinds, evidence: d.evidence, anchorMode: d.anchorMode, station: d.station, waitedMs: d.waitedMs, ref: d.ref };
        await recordQuietly(s.subject, "recovery.completed", { method: d.method, ref: d.ref, device: s.deviceId, platform: s.platform, kinds: d.kinds, evidence: d.evidence, anchorMode: d.anchorMode, station: d.station, waitedMs: d.waitedMs });
      } else if (linkCode) evidence = { via, approvedLink: true };
      await recordQuietly(s.subject, "device.added", { device: s.deviceId, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, soleBiometric: r.soleBiometric === true, ...evidence });
      await recordQuietly(s.subject, "session.opened", { device: s.deviceId, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(String(r.device?.sigDevice || ""))) });
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
      // Throttling, and why it is shaped this way (SRV-02). The account id is public to anyone who
      // has ever been offered a recovery link or contact slot, so nobody may spend the holder's
      // allowance by guessing: a request is never refused before its proof is checked, and only
      // FAILED proofs are counted. Past the budget a failure is answered 429 and kept out of the
      // ledger (the ledger write is the only cost worth protecting), but a valid proof of the real
      // holder always signs in. A lockout here can never cause a Check-in wipe: wipes come from a
      // missed deadline in keyshare, or a duress sign-in, never from a refused sign-in.
      // Presence (PC-01): the duress flag is part of the signed sign-in, never a request of its
      // own. The liveness key signs the plain challenge; the device key, released by the same
      // live check, signs the challenge with the flag. Apps that send no flag sign the plain one.
      const who = `${r.id}/${r.device}`;
      const reported = r.d === 0 || r.d === 1;
      const liveMsg = loginMessage(s.th, who, c.nonce);
      const v = await internalJson("identity", "POST", "/internal/verify", {
        json: { account: r.id, device: r.device, sig: r.sig, live: r.live, policy: devicePolicy,
          message: b64u(reported ? loginPresenceMessage(s.th, who, c.nonce, r.d) : liveMsg), liveMessage: b64u(liveMsg) },
      });
      const failed = v.status >= 400 && v.status < 500;
      // SRV-24: identity gives an unknown account, an unknown device and a wrong key one answer
      // after the same work; `known` (gateway only) says whether there is a ledger to note it in.
      // The note is written after the reply, so it can't make a real account's refusal slower.
      const known = v.status !== 401 || v.data?.error !== "bad_signature" || v.data?.known === true;
      const noteLater = (detail) => { if (known) setImmediate(() => recordQuietly(r.id, "access.denied", { ...detail, device: r.device })); };
      const throttled = failed && ![loginFailId.take(r.id), loginFailIp.take(rateKey(s.clientIp || "")), loginFailAll.take("*")].every(Boolean);
      if (throttled) {
        if (loginNote.take(r.id)) noteLater({ reason: "sign_in_throttled" });
        throw new HttpError(429, "rate_limited", "Too many failed sign-in attempts. Wait a few minutes.");
      }
      if (v.status === 401) {
        const live = v.data?.error === "bad_live_proof";
        noteLater({ reason: live ? "no_live_biometric" : "bad_login_proof" });
        throw new HttpError(401, live ? "bad_live_proof" : "bad_proof", live ? "Sign-in needs a live face or fingerprint check on this device." : "Sign-in proof was rejected.");
      }
      if (v.status === 403 && ["device_removed", "device_not_proven"].includes(v.data?.error)) {
        await recordQuietly(r.id, "access.denied", { reason: v.data.error, device: r.device });
      }
      if (v.status !== 200) fail(v);
      bindSession(s, v.data, r.interrupt);
      await recordQuietly(s.subject, "session.opened", { device: s.deviceId, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(r.sig)) });
      await presence(s, reported && r.d === 1, { th: b64u(s.th), nonce: b64u(c.nonce), sig: String(r.sig), ...(r.live ? { live: String(r.live) } : {}) });
      return { status: 200, json: sessionView(s) };
    },

    /**
     * LIVE-06. The phone's keys are gone, so it holds nothing it can sign with: the report is
     * unauthenticated, and so it does as little as possible. The device is marked as needing
     * setup again (its next sign-in clears that) and its owner's Activity says so, at most
     * once a day per device. The answer is the same whether or not the account or device
     * exists, so it tells a stranger nothing.
     */
    async keyInvalidated(s, body) {
      const { id, device } = parseJson(body) || {};
      if (!re(ID_RE).test(String(id)) || !re(DEV_RE).test(String(device))) throw new HttpError(400, "bad_identity", "Unknown identity format");
      const mine = !s.subject || s.subject === id; // a signed-in session speaks only for its own account
      if (mine && keysGoneNote.take(device)) {
        const r = await internalJson("identity", "POST", `/internal/devices/${device}/keys-gone`, { json: { account: id } }).catch(() => null);
        if (r?.status === 200 && r.data?.marked) await recordQuietly(id, "device.keys_invalidated", { device, platform: r.data.platform });
      }
      return { status: 202, json: { ok: true } };
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
      await internalJson("keyshare", "DELETE", "/shares", { claims }).catch(() => {});
      await internalJson("recovery", "DELETE", "/card", { claims }).catch(() => {});
      await internalJson("recovery", "DELETE", "/contacts", { claims }).catch(() => {});
      await internalJson("recovery", "DELETE", "/anchor", { claims }).catch(() => {});
      await internalJson("recovery", "DELETE", "/keys", { claims }).catch(() => {});
      const closed = await internalJson("identity", "DELETE", "/me", { claims });
      if (closed.status === 200) await recordQuietly(s.subject, "identity.closed", { proof: stepUp.proof });
      const subject = s.subject;
      s.closeAfterReply = true;
      dropWhere((x) => x !== s && x.subject === subject);
      return { status: closed.status, json: { closed: closed.status === 200, erasedItems: wiped.data.deleted } };
    },

    /**
     * Change this account's recovery mode, with a fresh live check. The statement is signed by
     * the account key (only a device holding the seed can make one), and every service checks
     * it again. To holder-only, the recovery service goes first: it refuses while any card,
     * witnesses, ID anchor or security key is left (the app deletes each one first, each under
     * its own step-up). To hardened, identity goes first. Either way a half-done switch leaves
     * the stricter answer in force, and the ledger entry is written before the second service
     * is told: if the ledger can't record it, the switch stops there.
     */
    async setRecoveryMode(s, body, stepUp) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Changing how you recover needs a fresh biometric check.");
      const r = parseJson(body) || {};
      const statement = { mode: r.mode, version: r.version, epoch: r.epoch, prev: r.prev, sig: r.sig };
      await syncMode(s.subject); // both services on the newest statement first, so the new one chains to it
      const cur = await internalJson("identity", "GET", `/internal/recovery-mode/${s.subject}`).catch(() => ({ status: 503 }));
      if (cur.status !== 200) throw new HttpError(503, "identity_unavailable", "identity service is unavailable");
      const toRecovery = () => internalJson("recovery", "POST", "/internal/recovery-mode", { json: { account: s.subject, dsaPk: cur.data.dsaPk, ...statement } });
      const toIdentity = () => internalJson("identity", "POST", "/internal/recovery-mode", { json: { account: s.subject, ...statement } });
      const steps = r.mode === "holder-only" ? [toRecovery, toIdentity] : [toIdentity, toRecovery];
      // Checked once before anything is written, so a bad statement leaves no ledger entry.
      const probe = await steps[0]();
      if (probe.status !== 200) fail(probe);
      const from = cur.data.recoveryMode || { mode: "hardened", epoch: 1 };
      await record(s.subject, "recovery.mode_set", { mode: r.mode, version: r.version, epoch: r.epoch, from: from.mode, ...(r.epoch !== from.epoch ? { newPieces: true } : {}), proof: stepUp.proof });
      const done = await steps[1]();
      if (done.status !== 200) fail(done);
      return { status: 200, json: { mode: r.mode, version: r.version, epoch: r.epoch } };
    },

    // A new device asks to recover. For a card the account is known now, so its devices are alerted now.
    async startRecovery(s, body) {
      if (!recoveryStartLimit.take(rateKey(s.clientIp || ""))) throw new HttpError(429, "rate_limited", "Too many recoveries started from this network. Wait an hour and try again.");
      let r = await internalJson("recovery", "POST", "/requests", { body });
      if (r.status >= 300) fail(r);
      // The recovery service's mode for that account may be stale (a deleted or rolled-back row):
      // bring it up to identity's. Switching it to holder-only cancels this request at once.
      if (r.data.account && await syncMode(r.data.account)) {
        const again = await internalJson("recovery", "GET", `/internal/recovery-mode/${r.data.account}`).catch(() => null);
        if (again?.data?.mode !== "hardened") throw new HttpError(409, "holder_only", "This HumID opens only on its own devices. It has no recovery to set up or use.");
      }
      if (r.data.account) {
        await recordQuietly(r.data.account, "recovery.requested", { method: r.data.method, ref: r.data.ref, platform: r.data.platform, releaseAt: r.data.releaseAt, kinds: r.data.kinds });
        if (r.data.method === "quorum") await recordQuietly(r.data.account, "recovery.evidence", { ref: r.data.ref, kind: "card", kinds: r.data.kinds, releaseAt: r.data.releaseAt });
      }
      const { first: _f, ...out } = r.data;
      return { status: 201, json: out };
    },

    // Two-proof recovery: the new device adds its seal card, its live ID chip or its security key.
    async addEvidence(s, body, stepUp, m, route) {
      const r = await internalJson("recovery", "POST", `/requests/${m[1]}/${route.kind}`, { body });
      if (r.status === 200 && r.data?.account && await syncMode(r.data.account)) {
        const again = await internalJson("recovery", "GET", `/internal/recovery-mode/${r.data.account}`).catch(() => null);
        if (again?.data?.mode !== "hardened") throw new HttpError(409, "holder_only", "This HumID opens only on its own devices. It has no recovery to set up or use.");
      }
      if (r.status !== 200) {
        // A stored security key's signature checked and failed, or its counter went backwards: its
        // owner sees it in Activity, at most once an hour, so a stranger can't flood the record.
        if (route.kind === "key" && r.data?.account && ["key_cloned", "bad_key_proof"].includes(r.data.error) && keyRefusedNote.take(`${r.data.account}:${r.data.error}`)) {
          await recordQuietly(r.data.account, "recovery.key_refused", { reason: r.data.error, ref: r.data.ref });
        }
        fail(r); // fail() passes on only the code and the message
      }
      const d = r.data;
      if (d.first) await recordQuietly(d.account, "recovery.requested", { method: "quorum", ref: d.ref, platform: d.platform, kinds: d.kinds });
      await recordQuietly(d.account, "recovery.evidence", { ref: d.ref, kind: route.kind, anchorMode: d.anchorMode, kinds: d.kinds, releaseAt: d.releaseAt, evidence: d.evidence });
      const { first: _f, ...out } = d;
      return { status: 200, json: out };
    },

    // A verification station vouches, in person, for the ID chip of whoever is recovering.
    async stationVerify(s, body, stepUp, m) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Verifying needs the operator's fresh biometric check.");
      const r = await internalJson("recovery", "POST", `/station/requests/${m[1]}/verify`, { claims: claimsFor(s, { stepUp }), body });
      if (r.status !== 200) fail(r);
      const d = r.data;
      if (d.first) await recordQuietly(d.account, "recovery.requested", { method: "quorum", ref: d.ref, platform: d.platform, kinds: d.kinds });
      await recordQuietly(d.account, "recovery.station_verified", { ref: d.ref, station: s.subject, country: d.country, kinds: d.kinds, releaseAt: d.releaseAt, chipProof: !!d.chipProof });
      await recordQuietly(s.subject, "station.verified", { ref: d.ref, country: d.country, proof: stepUp.proof, chipProof: !!d.chipProof });
      return { status: 200, json: { verified: true, kinds: d.kinds, releaseAt: d.releaseAt, platform: d.platform, country: d.country, chipProof: !!d.chipProof } };
    },

    /**
     * Issue an approval for one request: method and path (which carry the target ids), for
     * this device, with a single-use nonce that expires in 60 s. The device's secure chip
     * signs exactly this during the live check; the request is refused if anything differs.
     */
    async stepUpNonce(s, body) {
      const r = parseJson(body) || {};
      const m = String(r.m || "").toUpperCase(), p = String(r.p || "");
      if (!["GET", "POST", "PUT", "DELETE"].includes(m) || !p.startsWith("/") || p.length > 512) throw new HttpError(400, "bad_action", "Unknown action");
      const route = ROUTES.find((x) => x.m === m && x.p.test(new URL(p, "http://inner").pathname));
      if (!route) throw new HttpError(404, "not_found", "No such endpoint");
      s.stepUps ||= new Map();
      const now = Date.now();
      for (const [k, v] of s.stepUps) if (v.exp < now) s.stepUps.delete(k);
      while (s.stepUps.size >= 8) s.stepUps.delete(s.stepUps.keys().next().value); // a few outstanding at most
      const nonce = random(16);
      const exp = now + STEP_UP_NONCE_MS;
      s.stepUps.set(b64u(nonce), { m, p, exp });
      return json(200, { nonce: b64u(nonce), exp, device: s.deviceId });
    },

    /* ---- person to person (4.0): stamps and the relay ---- */

    // The stamp keys, and the pass key ids beside them so the app can refuse a server that
    // stamps with its pass key (a blind signer signs whatever it's handed).
    // ?since=ms: only retired stamp keys whose epoch ended after it (a phone that has the rest).
    async msgKeys(s, body, stepUp, m, route, meta) {
      const sp = new URL(String(meta?.p || "/"), "http://inner").searchParams;
      const since = Number(sp.get("since") || 0);
      // all=1: every retired key (a page of them, from `since`), for stamped media and evidence (MSG-10)
      const q = [Number.isSafeInteger(since) && since > 0 ? `since=${since}` : "", sp.get("all") === "1" ? "all=1" : ""].filter(Boolean).join("&");
      const qs = q ? `?${q}` : "";
      const [st, pk] = await Promise.all([internalJson("access", "GET", `/internal/stamp/keys${qs}`), internalJson("access", "GET", "/internal/keys")]);
      if (st.status !== 200) fail(st);
      if (pk.status !== 200) fail(pk);
      return { status: 200, json: { stamp: st.data, passKeyIds: (pk.data.keys || []).map((k) => k.id) } };
    },

    // Public, so on a small server exact daily counts would show one person's activity (and
    // checks − stamps would count "delete for both"). Only days with at least STATS_MIN live
    // checks are shown, both numbers rounded down to a hundred, and "checks" only as the rounded
    // total (security review MSG-13).
    async msgStats() {
      const r = await internalJson("access", "GET", "/internal/stamp/stats");
      if (r.status !== 200) fail(r);
      const round = (n) => Math.floor(n / 100) * 100;
      const days = (r.data?.days || []).filter((d) => d.checks >= STATS_MIN).map((d) => ({ day: d.day, stamps: round(d.stamps), checks: round(d.checks) }));
      return { status: 200, json: { days, min: STATS_MIN, rounded: 100 } };
    },

    // One live check → the stamps it approved. The step-up's signature covers this request's
    // body, so the device's secure chip approved exactly these blinded values. The issuer is
    // told nothing about the account; it signs blind and counts.
    // A stamp says "a live face or fingerprint check on a proven phone", so it needs exactly that,
    // whatever the device policy lets sign in: a desktop under `biometric` (or anything under
    // `demo`) has no hardware liveness key, and a script could stamp in a loop (MSG-03).
    async msgStamp(s, body, stepUp) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "A live stamp needs a fresh live check.");
      if (!(stepUp.live === true && stepUp.assurance === "hardware") && !DEMO_STAMPS) {
        throw new HttpError(403, "stamp_needs_proven_phone", "Sending needs a phone whose secure chip proves a live face or fingerprint check. This device can't.");
      }
      const r = parseJson(body) || {};
      if (!Array.isArray(r.blinded) || r.blinded.length < 1 || r.blinded.length > 2) throw new HttpError(400, "bad_request", "One check approves 1 or 2 stamps");
      const out = await internalJson("access", "POST", "/internal/stamp/sign", { json: { kid: r.kid, blinded: r.blinded } });
      if (out.status !== 200) fail(out);
      return { status: 200, json: out.data };
    },

    async relayPut(s, body, stepUp, m, route, meta) {
      relaySession(s);
      const h = meta.h || {};
      const box = String(h["x-humid-box"] || ""), tag = h["x-humid-tag"] ? String(h["x-humid-tag"]) : "";
      if (!isBox(box)) throw new HttpError(400, "bad_box", "Bad mailbox id");
      if (tag && !TAG_RE.test(tag)) throw new HttpError(400, "bad_tag", "Bad unsend tag");
      const res = await internal("relay", "POST", "/internal/put", { claims: relayClaims(s), body, headers: { "x-humid-box": box, ...(tag ? { "x-humid-tag": tag } : {}) } });
      return { status: res.status, headers: { "content-type": "application/json" }, body: res.body };
    },
    async relayTake(s, body) {
      relaySession(s);
      const res = await internal("relay", "POST", "/internal/take", { claims: relayClaims(s), body, headers: { "content-type": "application/json" } });
      return { status: res.status, headers: { "content-type": "application/json" }, body: res.body };
    },
    async relayRetract(s, body) {
      relaySession(s);
      const res = await internal("relay", "POST", "/internal/retract", { claims: relayClaims(s), body, headers: { "content-type": "application/json" } });
      return { status: res.status, headers: { "content-type": "application/json" }, body: res.body };
    },

    // Older apps reported presence here, after the sign-in. The flag in this request is
    // ignored (PC-01): it was a bare request any signed-in session could send, and a duress
    // signal locks the account down and, with Check-in armed, erases the vault. Duress now
    // arrives only inside a live, signed sign-in (`login`, field d). Same answer as before.
    async presence() {
      return { status: 200, json: { ok: true } };
    },

    /* ---- Check-in (docs/CHECKIN.md): keyshare holds the keys and the clock; this relays ---- */

    async checkinStatus(s) {
      needCheckin();
      const r = await internalJson("keyshare", "GET", "/internal/checkin", { claims: claimsFor(s) }).catch(() => ({ status: 503 }));
      if (s.duress) return { status: 200, json: decoyView(s.decoyCheckin) }; // same work, then the calm version
      if (r.status !== 200) throw new HttpError(503, "keyshare_unavailable", "Check-in can't be reached right now. Try again.");
      return { status: 200, json: r.data };
    },

    // Arm, or change the settings of an armed Check-in. The app sends its settings and which
    // documents are decoys (kept out of the erase); the gateway adds every document the vault
    // holds, so keyshare can refuse if any of them couldn't be erased for good.
    async checkinArm(s, body, stepUp) {
      needCheckin();
      if (!stepUp) throw new HttpError(403, "step_up_required", "Turning on Check-in needs a fresh biometric check.");
      const r = parseJson(body) || {};
      const settings = { windowMs: Number(r.windowMs), maxWindowMs: Number(r.maxWindowMs ?? r.windowMs), graceMs: Number(r.graceMs) };
      const claims = claimsFor(s, { stepUp });
      const list = await internalJson("vault", "GET", "/objects", { claims });
      if (list.status !== 200) fail(list);
      if (s.duress) {
        checkSettings(settings);
        const t = Date.now();
        s.decoyCheckin = decoyFrom({ ...settings, deadline: t + settings.windowMs, armedAt: s.decoyCheckin?.armedAt ?? t });
        return { status: 200, json: decoyView(s.decoyCheckin) };
      }
      const out = await internalJson("keyshare", "POST", "/internal/checkin/arm", {
        claims: claimsFor(s, { stepUp: withoutBody(stepUp) }), json: { objects: list.data.items.map((i) => i.id), holderBody: stepUp.holder.body },
      }).catch(() => ({ status: 503, data: { error: "keyshare_unavailable", message: "Check-in can't be turned on right now. Try again." } }));
      if (out.status !== 200) return { status: out.status, json: out.data }; // e.g. unsplit_items, with which ones
      await recordQuietly(s.subject, "checkin.armed", { windowMs: out.data.windowMs, maxWindowMs: out.data.maxWindowMs, graceMs: out.data.graceMs, kept: Array.isArray(r.keep) ? r.keep.length : 0, proof: stepUp.proof });
      return { status: 200, json: out.data };
    },

    // A check-in: one live check sets the next deadline. Not in the ledger (see ledger/EVENT_TYPES).
    async checkinCheck(s, body, stepUp) {
      needCheckin();
      if (!stepUp) throw new HttpError(403, "step_up_required", "Checking in needs a fresh biometric check.");
      const r = parseJson(body) || {};
      const next = r.nextWindowMs == null ? null : Number(r.nextWindowMs);
      if (s.duress) {
        // It looks like a check-in. The vault was already erased when this session opened.
        await internalJson("keyshare", "GET", "/internal/checkin", { claims: claimsFor(s) }).catch(() => null);
        setImmediate(() => eraseNow(s.subject, s.duressProof));
        const d = s.decoyCheckin, v = decoyView(d);
        if (v.state === "erased") throw new HttpError(410, "vault_erased", "Your vault was erased by Check-in.");
        if (v.state === "off") throw new HttpError(409, "checkin_off", "Check-in isn't on.");
        const n = next ?? d.windowMs;
        if (!CHECKIN_WINDOWS.includes(n)) throw new HttpError(400, "bad_checkin", "Check-in can't use that window.");
        if (n > d.maxWindowMs) throw new HttpError(400, "bad_checkin", "That's longer than the longest window you allowed.");
        d.deadline = Date.now() + n; d.erasesAt = d.deadline + d.graceMs;
        return { status: 200, json: decoyView(d) };
      }
      const out = await internalJson("keyshare", "POST", "/internal/checkin/check", { claims: claimsFor(s, { stepUp }), json: next == null ? {} : { nextWindowMs: next } })
        .catch(() => ({ status: 503, data: { error: "keyshare_unavailable", message: "Check-in can't be reached right now. Try again." } }));
      if (out.status !== 200) fail(out);
      return { status: 200, json: out.data };
    },

    async checkinDisarm(s, body, stepUp) {
      needCheckin();
      if (!stepUp) throw new HttpError(403, "step_up_required", "Turning off Check-in needs a fresh biometric check.");
      if (s.duress) {
        await internalJson("keyshare", "GET", "/internal/checkin", { claims: claimsFor(s) }).catch(() => null);
        setImmediate(() => eraseNow(s.subject, s.duressProof));
        if (decoyView(s.decoyCheckin).state === "erased") throw new HttpError(410, "vault_erased", "Your vault was erased by Check-in.");
        s.decoyCheckin = null;
        return { status: 200, json: { state: "off" } };
      }
      const out = await internalJson("keyshare", "POST", "/internal/checkin/disarm", { claims: claimsFor(s, { stepUp }) })
        .catch(() => ({ status: 503, data: { error: "keyshare_unavailable", message: "Check-in can't be reached right now. Try again." } }));
      if (out.status !== 200) fail(out);
      await recordQuietly(s.subject, "checkin.disarmed", { proof: stepUp.proof });
      return { status: 200, json: out.data };
    },

    async duressStatus(s) {
      if (s.duress) return { status: 200, json: { lockdown: false } }; // a decoy session sees a calm account
      const r = await internalJson("identity", "GET", `/internal/lockdown/${s.subject}`);
      if (r.status !== 200) fail(r);
      return { status: 200, json: r.data };
    },

    async clearDuress(s, body, stepUp) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Lifting lockdown needs a fresh biometric check.");
      if (s.duress) throw busy();
      const r = await internalJson("identity", "POST", `/internal/lockdown/${s.subject}/clear`, { claims: claimsFor(s, { stepUp }) });
      if (r.status !== 200) fail(r);
      if (r.data.cleared) await recordQuietly(s.subject, "duress.cleared", { device: s.deviceId, since: r.data.since, proof: stepUp.proof });
      return { status: 200, json: r.data };
    },

    /* ---- server administration: only relayed here, decided by the admin console ---- */

    // An administrator's phone asks how the server is doing (counts and alerts, nothing personal).
    async adminSummary(s) {
      const sum = admin ? await adminCall(() => admin.summary()) : null;
      if (!sum || !Array.isArray(sum.approvers) || !sum.approvers.includes(s.subject)) throw new HttpError(404, "not_admin", "This HumID doesn't administer this server.");
      const { approvers, ...rest } = sum;
      return { status: 200, json: rest };
    },

    // What a code from the admin console asks for. Enrolment codes are for any signed-in
    // HumID (the console then shows a check the person compares); change codes only for
    // an administrator the console already trusts.
    async adminRequest(s, body, stepUp, m) {
      const r = await adminLookup(s, m[1]);
      return { status: 200, json: { code: m[1], kind: r.kind, title: String(r.title || ""), lines: (r.lines || []).map(String).slice(0, 12), digest: r.digest, check: r.check, expiresAt: r.expiresAt, server: htp.fingerprint } };
    },

    // The live check approves exactly { digest } for exactly this code. Written to this
    // account's ledger first (fail closed), then handed to the console with everything it
    // needs to check the signature against the keys it pinned for this phone.
    async adminApprove(s, body, stepUp, m, route, meta) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Approving a server change needs a fresh biometric check.");
      const code = m[1];
      const r = await adminLookup(s, code);
      const b = parseJson(body) || {};
      if (typeof b.digest !== "string" || b.digest !== r.digest) throw new HttpError(409, "admin_request_changed", "This request changed on the server. Look it up again.");
      await record(s.subject, "admin.approved", { kind: r.kind, title: String(r.title || "").slice(0, 80), digest: r.digest.slice(0, 16), device: s.deviceId, proof: stepUp.proof });
      const raw = stepUp.raw;
      await adminCall(() => admin.approved(code, {
        code, account: s.subject, device: s.deviceId, platform: s.platform, proofLevel: s.proof, assurance: s.assurance,
        deviceDsaPk: b64u(s.dsaPk), livePub: s.livePub ? b64u(s.livePub) : null,
        th: b64u(s.th), seq: raw.seq, method: meta.m, path: meta.p, body: b64u(body), at: raw.at,
        sig: String(raw.sig), live: raw.live ? String(raw.live) : null, nonce: raw.nonce, exp: raw.exp,
        approvedAt: Date.now(),
      }));
      return { status: 200, json: { approved: true, kind: r.kind } };
    },

    // A recovery contact releases their share. Recorded in both people's ledgers.
    async helpRecover(s, body, stepUp, m) {
      if (!stepUp) throw new HttpError(403, "step_up_required", "Releasing your piece needs a fresh biometric check.");
      const r = await internalJson("recovery", "POST", `/help/${m[1]}`, { claims: claimsFor(s, { stepUp }), body });
      if (r.status !== 200) fail(r);
      const d = r.data;
      if (d.first) await recordQuietly(d.owner, "recovery.requested", { method: d.method, ref: d.ref, platform: d.platform });
      await recordQuietly(d.owner, "recovery.approved", { ref: d.ref, contact: s.subject, approvals: d.approvals, threshold: d.threshold, releaseAt: d.releaseAt, kinds: d.kinds });
      await recordQuietly(s.subject, "recovery.helped", { owner: d.owner, ref: d.ref, proof: stepUp.proof });
      return { status: 200, json: { approvals: d.approvals, threshold: d.threshold, releaseAt: d.releaseAt } };
    },
  };

  /** The relay is reached only from a session that never signed in: no account ever touches a mailbox. */
  function relaySession(s) {
    if (s.subject) throw new HttpError(400, "signed_in", "Use the relay from a session that isn't signed in.");
  }
  /** What the relay is told about the caller: a rate key (IPv4 address or IPv6 /64), for limits only. */
  const relayClaims = (s) => ({ rk: rateKey(s.clientIp || "") });

  /* ---------- the encrypted call ---------- */

  /** SRV-32: the route's own cap. Relay routes keep the frame cap (they only ever come from a session that isn't signed in, capped at maxAnonCallBytes). */
  const callCap = (route) => {
    const c = route.relay ? "max" : CALL_CAPS[capKey(route)] ?? CALL_CAP_DEFAULT;
    return c === "max" ? maxCallBytes : Math.min(c, maxCallBytes);
  };

  async function dispatch(s, seq, meta, body) {
    const url = new URL(String(meta.p || "/"), "http://inner");
    const route = ROUTES.find((r) => r.m === meta.m && r.p.test(url.pathname));
    if (!route) throw new HttpError(404, "not_found", "No such endpoint");
    if (route.auth && !s.subject) throw new HttpError(401, "sign_in_required", "Sign in first");
    if (route.msg && !MESSAGING) throw new HttpError(404, "not_found", "No such endpoint");
    if (body.length > callCap(route)) throw new HttpError(413, "too_large", "Request body is too large for this endpoint.");
    if (!s.subject && meta.m !== "GET" && !route.relay && !anonLimit.take(s.sidText)) throw new HttpError(429, "rate_limited", "Slow down");

    // Step-up: a fresh biometric signature over exactly this request, by this session's device key.
    let stepUp = null;
    if (meta.proof) {
      if (!s.subject) throw new HttpError(401, "sign_in_required", "Sign in first");
      const at = Number(meta.proof.at), now = Date.now();
      if (!Number.isSafeInteger(at) || now - at > STEP_UP_MAX_AGE_MS || at - now > CLOCK_SKEW_MS) throw new HttpError(403, "step_up_stale", "Biometric check is too old. Try again.");
      // The approval the server issued for this action: used once, here, whatever happens next.
      const nonceKey = typeof meta.proof.nonce === "string" ? meta.proof.nonce : "";
      const issued = nonceKey && s.stepUps?.get(nonceKey);
      if (!issued) throw new HttpError(403, "step_up_unknown", nonceKey ? "That approval was already used or never issued. Try again." : "Update HumID to approve this.");
      s.stepUps.delete(nonceKey);
      if (issued.m !== meta.m || issued.p !== meta.p) throw new HttpError(403, "step_up_mismatch", "That approval was for a different action.");
      if (issued.exp < now || Number(meta.proof.exp) !== issued.exp) throw new HttpError(403, "step_up_stale", "Biometric check is too old. Try again.");
      const action = actionBytes({ method: meta.m, path: meta.p, device: s.deviceId, nonce: unb64u(nonceKey), exp: issued.exp });
      const sig = unb64u(String(meta.proof.sig));
      if (!verify(sig, stepUpMessage(s.th, seq, meta.m, meta.p, body, at, action), s.dsaPk)) {
        await recordQuietly(s.subject, "access.denied", { path: url.pathname.replace(/[0-9a-f-]{36}/, ":id"), reason: "bad_step_up" });
        throw new HttpError(401, "bad_proof", "Biometric proof was rejected.");
      }
      // The device's secure chip must have signed this request slot during a live biometric check.
      if (s.livePub) {
        let live = null;
        try { live = meta.proof.live ? unb64u(String(meta.proof.live)) : null; } catch {}
        if (!verifyLiveSig(s.livePub, liveMessage(s.th, seq, meta.m, meta.p, at, action), live)) {
          await recordQuietly(s.subject, "access.denied", { path: url.pathname.replace(/[0-9a-f-]{36}/, ":id"), reason: "no_live_biometric" });
          throw new HttpError(401, "bad_live_proof", "This needs a live face or fingerprint check on this device.");
        }
      }
      const i = meta.proof.interrupt || {};
      stepUp = { at, proof: proofHash(sig), method: String(i.method || s.gateMethod).slice(0, 64), assurance: s.assurance, live: !!s.livePub };
      // The proof as signed, for the service that acts on it to check again (SRV-30).
      Object.defineProperty(stepUp, "holder", { value: await holderProof(s, seq, meta, body, meta.proof, nonceKey, issued.exp), enumerable: true });
      // The proof as signed, for a handler that hands it on to be checked again elsewhere (admin approvals).
      Object.defineProperty(stepUp, "raw", { value: { seq, at, sig: meta.proof.sig, live: meta.proof.live || null, nonce: nonceKey, exp: issued.exp }, enumerable: false });
    }

    // Duress lockdown: sensitive changes fail the way a busy server would.
    if (route.guard && s.subject && await lockedDown(s)) {
      await recordQuietly(s.subject, "access.denied", { path: url.pathname.replace(/[0-9a-f-]{36}/, ":id"), reason: "lockdown" });
      throw busy();
    }

    // Before any recovery route of a signed-in account: the recovery service on its newest mode.
    if (s.subject && url.pathname.startsWith("/recovery/") && !url.pathname.startsWith("/recovery/links")) await syncMode(s.subject);

    if (route.h) return handlers[route.h](s, body, stepUp, url.pathname.match(route.p), route, meta);

    const headers = {};
    for (const k of FORWARD_REQ_HEADERS) if (meta.h?.[k]) headers[k] = String(meta.h[k]);
    const path = url.pathname.replace(route.p, route.path) + url.search;
    const claims = s.subject ? claimsFor(s, stepUp ? { stepUp } : {}) : { sid: s.sidText.slice(0, 8) };
    let res = await internal(route.to, meta.m, path, { claims, body, headers });
    // An error passed straight through carries only its code and message: nothing a service
    // added for the gateway's own use (an account, a reference) reaches the caller.
    if (res.status >= 400) {
      const e = safeJson(res.body);
      if (e && typeof e === "object" && Object.keys(e).some((k) => k !== "error" && k !== "message")) {
        res = { ...res, body: Buffer.from(JSON.stringify({ error: e.error, message: e.message })) };
      }
    }

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

  /**
   * Recovery modes (V74-01/02): identity and the recovery service each keep the account's signed
   * statement. Bring whichever is behind (a row deleted, rolled back, or restored from an old
   * backup) up to the newest one either holds. Both are signed by the account key and chained,
   * so "newest" can't be forged, only withheld; the holder's own devices check for that.
   * Returns true when the recovery service's answer changed.
   */
  async function syncMode(account) {
    if (!re(ID_RE).test(String(account || ""))) return false;
    try {
      const [idr, rec] = await Promise.all([
        internalJson("identity", "GET", `/internal/recovery-mode/${account}`),
        internalJson("recovery", "GET", `/internal/recovery-mode/${account}`),
      ]);
      if (idr.status !== 200 || rec.status !== 200) return false;
      const i = idr.data.recoveryMode, r = rec.data;
      if (i?.version && (r.broken || r.version < i.version)) {
        const pushed = await internalJson("recovery", "POST", "/internal/recovery-mode", { json: { account, dsaPk: idr.data.dsaPk, mode: i.mode, version: i.version, epoch: i.epoch, prev: i.prev, sig: i.sig, sync: true } });
        if (pushed.status !== 200) log.warn("recovery mode: couldn't bring recovery up to identity", { status: pushed.status, error: pushed.data?.error });
        return pushed.status === 200;
      }
      if (r.statement && r.version > (i?.version || 0)) {
        const pushed = await internalJson("identity", "POST", "/internal/recovery-mode", { json: { account, ...r.statement } });
        if (pushed.status !== 200) log.warn("recovery mode: couldn't bring identity up to recovery", { status: pushed.status, error: pushed.data?.error });
      }
    } catch (e) { log.warn("recovery mode sync failed", { err: e.message }); }
    return false;
  }

  async function adminCall(fn) {
    try { return await fn(); }
    catch (e) { log.warn("admin console bridge failed", { err: e.message }); throw new HttpError(503, "admin_unavailable", "The server's admin console isn't answering. Try again in a minute."); }
  }

  async function adminLookup(s, code) {
    if (!admin) throw new HttpError(404, "no_admin_console", "This server has no admin console.");
    const r = await adminCall(() => admin.request(code));
    if (!r || !(r.expiresAt > Date.now())) throw new HttpError(404, "admin_request_unknown", "No request with that code, or it expired. Make a new one on the console.");
    if (r.kind !== "enrol" && !(Array.isArray(r.approvers) && r.approvers.includes(s.subject))) {
      await recordQuietly(s.subject, "access.denied", { path: "/admin/requests/:code", reason: "not_admin" });
      throw new HttpError(403, "not_admin", "This HumID isn't an administrator of this server.");
    }
    if (typeof r.digest !== "string" || !/^[0-9a-f]{64}$/.test(r.digest)) throw new HttpError(503, "admin_unavailable", "The server's admin console sent a bad request.");
    return r;
  }

  /* ---------- Check-in ---------- */

  function needCheckin() { if (!CHECKIN) throw new HttpError(404, "not_found", "No such endpoint"); }

  /** The same checks keyshare makes, with the same answers, for a duress session that must look ordinary. */
  function checkSettings({ windowMs, maxWindowMs, graceMs }) {
    if (!CHECKIN_WINDOWS.includes(windowMs)) throw new HttpError(400, "bad_checkin", "Check-in can't use that window.");
    if (!CHECKIN_WINDOWS.includes(maxWindowMs)) throw new HttpError(400, "bad_checkin", "Check-in can't use that longest window.");
    if (!CHECKIN_GRACES.includes(graceMs)) throw new HttpError(400, "bad_checkin", "Check-in can't use that grace period.");
    if (maxWindowMs < windowMs) throw new HttpError(400, "bad_checkin", "The longest window can't be shorter than the usual one.");
  }

  /** A duress session's Check-in: a copy of the real one as it was at unlock, moved only by that session. */
  const decoyFrom = (st) => ({ deadline: st.deadline, erasesAt: st.deadline + st.graceMs, windowMs: st.windowMs, maxWindowMs: st.maxWindowMs, graceMs: st.graceMs, armedAt: st.armedAt });
  /** It reads exactly like keyshare's status, field for field. */
  function decoyView(d) {
    if (!d) return { state: "off" };
    const t = Date.now();
    if (t >= d.erasesAt) return { state: "erased", erasedAt: d.erasesAt };
    return { state: t < d.deadline ? "armed" : "locked", deadline: d.deadline, erasesAt: d.erasesAt, windowMs: d.windowMs, maxWindowMs: d.maxWindowMs, graceMs: d.graceMs, armedAt: d.armedAt };
  }

  /** A duress signal: if this account is armed, keyshare destroys its fuse key now. Then tidy up. */
  async function eraseNow(account, duressProof) {
    if (!duressProof) return; // only a duress sign-in can set off an erase (keyshare checks it: SRV-30)
    const r = await internalJson("keyshare", "POST", "/internal/checkin/erase", { claims: { sub: account, duress: duressProof } })
      .catch((e) => { log.warn("check-in erase: keyshare", { err: e.message }); return null; });
    if (r?.data?.erased) await sweepCheckin().catch(() => {});
  }

  /**
   * After keyshare destroys an account's keys (a missed check-in, a duress signal, a restart),
   * drop the envelopes and index entries those keys opened, then write it in the holder's
   * ledger. The keys are already gone, so nothing here is urgent: whatever fails now is tried
   * again on the next sweep, the ledger entry included (written after the fact, never first).
   */
  let sweeping = null;
  function sweepCheckin() {
    if (!CHECKIN) return Promise.resolve(0);
    sweeping ||= (async () => {
      let n = 0;
      const list = () => internalJson("keyshare", "GET", "/internal/checkin/erased");
      const r = await list().catch(() => list()).catch(() => null); // once more: keyshare may have just restarted
      for (const e of r?.status === 200 ? r.data.erased : []) {
        const claims = { sub: e.owner };
        const v = await internalJson("vault", "DELETE", "/internal/objects", { claims, json: { token: e.token } }).catch(() => null);
        if (v?.status !== 200) continue;
        // Once per erase, however many sweeps it takes (a lost "cleaned" mustn't write it twice).
        // The count is keyshare's: how many document keys were destroyed.
        const at = new Date(e.erasedAt).toISOString();
        const seen = await internalJson("ledger", "GET", "/events?limit=100", { claims }).catch(() => null);
        if (seen?.status !== 200) continue;
        const done = (seen.data.entries || []).some((x) => { try { const b = JSON.parse(x.body); return b.type === "checkin.erased" && b.detail?.at === at; } catch { return false; } });
        if (!done) {
          try { await record(e.owner, "checkin.erased", { count: e.count ?? v.data.deleted, at }); }
          catch { continue; }
        }
        await internalJson("keyshare", "POST", `/internal/checkin/erased/${e.owner}/cleaned`).catch(() => {});
        n++;
      }
      return n;
    })().finally(() => { sweeping = null; });
    return sweeping;
  }
  if (CHECKIN && checkinSweepMs > 0) setInterval(() => { sweepCheckin().catch(() => {}); }, checkinSweepMs).unref();

  async function lockedDown(s) {
    if (s.duress) return true;
    const r = await internalJson("identity", "GET", `/internal/lockdown/${s.subject}`).catch(() => null);
    return !!r?.data?.lockdown;
  }

  const safeJson = (b) => { try { return JSON.parse(Buffer.from(b).toString()); } catch { return null; } };

  function callLimitFor(prefix) {
    // Anything that isn't a well-formed request header is left to htp.open (bad_frame) under the small cap.
    let h;
    try { h = parseHeader(concat(prefix, new Uint8Array(16))); } catch { h = null; }
    if (prefix.length < HEADER_LEN || !h || h.dir !== DIR.request) return maxAnonCallBytes;
    const s = htp.sessions.get(b64u(h.sid));
    if (!s) throw new HttpError(401, "session_unknown", "Unknown session; handshake again.");
    return s.subject ? maxCallBytes : Math.min(maxCallBytes, maxAnonCallBytes);
  }

  async function call({ req, body }) {
    let opened;
    try { opened = await htp.open(body); }
    catch (e) {
      if (e instanceof HtpServerError) return json(e.status, { error: e.code, message: e.message });
      throw e;
    }
    const { session: s, seq, meta, body: inner } = opened;
    s.clientIp = clientIp(req);
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
    // UI; the gateway enforces it on every sign-in and step-up. It's signed with the server's
    // ML-DSA-87 key (CRYPTO-07), so the app believes it only from the server it pinned.
    ["GET", "/htp/v1/keys", () => json(200, { ...htp.publicKeys(), ...htp.signedPolicy({ devicePolicy, registration, splitKeys: true, ...(MESSAGING ? { messaging: { stampsPerCheck: 2, stampNeeds: DEMO_STAMPS ? "any" : "hardware" } } : {}), ...(passBuyUrl ? { passBuyUrl } : {}), ...(CHECKIN ? { checkin: CHECKIN_POLICY } : {}) }) }), { public: true }],
    ["POST", "/htp/v1/hello", ({ req, body }) => {
      const group = rateKey(clientIp(req) || "");
      if (!helloLimit.take(group)) return json(429, { error: "rate_limited", message: "Too many handshakes" });
      try { return json(200, htp.hello(parseJson(body), Date.now(), { group })); }
      catch (e) { if (e instanceof HtpServerError) return json(e.status, { error: e.code, message: e.message }); throw e; }
    }, { public: true, bodyLimit: 16 * 1024 }],
    // The frame header names the session, so the cap is chosen from its first bytes: an unknown
    // session is refused at once, a session that has not signed in gets a small cap, and only a
    // signed-in session may send a large frame (vault uploads).
    ["POST", "/htp/v1/call", call, { public: true, admit: admitBody(), readLimit: { max: maxCallBytes, peek: HEADER_LEN, decide: callLimitFor } }],
    // The public transparency log: anyone can fetch checkpoints and consistency proofs, and
    // configured cosigners can vouch for them. No account data: only tree sizes and hashes.
    ["GET", "/tlog/v1/checkpoint", () => internal("ledger", "GET", "/tlog/checkpoint"), { public: true }],
    ["GET", "/tlog/v1/consistency", ({ query }) => {
      const q = new URLSearchParams();
      for (const k of ["from", "to"]) if (query.get(k) != null) q.set(k, String(Number(query.get(k))));
      return internal("ledger", "GET", `/tlog/consistency?${q}`);
    }, { public: true }],
    ["POST", "/tlog/v1/cosign", ({ req, body }) => {
      if (!helloLimit.take(rateKey(clientIp(req) || ""))) return json(429, { error: "rate_limited", message: "Slow down" });
      return internal("ledger", "POST", "/tlog/cosign", { body, headers: { "content-type": "application/json" } });
    }, { public: true, bodyLimit: 16 * 1024, admit: admitBody() }],
    ["OPTIONS", "/htp/v1/keys", () => ({ status: 204, headers: {}, body: "" }), { public: true }],
    ["OPTIONS", "/htp/v1/hello", () => ({ status: 204, headers: {}, body: "" }), { public: true }],
    ["OPTIONS", "/htp/v1/call", () => ({ status: 204, headers: {}, body: "" }), { public: true }],
  ];

  const svc = createService({ name: "gateway", port, routes, extraHeaders: cors });
  return { ...svc, htp, sweepCheckin };
}

/** Internal TLS from files: HUMID_TLS_CA, HUMID_TLS_CERT, HUMID_TLS_KEY (a sealed key file opens with the seal key). */
export function tlsFromEnv(env = process.env, seal = sealerFromEnv(env)) {
  const { HUMID_TLS_CA: ca, HUMID_TLS_CERT: cert, HUMID_TLS_KEY: key } = env;
  if (!ca && !cert && !key) return null;
  if (!ca || !cert || !key) throw new Error("Internal TLS needs all of HUMID_TLS_CA, HUMID_TLS_CERT and HUMID_TLS_KEY");
  return { ca: readFileSync(ca, "utf8"), cert: readFileSync(cert, "utf8"), key: seal.open("tls/key", readFileSync(key)).toString("utf8") };
}

if (isMain(import.meta.url)) {
  if (process.argv.includes("keygen")) {
    // `docker compose run --rm gateway server.mjs keygen` -> lines for deploy/.env
    const { newInternalKeys, newStatementKeys } = await import("@humid/svc");
    const k = newInternalKeys();
    process.stdout.write(`HUMID_INTERNAL_SK=${k.sk}\nHUMID_INTERNAL_PK=${k.pk}\n`);
    if (process.argv.includes("statements") || !process.argv.includes("internal-only")) {
      // SRV-30: what the gateway's key alone can't do. Only identity, ledger (core) and keyshare (keys) get the private halves.
      const c = newStatementKeys(), ks = newStatementKeys();
      process.stdout.write(`HUMID_CORE_STATEMENT_SK=${c.sk}\nHUMID_CORE_STATEMENT_PK=${c.pk}\nHUMID_KEYS_STATEMENT_SK=${ks.sk}\nHUMID_KEYS_STATEMENT_PK=${ks.pk}\n`);
    }
  } else createGateway().start();
}
