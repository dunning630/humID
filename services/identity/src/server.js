// identity — accounts and their devices. Stores only PUBLIC keys and verifies
// the biometric-bound signatures the gateway passes in. It never sees a
// private key, a seed, a document or a biometric.
//
// An account is identified by its ML-DSA-87 account key (derived from the
// account seed every device of the account holds). Each device signs in with
// its own ML-DSA-87 key, so one device can be removed without the others.
// A device joins only with two signatures over deviceMessage: the account key
// (authorises) and the device key (proof of possession).
//
// Liveness. Phones also present a hardware liveness key: an ECDSA P-256 key
// in the Secure Enclave / Android Keystore that signs only right after a live
// Face ID, Touch ID or Class 3 biometric match. At enrolment its attestation
// (Android key attestation, Apple App Attest) is checked and it must sign the
// device statement; every sign-in must then carry its signature too. Policy
// (from the gateway): "attested" accepts only such devices, "biometric" also
// accepts desktop biometric-only gates without hardware proof, "demo" accepts
// anything (local development only).

import { createService, serviceTlsFromEnv, openDb, env, json, parseJson, parseObject, verifyAssertion, unb64u, b64u, HttpError, isMain } from "@humid/svc";
import { identityId, deviceId, registerMessage, deviceMessage, verify, sha3_256, toHex, STEP_UP_MAX_AGE_MS } from "@humid/htp";
import { verifyLiveKey, verifyLiveSig, AttestationError, revocationList, STATUS_URL, HUMID_ANDROID_RELEASE_CERT } from "@humid/attest";

/** An attestation is made for one enrolment, in a session at most this old. */
export const ATTEST_MAX_AGE_MS = 5 * 60_000;

const SIZES = { kemPk: 1568, dsaPk: 2592, xPk: 32 };
const VIA = new Set(["register", "link", "card", "contacts", "quorum"]);
const POLICIES = new Set(["attested", "biometric", "demo"]);
/** Desktop gates that only ever accept a biometric, enforced by the OS (no hardware proof). */
export const DESKTOP_BIOMETRIC = new Set(["macos-keychain-biometry", "windows-winbio-fingerprint", "linux-fprintd-keyring"]);
const attested = (proof) => /^(android|apple)-/.test(proof || "");

const list = (v) => String(v || "").split(",").map((x) => x.trim()).filter(Boolean);

export function createIdentity({
  /** Mutual TLS when the gateway calls from another machine (server 3.0): HUMID_TLS_* files. */
  tls = serviceTlsFromEnv(),
  port = Number(env("PORT", "8081")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  // After a duress signal the account stays locked down until its owner clears it, calmly, at least this long after the last signal.
  duressCoolOffMs = Number(env("HUMID_DURESS_COOLOFF_MS", String(24 * 3600_000))),
  // Google's list of revoked or suspended attestation certificates ("" turns it off).
  statusUrl = env("HUMID_ATTESTATION_STATUS_URL", STATUS_URL),
  statusRequired = env("HUMID_ATTESTATION_STATUS_REQUIRED", "0") === "1",
  attest = {
    androidPackages: list(env("HUMID_ANDROID_PACKAGES", "app.humid.vault")),
    // the official HumID app's signing certificate, plus any the operator adds (their own builds)
    androidDigests: [HUMID_ANDROID_RELEASE_CERT, ...list(env("HUMID_ANDROID_CERT_DIGESTS", "")).map((d) => d.toLowerCase().replace(/:/g, ""))],
    // Test builds only: accept an Android app signed by anyone. Never in production.
    allowAnySigner: env("HUMID_ANDROID_ALLOW_ANY_SIGNER", "0") === "1",
    // YYYYMM: refuse phones whose security patch is older (empty: no minimum).
    minPatchLevel: Number(env("HUMID_ANDROID_MIN_PATCH", "")) || undefined,
    iosAppId: env("HUMID_IOS_APP_ID", "") || undefined,             // "<Apple Team ID>.app.humid.vault"
    appAttestEnvironment: env("HUMID_APP_ATTEST_ENV", "production"),  // or "development" for Xcode builds
    requireLockedBoot: env("HUMID_REQUIRE_LOCKED_BOOT", "1") !== "0",
  },
} = {}) {
  const db = openDb(dataDir, "identity.db", [
    `CREATE TABLE identities (
       id TEXT PRIMARY KEY,
       kem_pk BLOB NOT NULL, dsa_pk BLOB NOT NULL, x_pk BLOB NOT NULL,
       commit_hex TEXT NOT NULL,
       status TEXT NOT NULL DEFAULT 'active',
       created_at TEXT NOT NULL)`,
    // v1 device log (one row per enrolment, no keys). Superseded by device_keys; kept for history.
    `CREATE TABLE devices (
       identity_id TEXT NOT NULL REFERENCES identities(id),
       platform TEXT, gate_method TEXT, assurance TEXT,
       enrolled_at TEXT NOT NULL)`,
    `CREATE TABLE device_keys (
       id TEXT PRIMARY KEY,
       account_id TEXT NOT NULL REFERENCES identities(id),
       dsa_pk BLOB NOT NULL,
       platform TEXT, gate_method TEXT, assurance TEXT,
       via TEXT NOT NULL,
       enrolled_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT)`,
    `CREATE INDEX device_keys_account ON device_keys(account_id, enrolled_at)`,
    // Hardware liveness key and what proved it (android-strongbox | android-tee | apple-secure-enclave | none).
    `ALTER TABLE device_keys ADD COLUMN live_pub BLOB;
     ALTER TABLE device_keys ADD COLUMN proof TEXT NOT NULL DEFAULT 'none';
     ALTER TABLE device_keys ADD COLUMN proof_detail TEXT`,
    // Duress: a silent lockdown of sensitive changes (devices, recovery, closing), set by the owner's duress gesture.
    `ALTER TABLE identities ADD COLUMN lockdown_at TEXT;
     ALTER TABLE identities ADD COLUMN last_duress_at TEXT`,
    // Each attestation challenge (a session's transcript hash) enrols at most one device.
    `CREATE TABLE attest_challenges (th TEXT PRIMARY KEY, device_id TEXT NOT NULL, used_at TEXT NOT NULL)`,
  ]);
  const status = attest.revokedSerials ? null : revocationList({ url: statusUrl, required: statusRequired, log: (event, detail) => console.warn(JSON.stringify({ t: new Date().toISOString(), svc: "identity", event, ...detail })) });
  if (status) attest = { ...attest, revokedSerials: () => status.serials() };
  const usedChallenge = db.prepare("SELECT device_id FROM attest_challenges WHERE th = ?");
  const useChallenge = db.prepare("INSERT OR IGNORE INTO attest_challenges (th, device_id, used_at) VALUES (?, ?, ?)");

  const getAccount = db.prepare("SELECT * FROM identities WHERE id = ?");
  const getDevice = db.prepare("SELECT * FROM device_keys WHERE id = ?");
  const activeDevices = db.prepare("SELECT * FROM device_keys WHERE account_id = ? AND revoked_at IS NULL ORDER BY enrolled_at");

  const fp = (b) => toHex(sha3_256(b));
  const deviceView = (d, current) => ({
    id: d.id, platform: d.platform, gateMethod: d.gate_method, assurance: d.assurance, via: d.via, proof: d.proof,
    enrolledAt: d.enrolled_at, lastSeenAt: d.last_seen_at, current: d.id === current,
  });

  /** Which devices the server's policy accepts. Server-derived proof, never the device's claim. */
  function allowed(policy, proof, gateMethod) {
    if (!POLICIES.has(policy)) throw new HttpError(500, "bad_policy", "Unknown device policy");
    if (policy === "demo" || attested(proof)) return;
    if (policy === "biometric" && proof === "none" && DESKTOP_BIOMETRIC.has(gateMethod)) return;
    throw new HttpError(403, "device_not_proven", policy === "attested"
      ? "This vault accepts only iPhones and Android phones whose secure chip proves a live face or fingerprint."
      : "This device can't prove a live face or fingerprint check.");
  }

  /**
   * Check the liveness key: its attestation, and its signature over this enrolment.
   * An attestation's challenge is the session transcript: it must be fresh (a session
   * opened in the last few minutes) and enrol one device only.
   */
  function liveness(live, th, message, deviceIdHex, sessionAgeMs) {
    if (!live) return { proof: "none", livePub: null, detail: null };
    const livePub = unb64u(String(live.pub || ""));
    if (!verifyLiveSig(livePub, message, unb64u(String(live.sig || "")))) {
      throw new HttpError(401, "bad_live_proof", "The device's secure chip did not sign this enrolment.");
    }
    if (!live.attestation) return { proof: "unattested-key", livePub, detail: null };
    if (!(Number.isFinite(sessionAgeMs) && sessionAgeMs >= 0 && sessionAgeMs <= ATTEST_MAX_AGE_MS)) {
      throw new HttpError(403, "attestation_stale", "The device's proof is too old. Start adding it again.");
    }
    const thHex = toHex(th);
    const used = usedChallenge.get(thHex);
    if (used && used.device_id !== deviceIdHex) throw new HttpError(409, "challenge_used", "This proof was already used to add another device.");
    const a = live.attestation;
    const att = a.kind === "android-key"
      ? { kind: a.kind, chain: (Array.isArray(a.chain) ? a.chain : []).slice(0, 10).map((c) => unb64u(String(c))) }
      : { kind: a.kind, object: unb64u(String(a.object || "")) };
    try {
      const { proof, detail } = verifyLiveKey({ pub: livePub, attestation: att }, th, attest);
      useChallenge.run(thHex, deviceIdHex, new Date().toISOString());
      return { proof, livePub, detail };
    } catch (e) {
      if (e instanceof AttestationError) throw new HttpError(403, e.code, e.message);
      throw e;
    }
  }
  const assuranceOf = (proof, gateMethod) => (attested(proof) ? "hardware" : DESKTOP_BIOMETRIC.has(gateMethod) ? "os" : "none");
  const accountView = (r, current) => ({
    id: r.id, status: r.status, createdAt: r.created_at, commit: r.commit_hex,
    dsaFp: fp(r.dsa_pk), kemFp: fp(r.kem_pk),
    devices: activeDevices.all(r.id).map((d) => deviceView(d, current)),
  });
  const active = (id) => {
    const r = getAccount.get(id);
    if (!r || r.status !== "active") throw new HttpError(404, "unknown_identity", "No such identity");
    return r;
  };
  const gatewayOnly = (claims) => { if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
  const key = (v, name, size) => {
    const b = unb64u(String(v ?? ""));
    if (b.length !== size) throw new HttpError(400, "bad_key", `${name} has the wrong length`);
    return b;
  };

  /** Add a device after checking both signatures over deviceMessage, its liveness key and the policy. */
  function addDevice(account, th, d, via, policy, sessionAgeMs) {
    if (!VIA.has(via)) throw new HttpError(400, "bad_via", "Unknown enrolment route");
    const dsaPk = key(d?.dsaPk, "device dsaPk", SIZES.dsaPk);
    const msg = deviceMessage(th, account.id, dsaPk);
    if (!verify(unb64u(String(d.sigAccount || "")), msg, new Uint8Array(account.dsa_pk))) {
      throw new HttpError(401, "bad_proof", "This device was not authorised by the account key.");
    }
    if (!verify(unb64u(String(d.sigDevice || "")), msg, dsaPk)) {
      throw new HttpError(401, "bad_proof", "Proof of possession failed for the device key.");
    }
    const gateMethod = String(d.gateMethod || "unknown").slice(0, 64);
    const id = deviceId(dsaPk);
    const live = liveness(d.live, th, msg, id, sessionAgeMs);
    allowed(policy, live.proof, gateMethod);
    const existing = getDevice.get(id);
    if (existing) {
      if (existing.account_id !== account.id) throw new HttpError(409, "device_taken", "This device key belongs to another account.");
      if (existing.revoked_at) throw new HttpError(409, "device_removed", "This device was removed from the account.");
      return { device: existing, created: false };
    }
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO device_keys (id, account_id, dsa_pk, platform, gate_method, assurance, via, enrolled_at, last_seen_at, live_pub, proof, proof_detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, account.id, dsaPk, String(d.platform || "unknown").slice(0, 40), gateMethod, assuranceOf(live.proof, gateMethod), via, now, now,
        live.livePub, live.proof, live.detail ? JSON.stringify(live.detail) : null);
    return { device: getDevice.get(id), created: true };
  }

  const internalDevice = (device) => ({ device: deviceView(device, device.id), deviceDsaPk: b64u(device.dsa_pk), deviceLivePub: device.live_pub ? b64u(device.live_pub) : null });
  const respondWithDevice = (status, account, device) => json(status, { ...accountView(account, device.id), ...internalDevice(device) });

  const routes = [
    // First device: creates the account (proof of possession of the account keys) and enrols the device.
    ["POST", "/internal/register", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const keys = {};
      for (const k of Object.keys(SIZES)) keys[k] = key(r[k], k, SIZES[k]);
      const commit = String(r.commit || "");
      if (!/^[0-9a-f]{64}$/.test(commit)) throw new HttpError(400, "bad_commit", "Identity commit must be 64 hex characters");
      const th = unb64u(String(r.th));
      if (!verify(unb64u(String(r.sig || "")), registerMessage(th, keys, commit), keys.dsaPk)) {
        throw new HttpError(401, "bad_proof", "Proof of possession failed: the device does not hold this identity key.");
      }
      const id = identityId(keys.dsaPk);
      const existing = getAccount.get(id);
      if (existing && existing.status !== "active") throw new HttpError(409, "identity_closed", "This identity was closed.");
      db.exec("BEGIN");
      try {
        if (!existing) {
          db.prepare("INSERT INTO identities (id, kem_pk, dsa_pk, x_pk, commit_hex, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .run(id, keys.kemPk, keys.dsaPk, keys.xPk, commit, new Date().toISOString());
        }
        const { device } = addDevice(getAccount.get(id), th, r.device, "register", r.policy, Number(r.sessionAgeMs));
        db.exec("COMMIT");
        return respondWithDevice(existing ? 200 : 201, getAccount.get(id), device);
      } catch (e) { db.exec("ROLLBACK"); throw e; }
    }],

    // Another device joins an existing account (after a device link or a recovery).
    ["POST", "/internal/devices", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const account = active(String(r.account));
      const { device, created } = addDevice(account, unb64u(String(r.th)), r.device, String(r.via), r.policy, Number(r.sessionAgeMs));
      return respondWithDevice(created ? 201 : 200, account, device);
    }],

    // Check a sign-in signature made by one device of an account.
    ["POST", "/internal/verify", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const account = active(String(r.account));
      const device = getDevice.get(String(r.device));
      if (!device || device.account_id !== account.id) throw new HttpError(404, "unknown_device", "This device is not part of the identity.");
      if (device.revoked_at) throw new HttpError(403, "device_removed", "This device was removed from your HumID.");
      const message = unb64u(String(r.message));
      if (!verify(unb64u(String(r.sig)), message, new Uint8Array(device.dsa_pk))) return json(401, { ok: false, error: "bad_signature" });
      // A device with a liveness key must prove a live biometric on every sign-in.
      if (device.live_pub && !verifyLiveSig(device.live_pub, message, r.live ? unb64u(String(r.live)) : null)) {
        return json(401, { ok: false, error: "bad_live_proof", message: "The device's secure chip did not confirm a live biometric." });
      }
      allowed(r.policy, device.proof, device.gate_method); // the server's policy may have tightened since enrolment
      db.prepare("UPDATE device_keys SET last_seen_at = ? WHERE id = ?").run(new Date().toISOString(), device.id);
      return json(200, { ok: true, ...accountView(account, device.id), ...internalDevice(device) });
    }],

    // Duress. The gateway sets and reads this; it is never shown in /me.
    ["POST", "/internal/duress", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      active(String(r.account));
      const t = new Date().toISOString();
      db.prepare("UPDATE identities SET lockdown_at = COALESCE(lockdown_at, ?), last_duress_at = ? WHERE id = ?").run(t, t, String(r.account));
      return json(200, { lockdown: true, since: getAccount.get(String(r.account)).lockdown_at });
    }],
    ["GET", "/internal/lockdown/:id", ({ params, claims }) => {
      gatewayOnly(claims);
      const a = getAccount.get(params.id);
      const last = a?.last_duress_at ? Date.parse(a.last_duress_at) : null;
      return json(200, { lockdown: !!a?.lockdown_at, since: a?.lockdown_at || null, lastDuressAt: a?.last_duress_at || null, clearableAt: last ? last + duressCoolOffMs : null });
    }],
    ["POST", "/internal/lockdown/:id/clear", ({ params, claims }) => {
      gatewayOnly(claims);
      const a = active(params.id);
      if (!a.lockdown_at) return json(200, { cleared: false, lockdown: false });
      const clearableAt = Date.parse(a.last_duress_at) + duressCoolOffMs;
      if (Date.now() < clearableAt) throw new HttpError(409, "too_soon", "Lockdown can be lifted once it has been calm for a while.");
      db.prepare("UPDATE identities SET lockdown_at = NULL WHERE id = ?").run(a.id);
      return json(200, { cleared: true, lockdown: false, since: a.lockdown_at });
    }],

    // The holder's own profile and devices.
    ["GET", "/me", ({ claims }) => json(200, accountView(active(claims.sub), claims.device))],

    // Remove another device. Needs a fresh biometric check on the device asking.
    ["DELETE", "/devices/:id", ({ params, claims }) => {
      const account = active(claims.sub);
      if (!claims.stepUp || Date.now() - claims.stepUp.at > STEP_UP_MAX_AGE_MS) throw new HttpError(403, "step_up_required", "Removing a device needs a fresh biometric check.");
      const d = getDevice.get(params.id);
      if (!d || d.account_id !== account.id || d.revoked_at) throw new HttpError(404, "unknown_device", "No such device on your HumID.");
      if (d.id === claims.device) throw new HttpError(400, "current_device", "You can't remove the device you're using. Remove it from another device.");
      db.prepare("UPDATE device_keys SET revoked_at = ? WHERE id = ?").run(new Date().toISOString(), d.id);
      return json(200, { removed: true, device: deviceView(d, claims.device) });
    }],

    // Close the account. Public keys stay on file (closed) so old ledger proofs remain checkable.
    ["DELETE", "/me", ({ claims }) => {
      active(claims.sub);
      if (!claims.stepUp || Date.now() - claims.stepUp.at > STEP_UP_MAX_AGE_MS) throw new HttpError(403, "step_up_required", "Closing an identity needs a fresh biometric check.");
      const now = new Date().toISOString();
      db.prepare("UPDATE identities SET status = 'closed' WHERE id = ?").run(claims.sub);
      db.prepare("UPDATE device_keys SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL").run(now, claims.sub);
      return json(200, { closed: true });
    }],
  ];

  return createService({ tls, name: "identity", port, routes, bodyLimit: 64 * 1024, verify: (t) => verifyAssertion(internalPk, t, "identity") });
}

if (isMain(import.meta.url)) createIdentity().start();
