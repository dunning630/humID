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

import { createService, serviceTlsFromEnv, openDb, env, json, parseJson, parseObject, verifyAssertion, signStatement, unb64u, b64u, HttpError, isMain, logger, sealerFromEnv } from "@humid/svc";
import { holderProofs } from "@humid/svc/holder";
import { identityId, deviceId, registerMessage, deviceMessage, verify, sha3_256, toHex, STEP_UP_MAX_AGE_MS, ml_dsa87 } from "@humid/htp";
import { recoveryModeMessage, isRecoveryMode, followsMode, RECMODE_GENESIS, RECOVERY_MODES } from "@humid/recovery";
import { verifyLiveKey, verifyLiveSig, AttestationError, revocationList, runStatusFetcher, STATUS_URL, STATUS_MAX_AGE_MS, HUMID_ANDROID_RELEASE_CERT } from "@humid/attest";

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
  /**
   * The core role's statement key (SRV-30): vouches to vault and keyshare that a device key
   * belongs to an account, so they can check the holder's own proof. Never given to the gateway.
   */
  statementSk = sealerFromEnv().openText("humid.env/HUMID_CORE_STATEMENT_SK", env("HUMID_CORE_STATEMENT_SK", "")),
  // After a duress signal the account stays locked down until its owner clears it, calmly, at least this long after the last signal.
  duressCoolOffMs = Number(env("HUMID_DURESS_COOLOFF_MS", String(24 * 3600_000))),
  // Google's list of revoked or suspended attestation certificates ("" turns it off), fetched
  // here, or (Docker, where identity has no route to the internet) read from the file the
  // attestation-status sidecar keeps up to date. A file wins over the URL.
  statusUrl = env("HUMID_ATTESTATION_STATUS_URL", STATUS_URL),
  statusFile = env("HUMID_ATTESTATION_STATUS_FILE", ""),
  // 1: refuse an Android phone while the list is missing or older than statusMaxAgeMs · 0: accept it
  // unchecked (logged) · unset: 1 for the attested device policy, 0 for the others.
  statusRequired = statusRequiredFromEnv(env("HUMID_ATTESTATION_STATUS_REQUIRED", "auto")),
  statusMaxAgeMs = Number(env("HUMID_ATTESTATION_STATUS_MAX_AGE_MS", String(STATUS_MAX_AGE_MS))),
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
  /**
   * The gateway's device policy, for the start-up check and banner only (every request
   * still carries the gateway's policy). Same variable the gateway reads.
   */
  devicePolicy = env("HUMID_DEVICE_POLICY", "attested"),
  /** HUMID_INSECURE_TEST=1: allow test-only attestation shortcuts together with the attested policy. */
  insecureTest = env("HUMID_INSECURE_TEST", "0") === "1",
} = {}) {
  const log = logger("identity");
  if (!(Number.isFinite(statusMaxAgeMs) && statusMaxAgeMs > 0)) throw new Error("HUMID_ATTESTATION_STATUS_MAX_AGE_MS must be a positive number of milliseconds");
  // LIVE-04: accepting an Android app signed by anyone drops the "genuine HumID app" half of
  // the hardware proof. It's for test builds; with the attested policy it needs a second,
  // explicit flag, so it can't arrive silently in a copied .env.
  if (attest.allowAnySigner && devicePolicy === "attested" && !insecureTest) {
    throw new Error("HUMID_ANDROID_ALLOW_ANY_SIGNER=1 accepts any self-signed copy of the HumID app as genuine, so it is refused with HUMID_DEVICE_POLICY=attested. For a test server only, also set HUMID_INSECURE_TEST=1.");
  }
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
    // Recovery mode (docs/RECOVERY.md#two-recovery-modes), signed by the account key over
    // recoveryModeMessage. No row (NULL) means an account from before modes: hardened.
    `ALTER TABLE identities ADD COLUMN recovery_mode TEXT;
     ALTER TABLE identities ADD COLUMN recovery_mode_version INTEGER;
     ALTER TABLE identities ADD COLUMN recovery_mode_epoch INTEGER;
     ALTER TABLE identities ADD COLUMN recovery_mode_sig BLOB`,
    // LIVE-06: the device reported its biometric keys gone (fingerprints or face changed, app
    // reinstalled); it needs setting up again. Cleared by its next successful sign-in.
    `ALTER TABLE device_keys ADD COLUMN keys_gone_at TEXT`,
    // Statements are chained (V74-01/02): each names the hash of the one before.
    `ALTER TABLE identities ADD COLUMN recovery_mode_prev TEXT`,
  ]);
  const status = attest.revokedSerials ? null : revocationList({ url: statusUrl, file: statusFile, maxAgeMs: statusMaxAgeMs, log: (event, detail) => console.warn(JSON.stringify({ t: new Date().toISOString(), svc: "identity", event, ...detail })) });
  /** Whether a phone may be checked against a missing or stale list, under the gateway's policy. */
  const statusNeeded = (policy) => statusRequired === "auto" ? policy === "attested" : statusRequired;
  /** The attestation rules for one enrolment under `policy` (revocation fails closed when needed). */
  const attestFor = (policy) => status ? { ...attest, revokedSerials: () => status.serials({ required: statusNeeded(policy) }) } : attest;
  const usedChallenge = db.prepare("SELECT device_id FROM attest_challenges WHERE th = ?");
  const useChallenge = db.prepare("INSERT OR IGNORE INTO attest_challenges (th, device_id, used_at) VALUES (?, ?, ?)");

  const getAccount = db.prepare("SELECT * FROM identities WHERE id = ?");
  // A key no device has: sign-in proofs for an account or device that doesn't exist are checked
  // against it, so they cost the same as a wrong signature from a real device (SRV-24).
  const nobodyPk = ml_dsa87.keygen().publicKey;
  const getDevice = db.prepare("SELECT * FROM device_keys WHERE id = ?");
  const activeDevices = db.prepare("SELECT * FROM device_keys WHERE account_id = ? AND revoked_at IS NULL ORDER BY enrolled_at");

  const fp = (b) => toHex(sha3_256(b));
  const deviceView = (d, current) => ({
    id: d.id, platform: d.platform, gateMethod: d.gate_method, assurance: d.assurance, via: d.via, proof: d.proof,
    enrolledAt: d.enrolled_at, lastSeenAt: d.last_seen_at, current: d.id === current,
    ...(d.keys_gone_at ? { needsSetup: true, keysGoneAt: d.keys_gone_at } : {}),
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
  function liveness(live, th, message, deviceIdHex, sessionAgeMs, policy) {
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
      const { proof, detail } = verifyLiveKey({ pub: livePub, attestation: att }, th, attestFor(policy));
      useChallenge.run(thHex, deviceIdHex, new Date().toISOString());
      return { proof, livePub, detail };
    } catch (e) {
      if (e instanceof AttestationError) throw new HttpError(403, e.code, e.message);
      throw e;
    }
  }
  /**
   * A recovery mode statement { mode, version, epoch, prev, sig } for `account`, checked
   * against its account key, and against the one on file: it must follow it (followsMode:
   * a higher version, an epoch no lower, chained to it). The same statement again is accepted
   * (a retried request, or the gateway reconciling identity and recovery).
   */
  function checkedMode(account, m) {
    const mode = String(m?.mode || ""), version = Number(m?.version), epoch = Number(m?.epoch), prev = String(m?.prev ?? RECMODE_GENESIS);
    const u32 = (n) => Number.isSafeInteger(n) && n >= 1 && n < 2 ** 32;
    if (!isRecoveryMode(mode) || !u32(version) || !u32(epoch)) throw new HttpError(400, "bad_recovery_mode", "Unknown recovery mode.");
    const sig = unb64u(String(m?.sig || ""));
    let ok = false;
    try { ok = verify(sig, recoveryModeMessage(account.id, mode, version, epoch, prev), new Uint8Array(account.dsa_pk)); } catch { ok = false; }
    if (!ok) throw new HttpError(401, "bad_proof", "The recovery mode wasn't signed by this account's key.");
    const next = { mode, version, epoch, prev, sig };
    if (!followsMode(account.id, statementOf(account), next)) throw new HttpError(409, "stale_recovery_mode", "A newer recovery choice is already on file.");
    return next;
  }
  const statementOf = (r) => (r.recovery_mode ? { mode: r.recovery_mode, version: r.recovery_mode_version, epoch: r.recovery_mode_epoch, prev: r.recovery_mode_prev || RECMODE_GENESIS } : null);
  const saveMode = (id, m) => db.prepare("UPDATE identities SET recovery_mode = ?, recovery_mode_version = ?, recovery_mode_epoch = ?, recovery_mode_prev = ?, recovery_mode_sig = ? WHERE id = ?").run(m.mode, m.version, m.epoch, m.prev, m.sig, id);
  const modeView = (r) => (r.recovery_mode ? { ...statementOf(r), sig: b64u(r.recovery_mode_sig) } : null);
  const assuranceOf = (proof, gateMethod) => (attested(proof) ? "hardware" : DESKTOP_BIOMETRIC.has(gateMethod) ? "os" : "none");
  const accountView = (r, current) => ({
    id: r.id, status: r.status, createdAt: r.created_at, commit: r.commit_hex,
    dsaFp: fp(r.dsa_pk), kemFp: fp(r.kem_pk),
    // The signed statement itself, so every device checks it against the account key.
    recoveryMode: modeView(r),
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
    const live = liveness(d.live, th, msg, id, sessionAgeMs, policy);
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

  // The holder's own approval for removing a device or closing the account, checked here too
  // (SRV-30), against the device keys this service holds.
  const proofs = holderProofs({
    resolve: (deviceIdText, account) => {
      const d = getDevice.get(deviceIdText);
      if (!d || d.account_id !== account || d.revoked_at) return null;
      return { dsaPk: new Uint8Array(d.dsa_pk), livePub: d.live_pub ? new Uint8Array(d.live_pub) : null };
    },
  });
  const needHolder = (claims, method, path) => {
    if (!claims.stepUp) throw new HttpError(403, "step_up_required", "This needs a fresh biometric check.");
    proofs.check(claims.holder, { sub: claims.sub, method, path });
  };

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
          // The choice made at setup, signed by the same account key.
          if (r.recoveryMode != null) saveMode(id, checkedMode(getAccount.get(id), r.recoveryMode));
        }
        const { device } = addDevice(getAccount.get(id), th, r.device, "register", r.policy, Number(r.sessionAgeMs));
        db.exec("COMMIT");
        const out = respondWithDevice(existing ? 200 : 201, getAccount.get(id), device);
        // A new account, in this session: the recovery service stores its setup card on this and
        // the account key's own signature over the card (SRV-30), never on the gateway's word.
        if (!existing && statementSk) {
          const v = JSON.parse(Buffer.from(out.body).toString());
          v.created = signStatement(statementSk, "created", { account: id, th: b64u(th) }, 120_000);
          out.body = Buffer.from(JSON.stringify(v));
        }
        return out;
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

    // Gateway only: is this device already part of that account? (A device that already
    // joined may sign in to finish joining again without fresh evidence.)
    ["GET", "/internal/devices/:id", ({ params, claims }) => {
      gatewayOnly(claims);
      const d = getDevice.get(params.id);
      if (!d) throw new HttpError(404, "unknown_device", "No such device.");
      return json(200, { account: d.account_id, revoked: !!d.revoked_at });
    }],
    // Gateway only (LIVE-06): a device says Android or iOS destroyed its keys. It can't sign
    // anything any more, so this is unauthenticated by necessity; it only marks the device as
    // needing setup again, and that device's next sign-in clears it. True when newly marked.
    ["POST", "/internal/devices/:id/keys-gone", ({ params, claims, body }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const d = getDevice.get(params.id);
      if (!d || d.account_id !== String(r.account) || d.revoked_at || d.keys_gone_at || getAccount.get(d.account_id)?.status !== "active") return json(200, { marked: false });
      db.prepare("UPDATE device_keys SET keys_gone_at = ? WHERE id = ? AND keys_gone_at IS NULL").run(new Date().toISOString(), d.id);
      return json(200, { marked: true, platform: d.platform });
    }],
    // Gateway only: undo an enrolment whose evidence turned out to be spent meanwhile.
    // Only a device enrolled moments ago (SRV-30): the gateway's key alone can't remove an older one.
    ["POST", "/internal/devices/:id/revoke", ({ params, claims, body }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      db.prepare("UPDATE device_keys SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL AND enrolled_at > ?").run(new Date().toISOString(), params.id, String(r.account), new Date(Date.now() - 120_000).toISOString());
      return json(200, { revoked: true });
    }],

    // Check a sign-in signature made by one device of an account.
    // SRV-24: an unknown account, an unknown device and a wrong key get one answer (401
    // bad_signature) after the same work: the signature is checked first, against a throwaway
    // key when there is no such device, so neither the answer nor its timing says which. Only a
    // caller who has just proved they hold this device's key learns more (closed, removed, no
    // live check). `known` is for the gateway alone (whether to note it in a ledger); it strips it.
    ["POST", "/internal/verify", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const account = getAccount.get(String(r.account));
      const found = getDevice.get(String(r.device));
      const device = account && found && found.account_id === account.id ? found : null;
      let message, sig;
      try { message = unb64u(String(r.message)); sig = unb64u(String(r.sig)); } catch { message = new Uint8Array(0); sig = new Uint8Array(0); }
      const signedOk = verify(sig, message, device ? new Uint8Array(device.dsa_pk) : nobodyPk);
      if (!device || !signedOk) return json(401, { ok: false, error: "bad_signature", message: "Sign-in proof was rejected.", known: !!(device && account.status === "active" && !device.revoked_at) });
      if (account.status !== "active") throw new HttpError(404, "unknown_identity", "No such identity");
      if (device.revoked_at) throw new HttpError(403, "device_removed", "This device was removed from your HumID.");
      // The liveness key signs the challenge it was given before the prompt; the device key may
      // sign a longer message that also carries what the check decided (the duress flag).
      const liveMessage = r.liveMessage != null ? unb64u(String(r.liveMessage)) : message;
      // A device with a liveness key must prove a live biometric on every sign-in.
      if (device.live_pub && !verifyLiveSig(device.live_pub, liveMessage, r.live ? unb64u(String(r.live)) : null)) {
        return json(401, { ok: false, error: "bad_live_proof", message: "The device's secure chip did not confirm a live biometric." });
      }
      allowed(r.policy, device.proof, device.gate_method); // the server's policy may have tightened since enrolment
      // A live sign-in proves this device's keys are there: any "keys gone" report about it is void.
      db.prepare("UPDATE device_keys SET last_seen_at = ?, keys_gone_at = NULL WHERE id = ?").run(new Date().toISOString(), device.id);
      return json(200, { ok: true, ...accountView(account, device.id), ...internalDevice(device) });
    }],

    // Recovery mode: the account's signed statement, and its public key so another service can check it too.
    ["GET", "/internal/recovery-mode/:id", ({ params, claims }) => {
      gatewayOnly(claims);
      const a = active(params.id);
      return json(200, { account: a.id, dsaPk: b64u(a.dsa_pk), recoveryMode: modeView(a) || { mode: RECOVERY_MODES.hardened, version: 0, epoch: 1, prev: RECMODE_GENESIS, sig: null } });
    }],
    ["POST", "/internal/recovery-mode", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const a = active(String(r.account));
      saveMode(a.id, checkedMode(a, r));
      return json(200, { recoveryMode: modeView(getAccount.get(a.id)) });
    }],
    // SRV-30: this device key (and liveness key) belongs to this account, now. Vault and keyshare
    // check the holder's proofs against it; the gateway can ask, but can't make it vouch for a
    // key the account didn't add (adding one needs the account key's signature).
    ["POST", "/internal/vouch", ({ body, claims }) => {
      gatewayOnly(claims);
      if (!statementSk) throw new HttpError(503, "no_statement_key", "This server has no core statement key (HUMID_CORE_STATEMENT_SK).");
      const r = parseObject(body);
      const account = active(String(r.account));
      const d = getDevice.get(String(r.device));
      if (!d || d.account_id !== account.id || d.revoked_at) throw new HttpError(404, "unknown_device", "This device is not part of the identity.");
      const vouch = signStatement(statementSk, "device", { account: account.id, device: d.id, dsaPk: b64u(d.dsa_pk), ...(d.live_pub ? { livePub: b64u(d.live_pub) } : {}) }, 120_000);
      return json(200, { vouch });
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
    // Lifting a lockdown needs the holder's own live check, checked here (SRV-30).
    ["POST", "/internal/lockdown/:id/clear", ({ params, claims }) => {
      gatewayOnly(claims);
      if (claims.sub !== params.id) throw new HttpError(403, "forbidden", "Only the account itself can lift its lockdown.");
      needHolder(claims, "POST", "/auth/duress/clear");
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
      needHolder(claims, "DELETE", `/identity/devices/${params.id}`);
      const d = getDevice.get(params.id);
      if (!d || d.account_id !== account.id || d.revoked_at) throw new HttpError(404, "unknown_device", "No such device on your HumID.");
      if (d.id === claims.device) throw new HttpError(400, "current_device", "You can't remove the device you're using. Remove it from another device.");
      db.prepare("UPDATE device_keys SET revoked_at = ? WHERE id = ?").run(new Date().toISOString(), d.id);
      return json(200, { removed: true, device: deviceView(d, claims.device) });
    }],

    // Close the account. Public keys stay on file (closed) so old ledger proofs remain checkable.
    ["DELETE", "/me", ({ claims }) => {
      active(claims.sub);
      needHolder(claims, "DELETE", "/identity/me");
      const now = new Date().toISOString();
      db.prepare("UPDATE identities SET status = 'closed' WHERE id = ?").run(claims.sub);
      db.prepare("UPDATE device_keys SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL").run(now, claims.sub);
      return json(200, { closed: true });
    }],
  ];

  const svc = createService({ tls, name: "identity", port, routes, bodyLimit: 64 * 1024, verify: (t) => verifyAssertion(internalPk, t, "identity") });

  /**
   * The live-human posture in one line (LIVE-04): everything that decides how much a
   * device's "a live face or fingerprint approved this" is worth, so an operator can read
   * it in the log instead of five settings across two services. `weakened` lists each
   * setting below the strongest, and is logged as a warning when it isn't empty.
   */
  function posture() {
    const p = {
      devicePolicy,
      requireLockedBoot: attest.requireLockedBoot !== false,
      allowAnySigner: !!attest.allowAnySigner,
      appAttestEnv: attest.appAttestEnvironment || "production",
      androidMinPatch: attest.minPatchLevel || null,
      revocation: status ? status.source : "fixed",
      revocationRequired: statusNeeded(devicePolicy),
      revocationMaxAgeH: Math.round(statusMaxAgeMs / 3600_000),
      iphones: !!attest.iosAppId,
    };
    const weakened = [];
    if (p.devicePolicy !== "attested") weakened.push(`HUMID_DEVICE_POLICY=${p.devicePolicy}: devices that can't prove a live check are accepted`);
    if (!p.requireLockedBoot) weakened.push("HUMID_REQUIRE_LOCKED_BOOT=0: rooted and unlocked-bootloader Android phones are accepted");
    if (p.allowAnySigner) weakened.push("HUMID_ANDROID_ALLOW_ANY_SIGNER=1: any self-signed copy of the HumID app counts as genuine (test builds only)");
    if (p.appAttestEnv !== "production") weakened.push(`HUMID_APP_ATTEST_ENV=${p.appAttestEnv}: Xcode debug builds count as the App Store app`);
    if (p.revocation === "off") weakened.push("HUMID_ATTESTATION_STATUS_URL is empty: Google's revoked-key list is never checked");
    else if (!p.revocationRequired) weakened.push("HUMID_ATTESTATION_STATUS_REQUIRED=0: Android phones are accepted when Google's revoked-key list is missing or stale");
    return { ...p, weakened };
  }
  const start = async (...a) => {
    const p = posture();
    (p.weakened.length ? log.warn : log.info)("live-human posture", p);
    return svc.start(...a);
  };
  return { ...svc, start, posture, revocation: status, stop: (...a) => { status?.stop(); return svc.stop(...a); } };
}

/** "1" | "0" | "auto" (HUMID_ATTESTATION_STATUS_REQUIRED unset): true, false or "auto". */
export function statusRequiredFromEnv(v) {
  const s = String(v ?? "auto").trim().toLowerCase();
  if (s === "1" || s === "true") return true;
  if (s === "0" || s === "false") return false;
  if (s === "auto" || s === "") return "auto";
  throw new Error("HUMID_ATTESTATION_STATUS_REQUIRED must be 1, 0 or unset");
}

if (isMain(import.meta.url)) {
  if (process.argv[2] === "status-fetch") {
    // The attestation-status sidecar (deploy/docker-compose.yml): the only HumID process with a
    // route to the internet, and it holds no keys and reaches no other service. It fetches
    // Google's list every few hours and writes it where identity reads it.
    runStatusFetcher({
      url: env("HUMID_ATTESTATION_STATUS_URL", STATUS_URL),
      file: env("HUMID_ATTESTATION_STATUS_FILE", "/status/attestation-status.json"),
      log: (event, detail) => process.stdout.write(JSON.stringify({ t: new Date().toISOString(), level: event.endsWith("unavailable") ? "warn" : "info", service: "attestation-status", msg: event, ...detail }) + "\n"),
    });
  } else createIdentity().start();
}
