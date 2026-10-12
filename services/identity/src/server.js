// identity — accounts and their devices. Stores only PUBLIC keys and verifies
// the biometric-bound signatures the gateway passes in. It never sees a
// private key, a seed, a document or a biometric.
//
// An account is identified by its ML-DSA-87 account key (derived from the
// account seed every device of the account holds). Each device signs in with
// its own ML-DSA-87 key, so one device can be removed without the others.
// A device joins only with two signatures over deviceMessage: the account key
// (authorises) and the device key (proof of possession).

import { createService, openDb, env, json, parseJson, verifyAssertion, unb64u, b64u, HttpError } from "@humid/svc";
import { identityId, deviceId, registerMessage, deviceMessage, verify, sha3_256, toHex, STEP_UP_MAX_AGE_MS } from "@humid/htp";

const SIZES = { kemPk: 1568, dsaPk: 2592, xPk: 32 };
const VIA = new Set(["register", "link", "card", "contacts"]);

export function createIdentity({ port = Number(env("PORT", "8081")), dataDir = env("DATA_DIR", "/data"), internalPk = env("HUMID_INTERNAL_PK") } = {}) {
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
  ]);

  const getAccount = db.prepare("SELECT * FROM identities WHERE id = ?");
  const getDevice = db.prepare("SELECT * FROM device_keys WHERE id = ?");
  const activeDevices = db.prepare("SELECT * FROM device_keys WHERE account_id = ? AND revoked_at IS NULL ORDER BY enrolled_at");

  const fp = (b) => toHex(sha3_256(b));
  const deviceView = (d, current) => ({
    id: d.id, platform: d.platform, gateMethod: d.gate_method, assurance: d.assurance, via: d.via,
    enrolledAt: d.enrolled_at, lastSeenAt: d.last_seen_at, current: d.id === current,
  });
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

  /** Add a device after checking both signatures over deviceMessage. */
  function addDevice(account, th, d, via) {
    if (!VIA.has(via)) throw new HttpError(400, "bad_via", "Unknown enrolment route");
    const dsaPk = key(d?.dsaPk, "device dsaPk", SIZES.dsaPk);
    const msg = deviceMessage(th, account.id, dsaPk);
    if (!verify(unb64u(String(d.sigAccount || "")), msg, new Uint8Array(account.dsa_pk))) {
      throw new HttpError(401, "bad_proof", "This device was not authorised by the account key.");
    }
    if (!verify(unb64u(String(d.sigDevice || "")), msg, dsaPk)) {
      throw new HttpError(401, "bad_proof", "Proof of possession failed for the device key.");
    }
    const id = deviceId(dsaPk);
    const existing = getDevice.get(id);
    if (existing) {
      if (existing.account_id !== account.id) throw new HttpError(409, "device_taken", "This device key belongs to another account.");
      if (existing.revoked_at) throw new HttpError(409, "device_removed", "This device was removed from the account.");
      return { device: existing, created: false };
    }
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO device_keys (id, account_id, dsa_pk, platform, gate_method, assurance, via, enrolled_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, account.id, dsaPk, String(d.platform || "unknown").slice(0, 40), String(d.gateMethod || "unknown").slice(0, 64),
        ["hardware", "os", "none"].includes(d.assurance) ? d.assurance : "none", via, now, now);
    return { device: getDevice.get(id), created: true };
  }

  const respondWithDevice = (status, account, device) =>
    json(status, { ...accountView(account, device.id), device: deviceView(device, device.id), deviceDsaPk: b64u(device.dsa_pk) });

  const routes = [
    // First device: creates the account (proof of possession of the account keys) and enrols the device.
    ["POST", "/internal/register", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body);
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
        const { device } = addDevice(getAccount.get(id), th, r.device, "register");
        db.exec("COMMIT");
        return respondWithDevice(existing ? 200 : 201, getAccount.get(id), device);
      } catch (e) { db.exec("ROLLBACK"); throw e; }
    }],

    // Another device joins an existing account (after a device link or a recovery).
    ["POST", "/internal/devices", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body);
      const account = active(String(r.account));
      const { device, created } = addDevice(account, unb64u(String(r.th)), r.device, String(r.via));
      return respondWithDevice(created ? 201 : 200, account, device);
    }],

    // Check a sign-in signature made by one device of an account.
    ["POST", "/internal/verify", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body);
      const account = active(String(r.account));
      const device = getDevice.get(String(r.device));
      if (!device || device.account_id !== account.id) throw new HttpError(404, "unknown_device", "This device is not part of the identity.");
      if (device.revoked_at) throw new HttpError(403, "device_removed", "This device was removed from your HumID.");
      if (!verify(unb64u(String(r.sig)), unb64u(String(r.message)), new Uint8Array(device.dsa_pk))) return json(401, { ok: false, error: "bad_signature" });
      db.prepare("UPDATE device_keys SET last_seen_at = ? WHERE id = ?").run(new Date().toISOString(), device.id);
      return json(200, { ok: true, ...accountView(account, device.id), device: deviceView(device, device.id), deviceDsaPk: b64u(device.dsa_pk) });
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
      if (!claims.stepUp) throw new HttpError(403, "step_up_required", "Closing an identity needs a fresh biometric check.");
      const now = new Date().toISOString();
      db.prepare("UPDATE identities SET status = 'closed' WHERE id = ?").run(claims.sub);
      db.prepare("UPDATE device_keys SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL").run(now, claims.sub);
      return json(200, { closed: true });
    }],
  ];

  return createService({ name: "identity", port, routes, bodyLimit: 64 * 1024, verify: (t) => verifyAssertion(internalPk, t, "identity") });
}

if (import.meta.url === `file://${process.argv[1]}`) createIdentity().start();
