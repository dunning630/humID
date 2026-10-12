// identity — who is who. Stores only PUBLIC keys (ML-KEM-1024, ML-DSA-87,
// X25519) and verifies the biometric-bound signatures the gateway passes in.
// It never sees a private key, a seed, a document or a biometric.

import { createService, openDb, env, json, parseJson, verifyAssertion, unb64u, b64u, HttpError } from "@humid/svc";
import { identityId, registerMessage, verify, sha3_256, toHex } from "@humid/htp";

const SIZES = { kemPk: 1568, dsaPk: 2592, xPk: 32 };

export function createIdentity({ port = Number(env("PORT", "8081")), dataDir = env("DATA_DIR", "/data"), internalPk = env("HUMID_INTERNAL_PK") } = {}) {
  const db = openDb(dataDir, "identity.db", [
    `CREATE TABLE identities (
       id TEXT PRIMARY KEY,
       kem_pk BLOB NOT NULL, dsa_pk BLOB NOT NULL, x_pk BLOB NOT NULL,
       commit_hex TEXT NOT NULL,
       status TEXT NOT NULL DEFAULT 'active',
       created_at TEXT NOT NULL)`,
    `CREATE TABLE devices (
       identity_id TEXT NOT NULL REFERENCES identities(id),
       platform TEXT, gate_method TEXT, assurance TEXT,
       enrolled_at TEXT NOT NULL)`,
  ]);

  const getRow = db.prepare("SELECT * FROM identities WHERE id = ?");
  const devicesFor = db.prepare("SELECT platform, gate_method, assurance, enrolled_at FROM devices WHERE identity_id = ? ORDER BY enrolled_at");

  const fp = (b) => toHex(sha3_256(b));
  const publicView = (r) => ({
    id: r.id, status: r.status, createdAt: r.created_at, commit: r.commit_hex,
    dsaFp: fp(r.dsa_pk), kemFp: fp(r.kem_pk),
    devices: devicesFor.all(r.id).map((d) => ({ platform: d.platform, gateMethod: d.gate_method, assurance: d.assurance, enrolledAt: d.enrolled_at })),
  });
  const active = (id) => {
    const r = getRow.get(id);
    if (!r || r.status !== "active") throw new HttpError(404, "unknown_identity", "No such identity");
    return r;
  };

  const verifyClaims = (token) => verifyAssertion(internalPk, token, "identity");

  const routes = [
    // Called by the gateway during enrolment. th = the HTP session transcript the proof is bound to.
    ["POST", "/internal/register", ({ body, claims }) => {
      if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only");
      const r = parseJson(body);
      const keys = {};
      for (const k of Object.keys(SIZES)) {
        keys[k] = unb64u(r[k]);
        if (keys[k].length !== SIZES[k]) throw new HttpError(400, "bad_key", `${k} has the wrong length`);
      }
      const commit = String(r.commit || "");
      if (!/^[0-9a-f]{64}$/.test(commit)) throw new HttpError(400, "bad_commit", "Identity commit must be 64 hex characters");
      const th = unb64u(r.th);
      if (!verify(unb64u(r.sig), registerMessage(th, keys, commit), keys.dsaPk)) {
        throw new HttpError(401, "bad_proof", "Proof of possession failed: the device does not hold this identity key.");
      }
      const id = identityId(keys.dsaPk);
      const now = new Date().toISOString();
      const existing = getRow.get(id);
      if (!existing) {
        db.prepare("INSERT INTO identities (id, kem_pk, dsa_pk, x_pk, commit_hex, created_at) VALUES (?, ?, ?, ?, ?, ?)")
          .run(id, keys.kemPk, keys.dsaPk, keys.xPk, commit, now);
      } else if (existing.status !== "active") {
        throw new HttpError(409, "identity_closed", "This identity was closed.");
      }
      const d = r.device || {};
      db.prepare("INSERT INTO devices (identity_id, platform, gate_method, assurance, enrolled_at) VALUES (?, ?, ?, ?, ?)")
        .run(id, String(d.platform || "unknown").slice(0, 32), String(d.gateMethod || "unknown").slice(0, 64), String(d.assurance || "none").slice(0, 16), now);
      return json(existing ? 200 : 201, { ...publicView(getRow.get(id)), dsaPk: b64u(keys.dsaPk) });
    }],

    // Called by the gateway to check a login or step-up signature.
    ["POST", "/internal/verify", ({ body, claims }) => {
      if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only");
      const r = parseJson(body);
      const row = active(String(r.id));
      const ok = verify(unb64u(r.sig), unb64u(r.message), new Uint8Array(row.dsa_pk));
      if (!ok) return json(401, { ok: false, error: "bad_signature" });
      return json(200, { ok: true, ...publicView(row), dsaPk: b64u(row.dsa_pk) });
    }],

    // The holder's own profile (via the gateway, authenticated session).
    ["GET", "/me", ({ claims }) => json(200, publicView(active(claims.sub)))],

    // Close the identity. Public keys stay on file (closed) so old ledger proofs remain checkable.
    ["DELETE", "/me", ({ claims }) => {
      active(claims.sub);
      if (!claims.stepUp) throw new HttpError(403, "step_up_required", "Closing an identity needs a fresh biometric check.");
      db.prepare("UPDATE identities SET status = 'closed' WHERE id = ?").run(claims.sub);
      return json(200, { closed: true });
    }],
  ];

  return createService({ name: "identity", port, routes, bodyLimit: 64 * 1024, verify: verifyClaims });
}

if (import.meta.url === `file://${process.argv[1]}`) createIdentity().start();
