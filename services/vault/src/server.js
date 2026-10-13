// vault — zero-knowledge document storage.
//
// Receives HumID envelopes that were sealed ON THE PHONE (ML-KEM-1024 + X25519
// to the holder's own keys, signed with ML-DSA-87). The vault checks the
// signature and that the envelope is sealed to the caller, then stores the
// ciphertext. It cannot read contents or file names: the list view uses an
// "index" blob the app encrypts with a key only the holder can derive.
//
// Returning ciphertext requires a step-up proof: a fresh (≤ 60 s) biometric
// signature over this exact request, checked by the gateway. A stolen session
// alone cannot drain a vault.

import { mkdirSync, writeFileSync, readFileSync, unlinkSync, existsSync, renameSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { createService, openDb, env, json, bytes, verifyAssertion, unb64u, HttpError } from "@humid/svc";
import { suiteForEnvelope } from "@humid/crypto";
import { isEnvelope, MEDIA_TYPE } from "@humid/codec";
import { sha3_256, toHex, STEP_UP_MAX_AGE_MS, sealLiveMessage } from "@humid/htp";
import { verifyLiveSig } from "@humid/attest";

export function createVault({
  port = Number(env("PORT", "8082")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  quotaBytes = Number(env("VAULT_QUOTA_BYTES", String(250 * 1024 * 1024))),
  maxObjectBytes = Number(env("VAULT_MAX_OBJECT_BYTES", String(50 * 1024 * 1024))),
} = {}) {
  const blobDir = `${dataDir}/blobs`;
  mkdirSync(blobDir, { recursive: true });
  const db = openDb(dataDir, "vault.db", [
    `CREATE TABLE objects (
       id TEXT PRIMARY KEY,
       owner TEXT NOT NULL,
       blob TEXT NOT NULL,
       size INTEGER NOT NULL,
       idx BLOB NOT NULL,
       sealed_at TEXT, uploaded_at TEXT NOT NULL, updated_at TEXT NOT NULL,
       interrupt_method TEXT, assurance TEXT, signer_fp TEXT)`,
    `CREATE INDEX objects_owner ON objects(owner, uploaded_at)`,
  ]);

  const blobPath = (h) => `${blobDir}/${h.slice(0, 2)}/${h}`;
  const writeBlob = (data) => {
    const h = toHex(sha3_256(data));
    const p = blobPath(h);
    if (!existsSync(p)) {
      mkdirSync(`${blobDir}/${h.slice(0, 2)}`, { recursive: true });
      writeFileSync(`${p}.tmp`, data, { mode: 0o600 });
      renameSync(`${p}.tmp`, p);
    }
    return h;
  };

  const usage = (owner) => db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS b FROM objects WHERE owner = ?").get(owner);
  const own = (owner, id) => {
    const r = db.prepare("SELECT * FROM objects WHERE id = ? AND owner = ?").get(id, owner);
    if (!r) throw new HttpError(404, "not_found", "No such item in your vault");
    return r;
  };
  const view = (r) => ({
    id: r.id, size: r.size, index: Buffer.from(r.idx).toString("base64url"),
    sealedAt: r.sealed_at, uploadedAt: r.uploaded_at, updatedAt: r.updated_at,
    interruptMethod: r.interrupt_method, assurance: r.assurance,
  });
  const readIndex = (headers) => {
    const v = headers["x-humid-index"];
    if (!v) throw new HttpError(400, "missing_index", "Encrypted index entry is required");
    const idx = unb64u(String(v));
    if (idx.length < 28 || idx.length > 4096) throw new HttpError(400, "bad_index", "Index entry has an invalid size");
    return idx;
  };
  const requireStepUp = (claims) => {
    const s = claims.stepUp;
    if (!s || Date.now() - s.at > STEP_UP_MAX_AGE_MS) {
      throw new HttpError(403, "step_up_required", "This needs a fresh biometric check on your device.");
    }
  };
  const requireUser = (claims) => {
    if (!claims.sub) throw new HttpError(401, "unauthenticated", "Sign in first");
    return claims.sub;
  };

  const routes = [
    ["GET", "/objects", ({ claims }) => {
      const owner = requireUser(claims);
      const rows = db.prepare("SELECT * FROM objects WHERE owner = ? ORDER BY uploaded_at DESC").all(owner);
      const u = usage(owner);
      return json(200, { items: rows.map(view), usage: { count: u.n, bytes: u.b, quota: quotaBytes } });
    }],

    ["POST", "/objects", ({ claims, body, headers }) => {
      const owner = requireUser(claims);
      if (!isEnvelope(body)) throw new HttpError(400, "not_envelope", "Upload must be a sealed HumID envelope");
      let v;
      try { v = suiteForEnvelope(body).verify(body); } catch (e) { throw new HttpError(400, "bad_envelope", e.message); }
      if (!v.ok) throw new HttpError(400, "bad_signature", "Envelope signature or ciphertext hash is invalid");
      const signerFp = toHex(sha3_256(new Uint8Array(Buffer.from(v.manifest.signer.mldsa87Pk, "base64"))));
      if (signerFp !== claims.dsaFp) throw new HttpError(403, "not_signer", "Envelope was not signed by your identity");
      if (v.manifest.recipient?.kemPkFp !== claims.kemFp) throw new HttpError(403, "not_recipient", "Envelope is not sealed to your identity");
      // A device with a hardware liveness key must have sealed this with a live biometric check:
      // its secure chip signs the ciphertext hash inside the same check that releases the signing key.
      if (claims.livePub) {
        const live = v.manifest.interrupt?.live;
        let sig = null;
        try { sig = live ? unb64u(String(live)) : null; } catch {}
        if (!verifyLiveSig(unb64u(claims.livePub), sealLiveMessage(v.manifest.ciphertext.sha3_512), sig)) {
          throw new HttpError(403, "no_live_seal", "This document wasn't sealed with a live face or fingerprint check on this device.");
        }
      }
      const idx = readIndex(headers);
      const u = usage(owner);
      if (u.b + body.length > quotaBytes) throw new HttpError(507, "quota_exceeded", "Your vault is full");
      const now = new Date().toISOString();
      const id = randomUUID();
      const blob = writeBlob(body);
      db.prepare(`INSERT INTO objects (id, owner, blob, size, idx, sealed_at, uploaded_at, updated_at, interrupt_method, assurance, signer_fp)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, owner, blob, body.length, idx, v.manifest.created, now, now, v.manifest.interrupt?.method || null, v.manifest.interrupt?.assurance || null, signerFp);
      return json(201, view(own(owner, id)));
    }, { bodyLimit: maxObjectBytes }],

    ["GET", "/objects/:id", ({ claims, params }) => {
      const owner = requireUser(claims);
      requireStepUp(claims);
      const r = own(owner, params.id);
      return bytes(200, readFileSync(blobPath(r.blob)), MEDIA_TYPE, { "x-humid-size": String(r.size) });
    }],

    // Rename / recategorise: replaces the encrypted index entry only.
    ["PATCH", "/objects/:id", ({ claims, params, headers }) => {
      const owner = requireUser(claims);
      own(owner, params.id);
      db.prepare("UPDATE objects SET idx = ?, updated_at = ? WHERE id = ?").run(readIndex(headers), new Date().toISOString(), params.id);
      return json(200, view(own(owner, params.id)));
    }],

    ["DELETE", "/objects/:id", ({ claims, params }) => {
      const owner = requireUser(claims);
      requireStepUp(claims);
      const r = own(owner, params.id);
      db.prepare("DELETE FROM objects WHERE id = ?").run(r.id);
      const still = db.prepare("SELECT 1 FROM objects WHERE blob = ? LIMIT 1").get(r.blob);
      if (!still) try { unlinkSync(blobPath(r.blob)); } catch {}
      return json(200, { deleted: r.id });
    }],

    // Erase everything (account closure). Needs a step-up like any destructive act.
    ["DELETE", "/objects", ({ claims }) => {
      const owner = requireUser(claims);
      requireStepUp(claims);
      const rows = db.prepare("SELECT id, blob FROM objects WHERE owner = ?").all(owner);
      db.prepare("DELETE FROM objects WHERE owner = ?").run(owner);
      for (const r of rows) {
        if (!db.prepare("SELECT 1 FROM objects WHERE blob = ? LIMIT 1").get(r.blob)) try { unlinkSync(blobPath(r.blob)); } catch {}
      }
      return json(200, { deleted: rows.length });
    }],
  ];

  return createService({
    name: "vault", port, routes, bodyLimit: 64 * 1024,
    verify: (t) => verifyAssertion(internalPk, t, "vault"),
  });
}

if (import.meta.url === `file://${process.argv[1]}`) createVault().start();
