// keyshare — the second key of every split document (docs/SECURITY.md#compromised-phone).
//
// A phone that seals a document encrypts it under a fresh 256-bit document key, seals
// the result to the account's keys, and sends the document key here. From then on the
// phone forgets it. Opening the document needs BOTH the account keys and this key, and
// this service releases it only:
//   - to the document's own account,
//   - inside a live, chip-signed step-up for that exact document (the same check that
//     lets the vault return the envelope: no extra prompt), at most 60 seconds old,
//   - within a per-account hourly cap, so a hijacked phone can't drain the vault.
//
// Spyware that copies the account keys out of a phone's memory therefore opens nothing
// by itself. This service never sees an envelope, a name or an account key, and the
// vault never sees a document key: a breach of either one alone opens nothing.
//
// Shares are stored encrypted (AES-256-GCM, bound to account and document) under
// share-key.bin on this service's own volume. Keep that volume on separate storage
// from the vault's, ideally a separate host; the key file belongs in an HSM or KMS
// before real data (docs/SECURITY.md#before-real-data).

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { randomBytes, createCipheriv, createDecipheriv, hkdfSync } from "node:crypto";
import { createService, openDb, env, json, parseJson, verifyAssertion, unb64u, b64u, HttpError, isMain } from "@humid/svc";
import { STEP_UP_MAX_AGE_MS } from "@humid/htp";

const OBJ_RE = /^[0-9a-f-]{36}$/;
const SHARE_BYTES = 32;
const HOUR = 3_600_000;

export function createKeyshare({
  port = Number(env("PORT", "8086")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  releasesPerHour = Number(env("HUMID_SHARE_RELEASES_PER_HOUR", "120")),
  rollbackWindowMs = 120_000,
  now = () => Date.now(),
} = {}) {
  mkdirSync(dataDir, { recursive: true });
  const keyFile = `${dataDir}/share-key.bin`;
  if (!existsSync(keyFile)) writeFileSync(keyFile, randomBytes(32), { mode: 0o600 });
  const master = Buffer.from(hkdfSync("sha3-256", readFileSync(keyFile), Buffer.alloc(0), "HUMID-KEYSHARE-v1 at-rest", 32));

  const db = openDb(dataDir, "keyshare.db", [
    `CREATE TABLE shares (object TEXT PRIMARY KEY, owner TEXT NOT NULL, iv BLOB NOT NULL, ct BLOB NOT NULL,
                          created_at INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0, last_released_at INTEGER)`,
    `CREATE INDEX shares_owner ON shares(owner)`,
    `CREATE TABLE releases (owner TEXT NOT NULL, at INTEGER NOT NULL)`,
    `CREATE INDEX releases_owner ON releases(owner, at)`,
  ]);

  const aad = (owner, object) => Buffer.from(`HUMID-KEYSHARE-v1\0${owner}\0${object}`);
  const seal = (owner, object, share) => {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", master, iv).setAAD(aad(owner, object));
    return { iv, ct: Buffer.concat([c.update(share), c.final(), c.getAuthTag()]) };
  };
  const open = (row) => {
    const d = createDecipheriv("aes-256-gcm", master, row.iv).setAAD(aad(row.owner, row.object));
    d.setAuthTag(Buffer.from(row.ct).subarray(-16));
    return Buffer.concat([d.update(Buffer.from(row.ct).subarray(0, -16)), d.final()]);
  };

  const gatewayOnly = (claims) => { if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
  const owner = (claims) => { if (!claims.sub) throw new HttpError(401, "unauthenticated", "Sign in first"); return claims.sub; };
  const stepUp = (claims) => {
    const s = claims.stepUp;
    if (!s || now() - s.at > STEP_UP_MAX_AGE_MS) throw new HttpError(403, "step_up_required", "This needs a fresh biometric check on your device.");
  };
  const object = (id) => { if (!OBJ_RE.test(String(id))) throw new HttpError(400, "bad_object", "Unknown document id"); return String(id); };
  const mine = (o, id) => {
    const r = db.prepare("SELECT * FROM shares WHERE object = ?").get(id);
    if (!r || r.owner !== o) throw new HttpError(404, "no_share", "This document has no split key here.");
    return r;
  };

  const routes = [
    // Store a document's key, once, right after the vault accepted its envelope.
    ["PUT", "/internal/shares/:id", ({ claims, params, body }) => {
      gatewayOnly(claims);
      const o = owner(claims), id = object(params.id);
      let share;
      try { share = unb64u(String(parseJson(body)?.share || "")); } catch { share = null; }
      if (!share || share.length !== SHARE_BYTES) throw new HttpError(400, "bad_share", "A document key is 32 bytes.");
      const { iv, ct } = seal(o, id, share);
      const r = db.prepare("INSERT OR IGNORE INTO shares (object, owner, iv, ct, created_at) VALUES (?, ?, ?, ?, ?)").run(id, o, iv, ct, now());
      if (r.changes !== 1) throw new HttpError(409, "share_exists", "This document already has a key.");
      return json(201, { stored: true });
    }],

    // The gateway couldn't finish the upload: forget a key stored moments ago (never an older one).
    ["DELETE", "/internal/shares/:id", ({ claims, params }) => {
      gatewayOnly(claims);
      const o = owner(claims), id = object(params.id);
      const r = db.prepare("DELETE FROM shares WHERE object = ? AND owner = ? AND created_at > ?").run(id, o, now() - rollbackWindowMs);
      return json(200, { removed: r.changes === 1 });
    }],

    // Release one document's key: its owner, a fresh live step-up, under the hourly cap.
    ["GET", "/shares/:id", ({ claims, params }) => {
      const o = owner(claims);
      stepUp(claims);
      const r = db.prepare("SELECT * FROM shares WHERE object = ?").get(object(params.id));
      if (!r) return json(404, { error: "no_share", message: "This document has no split key." }); // sealed before split keys
      if (r.owner !== o) throw new HttpError(404, "no_share", "This document has no split key here.");
      const t = now();
      db.prepare("DELETE FROM releases WHERE at < ?").run(t - HOUR);
      const n = db.prepare("SELECT COUNT(*) AS n FROM releases WHERE owner = ? AND at > ?").get(o, t - HOUR).n;
      if (n >= releasesPerHour) throw new HttpError(429, "share_rate_limited", "You've opened a lot of documents in the last hour. Wait a while and try again.");
      db.prepare("INSERT INTO releases (owner, at) VALUES (?, ?)").run(o, t);
      db.prepare("UPDATE shares SET released = released + 1, last_released_at = ? WHERE object = ?").run(t, r.object);
      return json(200, { share: b64u(open(r)) });
    }],

    // The document was deleted (the gateway calls this after the vault, under the same step-up).
    ["DELETE", "/shares/:id", ({ claims, params }) => {
      const o = owner(claims);
      stepUp(claims);
      mine(o, object(params.id));
      db.prepare("DELETE FROM shares WHERE object = ?").run(params.id);
      return json(200, { deleted: true });
    }],

    // Account closed: every key goes.
    ["DELETE", "/shares", ({ claims }) => {
      const o = owner(claims);
      stepUp(claims);
      const r = db.prepare("DELETE FROM shares WHERE owner = ?").run(o);
      db.prepare("DELETE FROM releases WHERE owner = ?").run(o);
      return json(200, { deleted: r.changes });
    }],
  ];

  const svc = createService({ name: "keyshare", port, routes, bodyLimit: 4 * 1024, verify: (t) => verifyAssertion(internalPk, t, "keyshare") });
  return { ...svc, close: () => db.close() };
}

if (isMain(import.meta.url)) createKeyshare().start();
