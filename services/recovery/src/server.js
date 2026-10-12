// recovery — moves an account seed to a new device without ever holding it.
//
//   links      a new device asks to join; a signed-in device seals the seed to it
//   card       the seed encrypted under the owner's recovery card (opaque here)
//   contacts   Shamir shares of the seed, each sealed to one recovery contact
//   requests   a new device asks for the card blob or the contacts' shares;
//              released only after RECOVERY_DELAY_MS, cancellable by the owner
//
// Everything stored here is ciphertext or public keys. The service's job is
// the rules: who may store what, which keys a code commits to, and when a
// request is released. See docs/RECOVERY.md.

import { randomBytes } from "node:crypto";
import { createService, openDb, env, json, parseJson, verifyAssertion, unb64u, b64u, HttpError, logger } from "@humid/svc";
import { suiteForEnvelope } from "@humid/crypto";
import { isEnvelope } from "@humid/codec";
import { sha3_256, toHex, identityId, STEP_UP_MAX_AGE_MS } from "@humid/htp";
import { keyCode, parseCode, LINK_LABEL, OFFER_LABEL, REQUEST_LABEL, MIN_CONTACTS, MAX_CONTACTS } from "@humid/recovery";

const HOUR = 3600_000;
const SIZES = { kemPk: 1568, xPk: 32, dsaPk: 2592 };
const ENVELOPE_MAX = 64 * 1024;

export function createRecovery({
  port = Number(env("PORT", "8084")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  delayMs = Number(env("RECOVERY_DELAY_MS", String(72 * HOUR))),
  linkTtlMs = 10 * 60_000,
  offerTtlMs = 15 * 60_000,
  collectTtlMs = 7 * 24 * HOUR,   // contacts have a week to respond
  releasedTtlMs = 7 * 24 * HOUR,  // a released request can be collected for a week
  maxOpenPerAccount = 3,
} = {}) {
  const log = logger("recovery");
  const db = openDb(dataDir, "recovery.db", [
    `CREATE TABLE links (
       code TEXT PRIMARY KEY, kem_pk BLOB NOT NULL, x_pk BLOB NOT NULL, platform TEXT,
       created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
       status TEXT NOT NULL, account TEXT, envelope BLOB)`,
    `CREATE TABLE cards (account TEXT PRIMARY KEY, tag TEXT NOT NULL UNIQUE, blob BLOB NOT NULL, created_at TEXT NOT NULL)`,
    `CREATE TABLE guardian_sets (owner TEXT PRIMARY KEY, threshold INTEGER NOT NULL, n INTEGER NOT NULL, created_at TEXT NOT NULL)`,
    `CREATE TABLE guardians (
       owner TEXT NOT NULL, contact TEXT NOT NULL, envelope BLOB NOT NULL, label BLOB, created_at TEXT NOT NULL,
       PRIMARY KEY (owner, contact))`,
    `CREATE INDEX guardians_contact ON guardians(contact)`,
    `CREATE TABLE offers (code TEXT PRIMARY KEY, account TEXT NOT NULL, kem_pk BLOB NOT NULL, x_pk BLOB NOT NULL, dsa_pk BLOB NOT NULL, expires_at INTEGER NOT NULL)`,
    `CREATE TABLE requests (
       id TEXT PRIMARY KEY, ref TEXT NOT NULL UNIQUE, code TEXT UNIQUE, method TEXT NOT NULL,
       account TEXT, kem_pk BLOB, x_pk BLOB, platform TEXT,
       created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, release_at INTEGER,
       threshold INTEGER, status TEXT NOT NULL, closed_at INTEGER)`,
    `CREATE INDEX requests_account ON requests(account, status)`,
    `CREATE TABLE approvals (request_id TEXT NOT NULL, contact TEXT NOT NULL, envelope BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (request_id, contact))`,
  ]);

  /* ---------- helpers ---------- */

  const now = () => Date.now();
  const fp = (b) => toHex(sha3_256(b));
  const needUser = (c) => { if (!c?.sub) throw new HttpError(401, "sign_in_required", "Sign in first"); return c.sub; };
  const needStepUp = (c) => {
    needUser(c);
    if (!c.stepUp || now() - c.stepUp.at > STEP_UP_MAX_AGE_MS) throw new HttpError(403, "step_up_required", "This needs a fresh biometric check.");
  };
  const key = (v, name) => {
    const b = unb64u(String(v ?? ""));
    if (b.length !== SIZES[name]) throw new HttpError(400, "bad_key", `${name} has the wrong length`);
    return b;
  };
  const codeParam = (s) => {
    const c = parseCode(s);
    if (!c) throw new HttpError(400, "bad_code", "That code isn't valid. It has 12 letters and numbers.");
    return c;
  };
  const platformOf = (s) => String(s || "a new device").slice(0, 40);

  /** A sealed envelope from the signed-in account, addressed to the given KEM key. */
  function checkEnvelope(bytes, { signerFp, recipientKemPk }) {
    if (!bytes?.length || bytes.length > ENVELOPE_MAX || !isEnvelope(bytes)) throw new HttpError(400, "bad_envelope", "Not a HumID envelope");
    let v;
    try { v = suiteForEnvelope(bytes).verify(bytes); } catch { throw new HttpError(400, "bad_envelope", "Envelope could not be parsed"); }
    if (!v.ok) throw new HttpError(400, "bad_signature", "Envelope signature is invalid");
    if (fp(Buffer.from(v.manifest.signer.mldsa87Pk, "base64")) !== signerFp) throw new HttpError(403, "wrong_signer", "Envelope was not sealed by your account key");
    if (v.manifest.recipient.kemPkFp !== fp(recipientKemPk)) throw new HttpError(403, "wrong_recipient", "Envelope is not sealed to the expected device");
  }

  function sweep() {
    const t = now();
    db.prepare("DELETE FROM links WHERE expires_at < ?").run(t);
    db.prepare("DELETE FROM offers WHERE expires_at < ?").run(t);
    db.prepare("UPDATE requests SET status = 'expired', closed_at = ? WHERE status IN ('collecting', 'waiting') AND expires_at < ?").run(t, t);
    db.prepare("DELETE FROM approvals WHERE request_id IN (SELECT id FROM requests WHERE status IN ('expired', 'cancelled', 'completed'))").run();
  }
  setInterval(sweep, 60_000).unref();

  const getRequest = db.prepare("SELECT * FROM requests WHERE id = ?");
  const approvalCount = (id) => db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE request_id = ?").get(id).n;
  const openRequests = (account) => db.prepare("SELECT COUNT(*) AS n FROM requests WHERE account = ? AND status IN ('collecting', 'waiting')").get(account).n;

  /* ---------- links: add a device you still have ---------- */

  const links = [
    ["POST", "/links", ({ body }) => {
      const r = parseJson(body);
      const kemPk = key(r.kemPk, "kemPk"), xPk = key(r.xPk, "xPk");
      const code = keyCode(LINK_LABEL, kemPk, xPk);
      sweep();
      if (db.prepare("SELECT 1 FROM links WHERE code = ?").get(code)) throw new HttpError(409, "code_in_use", "Start again on the new device.");
      const t = now();
      db.prepare("INSERT INTO links (code, kem_pk, x_pk, platform, created_at, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, 'waiting')")
        .run(code, kemPk, xPk, platformOf(r.platform), t, t + linkTtlMs);
      return json(201, { code, expiresAt: t + linkTtlMs });
    }],
    ["GET", "/links/:code", ({ params, claims }) => {
      needUser(claims);
      const l = db.prepare("SELECT * FROM links WHERE code = ? AND expires_at > ?").get(codeParam(params.code), now());
      if (!l) throw new HttpError(404, "unknown_code", "No device is waiting with that code. Codes last 10 minutes.");
      if (l.status !== "waiting") throw new HttpError(409, "already_used", "That code was already used.");
      return json(200, { code: l.code, kemPk: b64u(l.kem_pk), xPk: b64u(l.x_pk), platform: l.platform, createdAt: l.created_at, expiresAt: l.expires_at });
    }],
    ["POST", "/links/:code/approve", ({ params, claims, body }) => {
      needStepUp(claims);
      const l = db.prepare("SELECT * FROM links WHERE code = ? AND expires_at > ?").get(codeParam(params.code), now());
      if (!l) throw new HttpError(404, "unknown_code", "That code expired. Start again on the new device.");
      if (l.status !== "waiting") throw new HttpError(409, "already_used", "That code was already used.");
      checkEnvelope(body, { signerFp: claims.dsaFp, recipientKemPk: new Uint8Array(l.kem_pk) });
      db.prepare("UPDATE links SET status = 'approved', account = ?, envelope = ? WHERE code = ?").run(claims.sub, body, l.code);
      return json(200, { approved: true, platform: l.platform });
    }, { bodyLimit: ENVELOPE_MAX }],
    // Polled by the new device. The code is what it showed; the envelope inside is sealed to its own keys.
    ["GET", "/links/:code/result", ({ params }) => {
      const l = db.prepare("SELECT * FROM links WHERE code = ?").get(codeParam(params.code));
      if (!l || l.expires_at < now()) return json(200, { status: "expired" });
      if (l.status === "waiting") return json(200, { status: "waiting", expiresAt: l.expires_at });
      return json(200, { status: "approved", account: l.account, envelope: b64u(l.envelope) });
    }],
  ];

  /* ---------- recovery card ---------- */

  const card = [
    ["PUT", "/card", ({ claims, body }) => {
      needStepUp(claims);
      const r = parseJson(body);
      const tag = String(r.tag || "");
      if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(tag)) throw new HttpError(400, "bad_tag", "Card tag is malformed");
      const blob = unb64u(String(r.blob || ""));
      if (blob.length !== 12 + 64 + 16) throw new HttpError(400, "bad_blob", "Card blob has the wrong size");
      const at = new Date().toISOString();
      db.exec("BEGIN");
      db.prepare("DELETE FROM cards WHERE account = ?").run(claims.sub);
      db.prepare("INSERT INTO cards (account, tag, blob, created_at) VALUES (?, ?, ?, ?)").run(claims.sub, tag, blob, at);
      db.exec("COMMIT");
      return json(200, { createdAt: at, replaced: true });
    }],
    ["GET", "/card", ({ claims }) => {
      const c = db.prepare("SELECT created_at FROM cards WHERE account = ?").get(needUser(claims));
      return json(200, c ? { exists: true, createdAt: c.created_at } : { exists: false });
    }],
    ["DELETE", "/card", ({ claims }) => {
      needStepUp(claims);
      const n = db.prepare("DELETE FROM cards WHERE account = ?").run(claims.sub).changes;
      return json(200, { removed: n > 0 });
    }],
  ];

  /* ---------- recovery contacts ---------- */

  const contacts = [
    // "Be a recovery contact": publish your account's public keys under a short code.
    ["POST", "/offers", ({ claims, body }) => {
      const sub = needUser(claims);
      const r = parseJson(body);
      const kemPk = key(r.kemPk, "kemPk"), xPk = key(r.xPk, "xPk"), dsaPk = key(r.dsaPk, "dsaPk");
      if (identityId(dsaPk) !== sub) throw new HttpError(403, "not_your_keys", "Those keys are not this account's keys.");
      const code = keyCode(OFFER_LABEL, kemPk, xPk, dsaPk);
      const exp = now() + offerTtlMs;
      db.prepare("INSERT OR REPLACE INTO offers (code, account, kem_pk, x_pk, dsa_pk, expires_at) VALUES (?, ?, ?, ?, ?, ?)").run(code, sub, kemPk, xPk, dsaPk, exp);
      return json(201, { code, expiresAt: exp });
    }],
    ["GET", "/offers/:code", ({ params, claims }) => {
      const sub = needUser(claims);
      const o = db.prepare("SELECT * FROM offers WHERE code = ? AND expires_at > ?").get(codeParam(params.code), now());
      if (!o) throw new HttpError(404, "unknown_code", "No one is offering with that code. Contact codes last 15 minutes.");
      if (o.account === sub) throw new HttpError(400, "self", "You can't be your own recovery contact.");
      return json(200, { code: o.code, account: o.account, kemPk: b64u(o.kem_pk), xPk: b64u(o.x_pk), dsaPk: b64u(o.dsa_pk) });
    }],
    // Replace the owner's whole contact set. Each share must be sealed to the keys the contact offered.
    ["PUT", "/contacts", ({ claims, body }) => {
      needStepUp(claims);
      const r = parseJson(body);
      const list = Array.isArray(r.guardians) ? r.guardians : [];
      const n = list.length, t = Number(r.threshold);
      if (n < MIN_CONTACTS || n > MAX_CONTACTS) throw new HttpError(400, "bad_count", `Choose ${MIN_CONTACTS} to ${MAX_CONTACTS} recovery contacts.`);
      if (!(Number.isInteger(t) && t >= 2 && t <= n)) throw new HttpError(400, "bad_threshold", "Threshold must be between 2 and the number of contacts.");
      const seen = new Set();
      const rows = list.map((g) => {
        const offer = db.prepare("SELECT * FROM offers WHERE code = ? AND expires_at > ?").get(codeParam(g.offer), now());
        if (!offer) throw new HttpError(404, "offer_expired", "A contact code expired. Ask them for a new one.");
        if (offer.account !== g.contact) throw new HttpError(400, "offer_mismatch", "Contact code doesn't match that contact.");
        if (offer.account === claims.sub) throw new HttpError(400, "self", "You can't be your own recovery contact.");
        if (seen.has(offer.account)) throw new HttpError(400, "duplicate", "Each contact can only be added once.");
        seen.add(offer.account);
        const envelope = unb64u(String(g.envelope || ""));
        checkEnvelope(envelope, { signerFp: claims.dsaFp, recipientKemPk: new Uint8Array(offer.kem_pk) });
        const label = g.label ? unb64u(String(g.label)) : null;
        if (label && label.length > 512) throw new HttpError(400, "bad_label", "Label too long");
        return { contact: offer.account, envelope, label };
      });
      const at = new Date().toISOString();
      db.exec("BEGIN");
      db.prepare("DELETE FROM guardians WHERE owner = ?").run(claims.sub);
      db.prepare("INSERT OR REPLACE INTO guardian_sets (owner, threshold, n, created_at) VALUES (?, ?, ?, ?)").run(claims.sub, t, n, at);
      for (const g of rows) db.prepare("INSERT INTO guardians (owner, contact, envelope, label, created_at) VALUES (?, ?, ?, ?, ?)").run(claims.sub, g.contact, g.envelope, g.label, at);
      db.exec("COMMIT");
      return json(200, { threshold: t, n, createdAt: at });
    }, { bodyLimit: MAX_CONTACTS * (ENVELOPE_MAX + 2048) }],
    ["GET", "/contacts", ({ claims }) => {
      const sub = needUser(claims);
      const set = db.prepare("SELECT * FROM guardian_sets WHERE owner = ?").get(sub);
      if (!set) return json(200, { n: 0, guardians: [] });
      const gs = db.prepare("SELECT contact, label, created_at FROM guardians WHERE owner = ? ORDER BY rowid").all(sub);
      return json(200, { n: set.n, threshold: set.threshold, createdAt: set.created_at, guardians: gs.map((g) => ({ contact: g.contact, label: g.label ? b64u(g.label) : null, createdAt: g.created_at })) });
    }],
    ["DELETE", "/contacts", ({ claims }) => {
      needStepUp(claims);
      db.prepare("DELETE FROM guardians WHERE owner = ?").run(claims.sub);
      const n = db.prepare("DELETE FROM guardian_sets WHERE owner = ?").run(claims.sub).changes;
      return json(200, { removed: n > 0 });
    }],
    // Shares this account holds for other people.
    ["GET", "/protecting", ({ claims }) => {
      const sub = needUser(claims);
      const rows = db.prepare("SELECT owner, envelope, created_at FROM guardians WHERE contact = ? ORDER BY created_at").all(sub);
      return json(200, { shares: rows.map((g) => ({ owner: g.owner, envelope: b64u(g.envelope), createdAt: g.created_at })) });
    }],
  ];

  /* ---------- recovery requests ---------- */

  const requestView = (q, { secret = false } = {}) => {
    const approvals = q.method === "contacts" ? approvalCount(q.id) : undefined;
    return {
      ...(secret ? { id: q.id } : {}), ref: q.ref, method: q.method, status: q.status, platform: q.platform,
      createdAt: q.created_at, releaseAt: q.release_at, expiresAt: q.expires_at,
      approvals, threshold: q.threshold ?? undefined,
    };
  };

  const requests = [
    // A new device starts a recovery. No sign-in: it has nothing to sign in with yet.
    ["POST", "/requests", ({ body }) => {
      const r = parseJson(body);
      const id = randomBytes(16).toString("base64url"), ref = randomBytes(8).toString("hex");
      const t = now();
      sweep();
      if (r.method === "card") {
        const c = db.prepare("SELECT account FROM cards WHERE tag = ?").get(String(r.tag || ""));
        if (!c) throw new HttpError(404, "unknown_card", "That recovery card isn't on file. Check the code, or it may have been replaced.");
        if (openRequests(c.account) >= maxOpenPerAccount) throw new HttpError(429, "too_many_requests", "There are already recoveries waiting for this HumID.");
        db.prepare(`INSERT INTO requests (id, ref, method, account, platform, created_at, expires_at, release_at, status)
                    VALUES (?, ?, 'card', ?, ?, ?, ?, ?, 'waiting')`)
          .run(id, ref, c.account, platformOf(r.platform), t, t + delayMs + releasedTtlMs, t + delayMs);
        return json(201, { ...requestView(getRequest.get(id), { secret: true }), account: c.account });
      }
      if (r.method === "contacts") {
        const kemPk = key(r.kemPk, "kemPk"), xPk = key(r.xPk, "xPk");
        const code = keyCode(REQUEST_LABEL, kemPk, xPk);
        if (db.prepare("SELECT 1 FROM requests WHERE code = ?").get(code)) throw new HttpError(409, "code_in_use", "Start again.");
        db.prepare(`INSERT INTO requests (id, ref, code, method, kem_pk, x_pk, platform, created_at, expires_at, status)
                    VALUES (?, ?, ?, 'contacts', ?, ?, ?, ?, ?, 'collecting')`)
          .run(id, ref, code, kemPk, xPk, platformOf(r.platform), t, t + collectTtlMs);
        return json(201, { ...requestView(getRequest.get(id), { secret: true }), code });
      }
      throw new HttpError(400, "bad_method", "Recover with a card or with contacts.");
    }],

    // Polled by the new device. The id is a 128-bit secret only it knows.
    ["GET", "/requests/:id", ({ params }) => {
      const q = getRequest.get(params.id);
      if (!q) throw new HttpError(404, "unknown_request", "No such recovery.");
      const v = { ...requestView(q, { secret: true }), account: q.account };
      if (q.status === "waiting" && q.release_at && now() >= q.release_at) {
        if (q.method === "card") {
          const c = db.prepare("SELECT blob FROM cards WHERE account = ?").get(q.account);
          if (!c) return json(200, { ...v, status: "cancelled", reason: "card_replaced" });
          return json(200, { ...v, status: "released", blob: b64u(c.blob) });
        }
        const shares = db.prepare("SELECT envelope FROM approvals WHERE request_id = ? ORDER BY created_at").all(q.id).map((a) => b64u(a.envelope));
        return json(200, { ...v, status: "released", shares });
      }
      return json(200, v);
    }],

    // Gateway only: the recovered device has joined the account.
    ["POST", "/requests/:id/complete", ({ params, claims, body }) => {
      if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only");
      const q = getRequest.get(params.id);
      const r = parseJson(body);
      if (!q || q.account !== r.account || q.status !== "waiting" || !q.release_at || now() < q.release_at) {
        throw new HttpError(409, "not_released", "That recovery is not released.");
      }
      db.prepare("UPDATE requests SET status = 'completed', closed_at = ? WHERE id = ?").run(now(), q.id);
      return json(200, { completed: true, method: q.method, ref: q.ref });
    }],

    // A contact looks up a recovery code someone sent them.
    ["GET", "/help/:code", ({ params, claims }) => {
      needUser(claims);
      const q = db.prepare("SELECT * FROM requests WHERE code = ?").get(codeParam(params.code));
      if (!q || !["collecting", "waiting"].includes(q.status) || q.expires_at < now()) throw new HttpError(404, "unknown_code", "No recovery is waiting with that code.");
      return json(200, { code: q.code, kemPk: b64u(q.kem_pk), xPk: b64u(q.x_pk), platform: q.platform, createdAt: q.created_at, status: q.status });
    }],

    // A contact releases their share to the requesting device, re-sealed to its recovery key.
    ["POST", "/help/:code", ({ params, claims, body }) => {
      needStepUp(claims);
      const r = parseJson(body);
      const q = db.prepare("SELECT * FROM requests WHERE code = ?").get(codeParam(params.code));
      if (!q || !["collecting", "waiting"].includes(q.status) || q.expires_at < now()) throw new HttpError(404, "unknown_code", "No recovery is waiting with that code.");
      const owner = String(r.owner || "");
      const g = db.prepare("SELECT 1 FROM guardians WHERE owner = ? AND contact = ?").get(owner, claims.sub);
      if (!g) throw new HttpError(403, "not_a_contact", "You aren't a recovery contact for that person.");
      if (q.account && q.account !== owner) throw new HttpError(409, "different_person", "Another contact already linked this recovery to someone else.");
      const envelope = unb64u(String(r.envelope || ""));
      checkEnvelope(envelope, { signerFp: claims.dsaFp, recipientKemPk: new Uint8Array(q.kem_pk) });
      const set = db.prepare("SELECT threshold FROM guardian_sets WHERE owner = ?").get(owner);
      const first = !q.account;
      if (first && openRequests(owner) >= maxOpenPerAccount) throw new HttpError(429, "too_many_requests", "There are already recoveries waiting for this person.");
      db.exec("BEGIN");
      db.prepare("INSERT OR REPLACE INTO approvals (request_id, contact, envelope, created_at) VALUES (?, ?, ?, ?)").run(q.id, claims.sub, envelope, now());
      const count = approvalCount(q.id);
      let releaseAt = q.release_at;
      let status = q.status;
      if (!releaseAt && count >= set.threshold) { releaseAt = now() + delayMs; status = "waiting"; }
      db.prepare("UPDATE requests SET account = ?, threshold = ?, release_at = ?, status = ?, expires_at = ? WHERE id = ?")
        .run(owner, set.threshold, releaseAt, status, releaseAt ? releaseAt + releasedTtlMs : q.expires_at, q.id);
      db.exec("COMMIT");
      return json(200, { owner, approvals: count, threshold: set.threshold, releaseAt, first, ref: q.ref, platform: q.platform });
    }, { bodyLimit: ENVELOPE_MAX + 4096 }],

    // The owner's devices: recoveries in progress for this account.
    ["GET", "/alerts", ({ claims }) => {
      const sub = needUser(claims);
      sweep();
      const rows = db.prepare("SELECT * FROM requests WHERE account = ? AND status IN ('collecting', 'waiting') ORDER BY created_at DESC").all(sub);
      return json(200, { alerts: rows.map((q) => requestView(q)) });
    }],
    ["POST", "/alerts/:ref/cancel", ({ params, claims }) => {
      needStepUp(claims);
      const q = db.prepare("SELECT * FROM requests WHERE ref = ? AND account = ?").get(String(params.ref), claims.sub);
      if (!q || !["collecting", "waiting"].includes(q.status)) throw new HttpError(404, "unknown_request", "That recovery is no longer open.");
      db.prepare("UPDATE requests SET status = 'cancelled', closed_at = ? WHERE id = ?").run(now(), q.id);
      db.prepare("DELETE FROM approvals WHERE request_id = ?").run(q.id);
      return json(200, { cancelled: true, method: q.method, ref: q.ref, platform: q.platform });
    }],
  ];

  log.info("recovery delay", { hours: +(delayMs / HOUR).toFixed(3) });
  return createService({
    name: "recovery", port, routes: [...links, ...card, ...contacts, ...requests], bodyLimit: 64 * 1024,
    verify: (t) => verifyAssertion(internalPk, t, "recovery"),
  });
}

if (import.meta.url === `file://${process.argv[1]}`) createRecovery().start();
