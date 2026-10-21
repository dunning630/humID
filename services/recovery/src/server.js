// recovery — moves an account seed to a new device without ever holding it.
//
//   links      a new device asks to join; a signed-in device seals the seed to it
//   card       a seal card: the seed (v1) or the card part (v2) under the owner's card
//   contacts   Shamir shares, each sealed to one recovery contact: of the seed (v1),
//              or of the witness part (v2)
//   anchor     the anchor part (v2), encrypted under the owner's identity anchor:
//              a passport or ID card chip, checked with ICAO passive authentication
//   requests   a new device asks for its parts back; released only after a wait
//              that depends on the evidence, cancellable by the owner's devices
//   stations   operators who check a person and their ID in person
//   duress     a silent signal from the owner that doubles every recovery wait
//
// Two-proof recovery (v2, "quorum"): the seed is split 2-of-3 into a witness,
// an anchor and a card part. A recovery needs two DIFFERENT kinds of proof, and
// waits longer the weaker they are (see quorumDelay in @humid/recovery).
//
// Everything stored here is ciphertext or public keys, except the anchor part,
// which is encrypted under a key derived from this server's secret AND the
// holder's identity fields (never stored), so a copy of the database alone
// opens nothing. See docs/RECOVERY.md and docs/CONTINUITY.md.

import { randomBytes, hkdfSync, createCipheriv, createDecipheriv } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { createService, openDb, env, json, parseJson, parseObject, verifyAssertion, unb64u, b64u, HttpError, logger, isMain } from "@humid/svc";
import { suiteForEnvelope } from "@humid/crypto";
import { isEnvelope } from "@humid/codec";
import { sha3_256, toHex, identityId, STEP_UP_MAX_AGE_MS } from "@humid/htp";
import {
  keyCode, parseCode, LINK_LABEL, OFFER_LABEL, REQUEST_LABEL, MIN_CONTACTS, MAX_CONTACTS,
  QUORUM, decodeQuorumPart, quorumDelay, evidenceLabel, DURESS_WINDOW_MS, CARD_PART_BLOB_BYTES, CARD_FULL_BLOB_BYTES,
} from "@humid/recovery";
import { passiveAuth, activeAuth, anchorOf, anchorSummary, stableIdentity, loadCscas, loadCscasFromTrustFile, AnchorError } from "@humid/anchor";

const HOUR = 3600_000;
const SIZES = { kemPk: 1568, xPk: 32, dsaPk: 2592 };
const ENVELOPE_MAX = 64 * 1024;
const CHIP_MAX = 48 * 1024;
const list = (v) => String(v || "").split(",").map((x) => x.trim()).filter(Boolean);

export function createRecovery({
  port = Number(env("PORT", "8084")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  delayMs = Number(env("RECOVERY_DELAY_MS", String(72 * HOUR))),
  cscaDir = env("HUMID_CSCA_DIR", ""),
  trustFile = env("HUMID_TRUST_STORE", ""),   // trust.json from tools/trust.mjs (ICAO / BSI master lists)
  cscas: extraCscas = [],
  stations = list(env("HUMID_STATION_ACCOUNTS", "")),
  linkTtlMs = 10 * 60_000,
  offerTtlMs = 15 * 60_000,
  collectTtlMs = 7 * 24 * HOUR,   // contacts have a week to respond
  releasedTtlMs = 7 * 24 * HOUR,  // a released request can be collected for a week
  challengeTtlMs = 5 * 60_000,
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
    // v2: two-proof recovery, identity anchors, stations, duress
    `ALTER TABLE cards ADD COLUMN scheme TEXT NOT NULL DEFAULT 'full';
     ALTER TABLE guardian_sets ADD COLUMN scheme TEXT NOT NULL DEFAULT 'full';
     CREATE TABLE anchors (
       account TEXT PRIMARY KEY, anchor TEXT NOT NULL UNIQUE, blob BLOB NOT NULL,
       document TEXT, country TEXT, created_at TEXT NOT NULL);
     ALTER TABLE requests ADD COLUMN card_ok INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE requests ADD COLUMN anchor_mode TEXT;
     ALTER TABLE requests ADD COLUMN anchor_blob BLOB;
     ALTER TABLE requests ADD COLUMN station TEXT;
     ALTER TABLE requests ADD COLUMN quorum_at INTEGER;
     CREATE TABLE challenges (request_id TEXT PRIMARY KEY, nonce BLOB NOT NULL, expires_at INTEGER NOT NULL);
     CREATE TABLE duress (account TEXT PRIMARY KEY, last_at INTEGER NOT NULL, count INTEGER NOT NULL);
     CREATE TABLE settings (account TEXT PRIMARY KEY, duress_alert INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)`,
  ]);

  /* ---------- the anchor secret and trusted countries ---------- */

  mkdirSync(dataDir, { recursive: true });
  const secretFile = `${dataDir}/anchor-secret.bin`;
  if (!existsSync(secretFile)) writeFileSync(secretFile, randomBytes(32), { mode: 0o600 });
  const anchorSecret = readFileSync(secretFile);
  const hmacKey = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.alloc(0), "HUMID-ANCHOR-v1 hmac", 32));
  // Country signing certificates: a folder of files, plus the trust store's
  // master-list CSCAs, re-read when the trust store file changes, so a
  // refreshed master list takes effect without a restart. A damaged trust
  // store keeps the last good set.
  const fixedCscas = [...loadCscas(cscaDir), ...extraCscas];
  let cscas = fixedCscas, trustMtime = -1;
  const currentCscas = () => {
    if (!trustFile) return cscas;
    let m = 0;
    try { m = statSync(trustFile).mtimeMs; } catch { m = 0; }
    if (m !== trustMtime) {
      try { cscas = [...fixedCscas, ...loadCscasFromTrustFile(trustFile)]; trustMtime = m; log.info("trust store loaded", { cscas: cscas.length }); }
      catch (e) { log.warn("trust store unreadable, keeping the last good set", { error: String(e?.message || e) }); trustMtime = m; }
    }
    return cscas;
  };
  const stationSet = new Set(stations);
  log.info("identity anchors", { countries: currentCscas().length, stations: stationSet.size });

  /** AES-256-GCM under a key from the server secret and `context` (identity fields, or a request id). */
  function wrap(context, salt, plain) {
    const key = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.from(salt), `HUMID-ANCHOR-WRAP-v1|${context}`, 32));
    const nonce = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", key, nonce);
    c.setAAD(Buffer.from(salt));
    const ct = Buffer.concat([c.update(plain), c.final()]);
    key.fill(0);
    return Buffer.concat([nonce, ct, c.getAuthTag()]);
  }
  function unwrap(context, salt, blob) {
    const key = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.from(salt), `HUMID-ANCHOR-WRAP-v1|${context}`, 32));
    try {
      const b = Buffer.from(blob);
      const d = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12));
      d.setAAD(Buffer.from(salt));
      d.setAuthTag(b.subarray(b.length - 16));
      return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]);
    } catch { throw new HttpError(409, "anchor_mismatch", "That ID doesn't open this HumID's anchor."); }
    finally { key.fill(0); }
  }

  /* ---------- helpers ---------- */

  const now = () => Date.now();
  const fp = (b) => toHex(sha3_256(b));
  const needUser = (c) => { if (!c?.sub) throw new HttpError(401, "sign_in_required", "Sign in first"); return c.sub; };
  const needStepUp = (c) => {
    needUser(c);
    if (!c.stepUp || now() - c.stepUp.at > STEP_UP_MAX_AGE_MS) throw new HttpError(403, "step_up_required", "This needs a fresh biometric check.");
  };
  const gatewayOnly = (c) => { if (c?.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
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
  // A device's own name for itself: shown to the person, never trusted. No control,
  // zero-width or direction-override characters (they can disguise what's shown).
  const platformOf = (s) => String(s || "").replace(/[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g, "").trim().slice(0, 40) || "a new device";

  /** A sealed envelope from the signed-in account, addressed to the given KEM key. */
  function checkEnvelope(bytes, { signerFp, recipientKemPk }) {
    if (!bytes?.length || bytes.length > ENVELOPE_MAX || !isEnvelope(bytes)) throw new HttpError(400, "bad_envelope", "Not a HumID envelope");
    let v;
    try { v = suiteForEnvelope(bytes).verify(bytes); } catch { throw new HttpError(400, "bad_envelope", "Envelope could not be parsed"); }
    if (!v.ok) throw new HttpError(400, "bad_signature", "Envelope signature is invalid");
    if (fp(Buffer.from(v.manifest.signer.mldsa87Pk, "base64")) !== signerFp) throw new HttpError(403, "wrong_signer", "Envelope was not sealed by your account key");
    if (v.manifest.recipient.kemPkFp !== fp(recipientKemPk)) throw new HttpError(403, "wrong_recipient", "Envelope is not sealed to the expected device");
  }

  /** Chip data from a request body: { dg1, sod, dg15? } as bytes. */
  function chipOf(c) {
    const b = (v, name, need) => {
      if (v == null || v === "") { if (need) throw new HttpError(400, "bad_chip_data", `The ID chip data is missing ${name}.`); return undefined; }
      const x = unb64u(String(v));
      if (!x.length || x.length > CHIP_MAX) throw new HttpError(400, "bad_chip_data", `${name} has the wrong size.`);
      return x;
    };
    return { dg1: b(c?.dg1, "DG1", true), sod: b(c?.sod, "the security object", true), dg15: b(c?.dg15, "DG15", false) };
  }
  /** Passive authentication, as an HTTP error on failure. */
  function checkChip(chip) {
    try { return passiveAuth(chip, { cscas: currentCscas() }); }
    catch (e) {
      if (e instanceof AnchorError) throw new HttpError(e.code === "no_trust" ? 501 : 422, e.code, e.message);
      throw e;
    }
  }

  function sweep() {
    const t = now();
    db.prepare("DELETE FROM links WHERE expires_at < ?").run(t);
    db.prepare("DELETE FROM offers WHERE expires_at < ?").run(t);
    db.prepare("DELETE FROM challenges WHERE expires_at < ?").run(t);
    db.prepare("UPDATE requests SET status = 'expired', closed_at = ? WHERE status IN ('collecting', 'waiting') AND expires_at < ?").run(t, t);
    db.prepare("DELETE FROM approvals WHERE request_id IN (SELECT id FROM requests WHERE status IN ('expired', 'cancelled', 'completed'))").run();
    db.prepare("UPDATE requests SET anchor_blob = NULL WHERE status IN ('expired', 'cancelled', 'completed') AND anchor_blob IS NOT NULL").run();
  }
  setInterval(sweep, 60_000).unref();

  const getRequest = db.prepare("SELECT * FROM requests WHERE id = ?");
  const approvalCount = (id) => db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE request_id = ?").get(id).n;
  const openRequests = (account) => db.prepare("SELECT COUNT(*) AS n FROM requests WHERE account = ? AND status IN ('collecting', 'waiting')").get(account).n;
  const recentDuress = (account, t = now()) => {
    const d = account && db.prepare("SELECT last_at FROM duress WHERE account = ?").get(account);
    return !!d && t - d.last_at < DURESS_WINDOW_MS;
  };
  const guardianSet = (owner) => db.prepare("SELECT * FROM guardian_sets WHERE owner = ?").get(owner);

  /* ---------- two-proof recovery: which proofs a request has, and when it opens ---------- */

  /** The kinds of proof a quorum request holds right now. */
  function kindsOf(q) {
    const k = [];
    if (q.card_ok) k.push("card");
    if (q.account && q.threshold && approvalCount(q.id) >= q.threshold) k.push("witness");
    if (q.anchor_mode) k.push("anchor");
    return k;
  }

  /** Recompute a quorum request's release time after new evidence (or a duress signal). */
  function evaluate(id) {
    const q = getRequest.get(id);
    if (!q || q.method !== "quorum" || !["collecting", "waiting"].includes(q.status)) return q;
    const kinds = kindsOf(q);
    const delay = quorumDelay(kinds, { base: delayMs, anchorMode: q.anchor_mode, duress: recentDuress(q.account) });
    if (delay == null) return q;
    const quorumAt = q.quorum_at ?? now();
    const releaseAt = quorumAt + delay;
    db.prepare("UPDATE requests SET quorum_at = ?, release_at = ?, status = 'waiting', expires_at = ? WHERE id = ?")
      .run(quorumAt, releaseAt, releaseAt + releasedTtlMs, q.id);
    return getRequest.get(id);
  }

  /** Tie a request to an account the first time a proof names it. Throws if proofs disagree. */
  function bindAccount(q, account) {
    if (q.account && q.account !== account) throw new HttpError(409, "different_person", "These proofs belong to different people. Nothing was released.");
    if (!q.account && openRequests(account) >= maxOpenPerAccount) throw new HttpError(429, "too_many_requests", "There are already recoveries waiting for this HumID.");
    const first = !q.account;
    if (first) {
      const set = guardianSet(account);
      db.prepare("UPDATE requests SET account = ?, threshold = ? WHERE id = ?").run(account, set?.scheme === "quorum" ? set.threshold : null, q.id);
    }
    return first;
  }

  /* ---------- links: add a device you still have ---------- */

  const links = [
    ["POST", "/links", ({ body }) => {
      const r = parseObject(body);
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

  /* ---------- seal card ---------- */

  const card = [
    ["PUT", "/card", ({ claims, body }) => {
      needStepUp(claims);
      const r = parseObject(body);
      const tag = String(r.tag || "");
      if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(tag)) throw new HttpError(400, "bad_tag", "Card tag is malformed");
      const blob = unb64u(String(r.blob || ""));
      // v1 cards hold the whole seed; v2 cards hold only the card part of two-proof recovery.
      const scheme = blob.length === CARD_PART_BLOB_BYTES ? "quorum" : blob.length === CARD_FULL_BLOB_BYTES ? "full" : null;
      if (!scheme) throw new HttpError(400, "bad_blob", "Card blob has the wrong size");
      const at = new Date().toISOString();
      db.exec("BEGIN");
      db.prepare("DELETE FROM cards WHERE account = ?").run(claims.sub);
      db.prepare("INSERT INTO cards (account, tag, blob, created_at, scheme) VALUES (?, ?, ?, ?, ?)").run(claims.sub, tag, blob, at, scheme);
      db.exec("COMMIT");
      return json(200, { createdAt: at, replaced: true, scheme });
    }],
    ["GET", "/card", ({ claims }) => {
      const c = db.prepare("SELECT created_at, scheme FROM cards WHERE account = ?").get(needUser(claims));
      return json(200, c ? { exists: true, createdAt: c.created_at, scheme: c.scheme } : { exists: false });
    }],
    ["DELETE", "/card", ({ claims }) => {
      needStepUp(claims);
      const n = db.prepare("DELETE FROM cards WHERE account = ?").run(claims.sub).changes;
      return json(200, { removed: n > 0 });
    }],
  ];

  /* ---------- identity anchor ---------- */

  const anchor = [
    ["GET", "/anchor", ({ claims }) => {
      const a = db.prepare("SELECT document, country, created_at FROM anchors WHERE account = ?").get(needUser(claims));
      return json(200, { available: currentCscas().length > 0, exists: !!a, ...(a ? { document: a.document, country: a.country, createdAt: a.created_at } : {}) });
    }],
    // The owner binds their passport or ID chip. The anchor part arrives over the encrypted channel
    // and is stored only encrypted under the identity fields, which aren't stored.
    ["PUT", "/anchor", ({ claims, body }) => {
      needStepUp(claims);
      const r = parseObject(body);
      const part = decodeQuorumPart(unb64u(String(r.part || "")));
      if (part.x !== QUORUM.anchor) throw new HttpError(400, "bad_part", "That isn't the anchor part.");
      const ok = checkChip(chipOf(r.chip));
      const anchorHash = anchorOf(ok.mrz, hmacKey);
      const taken = db.prepare("SELECT account FROM anchors WHERE anchor = ?").get(anchorHash);
      if (taken && taken.account !== claims.sub) throw new HttpError(409, "anchor_taken", "This ID already anchors another HumID.");
      const blob = wrap(stableIdentity(ok.mrz), claims.sub, Buffer.from(unb64u(String(r.part))));
      const { document, country } = anchorSummary(ok.mrz);
      const at = new Date().toISOString();
      db.prepare("INSERT OR REPLACE INTO anchors (account, anchor, blob, document, country, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(claims.sub, anchorHash, blob, document, country, at);
      return json(200, { createdAt: at, document, country });
    }, { bodyLimit: 3 * CHIP_MAX }],
    ["DELETE", "/anchor", ({ claims }) => {
      needStepUp(claims);
      const n = db.prepare("DELETE FROM anchors WHERE account = ?").run(claims.sub).changes;
      return json(200, { removed: n > 0 });
    }],
  ];

  /** Find the anchored account for a verified chip and decrypt its anchor part. */
  function openAnchor(mrz) {
    const a = db.prepare("SELECT * FROM anchors WHERE anchor = ?").get(anchorOf(mrz, hmacKey));
    if (!a) throw new HttpError(404, "unknown_anchor", "This ID doesn't anchor any HumID on this server.");
    return { account: a.account, part: unwrap(stableIdentity(mrz), a.account, a.blob) };
  }

  /* ---------- recovery contacts ---------- */

  const contacts = [
    // "Be a recovery contact": publish your account's public keys under a short code.
    ["POST", "/offers", ({ claims, body }) => {
      const sub = needUser(claims);
      const r = parseObject(body);
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
    // scheme "quorum": the shares rebuild the witness part; "full" (v1): they rebuild the seed.
    ["PUT", "/contacts", ({ claims, body }) => {
      needStepUp(claims);
      const r = parseObject(body);
      const scheme = r.scheme === "quorum" ? "quorum" : "full";
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
      db.prepare("INSERT OR REPLACE INTO guardian_sets (owner, threshold, n, created_at, scheme) VALUES (?, ?, ?, ?, ?)").run(claims.sub, t, n, at, scheme);
      for (const g of rows) db.prepare("INSERT INTO guardians (owner, contact, envelope, label, created_at) VALUES (?, ?, ?, ?, ?)").run(claims.sub, g.contact, g.envelope, g.label, at);
      db.exec("COMMIT");
      return json(200, { threshold: t, n, createdAt: at, scheme });
    }, { bodyLimit: MAX_CONTACTS * (ENVELOPE_MAX + 2048) }],
    ["GET", "/contacts", ({ claims }) => {
      const sub = needUser(claims);
      const set = guardianSet(sub);
      if (!set) return json(200, { n: 0, guardians: [] });
      const gs = db.prepare("SELECT contact, label, created_at FROM guardians WHERE owner = ? ORDER BY rowid").all(sub);
      return json(200, { n: set.n, threshold: set.threshold, createdAt: set.created_at, scheme: set.scheme, guardians: gs.map((g) => ({ contact: g.contact, label: g.label ? b64u(g.label) : null, createdAt: g.created_at })) });
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
    // Witness alerts: recoveries in progress for people you protect, and duress signals they chose to share with you.
    ["GET", "/protecting/alerts", ({ claims }) => {
      const sub = needUser(claims);
      sweep();
      const owners = db.prepare("SELECT owner FROM guardians WHERE contact = ?").all(sub).map((r) => r.owner);
      const out = [];
      for (const owner of owners) {
        for (const q of db.prepare("SELECT * FROM requests WHERE account = ? AND status IN ('collecting', 'waiting') ORDER BY created_at DESC").all(owner)) {
          out.push({ kind: "recovery", owner, ...requestView(q) });
        }
        const d = db.prepare("SELECT d.last_at FROM duress d JOIN settings s ON s.account = d.account WHERE d.account = ? AND s.duress_alert = 1").get(owner);
        if (d && now() - d.last_at < 7 * 24 * HOUR) out.push({ kind: "duress", owner, at: d.last_at });
      }
      return json(200, { alerts: out });
    }],
  ];

  /* ---------- recovery requests ---------- */

  function requestView(q, { secret = false } = {}) {
    const approvals = q.account && q.threshold ? approvalCount(q.id) : q.method === "contacts" ? approvalCount(q.id) : undefined;
    const kinds = q.method === "quorum" ? kindsOf(q) : undefined;
    return {
      ...(secret ? { id: q.id } : {}), ref: q.ref, method: q.method, status: q.status, platform: q.platform,
      createdAt: q.created_at, releaseAt: q.release_at, expiresAt: q.expires_at,
      approvals, threshold: q.threshold ?? undefined,
      ...(kinds ? { kinds, anchorMode: q.anchor_mode || undefined, evidence: evidenceLabel(kinds, q.anchor_mode), duress: recentDuress(q.account) || undefined } : {}),
    };
  }

  const openQuorum = (id) => {
    const q = getRequest.get(String(id));
    if (!q || q.method !== "quorum") throw new HttpError(404, "unknown_request", "No such recovery.");
    if (!["collecting", "waiting"].includes(q.status) || q.expires_at < now()) throw new HttpError(409, "closed", "This recovery is no longer open. Start again.");
    return q;
  };

  /** Attach the seal card to a quorum request. */
  function attachCard(q, tag) {
    const c = db.prepare("SELECT account, scheme FROM cards WHERE tag = ?").get(String(tag || ""));
    if (!c) throw new HttpError(404, "unknown_card", "That seal card isn't on file. Check the code, or it may have been replaced.");
    if (c.scheme !== "quorum") throw new HttpError(409, "old_card", "This is an older single-proof card. Recover with it on its own.");
    const first = bindAccount(q, c.account);
    db.prepare("UPDATE requests SET card_ok = 1 WHERE id = ?").run(q.id);
    return first;
  }

  const created = (q, extra = {}) => json(201, { ...requestView(getRequest.get(q.id), { secret: true }), account: getRequest.get(q.id).account, ...extra });

  const requests = [
    // A new device starts a recovery. No sign-in: it has nothing to sign in with yet.
    ["POST", "/requests", ({ body }) => {
      const r = parseObject(body);
      const id = randomBytes(16).toString("base64url"), ref = randomBytes(8).toString("hex");
      const t = now();
      sweep();
      if (r.method === "card") {
        const c = db.prepare("SELECT account, scheme FROM cards WHERE tag = ?").get(String(r.tag || ""));
        if (!c) throw new HttpError(404, "unknown_card", "That recovery card isn't on file. Check the code, or it may have been replaced.");
        if (c.scheme === "quorum") throw new HttpError(409, "needs_second_proof", "This seal card is one of two proofs. Choose Prove it's me, then add your witnesses or your ID.");
        if (openRequests(c.account) >= maxOpenPerAccount) throw new HttpError(429, "too_many_requests", "There are already recoveries waiting for this HumID.");
        const delay = recentDuress(c.account) ? delayMs * 2 : delayMs;
        db.prepare(`INSERT INTO requests (id, ref, method, account, platform, created_at, expires_at, release_at, status)
                    VALUES (?, ?, 'card', ?, ?, ?, ?, ?, 'waiting')`)
          .run(id, ref, c.account, platformOf(r.platform), t, t + delay + releasedTtlMs, t + delay);
        return json(201, { ...requestView(getRequest.get(id), { secret: true }), account: c.account });
      }
      if (r.method === "contacts" || r.method === "quorum") {
        const kemPk = key(r.kemPk, "kemPk"), xPk = key(r.xPk, "xPk");
        const code = keyCode(REQUEST_LABEL, kemPk, xPk);
        if (db.prepare("SELECT 1 FROM requests WHERE code = ?").get(code)) throw new HttpError(409, "code_in_use", "Start again.");
        db.prepare(`INSERT INTO requests (id, ref, code, method, kem_pk, x_pk, platform, created_at, expires_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'collecting')`)
          .run(id, ref, code, r.method, kemPk, xPk, platformOf(r.platform), t, t + collectTtlMs);
        let first = false;
        if (r.method === "quorum" && r.tag) {
          try { first = attachCard(getRequest.get(id), r.tag); }
          catch (e) { db.prepare("DELETE FROM requests WHERE id = ?").run(id); throw e; }
        }
        return created({ id }, { code, first });
      }
      throw new HttpError(400, "bad_method", "Recover with a card, with contacts, or with two proofs.");
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
        if (q.method === "contacts") return json(200, { ...v, status: "released", shares });
        // Quorum: every part the request earned. The device needs any two.
        const out = { ...v, status: "released" };
        const kinds = kindsOf(q);
        if (kinds.includes("witness")) out.shares = shares;
        if (kinds.includes("card")) {
          const c = db.prepare("SELECT blob, scheme FROM cards WHERE account = ?").get(q.account);
          if (c?.scheme === "quorum") out.blob = b64u(c.blob);
        }
        if (kinds.includes("anchor") && q.anchor_blob) out.anchorPart = b64u(unwrap(`request ${q.id}`, q.ref, q.anchor_blob));
        return json(200, out);
      }
      return json(200, v);
    }],

    // Two proofs: add the seal card after starting.
    ["POST", "/requests/:id/card", ({ params, body }) => {
      const q = openQuorum(params.id);
      const first = attachCard(q, parseObject(body).tag);
      const e = evaluate(q.id);
      return json(200, { ...requestView(e), account: e.account, first });
    }],
    // Two proofs: a fresh challenge for the ID chip (Active Authentication).
    ["POST", "/requests/:id/challenge", ({ params }) => {
      const q = openQuorum(params.id);
      const nonce = randomBytes(8);
      db.prepare("INSERT OR REPLACE INTO challenges (request_id, nonce, expires_at) VALUES (?, ?, ?)").run(q.id, nonce, now() + challengeTtlMs);
      return json(200, { nonce: b64u(nonce), expiresAt: now() + challengeTtlMs });
    }],
    // Two proofs: the ID chip, live. Passive authentication says the data is genuine;
    // the chip's answer to this request's challenge says the chip itself is here, not a copy.
    ["POST", "/requests/:id/anchor", ({ params, body }) => {
      const q = openQuorum(params.id);
      const r = parseObject(body);
      const chip = chipOf(r.chip);
      const ok = checkChip(chip);
      if (!ok.hasAaKey) throw new HttpError(422, "no_chip_proof", ok.aaRequired ? "Send the chip's authentication key (DG15) too." : "This ID's chip can't prove it's present. Verify at a HumID station instead.");
      const ch = db.prepare("SELECT nonce FROM challenges WHERE request_id = ? AND expires_at > ?").get(q.id, now());
      db.prepare("DELETE FROM challenges WHERE request_id = ?").run(q.id); // one answer per challenge
      if (!ch) throw new HttpError(409, "challenge_expired", "The chip challenge expired. Scan your ID again.");
      try { activeAuth({ dg15: chip.dg15, nonce: ch.nonce, signature: unb64u(String(r.signature || "")), hash: r.hash }); }
      catch (e) { if (e instanceof AnchorError) throw new HttpError(422, e.code, e.message); throw e; }
      const { account, part } = openAnchor(ok.mrz);
      const first = bindAccount(q, account);
      if (q.anchor_mode !== "station") {
        db.prepare("UPDATE requests SET anchor_mode = 'remote', anchor_blob = ? WHERE id = ?").run(wrap(`request ${q.id}`, q.ref, part), q.id);
      }
      part.fill(0);
      const e = evaluate(q.id);
      return json(200, { ...requestView(e), account: e.account, first });
    }, { bodyLimit: 3 * CHIP_MAX }],

    // Gateway only: the recovered device has joined the account.
    ["POST", "/requests/:id/complete", ({ params, claims, body }) => {
      gatewayOnly(claims);
      const q = getRequest.get(params.id);
      const r = parseObject(body);
      if (!q || q.account !== r.account || q.status !== "waiting" || !q.release_at || now() < q.release_at) {
        throw new HttpError(409, "not_released", "That recovery is not released.");
      }
      db.prepare("UPDATE requests SET status = 'completed', closed_at = ?, anchor_blob = NULL WHERE id = ?").run(now(), q.id);
      const kinds = q.method === "quorum" ? kindsOf(q) : [q.method];
      return json(200, { completed: true, method: q.method, ref: q.ref, kinds, anchorMode: q.anchor_mode || undefined, evidence: q.method === "quorum" ? evidenceLabel(kinds, q.anchor_mode) : undefined, station: q.station || undefined, waitedMs: q.release_at - (q.quorum_at ?? q.created_at) });
    }],

    // A contact looks up a recovery code someone sent them.
    ["GET", "/help/:code", ({ params, claims }) => {
      needUser(claims);
      const q = db.prepare("SELECT * FROM requests WHERE code = ?").get(codeParam(params.code));
      if (!q || !["collecting", "waiting"].includes(q.status) || q.expires_at < now()) throw new HttpError(404, "unknown_code", "No recovery is waiting with that code.");
      return json(200, { code: q.code, kemPk: b64u(q.kem_pk), xPk: b64u(q.x_pk), platform: q.platform, createdAt: q.created_at, status: q.status, method: q.method });
    }],

    // A contact releases their share to the requesting device, re-sealed to its recovery key.
    ["POST", "/help/:code", ({ params, claims, body }) => {
      needStepUp(claims);
      const r = parseObject(body);
      const q = db.prepare("SELECT * FROM requests WHERE code = ?").get(codeParam(params.code));
      if (!q || !["collecting", "waiting"].includes(q.status) || q.expires_at < now()) throw new HttpError(404, "unknown_code", "No recovery is waiting with that code.");
      const owner = String(r.owner || "");
      const g = db.prepare("SELECT 1 FROM guardians WHERE owner = ? AND contact = ?").get(owner, claims.sub);
      if (!g) throw new HttpError(403, "not_a_contact", "You aren't a recovery contact for that person.");
      const set = guardianSet(owner);
      // v1 contacts rebuild the seed on their own; v2 witnesses are one of two proofs.
      if (q.method === "contacts" && set.scheme === "quorum") throw new HttpError(409, "needs_second_proof", "They need to start again with Prove it's me: you're one of two proofs now.");
      if (q.method === "quorum" && set.scheme !== "quorum") throw new HttpError(409, "old_contacts", "They set you up with an older version. Ask them to start again with My recovery contacts.");
      if (q.account && q.account !== owner) throw new HttpError(409, "different_person", "Another proof already linked this recovery to someone else.");
      const envelope = unb64u(String(r.envelope || ""));
      checkEnvelope(envelope, { signerFp: claims.dsaFp, recipientKemPk: new Uint8Array(q.kem_pk) });
      const first = !q.account;
      if (first && openRequests(owner) >= maxOpenPerAccount) throw new HttpError(429, "too_many_requests", "There are already recoveries waiting for this person.");
      db.exec("BEGIN");
      db.prepare("INSERT OR REPLACE INTO approvals (request_id, contact, envelope, created_at) VALUES (?, ?, ?, ?)").run(q.id, claims.sub, envelope, now());
      const count = approvalCount(q.id);
      if (q.method === "quorum") {
        db.prepare("UPDATE requests SET account = ?, threshold = ? WHERE id = ?").run(owner, set.threshold, q.id);
        db.exec("COMMIT");
        const e = evaluate(q.id);
        return json(200, { owner, approvals: count, threshold: set.threshold, releaseAt: e.release_at, first, ref: q.ref, platform: q.platform, kinds: kindsOf(e), method: "quorum" });
      }
      let releaseAt = q.release_at;
      let status = q.status;
      if (!releaseAt && count >= set.threshold) { releaseAt = now() + (recentDuress(owner) ? delayMs * 2 : delayMs); status = "waiting"; }
      db.prepare("UPDATE requests SET account = ?, threshold = ?, release_at = ?, status = ?, expires_at = ?, quorum_at = ? WHERE id = ?")
        .run(owner, set.threshold, releaseAt, status, releaseAt ? releaseAt + releasedTtlMs : q.expires_at, q.quorum_at ?? (releaseAt ? now() : null), q.id);
      db.exec("COMMIT");
      return json(200, { owner, approvals: count, threshold: set.threshold, releaseAt, first, ref: q.ref, platform: q.platform, method: "contacts" });
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
      db.prepare("UPDATE requests SET status = 'cancelled', closed_at = ?, anchor_blob = NULL WHERE id = ?").run(now(), q.id);
      db.prepare("DELETE FROM approvals WHERE request_id = ?").run(q.id);
      return json(200, { cancelled: true, method: q.method, ref: q.ref, platform: q.platform });
    }],
  ];

  /* ---------- verification stations ---------- */
  // A station is a HumID account run by an operator (configured in HUMID_STATION_ACCOUNTS).
  // The operator checks the document and the person in front of them, the chip passes
  // passive authentication, and the station's own live biometric signs the result.

  const isStation = (sub) => stationSet.has(sub) || stationSet.has("*"); // "*": every account (local development only)
  const needStation = (c) => { const sub = needUser(c); if (!isStation(sub)) throw new HttpError(403, "not_a_station", "This HumID isn't a verification station."); return sub; };
  const stationRequest = (code) => {
    const q = db.prepare("SELECT * FROM requests WHERE code = ?").get(codeParam(code));
    if (!q || q.method !== "quorum" || !["collecting", "waiting"].includes(q.status) || q.expires_at < now()) throw new HttpError(404, "unknown_code", "No recovery is waiting with that code.");
    return q;
  };

  const station = [
    ["GET", "/station", ({ claims }) => json(200, { station: isStation(needUser(claims)), countries: currentCscas().length })],
    ["GET", "/station/requests/:code", ({ params, claims }) => {
      needStation(claims);
      const q = stationRequest(params.code);
      return json(200, { code: q.code, platform: q.platform, createdAt: q.created_at, status: q.status, kinds: kindsOf(q), anchorMode: q.anchor_mode || undefined });
    }],
    // A fresh challenge for the chip in front of the operator. A chip that can answer
    // (its SOD lists an Active Authentication key) must, so copied chip data isn't enough.
    ["POST", "/station/requests/:code/challenge", ({ params, claims }) => {
      needStation(claims);
      const q = stationRequest(params.code);
      const nonce = randomBytes(8);
      db.prepare("INSERT OR REPLACE INTO challenges (request_id, nonce, expires_at) VALUES (?, ?, ?)").run(`station:${q.id}`, nonce, now() + challengeTtlMs);
      return json(200, { nonce: b64u(nonce), expiresAt: now() + challengeTtlMs });
    }],
    ["POST", "/station/requests/:code/verify", ({ params, claims, body }) => {
      needStation(claims);
      needStepUp(claims);
      const q = stationRequest(params.code);
      const r = parseObject(body);
      const c = r.checks || {};
      if (!(c.document === true && c.face === true && c.present === true)) {
        throw new HttpError(400, "checks_incomplete", "Confirm the document is genuine, the face matches its photo, and the person is here.");
      }
      const chip = chipOf(r.chip);
      const ok = checkChip(chip);
      // One answer per challenge, whatever the outcome.
      const ch = db.prepare("SELECT nonce FROM challenges WHERE request_id = ? AND expires_at > ?").get(`station:${q.id}`, now());
      db.prepare("DELETE FROM challenges WHERE request_id = ?").run(`station:${q.id}`);
      if (ok.aaRequired) {
        if (!ok.hasAaKey) throw new HttpError(422, "no_chip_proof", "Read the chip itself: its authentication key (DG15) is missing.");
        if (!ch) throw new HttpError(409, "challenge_expired", "The chip challenge expired. Read the chip again.");
        try { activeAuth({ dg15: chip.dg15, nonce: ch.nonce, signature: unb64u(String(r.signature || "")), hash: r.hash }); }
        catch (e) { if (e instanceof AnchorError) throw new HttpError(422, e.code, e.message); throw e; }
      }
      const { account, part } = openAnchor(ok.mrz);
      if (account === claims.sub) throw new HttpError(400, "self", "A station can't verify its own operator.");
      const first = bindAccount(q, account);
      db.prepare("UPDATE requests SET anchor_mode = 'station', anchor_blob = ?, station = ? WHERE id = ?").run(wrap(`request ${q.id}`, q.ref, part), claims.sub, q.id);
      part.fill(0);
      const e = evaluate(q.id);
      // The operator learns the outcome, not whose HumID it is.
      return json(200, { verified: true, kinds: kindsOf(e), releaseAt: e.release_at, platform: e.platform, ref: e.ref, account: e.account, first, country: ok.issuerCountry, chipProof: ok.aaRequired });
    }, { bodyLimit: 3 * CHIP_MAX }],
  ];

  /* ---------- duress and settings ---------- */

  const duress = [
    // Gateway only: the owner unlocked with their duress gesture.
    ["POST", "/internal/duress", ({ claims, body }) => {
      gatewayOnly(claims);
      const { account } = parseObject(body);
      if (!/^hid_[0-9a-f]{40}$/.test(String(account))) throw new HttpError(400, "bad_subject", "Unknown subject");
      db.prepare(`INSERT INTO duress (account, last_at, count) VALUES (?, ?, 1)
                  ON CONFLICT(account) DO UPDATE SET last_at = excluded.last_at, count = count + 1`).run(account, now());
      // Every recovery already under way waits twice as long now.
      const open = db.prepare("SELECT * FROM requests WHERE account = ? AND status IN ('collecting', 'waiting')").all(account);
      for (const q of open) {
        if (q.method === "quorum") { evaluate(q.id); continue; }
        if (!q.release_at) continue; // contacts still collecting: the wait will start doubled
        const releaseAt = Math.max(q.release_at, (q.quorum_at ?? q.created_at) + 2 * delayMs);
        db.prepare("UPDATE requests SET release_at = ?, expires_at = ? WHERE id = ?").run(releaseAt, releaseAt + releasedTtlMs, q.id);
      }
      const s = db.prepare("SELECT duress_alert FROM settings WHERE account = ?").get(account);
      return json(200, { recorded: true, slowed: open.length, alertWitnesses: !!s?.duress_alert });
    }],
    ["GET", "/settings", ({ claims }) => {
      const s = db.prepare("SELECT * FROM settings WHERE account = ?").get(needUser(claims));
      return json(200, { duressAlert: !!s?.duress_alert });
    }],
    ["PUT", "/settings", ({ claims, body }) => {
      needStepUp(claims);
      const r = parseObject(body);
      db.prepare(`INSERT INTO settings (account, duress_alert, updated_at) VALUES (?, ?, ?)
                  ON CONFLICT(account) DO UPDATE SET duress_alert = excluded.duress_alert, updated_at = excluded.updated_at`)
        .run(claims.sub, r.duressAlert ? 1 : 0, new Date().toISOString());
      return json(200, { duressAlert: !!r.duressAlert });
    }],
  ];

  log.info("recovery delay", { hours: +(delayMs / HOUR).toFixed(3) });
  return createService({
    name: "recovery", port, routes: [...links, ...card, ...anchor, ...contacts, ...requests, ...station, ...duress], bodyLimit: 64 * 1024,
    verify: (t) => verifyAssertion(internalPk, t, "recovery"),
  });
}

if (isMain(import.meta.url)) createRecovery().start();
