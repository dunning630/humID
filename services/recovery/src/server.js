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
//   keys       FIDO2 security keys (4.0): the key part under each key's hmac-secret,
//              and each key's public key, so a recovery counts a key only when the
//              key itself signs a fresh challenge with its PIN (docs/SECURITY-KEY.md)
//
// Two-proof recovery (v2, "quorum"): the seed is split into a witness, an anchor,
// a card and (4.0) a security-key part; any two different ones rebuild it. A recovery needs two DIFFERENT kinds of proof, and
// waits longer the weaker they are (see quorumDelay in @humid/recovery).
//
// Everything stored here is ciphertext or public keys, except the anchor part,
// which is encrypted under a key derived from this server's secret AND the
// holder's identity fields (never stored), so a copy of the database alone
// opens nothing. See docs/RECOVERY.md and docs/CONTINUITY.md.

import { randomBytes, hkdfSync, createCipheriv, createDecipheriv, createHash, createPublicKey, verify as verifySig } from "node:crypto";
import { mkdirSync } from "node:fs";
import { createService, serviceTlsFromEnv, sealerFromEnv, secretFile, openDb, env, json, parseJson, parseObject, verifyAssertion, unb64u, b64u, HttpError, logger, isMain } from "@humid/svc";
import { suiteForEnvelope } from "@humid/crypto";
import { isEnvelope } from "@humid/codec";
import { sha3_256, toHex, identityId, STEP_UP_MAX_AGE_MS } from "@humid/htp";
import {
  keyCode, parseCode, LINK_LABEL, OFFER_LABEL, REQUEST_LABEL, MIN_CONTACTS, MAX_CONTACTS,
  QUORUM, decodeQuorumPart, quorumDelay, evidenceLabel, DURESS_WINDOW_MS, CARD_PART_BLOB_BYTES, CARD_FULL_BLOB_BYTES, KEY_PART_BLOB_BYTES,
} from "@humid/recovery";

/* Security keys (docs/SECURITY-KEY.md). The relying party no website can claim, and what the key signs. */
const KEY_RP_ID = "recovery.humid.invalid";
const KEY_RP_HASH = createHash("sha256").update(KEY_RP_ID).digest();
const KEY_FLAGS = { UP: 0x01, UV: 0x04, AT: 0x40 };
const keyClientDataHash = (purpose, challenge) => createHash("sha256").update(`HUMID-KEY-v1 ${purpose} `).update(challenge).digest();
import { passiveAuth, activeAuth, anchorOf, anchorSummary, stableIdentity, loadCscas, AnchorError } from "@humid/anchor";

const HOUR = 3600_000;
const SIZES = { kemPk: 1568, xPk: 32, dsaPk: 2592 };
const ENVELOPE_MAX = 64 * 1024;
const CHIP_MAX = 48 * 1024;
const list = (v) => String(v || "").split(",").map((x) => x.trim()).filter(Boolean);

export function createRecovery({
  /** Mutual TLS when the gateway calls from another machine (server 3.0): HUMID_TLS_* files. */
  tls = serviceTlsFromEnv(),
  /** Secrets sealed at rest (packages/svc/src/seal.js). */
  seal = sealerFromEnv(),
  port = Number(env("PORT", "8084")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  delayMs = Number(env("RECOVERY_DELAY_MS", String(72 * HOUR))),
  cscaDir = env("HUMID_CSCA_DIR", ""),
  cscas: extraCscas = [],
  stations = list(env("HUMID_STATION_ACCOUNTS", "")),
  linkTtlMs = 10 * 60_000,
  offerTtlMs = 15 * 60_000,
  collectTtlMs = 7 * 24 * HOUR,   // contacts have a week to respond
  releasedTtlMs = 7 * 24 * HOUR,  // a released request can be collected for a week
  challengeTtlMs = 5 * 60_000,
  maxOpenPerAccount = 3,
  maxKeysPerAccount = 4,
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
    // 4.0: security keys. pub is the credential's P-256 point; sign_count its last counter.
    `CREATE TABLE seckeys (
       id TEXT PRIMARY KEY, account TEXT NOT NULL, tag TEXT NOT NULL UNIQUE, blob BLOB NOT NULL,
       pub BLOB NOT NULL, cred_id BLOB NOT NULL, sign_count INTEGER NOT NULL, label BLOB, created_at TEXT NOT NULL);
     CREATE INDEX seckeys_account ON seckeys(account);
     CREATE TABLE key_challenges (scope TEXT PRIMARY KEY, nonce BLOB NOT NULL, expires_at INTEGER NOT NULL);
     ALTER TABLE requests ADD COLUMN key_id TEXT`,
  ]);

  /* ---------- the anchor secret and trusted countries ---------- */

  mkdirSync(dataDir, { recursive: true });
  // Sealed at rest when the server has a seal key (a plain one is sealed in place: the same secret).
  const anchorSecret = secretFile(`${dataDir}/anchor-secret.bin`, { seal, name: "recovery/anchor-secret", make: () => randomBytes(32), log });
  const hmacKey = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.alloc(0), "HUMID-ANCHOR-v1 hmac", 32));
  const cscas = [...loadCscas(cscaDir), ...extraCscas];
  const stationSet = new Set(stations);
  log.info("identity anchors", { countries: cscas.length, stations: stationSet.size });

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
    try { return passiveAuth(chip, { cscas }); }
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
    db.prepare("DELETE FROM key_challenges WHERE expires_at < ?").run(t);
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
    // A key removed during the wait no longer counts: its owner withdrew it.
    if (q.key_id && db.prepare("SELECT 1 FROM seckeys WHERE id = ? AND account = ?").get(q.key_id, q.account)) k.push("key");
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

  /**
   * A proof was withdrawn (a key or card removed): every open recovery of `account` that
   * no longer has two kinds of proof goes back to collecting, and its wait is gone.
   */
  function demote(account) {
    for (const q of db.prepare("SELECT * FROM requests WHERE account = ? AND method = 'quorum' AND status = 'waiting'").all(account)) {
      if (kindsOf(q).length >= 2) { evaluate(q.id); continue; }
      db.prepare("UPDATE requests SET status = 'collecting', release_at = NULL, quorum_at = NULL, expires_at = ? WHERE id = ?").run(now() + collectTtlMs, q.id);
    }
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
      // The old card no longer counts as a proof in a recovery under way.
      db.prepare("UPDATE requests SET card_ok = 0 WHERE account = ? AND method = 'quorum' AND status IN ('collecting', 'waiting')").run(claims.sub);
      db.exec("COMMIT");
      demote(claims.sub);
      return json(200, { createdAt: at, replaced: true, scheme });
    }],
    ["GET", "/card", ({ claims }) => {
      const c = db.prepare("SELECT created_at, scheme FROM cards WHERE account = ?").get(needUser(claims));
      return json(200, c ? { exists: true, createdAt: c.created_at, scheme: c.scheme } : { exists: false });
    }],
    ["DELETE", "/card", ({ claims }) => {
      needStepUp(claims);
      const n = db.prepare("DELETE FROM cards WHERE account = ?").run(claims.sub).changes;
      // A removed card no longer counts as a proof in a recovery under way.
      db.prepare("UPDATE requests SET card_ok = 0 WHERE account = ? AND method = 'quorum' AND status IN ('collecting', 'waiting')").run(claims.sub);
      demote(claims.sub);
      return json(200, { removed: n > 0 });
    }],
  ];

  /* ---------- identity anchor ---------- */

  const anchor = [
    ["GET", "/anchor", ({ claims }) => {
      const a = db.prepare("SELECT document, country, created_at FROM anchors WHERE account = ?").get(needUser(claims));
      return json(200, { available: cscas.length > 0, exists: !!a, ...(a ? { document: a.document, country: a.country, createdAt: a.created_at } : {}) });
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

  /* ---------- security keys (4.0) ---------- */

  const keyIdOf = (tag) => toHex(sha3_256(Buffer.from(`HUMID-KEY-ID-v1|${tag}`))).slice(0, 32);
  const keyIdParam = (s) => { if (!/^[0-9a-f]{32}$/.test(String(s))) throw new HttpError(400, "bad_key_id", "Unknown security key."); return String(s); };

  /** A one-use challenge for `scope` ("add:<account>" or "recover:<request id>"). */
  function issueKeyChallenge(scope) {
    const nonce = randomBytes(32);
    db.prepare("INSERT OR REPLACE INTO key_challenges (scope, nonce, expires_at) VALUES (?, ?, ?)").run(scope, nonce, now() + challengeTtlMs);
    return { challenge: b64u(nonce), expiresAt: now() + challengeTtlMs };
  }
  /** Take the challenge for `scope` (one answer per challenge, whatever the outcome). */
  function takeKeyChallenge(scope) {
    const ch = db.prepare("SELECT nonce FROM key_challenges WHERE scope = ? AND expires_at > ?").get(scope, now());
    db.prepare("DELETE FROM key_challenges WHERE scope = ?").run(scope);
    if (!ch) throw new HttpError(409, "challenge_expired", "That took too long. Hold your security key to the phone again.");
    return Buffer.from(ch.nonce);
  }

  /** A P-256 public key from its 65-byte point; refuses anything that isn't on the curve. */
  function keyPub(point) {
    const b = Buffer.from(point);
    if (b.length !== 65 || b[0] !== 4) throw new HttpError(400, "bad_key", "That security key's public key is malformed.");
    try {
      return createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x: b.subarray(1, 33).toString("base64url"), y: b.subarray(33).toString("base64url") } });
    } catch { throw new HttpError(400, "bad_key", "That security key's public key is malformed."); }
  }

  /**
   * Check a security key's answer to `challenge`: its signature over authenticatorData ‖
   * clientDataHash, this relying party, present (UP) and PIN-verified (UV). Returns its counter.
   */
  function checkKeyAnswer({ pub, authData, signature }, purpose, challenge) {
    const ad = Buffer.from(authData || []), sig = Buffer.from(signature || []);
    if (ad.length < 37 || ad.length > 1024 || sig.length < 8 || sig.length > 80) throw new HttpError(400, "bad_key_proof", "The security key's answer is malformed.");
    if (!ad.subarray(0, 32).equals(KEY_RP_HASH)) throw new HttpError(422, "bad_key_proof", "That answer wasn't made for HumID recovery.");
    const flags = ad[32];
    if (!(flags & KEY_FLAGS.UP) || !(flags & KEY_FLAGS.UV)) throw new HttpError(422, "bad_key_proof", "The security key didn't confirm its PIN.");
    if (flags & KEY_FLAGS.AT) throw new HttpError(422, "bad_key_proof", "The security key's answer is malformed.");
    const ok = (() => { try { return verifySig("sha256", Buffer.concat([ad, keyClientDataHash(purpose, challenge)]), { key: keyPub(pub), dsaEncoding: "der" }, sig); } catch { return false; } })();
    if (!ok) throw new HttpError(422, "bad_key_proof", "The security key's signature didn't check out.");
    return ad.readUInt32BE(33);
  }
  /** A counter must move forward, unless the key keeps it at zero. Backwards means a copy. */
  const counterOk = (stored, next) => (stored === 0 && next === 0) || next > stored;

  const keys = [
    ["GET", "/keys", ({ claims }) => {
      const rows = db.prepare("SELECT id, label, created_at FROM seckeys WHERE account = ? ORDER BY created_at, id").all(needUser(claims));
      return json(200, { keys: rows.map((r) => ({ id: r.id, label: r.label ? b64u(r.label) : null, createdAt: r.created_at })), max: maxKeysPerAccount });
    }],
    // Adding a key: the key signs this challenge, with its PIN, in the same step that gives the phone its secret.
    // `exclude` lists the credentials this account already has, so a key that holds one refuses to make another.
    ["POST", "/keys/challenge", ({ claims }) => {
      const sub = needUser(claims);
      const exclude = db.prepare("SELECT cred_id FROM seckeys WHERE account = ?").all(sub).map((k) => b64u(k.cred_id));
      return json(200, { ...issueKeyChallenge(`add:${sub}`), exclude });
    }],
    ["POST", "/keys", ({ claims, body }) => {
      needStepUp(claims);
      const r = parseObject(body);
      const tag = String(r.tag || "");
      if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(tag)) throw new HttpError(400, "bad_tag", "Key tag is malformed");
      const blob = unb64u(String(r.blob || ""));
      if (blob.length !== KEY_PART_BLOB_BYTES) throw new HttpError(400, "bad_blob", "Key blob has the wrong size");
      const pub = unb64u(String(r.pub || ""));
      keyPub(pub);
      const credId = unb64u(String(r.credentialId || ""));
      if (credId.length < 16 || credId.length > 1023) throw new HttpError(400, "bad_credential", "That security key's credential id is malformed.");
      const label = r.label ? unb64u(String(r.label)) : null;
      if (label && label.length > 512) throw new HttpError(400, "bad_label", "Label too long");
      const challenge = takeKeyChallenge(`add:${claims.sub}`);
      const count = checkKeyAnswer({ pub, authData: unb64u(String(r.authData || "")), signature: unb64u(String(r.signature || "")) }, "add", challenge);
      const mine = db.prepare("SELECT tag, pub, cred_id FROM seckeys WHERE account = ?").all(claims.sub);
      if (mine.some((k) => k.tag === tag || Buffer.from(k.pub).equals(Buffer.from(pub)) || Buffer.from(k.cred_id).equals(Buffer.from(credId)))) throw new HttpError(409, "key_exists", "This security key is already one of yours.");
      if (mine.length >= maxKeysPerAccount) throw new HttpError(409, "too_many_keys", `You can keep up to ${maxKeysPerAccount} security keys. Remove one first.`);
      if (db.prepare("SELECT 1 FROM seckeys WHERE tag = ?").get(tag)) throw new HttpError(409, "key_exists", "This security key is already in use.");
      const id = keyIdOf(tag), at = new Date().toISOString();
      db.prepare("INSERT INTO seckeys (id, account, tag, blob, pub, cred_id, sign_count, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, claims.sub, tag, blob, pub, credId, count, label, at);
      return json(201, { id, createdAt: at, count: mine.length + 1 });
    }],
    ["DELETE", "/keys/:id", ({ params, claims }) => {
      needStepUp(claims);
      const n = db.prepare("DELETE FROM seckeys WHERE id = ? AND account = ?").run(keyIdParam(params.id), claims.sub).changes;
      if (!n) throw new HttpError(404, "unknown_key", "That security key isn't one of yours.");
      demote(claims.sub);
      return json(200, { removed: true, count: db.prepare("SELECT COUNT(*) AS n FROM seckeys WHERE account = ?").get(claims.sub).n });
    }],
    ["DELETE", "/keys", ({ claims }) => {
      needStepUp(claims);
      const n = db.prepare("DELETE FROM seckeys WHERE account = ?").run(claims.sub).changes;
      demote(claims.sub);
      return json(200, { removed: n });
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
        const kinds = kindsOf(q);
        if (kinds.length < 2) { demote(q.account); const d = getRequest.get(q.id); return json(200, { ...requestView(d, { secret: true }), account: d.account }); }
        const out = { ...v, status: "released" };
        if (kinds.includes("witness")) out.shares = shares;
        if (kinds.includes("card")) {
          const c = db.prepare("SELECT blob, scheme FROM cards WHERE account = ?").get(q.account);
          if (c?.scheme === "quorum") out.blob = b64u(c.blob);
        }
        if (kinds.includes("anchor") && q.anchor_blob) out.anchorPart = b64u(unwrap(`request ${q.id}`, q.ref, q.anchor_blob));
        if (kinds.includes("key")) out.keyBlob = b64u(db.prepare("SELECT blob FROM seckeys WHERE id = ?").get(q.key_id).blob);
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

    // Two proofs: a fresh challenge for a security key to sign, with its PIN.
    ["POST", "/requests/:id/key/challenge", ({ params }) => json(200, issueKeyChallenge(`recover:${openQuorum(params.id).id}`))],
    // Two proofs: the security key, live. It must sign this request's challenge with its PIN
    // verified; the tag only says which stored key to check the signature with.
    ["POST", "/requests/:id/key", ({ params, body }) => {
      const q = openQuorum(params.id);
      const r = parseObject(body);
      const list = Array.isArray(r.candidates) ? r.candidates.slice(0, 16) : [];
      const challenge = takeKeyChallenge(`recover:${q.id}`);
      if (!list.length) throw new HttpError(400, "no_key_proof", "Hold your security key to the phone.");
      const rows = [];
      for (const c of list) {
        const row = db.prepare("SELECT * FROM seckeys WHERE tag = ?").get(String(c?.tag || ""));
        if (row) rows.push({ row, c });
      }
      if (!rows.length) throw new HttpError(404, "unknown_key", "This security key isn't one added to a HumID on this server.");
      // One key can hold credentials for two people's HumIDs. Once another proof named the
      // account, use that one; before that, refuse to guess.
      const accounts = new Set(rows.map((x) => x.row.account));
      const pick = q.account ? rows.find((x) => x.row.account === q.account) : accounts.size === 1 ? rows[0] : null;
      if (!pick) throw new HttpError(409, q.account ? "different_person" : "key_ambiguous", q.account ? "These proofs belong to different people. Nothing was released." : "This security key holds more than one HumID. Add your other proof first, then the key.");
      // A stored key that answers wrongly is worth telling its owner about (the gateway records it).
      let count;
      try { count = checkKeyAnswer({ pub: pick.row.pub, authData: unb64u(String(pick.c.authData || "")), signature: unb64u(String(pick.c.signature || "")) }, "recover", challenge); }
      catch (e) { if (e instanceof HttpError) e.detail = { account: pick.row.account, ref: q.ref }; throw e; }
      if (!counterOk(pick.row.sign_count, count)) throw new HttpError(409, "key_cloned", "This security key's counter went backwards, which happens when a key has been copied. It doesn't count as a proof.", { account: pick.row.account, ref: q.ref });
      const first = bindAccount(q, pick.row.account);
      db.prepare("UPDATE seckeys SET sign_count = ? WHERE id = ?").run(count, pick.row.id);
      db.prepare("UPDATE requests SET key_id = ? WHERE id = ?").run(pick.row.id, q.id);
      const e = evaluate(q.id);
      return json(200, { ...requestView(e), account: e.account, first, tag: pick.row.tag });
    }, { bodyLimit: 16 * 1024 }],

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
    ["GET", "/station", ({ claims }) => json(200, { station: isStation(needUser(claims)), countries: cscas.length })],
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
  return createService({ tls,
    name: "recovery", port, routes: [...links, ...card, ...anchor, ...keys, ...contacts, ...requests, ...station, ...duress], bodyLimit: 64 * 1024,
    verify: (t) => verifyAssertion(internalPk, t, "recovery"),
  });
}

if (isMain(import.meta.url)) createRecovery().start();
