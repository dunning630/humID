// recovery — moves an account seed to a new device without ever holding it.
//
//   links      a new device asks to join; a signed-in device seals the seed to it
//   card       a seal card: the seed (v1) or the card part (v2) under the owner's card
//   contacts   Shamir shares, each sealed to one recovery contact: of the seed (v1),
//              or of the witness part (v2)
//   anchor     the anchor part, sealed ON THE PHONE under a key from one passport or ID
//              card chip's Active Authentication key (DG15), found by a keyed fingerprint of
//              that key. The chip is checked with ICAO passive authentication and must answer
//              a fresh challenge when it's linked and when it's used (docs/CONTINUITY.md)
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
// Recovery modes (docs/RECOVERY.md#two-recovery-modes): a holder-only account has no card,
// witnesses, anchor or security key here, ever. Its mode is a statement signed by its account
// key; every escrow route checks that signature and refuses (409 holder_only).
//
// Everything stored here is ciphertext or public keys. The card, witness and key parts open
// only with something this service never sees. The ANCHOR part does not (V74-03): it is sealed
// on the holder's phone under a key made from the chip's DG15 and wrapped again under this
// service's own secret, and DG15 is public chip data that passes through here at every link
// and recovery. This service doesn't store DG15, so a copy of its database and secret alone
// doesn't open the part; but an operator that records one request does. Against a hostile
// operator the passport is therefore not a separate proof: the passport plus any ONE other
// stolen proof is enough. The fix (a split wrap with an independent cosigner) is an open
// decision: docs/CONTINUITY.md, "The anchor and the operator". Anchors linked before chip
// binding (v1) are still found and used, and are re-linked on the holder's next chip read.

import { randomBytes, hkdfSync, createCipheriv, createDecipheriv, createHash, createPublicKey, verify as verifySig } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { createService, serviceTlsFromEnv, sealerFromEnv, secretFile, openDb, env, json, parseJson, parseObject, verifyAssertion, verifyStatement, unb64u, b64u, HttpError, logger, isMain } from "@humid/svc";
import { holderProofs } from "@humid/svc/holder";
import { suiteForEnvelope } from "@humid/crypto";
import { isEnvelope } from "@humid/codec";
import { sha3_256, toHex, identityId, verify as verifyDsa, setupCardMessage } from "@humid/htp";
import {
  keyCode, parseCode, LINK_LABEL, OFFER_LABEL, REQUEST_LABEL, MIN_CONTACTS, MAX_CONTACTS,
  QUORUM, quorumDelay, evidenceLabel, DURESS_WINDOW_MS, CARD_PART_BLOB_BYTES, CARD_FULL_BLOB_BYTES, KEY_PART_BLOB_BYTES, ANCHOR_PART_BLOB_BYTES,
  RECOVERY_MODES, isRecoveryMode, recoveryModeMessage, recoveryModeHash, RECMODE_GENESIS,
} from "@humid/recovery";

/* Security keys (docs/SECURITY-KEY.md). The relying party no website can claim, and what the key signs. */
const KEY_RP_ID = "recovery.humid.invalid";
const KEY_RP_HASH = createHash("sha256").update(KEY_RP_ID).digest();
const KEY_FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };
const keyClientDataHash = (purpose, challenge) => createHash("sha256").update(`HUMID-KEY-v1 ${purpose} `).update(challenge).digest();
import { passiveAuth, activeAuth, anchorOf, chipAnchorOf, anchorSummary, stableIdentity, loadCscas, loadCscasFromTrustFile, AnchorError } from "@humid/anchor";

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
  /**
   * The core role's statement key, public half (SRV-30): identity vouches with it that a device key
   * belongs to an account, so this service checks the holder's own live proof before it changes or
   * releases recovery material, instead of taking the gateway's word for it.
   */
  corePk = env("HUMID_CORE_STATEMENT_PK"),
  delayMs = Number(env("RECOVERY_DELAY_MS", String(72 * HOUR))),
  cscaDir = env("HUMID_CSCA_DIR", ""),
  trustFile = env("HUMID_TRUST_STORE", ""),   // trust.json from tools/trust.mjs (ICAO / BSI master lists)
  cscas: extraCscas = [],
  stations = list(env("HUMID_STATION_ACCOUNTS", "")),
  /** "*" in stations (every account is a station) is for local development only, and only with this set (HUMID_ALLOW_ANY_STATION=dev). */
  allowAnyStation = env("HUMID_ALLOW_ANY_STATION", "") === "dev",
  linkTtlMs = 10 * 60_000,
  offerTtlMs = 15 * 60_000,
  collectTtlMs = 7 * 24 * HOUR,   // contacts have a week to respond
  // SRV-34: a request nobody has proved anything for yet (a contacts or two-proof request not
  // yet tied to an account) is anonymous and costs nothing to make. It lives this long until its
  // first proof arrives (a day: time for a first witness to answer), then the week applies; and
  // at most this many exist at once (fail closed, like the relay's cap).
  unboundTtlMs = Number(env("HUMID_RECOVERY_UNBOUND_TTL_MS", String(24 * HOUR))),
  maxUnbound = Number(env("HUMID_RECOVERY_MAX_UNBOUND", "20000")),
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
    // A link names the device key that will join with it, and is spent by that one enrolment (PC-02).
    `ALTER TABLE links ADD COLUMN device_pk BLOB;
     ALTER TABLE links ADD COLUMN used_at INTEGER`,
    // 4.0: security keys. pub is the credential's P-256 point; sign_count its last counter.
    `CREATE TABLE seckeys (
       id TEXT PRIMARY KEY, account TEXT NOT NULL, tag TEXT NOT NULL UNIQUE, blob BLOB NOT NULL,
       pub BLOB NOT NULL, cred_id BLOB NOT NULL, sign_count INTEGER NOT NULL, label BLOB, created_at TEXT NOT NULL);
     CREATE INDEX seckeys_account ON seckeys(account);
     CREATE TABLE key_challenges (scope TEXT PRIMARY KEY, nonce BLOB NOT NULL, expires_at INTEGER NOT NULL);
     ALTER TABLE requests ADD COLUMN key_id TEXT`,
    // Recovery modes: the account's signed choice, and the account key that signed it.
    `CREATE TABLE modes (account TEXT PRIMARY KEY, mode TEXT NOT NULL, version INTEGER NOT NULL, epoch INTEGER NOT NULL, sig BLOB NOT NULL, dsa_pk BLOB NOT NULL, updated_at TEXT NOT NULL)`,
    // Anchors v2 (VAULT-01, CREDS-01..03): `anchor` is chipAnchorOf(DG15), one chip, not one
    // person; the blob is the phone's sealed part, wrapped again here. A v1 row keeps the old
    // identity-field hash and server-only wrap until it's re-linked. Link challenges per account.
    `ALTER TABLE anchors ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
     ALTER TABLE anchors ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1;
     ALTER TABLE requests ADD COLUMN anchor_key BLOB;
     CREATE TABLE anchor_challenges (account TEXT PRIMARY KEY, nonce BLOB NOT NULL, expires_at INTEGER NOT NULL)`,
    // Recovery epochs (CRYPTO-02): which set of recovery pieces each stored piece belongs to.
    `ALTER TABLE cards ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1;
     ALTER TABLE guardian_sets ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1;
     ALTER TABLE seckeys ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1`,
    // V74-01/02: statements are chained (prev), and the highest one ever accepted is kept apart
    // from the statement itself. The mark only goes up: a statement row that is missing or older
    // than its mark means someone deleted or rolled it back, and counts as holder-only.
    `ALTER TABLE modes ADD COLUMN prev TEXT NOT NULL DEFAULT '${"0".repeat(64)}';
     CREATE TABLE mode_marks (account TEXT PRIMARY KEY, version INTEGER NOT NULL, epoch INTEGER NOT NULL, hash TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  ]);

  /* ---------- the anchor secret and trusted countries ---------- */

  mkdirSync(dataDir, { recursive: true });
  // Sealed at rest when the server has a seal key (a plain one is sealed in place: the same secret).
  const anchorSecret = secretFile(`${dataDir}/anchor-secret.bin`, { seal, name: "recovery/anchor-secret", make: () => randomBytes(32), log });
  const hmacKey = Buffer.from(hkdfSync("sha3-256", anchorSecret, Buffer.alloc(0), "HUMID-ANCHOR-v1 hmac", 32));
  // Country signing certificates: a folder of files, plus the trust store's
  // master-list CSCAs, re-read when the trust store file changes, so a
  // refreshed master list takes effect without a restart. A damaged trust
  // store keeps the last good set.
  const fixedCscas = [...loadCscas(cscaDir), ...extraCscas];
  let cscas = fixedCscas, trustMtime = -1, trustRev = 0; // the highest store revision seen: an older file put back is refused
  const currentCscas = () => {
    if (!trustFile) return cscas;
    let m = 0;
    try { m = statSync(trustFile).mtimeMs; } catch { m = 0; }
    if (m !== trustMtime) {
      try { const t = loadCscasFromTrustFile(trustFile, { minRev: trustRev }); cscas = [...fixedCscas, ...t]; trustRev = t.rev ?? trustRev; trustMtime = m; log.info("trust store loaded", { cscas: cscas.length, rev: trustRev }); }
      catch (e) { log.warn("trust store unreadable, keeping the last good set", { error: String(e?.message || e) }); trustMtime = m; }
    }
    return cscas;
  };
  const stationSet = new Set(stations);
  // "*" makes every account a verification station, which can vouch any recovery onto the
  // fastest wait (VAULT-08). One env value away in production, so it needs a second, explicit flag.
  if (stationSet.has("*")) {
    if (!allowAnyStation) throw new Error('HUMID_STATION_ACCOUNTS="*" makes every account a verification station. That is for local development only: set HUMID_ALLOW_ANY_STATION=dev to allow it, or list the station accounts.');
    log.error("EVERY ACCOUNT IS A VERIFICATION STATION (HUMID_STATION_ACCOUNTS=*, HUMID_ALLOW_ANY_STATION=dev). Local development only: anyone can put any recovery on the fastest wait.");
  }
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
  // SRV-30: the holder's own approval of exactly this action (the app's method and path, and the
  // body this service received, which the gateway passes on unchanged), checked here against the
  // device key identity vouches for, once. The gateway's key alone changes and releases nothing.
  const proofs = holderProofs({ corePk, now });
  const needHolder = (c, method, path, body) => { proofs.check(c?.holder, { sub: needUser(c), method, path, body }); return c.sub; };
  /**
   * The recovery card made with a new account (gateway register): no step-up exists yet, so the
   * account key signs the card inside the registration's live check, and identity's "created"
   * statement says this account was made just now, in that session. Nothing else stores a card
   * without a step-up.
   */
  function setupCardOk(c, tag, blob) {
    const sc = c?.setupCard;
    if (!sc) return false;
    const created = verifyStatement(corePk, sc.created, "created");
    let dsaPk, th, sig;
    try { dsaPk = unb64u(String(sc.dsaPk || "")); th = unb64u(String(sc.th || "")); sig = unb64u(String(sc.sig || "")); } catch { return false; }
    if (created.account !== c.sub || created.th !== sc.th || identityId(dsaPk) !== c.sub) return false;
    if (db.prepare("SELECT 1 FROM cards WHERE account = ?").get(c.sub)) return false; // only the first card
    return verifyDsa(sig, setupCardMessage(th, c.sub, tag, blob), dsaPk);
  }
  const gatewayOnly = (c) => { if (c?.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
  const key = (v, name) => {
    const b = unb64u(String(v ?? ""));
    if (b.length !== SIZES[name]) throw new HttpError(400, "bad_key", `${name} has the wrong length`);
    return b;
  };
  const codeParam = (s) => {
    const c = parseCode(s);
    if (!c) throw new HttpError(400, "bad_code", "That code isn't valid. It has 12 or 16 letters and numbers.");
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

  /** A one-use Active Authentication challenge, kept under `table`/`id`; taken whatever the outcome. */
  const takeChallenge = (table, col, id) => {
    const ch = db.prepare(`SELECT nonce FROM ${table} WHERE ${col} = ? AND expires_at > ?`).get(id, now());
    db.prepare(`DELETE FROM ${table} WHERE ${col} = ?`).run(id);
    return ch ? Buffer.from(ch.nonce) : null;
  };
  /** The chip in front of the phone answered `nonce` with the key behind its DG15. */
  function liveChip(chip, ok, nonce, r) {
    if (!ok.hasAaKey) throw new HttpError(422, "no_chip_proof", ok.aaRequired ? "Send the chip's authentication key (DG15) too." : "This ID's chip can't prove it's present, so it can't hold a recovery part. Use witnesses, a recovery card or a security key.");
    if (!nonce) throw new HttpError(409, "challenge_expired", "The chip challenge expired. Scan your ID again.");
    try { activeAuth({ dg15: chip.dg15, nonce, signature: unb64u(String(r.signature || "")), hash: r.hash }); }
    catch (e) { if (e instanceof AnchorError) throw new HttpError(422, e.code, e.message); throw e; }
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
    db.prepare("DELETE FROM key_challenges WHERE expires_at < ?").run(t);
    db.prepare("UPDATE requests SET status = 'expired', closed_at = ? WHERE status IN ('collecting', 'waiting') AND expires_at < ?").run(t, t);
    // SRV-34: a request that got no first proof within unboundTtlMs (a day) ends then, not a week on, and
    // leaves no trace: nothing ties it to anyone. A first proof binds it to an account, and from
    // then on the week (collectTtlMs) applies.
    db.prepare("UPDATE requests SET status = 'expired', closed_at = ? WHERE status = 'collecting' AND account IS NULL AND created_at < ?").run(t, t - unboundTtlMs);
    db.prepare("DELETE FROM requests WHERE account IS NULL AND status IN ('expired', 'cancelled') AND id NOT IN (SELECT request_id FROM approvals)").run();
    db.prepare("DELETE FROM approvals WHERE request_id IN (SELECT id FROM requests WHERE status IN ('expired', 'cancelled', 'completed'))").run();
    db.prepare("UPDATE requests SET anchor_blob = NULL WHERE status IN ('expired', 'cancelled', 'completed') AND anchor_blob IS NOT NULL").run();
  }
  setInterval(sweep, 60_000).unref();

  const getRequest = db.prepare("SELECT * FROM requests WHERE id = ?");
  const approvalCount = (id) => db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE request_id = ?").get(id).n;
  const unboundCount = () => db.prepare("SELECT COUNT(*) AS n FROM requests WHERE account IS NULL AND status = 'collecting'").get().n;
  const openRequests = (account) => db.prepare("SELECT COUNT(*) AS n FROM requests WHERE account = ? AND status IN ('collecting', 'waiting')").get(account).n;
  const recentDuress = (account, t = now()) => {
    const d = account && db.prepare("SELECT last_at FROM duress WHERE account = ?").get(account);
    return !!d && t - d.last_at < DURESS_WINDOW_MS;
  };
  const guardianSet = (owner) => db.prepare("SELECT * FROM guardian_sets WHERE owner = ?").get(owner);

  /* ---------- recovery modes ---------- */

  const getMode = db.prepare("SELECT * FROM modes WHERE account = ?");
  const getMark = db.prepare("SELECT * FROM mode_marks WHERE account = ?");
  const u32ok = (n) => Number.isSafeInteger(n) && n >= 1 && n < 2 ** 32;
  /** A mode statement { mode, version, epoch, prev, sig, dsaPk } for `account`, checked. Throws if it isn't the account's own. */
  function checkStatement(account, st) {
    const mode = String(st?.mode || ""), version = Number(st?.version), epoch = Number(st?.epoch), prev = String(st?.prev ?? RECMODE_GENESIS);
    if (!isRecoveryMode(mode) || !u32ok(version) || !u32ok(epoch)) throw new HttpError(400, "bad_recovery_mode", "Unknown recovery mode.");
    const dsaPk = st.dsaPk instanceof Uint8Array ? st.dsaPk : unb64u(String(st.dsaPk || ""));
    const sig = st.sig instanceof Uint8Array ? st.sig : unb64u(String(st.sig || ""));
    let ok = false;
    try { ok = dsaPk.length === SIZES.dsaPk && identityId(dsaPk) === account && verifyDsa(sig, recoveryModeMessage(account, mode, version, epoch, prev), dsaPk); } catch { ok = false; }
    if (!ok) throw new HttpError(401, "bad_proof", "The recovery mode wasn't signed by this account's key.");
    return { mode, version, epoch, prev, sig, dsaPk, hash: recoveryModeHash(account, { mode, version, epoch, prev }) };
  }
  /**
   * This account's recovery mode. An account with neither a statement nor a mark is from before
   * modes: hardened. A stored statement is checked again every time, and against the mark: a
   * row changed on disk without the account key, deleted, or put back to an older one fails
   * closed (as holder-only: nothing more is stored or released) until a statement at least as
   * new as the mark arrives (from the holder, or from identity through the gateway).
   */
  function statementOf(account) {
    const m = account && getMode.get(account);
    const mark = account && getMark.get(account);
    const broken = (why) => { log.warn("recovery mode statement doesn't hold", { account, why }); return { mode: RECOVERY_MODES.holderOnly, version: mark?.version ?? m?.version ?? 0, epoch: Math.max(mark?.epoch ?? 1, m?.epoch ?? 1), sig: null, broken: true }; };
    if (!m) return mark ? broken("missing") : { mode: RECOVERY_MODES.hardened, version: 0, epoch: 1, sig: null };
    let st;
    try { st = checkStatement(account, { mode: m.mode, version: m.version, epoch: m.epoch, prev: m.prev, sig: new Uint8Array(m.sig), dsaPk: new Uint8Array(m.dsa_pk) }); }
    catch { return broken("signature"); }
    if (mark && (st.version < mark.version || st.epoch < mark.epoch || (st.version === mark.version && st.hash !== mark.hash))) return broken("rolled back");
    return st;
  }
  /** May `next` replace what's on file? Compared with the mark, which a deleted or rolled-back row doesn't lower. */
  function follows(account, next) {
    const mark = getMark.get(account);
    if (!mark) return true;
    if (next.version === mark.version) return next.hash === mark.hash;
    if (next.version < mark.version || next.epoch < mark.epoch) return false;
    return next.version > mark.version + 1 || next.prev === mark.hash;
  }
  const modeOf = (account) => statementOf(account).mode;
  /** Refuse anything that would store or use recovery material for a holder-only account. */
  function requireHardened(account) {
    if (modeOf(account) !== RECOVERY_MODES.hardened) throw new HttpError(409, "holder_only", "This HumID opens only on its own devices. It has no recovery to set up or use.");
  }
  /** What escrow this account still has here. */
  const escrowOf = (account) => [
    ...(db.prepare("SELECT 1 FROM cards WHERE account = ?").get(account) ? ["card"] : []),
    ...(db.prepare("SELECT 1 FROM guardian_sets WHERE owner = ?").get(account) || db.prepare("SELECT 1 FROM guardians WHERE owner = ?").get(account) ? ["contacts"] : []),
    ...(db.prepare("SELECT 1 FROM anchors WHERE account = ?").get(account) ? ["anchor"] : []),
    ...(db.prepare("SELECT 1 FROM seckeys WHERE account = ?").get(account) ? ["key"] : []),
  ];
  /**
   * The epoch a new piece claims must be the account's current one (from its signed statement).
   * An app that doesn't say is taken as epoch 1, which is right only while the account is still
   * on its first set: after a new set, a piece from an older app would silently never fit.
   */
  function requireEpoch(account, claimed) {
    const cur = statementOf(account).epoch || 1;
    const e = claimed == null ? 1 : Number(claimed);
    if (claimed == null && cur > 1) throw new HttpError(400, "update_required", "Update HumID to set up recovery: your recovery pieces were renewed.");
    if (e !== cur) throw new HttpError(409, "stale_epoch", "These recovery pieces are from an older set, so they wouldn't fit. Make them again.");
    return e;
  }
  /** A new set of pieces: everything stored from older sets is deleted, and no recovery under way can finish. */
  function retireOlderPieces(account, epoch) {
    db.exec("BEGIN");
    db.prepare("DELETE FROM cards WHERE account = ? AND epoch < ?").run(account, epoch);
    const sets = db.prepare("SELECT 1 FROM guardian_sets WHERE owner = ? AND epoch < ?").get(account, epoch);
    if (sets) { db.prepare("DELETE FROM guardians WHERE owner = ?").run(account); db.prepare("DELETE FROM guardian_sets WHERE owner = ?").run(account); }
    db.prepare("DELETE FROM anchors WHERE account = ? AND epoch < ?").run(account, epoch);
    db.prepare("DELETE FROM seckeys WHERE account = ? AND epoch < ?").run(account, epoch);
    db.prepare("UPDATE requests SET status = 'cancelled', closed_at = ?, anchor_blob = NULL WHERE account = ? AND status IN ('collecting', 'waiting')").run(now(), account);
    db.exec("COMMIT");
  }
  /**
   * Keep a newer signed statement. The same one again is fine; an older one never replaces it.
   * sync: the gateway is bringing this service up to identity's statement (it holds the account's
   * latest choice; this one's row was deleted, rolled back, or restored from an old backup).
   * The holder already made that switch, so pieces still here are left over or planted: for
   * holder-only they're deleted rather than refused.
   */
  function learnMode(account, st, { sync = false } = {}) {
    const m = checkStatement(account, st);
    if (!follows(account, m)) throw new HttpError(409, "stale_recovery_mode", "A newer recovery choice is already on file.");
    const mark = getMark.get(account);
    const cur = statementOf(account);
    if (cur.version === m.version && !cur.broken && mark) return m; // already on file
    if (m.mode === RECOVERY_MODES.holderOnly) {
      const left = escrowOf(account);
      // The holder deletes each proof first (each with its own check); only then is the switch accepted.
      if (left.length && !sync) throw new HttpError(409, "escrow_remains", `Remove your ${left.join(", ")} first.`, { left });
      if (left.length) deleteEscrow(account);
      // Recoveries already under way can't finish any more.
      db.prepare("UPDATE requests SET status = 'cancelled', closed_at = ?, anchor_blob = NULL WHERE account = ? AND status IN ('collecting', 'waiting')").run(now(), account);
    }
    const at = new Date().toISOString();
    db.exec("BEGIN");
    db.prepare(`INSERT INTO modes (account, mode, version, epoch, prev, sig, dsa_pk, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account) DO UPDATE SET mode = excluded.mode, version = excluded.version, epoch = excluded.epoch, prev = excluded.prev, sig = excluded.sig, dsa_pk = excluded.dsa_pk, updated_at = excluded.updated_at`)
      .run(account, m.mode, m.version, m.epoch, m.prev, m.sig, m.dsaPk, at);
    db.prepare(`INSERT INTO mode_marks (account, version, epoch, hash, updated_at) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(account) DO UPDATE SET version = excluded.version, epoch = excluded.epoch, hash = excluded.hash, updated_at = excluded.updated_at
                WHERE excluded.version >= mode_marks.version`)
      .run(account, m.version, m.epoch, m.hash, at);
    db.exec("COMMIT");
    // Pieces from an older epoch than this one, wherever they came from, are retired.
    retireOlderPieces(account, m.epoch);
    return m;
  }
  function deleteEscrow(account) {
    db.exec("BEGIN");
    db.prepare("DELETE FROM cards WHERE account = ?").run(account);
    db.prepare("DELETE FROM guardians WHERE owner = ?").run(account);
    db.prepare("DELETE FROM guardian_sets WHERE owner = ?").run(account);
    db.prepare("DELETE FROM anchors WHERE account = ?").run(account);
    db.prepare("DELETE FROM seckeys WHERE account = ?").run(account);
    db.exec("COMMIT");
  }

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
   * A proof was withdrawn (a key or card removed): every waiting recovery of `account` starts
   * its wait again from now if two kinds remain, and goes back to collecting if not.
   */
  function demote(account) {
    for (const q of db.prepare("SELECT * FROM requests WHERE account = ? AND method = 'quorum' AND status = 'waiting'").all(account)) {
      // Whatever remains, the wait starts again from now: a withdrawn proof never leaves a
      // shorter wait behind for the pair that's left.
      db.prepare("UPDATE requests SET status = 'collecting', release_at = NULL, quorum_at = NULL, expires_at = ? WHERE id = ?").run(now() + collectTtlMs, q.id);
      if (kindsOf(q).length >= 2) evaluate(q.id);
    }
  }

  /** Tie a request to an account the first time a proof names it. Throws if proofs disagree. */
  function bindAccount(q, account) {
    if (q.account && q.account !== account) throw new HttpError(409, "different_person", "These proofs belong to different people. Nothing was released.");
    requireHardened(account);
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
      // The device key that will join with this link. Only that key can enrol with it.
      if (r.devicePk == null) throw new HttpError(400, "update_required", "Update HumID on the new device to add it.");
      const devicePk = key(r.devicePk, "dsaPk");
      const code = keyCode(LINK_LABEL, kemPk, xPk);
      sweep();
      if (db.prepare("SELECT 1 FROM links WHERE code = ?").get(code)) throw new HttpError(409, "code_in_use", "Start again on the new device.");
      const t = now();
      db.prepare("INSERT INTO links (code, kem_pk, x_pk, platform, created_at, expires_at, status, device_pk) VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?)")
        .run(code, kemPk, xPk, platformOf(r.platform), t, t + linkTtlMs, devicePk);
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
      needHolder(claims, "POST", `/recovery/links/${params.code}/approve`, body);
      const l = db.prepare("SELECT * FROM links WHERE code = ? AND expires_at > ?").get(codeParam(params.code), now());
      if (!l) throw new HttpError(404, "unknown_code", "That code expired. Start again on the new device.");
      if (l.status !== "waiting") throw new HttpError(409, "already_used", "That code was already used.");
      checkEnvelope(body, { signerFp: claims.dsaFp, recipientKemPk: new Uint8Array(l.kem_pk) });
      // From approval, the new device has a full link lifetime to compare the check and join.
      db.prepare("UPDATE links SET status = 'approved', account = ?, envelope = ?, expires_at = ? WHERE code = ?").run(claims.sub, body, now() + linkTtlMs, l.code);
      return json(200, { approved: true, platform: l.platform });
    }, { bodyLimit: ENVELOPE_MAX }],
    // Gateway only (PC-02): a device may join an account through a link only if one of the
    // account's devices approved that link, with a live check, for exactly this device key.
    // Spent by that enrolment; given back if the enrolment itself then fails.
    ["POST", "/internal/links/:code/consume", ({ params, claims, body }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const devicePk = key(r.devicePk, "dsaPk");
      const l = db.prepare("SELECT * FROM links WHERE code = ? AND expires_at > ?").get(codeParam(params.code), now());
      const ok = l && l.status === "approved" && l.account === String(r.account) && l.device_pk && Buffer.from(l.device_pk).equals(Buffer.from(devicePk));
      if (!ok || db.prepare("UPDATE links SET status = 'used', used_at = ? WHERE code = ? AND status = 'approved'").run(now(), l.code).changes !== 1) {
        throw new HttpError(403, "not_approved", "None of your devices approved this one. Approve it from a device you already use.");
      }
      return json(200, { consumed: true });
    }],
    ["POST", "/internal/links/:code/restore", ({ params, claims, body }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      db.prepare("UPDATE links SET status = 'approved', used_at = NULL WHERE code = ? AND status = 'used' AND account = ?").run(codeParam(params.code), String(r.account));
      return json(200, { restored: true });
    }],
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
      needUser(claims);
      const r = parseObject(body);
      const tag = String(r.tag || "");
      if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(tag)) throw new HttpError(400, "bad_tag", "Card tag is malformed");
      const blob = unb64u(String(r.blob || ""));
      if (!setupCardOk(claims, tag, blob)) needHolder(claims, "PUT", "/recovery/card", body);
      requireHardened(claims.sub);
      // v1 cards hold the whole seed; v2 cards hold only the card part of two-proof recovery.
      const scheme = blob.length === CARD_PART_BLOB_BYTES ? "quorum" : blob.length === CARD_FULL_BLOB_BYTES ? "full" : null;
      if (!scheme) throw new HttpError(400, "bad_blob", "Card blob has the wrong size");
      const epoch = requireEpoch(claims.sub, r.epoch);
      const at = new Date().toISOString();
      db.exec("BEGIN");
      db.prepare("DELETE FROM cards WHERE account = ?").run(claims.sub);
      db.prepare("INSERT INTO cards (account, tag, blob, created_at, scheme, epoch) VALUES (?, ?, ?, ?, ?, ?)").run(claims.sub, tag, blob, at, scheme, epoch);
      // The old card no longer counts as a proof in a recovery under way.
      db.prepare("UPDATE requests SET card_ok = 0 WHERE account = ? AND method = 'quorum' AND status IN ('collecting', 'waiting')").run(claims.sub);
      db.exec("COMMIT");
      demote(claims.sub);
      return json(200, { createdAt: at, replaced: true, scheme });
    }],
    // Account closed: every piece of recovery material this account has here goes, under the
    // holder's approval for closing the account (one proof, used once, so one route for all of it).
    ["DELETE", "/escrow", ({ claims, body }) => {
      const sub = needHolder(claims, "DELETE", "/identity/me", body);
      const left = escrowOf(sub);
      deleteEscrow(sub);
      db.prepare("UPDATE requests SET status = 'cancelled', closed_at = ?, anchor_blob = NULL WHERE account = ? AND status IN ('collecting', 'waiting')").run(now(), sub);
      return json(200, { removed: left });
    }],
    ["GET", "/card", ({ claims }) => {
      const c = db.prepare("SELECT created_at, scheme FROM cards WHERE account = ?").get(needUser(claims));
      return json(200, c ? { exists: true, createdAt: c.created_at, scheme: c.scheme } : { exists: false });
    }],
    ["DELETE", "/card", ({ claims, body }) => {
      needHolder(claims, "DELETE", "/recovery/card", body);
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
      const a = db.prepare("SELECT document, country, created_at, version FROM anchors WHERE account = ?").get(needUser(claims));
      // version 1: linked before chip binding; the app re-links it on the holder's next chip read.
      return json(200, { available: currentCscas().length > 0, exists: !!a, ...(a ? { document: a.document, country: a.country, createdAt: a.created_at, version: a.version } : {}) });
    }],
    // A fresh challenge for the chip being linked (CREDS-02): copied chip files can't answer it.
    ["POST", "/anchor/challenge", ({ claims }) => {
      const sub = needUser(claims);
      requireHardened(sub);
      const nonce = randomBytes(8);
      db.prepare("INSERT OR REPLACE INTO anchor_challenges (account, nonce, expires_at) VALUES (?, ?, ?)").run(sub, nonce, now() + challengeTtlMs);
      return json(200, { nonce: b64u(nonce), expiresAt: now() + challengeTtlMs });
    }],
    // The owner links one passport or ID chip. The chip must be live (it answers the challenge
    // above), and the part arrives sealed by the phone under a key from that chip's DG15
    // (sealAnchorPart). That binds it to this chip; it doesn't hide it from this service, which
    // sees DG15 right here (V74-03). Only a fingerprint of DG15 is stored. One chip anchors one
    // HumID; a renewed passport is linked again.
    ["PUT", "/anchor", ({ claims, body }) => {
      needHolder(claims, "PUT", "/recovery/anchor", body);
      requireHardened(claims.sub);
      const r = parseObject(body);
      const sealed = unb64u(String(r.sealedPart || ""));
      if (r.part != null) throw new HttpError(400, "update_required", "Update HumID to link your ID: the part must be sealed to your chip first.");
      if (sealed.length !== ANCHOR_PART_BLOB_BYTES) throw new HttpError(400, "bad_part", "That isn't a sealed anchor part.");
      const epoch = requireEpoch(claims.sub, r.epoch);
      const chip = chipOf(r.chip);
      const ok = checkChip(chip);
      liveChip(chip, ok, takeChallenge("anchor_challenges", "account", claims.sub), r);
      const anchorHash = chipAnchorOf(chip.dg15, hmacKey);
      const taken = db.prepare("SELECT account FROM anchors WHERE anchor = ?").get(anchorHash);
      if (taken && taken.account !== claims.sub) throw new HttpError(409, "anchor_taken", "This ID already anchors another HumID.");
      const blob = wrap("chip v2", claims.sub, Buffer.from(sealed));
      const { document, country } = anchorSummary(ok.mrz);
      const at = new Date().toISOString();
      db.exec("BEGIN");
      db.prepare("DELETE FROM anchors WHERE account = ?").run(claims.sub);
      db.prepare("INSERT INTO anchors (account, anchor, blob, document, country, created_at, version, epoch) VALUES (?, ?, ?, ?, ?, ?, 2, ?)").run(claims.sub, anchorHash, blob, document, country, at, epoch);
      db.exec("COMMIT");
      return json(200, { createdAt: at, document, country, version: 2 });
    }, { bodyLimit: 3 * CHIP_MAX }],
    ["DELETE", "/anchor", ({ claims, body }) => {
      needHolder(claims, "DELETE", "/recovery/anchor", body);
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
    // A credential that says it can be backed up or synced (a passkey in a cloud account) isn't a
    // physical key: refused, at adding and at recovering (WebAuthn §6.1 BE/BS flags).
    if (flags & (KEY_FLAGS.BE | KEY_FLAGS.BS)) throw new HttpError(422, "synced_credential", "That's a synced passkey, not a security key. Use a hardware security key.");
    const ok = (() => { try { return verifySig("sha256", Buffer.concat([ad, keyClientDataHash(purpose, challenge)]), { key: keyPub(pub), dsaEncoding: "der" }, sig); } catch { return false; } })();
    // Only a signature that was actually checked and failed says anything about the stored key.
    if (!ok) throw Object.assign(new HttpError(422, "bad_key_proof", "The security key's signature didn't check out."), { checked: true });
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
      requireHardened(sub);
      const exclude = db.prepare("SELECT cred_id FROM seckeys WHERE account = ?").all(sub).map((k) => b64u(k.cred_id));
      return json(200, { ...issueKeyChallenge(`add:${sub}`), exclude });
    }],
    ["POST", "/keys", ({ claims, body }) => {
      needHolder(claims, "POST", "/recovery/keys", body);
      requireHardened(claims.sub);
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
      const epoch = requireEpoch(claims.sub, r.epoch);
      const challenge = takeKeyChallenge(`add:${claims.sub}`);
      const count = checkKeyAnswer({ pub, authData: unb64u(String(r.authData || "")), signature: unb64u(String(r.signature || "")) }, "add", challenge);
      const mine = db.prepare("SELECT tag, pub, cred_id FROM seckeys WHERE account = ?").all(claims.sub);
      if (mine.some((k) => k.tag === tag || Buffer.from(k.pub).equals(Buffer.from(pub)) || Buffer.from(k.cred_id).equals(Buffer.from(credId)))) throw new HttpError(409, "key_exists", "This security key is already one of yours.");
      if (mine.length >= maxKeysPerAccount) throw new HttpError(409, "too_many_keys", `You can keep up to ${maxKeysPerAccount} security keys. Remove one first.`);
      if (db.prepare("SELECT 1 FROM seckeys WHERE tag = ?").get(tag)) throw new HttpError(409, "key_exists", "This security key is already in use.");
      const id = keyIdOf(tag), at = new Date().toISOString();
      db.prepare("INSERT INTO seckeys (id, account, tag, blob, pub, cred_id, sign_count, label, created_at, epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, claims.sub, tag, blob, pub, credId, count, label, at, epoch);
      return json(201, { id, createdAt: at, count: mine.length + 1 });
    }],
    ["DELETE", "/keys/:id", ({ params, claims, body }) => {
      needHolder(claims, "DELETE", `/recovery/keys/${params.id}`, body);
      const n = db.prepare("DELETE FROM seckeys WHERE id = ? AND account = ?").run(keyIdParam(params.id), claims.sub).changes;
      if (!n) throw new HttpError(404, "unknown_key", "That security key isn't one of yours.");
      demote(claims.sub);
      return json(200, { removed: true, count: db.prepare("SELECT COUNT(*) AS n FROM seckeys WHERE account = ?").get(claims.sub).n });
    }],
    ["DELETE", "/keys", ({ claims, body }) => {
      needHolder(claims, "DELETE", "/recovery/keys", body);
      const n = db.prepare("DELETE FROM seckeys WHERE account = ?").run(claims.sub).changes;
      demote(claims.sub);
      return json(200, { removed: n });
    }],
  ];

  /**
   * Find the anchored account for a verified, live chip. v2: by that chip's own key, and what
   * comes back is the phone-sealed part (only DG15 opens it, which the recovering device
   * holds). v1 (linked before chip binding): by identity fields, the part itself.
   */
  function openAnchor(mrz, dg15) {
    const a2 = dg15 && db.prepare("SELECT * FROM anchors WHERE anchor = ? AND version = 2").get(chipAnchorOf(dg15, hmacKey));
    if (a2) return { account: a2.account, part: unwrap("chip v2", a2.account, a2.blob), sealed: true, epoch: a2.epoch };
    const a1 = db.prepare("SELECT * FROM anchors WHERE anchor = ? AND version = 1").get(anchorOf(mrz, hmacKey));
    if (!a1) throw new HttpError(404, "unknown_anchor", "This ID doesn't anchor any HumID on this server. If you renewed it, recover with your other proofs and link the new one.");
    return { account: a1.account, part: unwrap(stableIdentity(mrz), a1.account, a1.blob), sealed: false, epoch: 1 };
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
      needHolder(claims, "PUT", "/recovery/contacts", body);
      requireHardened(claims.sub);
      const r = parseObject(body);
      const scheme = r.scheme === "quorum" ? "quorum" : "full";
      const epoch = requireEpoch(claims.sub, r.epoch);
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
      db.prepare("INSERT OR REPLACE INTO guardian_sets (owner, threshold, n, created_at, scheme, epoch) VALUES (?, ?, ?, ?, ?, ?)").run(claims.sub, t, n, at, scheme, epoch);
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
    ["DELETE", "/contacts", ({ claims, body }) => {
      needHolder(claims, "DELETE", "/recovery/contacts", body);
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
        requireHardened(c.account);
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
        // SRV-34: unbound, it's anonymous: a ceiling on how many exist (and the sweep ends it early without a first proof).
        if (unboundCount() >= maxUnbound) throw new HttpError(503, "busy", "HumID is busy right now. Try again in a few minutes.");
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
        // A holder-only account releases nothing, whatever a request collected before the switch.
        if (modeOf(q.account) !== RECOVERY_MODES.hardened) return json(200, { ...v, status: "cancelled", reason: "holder_only" });
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
        // Which set of pieces these are: the device opens the card and key with it.
        const out = { ...v, status: "released", epoch: statementOf(q.account).epoch || 1 };
        if (kinds.includes("witness")) out.shares = shares;
        if (kinds.includes("card")) {
          const c = db.prepare("SELECT blob, scheme FROM cards WHERE account = ?").get(q.account);
          if (c?.scheme === "quorum") out.blob = b64u(c.blob);
        }
        if (kinds.includes("anchor") && q.anchor_blob) {
          const p = unwrap(`request ${q.id}`, q.ref, q.anchor_blob);
          // v2: the phone-sealed part (65-byte v1 parts are the part itself); a station recovery
          // also hands over the chip key the station read, sealed to this request's own keys.
          if (p.length === ANCHOR_PART_BLOB_BYTES) out.anchorSealed = b64u(p); else out.anchorPart = b64u(p);
          if (q.anchor_key) out.anchorKey = b64u(q.anchor_key);
        }
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
      liveChip(chip, ok, takeChallenge("challenges", "request_id", q.id), r); // one answer per challenge
      const { account, part, sealed, epoch } = openAnchor(ok.mrz, chip.dg15);
      const first = bindAccount(q, account);
      if (q.anchor_mode !== "station") {
        db.prepare("UPDATE requests SET anchor_mode = 'remote', anchor_blob = ? WHERE id = ?").run(wrap(`request ${q.id}`, q.ref, part), q.id);
      }
      part.fill(0);
      const e = evaluate(q.id);
      // sealed: the device opens the part with the key from the DG15 it just read.
      return json(200, { ...requestView(e), account: e.account, first, anchorSealed: sealed, anchorEpoch: epoch });
    }, { bodyLimit: 3 * CHIP_MAX }],

    // Gateway only (PC-02): may a device join this account on the strength of this recovery?
    // Only once it's released (its proofs in, its wait over, not cancelled), for that account,
    // by the route it was started with. Checked before the device is added; spent after.
    ["POST", "/internal/requests/:id/check", ({ params, claims, body }) => {
      gatewayOnly(claims);
      const q = getRequest.get(params.id);
      const r = parseObject(body);
      if (!q || q.account !== String(r.account) || q.method !== String(r.method) || q.status !== "waiting" || !q.release_at || now() < q.release_at) {
        throw new HttpError(403, "not_released", "That recovery isn't released yet, so this device can't join.");
      }
      if (modeOf(q.account) !== RECOVERY_MODES.hardened) throw new HttpError(403, "not_released", "This HumID opens only on its own devices. Add this device from one of them.");
      return json(200, { released: true });
    }],
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
      catch (e) { if (e instanceof HttpError && e.checked) e.detail = { account: pick.row.account, ref: q.ref }; throw e; }
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
      needHolder(claims, "POST", `/recovery/help/${params.code}`, body);
      const r = parseObject(body);
      const q = db.prepare("SELECT * FROM requests WHERE code = ?").get(codeParam(params.code));
      if (!q || !["collecting", "waiting"].includes(q.status) || q.expires_at < now()) throw new HttpError(404, "unknown_code", "No recovery is waiting with that code.");
      const owner = String(r.owner || "");
      const g = db.prepare("SELECT 1 FROM guardians WHERE owner = ? AND contact = ?").get(owner, claims.sub);
      if (!g) throw new HttpError(403, "not_a_contact", "You aren't a recovery contact for that person.");
      requireHardened(owner);
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
    ["POST", "/alerts/:ref/cancel", ({ params, claims, body }) => {
      needHolder(claims, "POST", `/recovery/alerts/${params.ref}/cancel`, body);
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
      // The recovering device's public keys: a station seals the chip's key to them (the app
      // checks them against the code it scanned, so a server can't swap in its own).
      return json(200, { code: q.code, platform: q.platform, createdAt: q.created_at, status: q.status, kinds: kindsOf(q), anchorMode: q.anchor_mode || undefined, kemPk: b64u(q.kem_pk), xPk: b64u(q.x_pk) });
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
      needHolder(claims, "POST", `/recovery/station/requests/${params.code}/verify`, body);
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
      const { account, part, sealed } = openAnchor(ok.mrz, chip.dg15);
      if (account === claims.sub) throw new HttpError(400, "self", "A station can't verify its own operator.");
      // A v2 part opens only with the chip's DG15: the station seals that to the recovering
      // device's own keys (it already has them, from the recovery code) and signs it with its account key.
      let anchorKey = null;
      if (sealed) {
        anchorKey = unb64u(String(r.chipKey || ""));
        if (!anchorKey.length) throw new HttpError(400, "update_required", "Update HumID on this station: it must hand the chip's key to the recovering phone.");
        checkEnvelope(anchorKey, { signerFp: claims.dsaFp, recipientKemPk: new Uint8Array(q.kem_pk) });
      }
      const first = bindAccount(q, account);
      db.prepare("UPDATE requests SET anchor_mode = 'station', anchor_blob = ?, station = ?, anchor_key = ? WHERE id = ?").run(wrap(`request ${q.id}`, q.ref, part), claims.sub, anchorKey, q.id);
      part.fill(0);
      const e = evaluate(q.id);
      // The operator learns the outcome, not whose HumID it is.
      return json(200, { verified: true, kinds: kindsOf(e), releaseAt: e.release_at, platform: e.platform, ref: e.ref, account: e.account, first, country: ok.issuerCountry, chipProof: ok.aaRequired });
    }, { bodyLimit: 3 * CHIP_MAX }],
  ];

  /* ---------- duress and settings ---------- */

  const modes = [
    // Gateway only: the account's signed recovery mode, at setup and when its holder switches.
    ["POST", "/internal/recovery-mode", ({ claims, body }) => {
      gatewayOnly(claims);
      const r = parseObject(body);
      const account = String(r.account || "");
      if (!/^hid_[0-9a-f]{40}$/.test(account)) throw new HttpError(400, "bad_subject", "Unknown subject");
      const m = learnMode(account, r, { sync: r.sync === true });
      return json(200, { mode: m.mode, version: m.version, epoch: m.epoch });
    }],
    // Gateway only: where this service stands, to compare with identity's statement.
    ["GET", "/internal/recovery-mode/:id", ({ params, claims }) => {
      gatewayOnly(claims);
      const st = statementOf(String(params.id));
      const mark = getMark.get(String(params.id));
      return json(200, {
        mode: st.mode, version: st.version, epoch: st.epoch, broken: !!st.broken, markVersion: mark?.version ?? 0,
        ...(st.sig ? { statement: { mode: st.mode, version: st.version, epoch: st.epoch, prev: st.prev, sig: b64u(st.sig) } } : {}),
      });
    }],
    // The account's signed statement as this service holds it, for the holder's devices to check
    // against their own account key, and what recovery material is still stored here.
    ["GET", "/mode", ({ claims }) => {
      const sub = needUser(claims);
      const st = statementOf(sub);
      return json(200, { mode: st.mode, version: st.version, epoch: st.epoch, prev: st.prev ?? RECMODE_GENESIS, sig: st.sig ? b64u(st.sig) : null, ...(st.broken ? { broken: true } : {}), escrow: escrowOf(sub) });
    }],
  ];

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
      needHolder(claims, "PUT", "/recovery/settings", body);
      const r = parseObject(body);
      db.prepare(`INSERT INTO settings (account, duress_alert, updated_at) VALUES (?, ?, ?)
                  ON CONFLICT(account) DO UPDATE SET duress_alert = excluded.duress_alert, updated_at = excluded.updated_at`)
        .run(claims.sub, r.duressAlert ? 1 : 0, new Date().toISOString());
      return json(200, { duressAlert: !!r.duressAlert });
    }],
  ];

  if (!corePk) throw new Error("recovery needs HUMID_CORE_STATEMENT_PK (run setup again, or init on Windows)");
  log.info("recovery delay", { hours: +(delayMs / HOUR).toFixed(3) });
  return createService({ tls,
    name: "recovery", port, routes: [...links, ...card, ...anchor, ...keys, ...contacts, ...requests, ...station, ...modes, ...duress], bodyLimit: 64 * 1024,
    verify: (t) => verifyAssertion(internalPk, t, "recovery"),
  });
}

if (isMain(import.meta.url)) createRecovery().start();
