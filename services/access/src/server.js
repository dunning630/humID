// access — anonymous payment for HumID. It knows which access codes were sold
// and which passes were spent, and nothing that connects the two, or either
// one to an account:
//
//   access code  bought for cash or online; the code is the receipt. Stored as a
//                hash, with its batch and the DAY it was minted and used.
//   pass         the app swaps a code for a pass this service signs BLIND
//                (RFC 9474): it never sees the pass it signs.
//   spend        registration spends the pass. Stored: a hash of the pass and
//                the DAY. No account id: the gateway creates the account after
//                the spend, and this service never learns which one.
//
// It is its own service, with its own database, so a breach of identity, vault
// or ledger learns nothing about payments, and a breach here learns nothing
// about accounts. Only the gateway can call it.
//
// Operators mint codes with:   node server.mjs mint <count> [batch]
// and sell them at a counter or through any store that delivers license keys.

import { createService, serviceTlsFromEnv, sealerFromEnv, isSealedText, openDb, env, json, parseJson, verifyAssertion, HttpError, isMain } from "@humid/svc";
import {
  parseAccessCode, accessCodeHash, newAccessCode, verifyPass, spentId, unb64u, b64u, PassError, MAX_KEYS,
} from "@humid/pass";
import { newIssuerKey, issuerKey, blindSign, KEY_BITS } from "@humid/pass/issuer";

const DAY = 86_400_000;
/** Stamps one live check may approve: one action that sends a few messages (a delete and an end). */
export const MAX_STAMPS_PER_CHECK = 4;
const day = (t = Date.now()) => new Date(t).toISOString().slice(0, 10); // dates only: no times to correlate

export function createAccess({
  /** Mutual TLS when the gateway calls from another machine (server 3.0): HUMID_TLS_* files. */
  tls = serviceTlsFromEnv(),
  /** Secrets sealed at rest (packages/svc/src/seal.js). */
  seal = sealerFromEnv(),
  port = Number(env("PORT", "8085")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  // A key signs new passes for issueDays, and its passes are accepted for acceptDays. With
  // a new key each issue period, at most two keys are ever published (MAX_KEYS).
  issueDays = Number(env("HUMID_PASS_ISSUE_DAYS", "365")),
  acceptDays = Number(env("HUMID_PASS_ACCEPT_DAYS", "545")),
  keyBits = Number(env("HUMID_PASS_KEY_BITS", String(KEY_BITS))),
  // Live stamps (HumID 4.0 messaging, docs/MESSAGING.md): a SEPARATE blind-signing key, never
  // the pass key. A blind signer signs whatever it is handed; with one shared key, a "stamp"
  // request could be a blinded access pass. Stamps matter only when received (the relay keeps
  // messages 14 days), so stamp keys rotate quickly.
  stampIssueDays = Number(env("HUMID_STAMP_ISSUE_DAYS", "90")),
  stampAcceptDays = Number(env("HUMID_STAMP_ACCEPT_DAYS", "120")),
  stampKeyBits = Number(env("HUMID_STAMP_KEY_BITS", String(KEY_BITS))),
  now = () => Date.now(),
} = {}) {
  if (!(stampAcceptDays > stampIssueDays && stampAcceptDays < 2 * stampIssueDays)) throw new Error("HUMID_STAMP_ACCEPT_DAYS must be between STAMP_ISSUE_DAYS and 2 × STAMP_ISSUE_DAYS");
  if (!(acceptDays > issueDays && acceptDays < 2 * issueDays)) throw new Error("HUMID_PASS_ACCEPT_DAYS must be between ISSUE_DAYS and 2 × ISSUE_DAYS, so at most two keys are live");
  const db = openDb(dataDir, "access.db", [
    `CREATE TABLE codes (hash TEXT PRIMARY KEY, batch TEXT NOT NULL, minted_day TEXT NOT NULL,
                         used_day TEXT, blinded_sha TEXT, kid TEXT)`,
    `CREATE TABLE spent (id TEXT PRIMARY KEY, day TEXT NOT NULL)`,
    // Issuer keys: the private key stays in this file on this service's own volume.
    `CREATE TABLE keys (id TEXT PRIMARY KEY, pem TEXT NOT NULL, issue_until INTEGER NOT NULL, accept_until INTEGER NOT NULL)`,
    // 4.0 live stamps: their own keys, and per-day totals only (how many messages a live human
    // approved, network-wide). Nothing about who asked, for what, or to whom.
    `CREATE TABLE stamp_keys (id TEXT PRIMARY KEY, pem TEXT NOT NULL, issue_until INTEGER NOT NULL, accept_until INTEGER NOT NULL);
     CREATE TABLE stamp_days (day TEXT PRIMARY KEY, stamps INTEGER NOT NULL, checks INTEGER NOT NULL)`,
  ]);

  /* ---------- keys ---------- */
  // Issuer private keys are sealed at rest when the server has a seal key; plain ones from before 3.0 are sealed in place.
  if (seal.on) {
    for (const row of db.prepare("SELECT id, pem FROM keys").all()) {
      if (!isSealedText(row.pem)) db.prepare("UPDATE keys SET pem = ? WHERE id = ?").run(seal.sealText(`access/issuer/${row.id}`, row.pem), row.id);
    }
  }
  const loaded = new Map();
  const load = (row) => {
    if (!loaded.has(row.id)) loaded.set(row.id, { ...issuerKey(seal.openText(`access/issuer/${row.id}`, row.pem)), issueUntil: row.issue_until, acceptUntil: row.accept_until });
    return loaded.get(row.id);
  };
  /** Keys whose passes are still accepted, newest first; makes a new issuing key when the last one's period ends. */
  function liveKeys() {
    const t = now();
    let rows = db.prepare("SELECT * FROM keys WHERE accept_until > ? ORDER BY issue_until DESC").all(t);
    if (!rows.length || rows[0].issue_until <= t) {
      const k = newIssuerKey(keyBits);
      db.prepare("INSERT INTO keys (id, pem, issue_until, accept_until) VALUES (?, ?, ?, ?)").run(k.id, seal.sealText(`access/issuer/${k.id}`, k.pem), t + issueDays * DAY, t + acceptDays * DAY);
      rows = db.prepare("SELECT * FROM keys WHERE accept_until > ? ORDER BY issue_until DESC").all(t);
    }
    return rows.slice(0, MAX_KEYS).map(load);
  }
  const issuing = () => liveKeys()[0];

  /* ---------- live stamp keys (separate from pass keys) ---------- */
  if (seal.on) {
    for (const row of db.prepare("SELECT id, pem FROM stamp_keys").all()) {
      if (!isSealedText(row.pem)) db.prepare("UPDATE stamp_keys SET pem = ? WHERE id = ?").run(seal.sealText(`access/stamp/${row.id}`, row.pem), row.id);
    }
  }
  const stampLoaded = new Map();
  const loadStamp = (row) => {
    if (!stampLoaded.has(row.id)) stampLoaded.set(row.id, { ...issuerKey(seal.openText(`access/stamp/${row.id}`, row.pem)), issueUntil: row.issue_until, acceptUntil: row.accept_until });
    return stampLoaded.get(row.id);
  };
  function liveStampKeys() {
    const t = now();
    let rows = db.prepare("SELECT * FROM stamp_keys WHERE accept_until > ? ORDER BY issue_until DESC").all(t);
    if (!rows.length || rows[0].issue_until <= t) {
      let k;
      // Never a pass key: different key, different id (checked, not assumed).
      const passIds = new Set(db.prepare("SELECT id FROM keys").all().map((r) => r.id));
      do { k = newIssuerKey(stampKeyBits); } while (passIds.has(k.id));
      db.prepare("INSERT INTO stamp_keys (id, pem, issue_until, accept_until) VALUES (?, ?, ?, ?)").run(k.id, seal.sealText(`access/stamp/${k.id}`, k.pem), t + stampIssueDays * DAY, t + stampAcceptDays * DAY);
      rows = db.prepare("SELECT * FROM stamp_keys WHERE accept_until > ? ORDER BY issue_until DESC").all(t);
    }
    return rows.slice(0, MAX_KEYS).map(loadStamp);
  }
  const countStamps = db.prepare(`INSERT INTO stamp_days (day, stamps, checks) VALUES (?, ?, 1)
    ON CONFLICT(day) DO UPDATE SET stamps = stamps + excluded.stamps, checks = checks + 1`);

  /* ---------- codes ---------- */
  function mint(count, batch = `batch-${day(now())}`) {
    const n = Math.max(1, Math.min(10_000, Math.floor(Number(count) || 0)));
    const b = String(batch).replace(/[^\w.-]/g, "").slice(0, 40) || "batch";
    const ins = db.prepare("INSERT INTO codes (hash, batch, minted_day) VALUES (?, ?, ?)");
    const codes = [];
    db.exec("BEGIN");
    try {
      for (let i = 0; i < n; i++) {
        const c = newAccessCode();
        ins.run(accessCodeHash(parseAccessCode(c)), b, day(now()));
        codes.push(c);
      }
      db.exec("COMMIT");
    } catch (e) { db.exec("ROLLBACK"); throw e; }
    return codes;
  }

  const gatewayOnly = (claims) => { if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
  const passFail = (e) => { if (e instanceof PassError) throw new HttpError(400, e.code, e.message); throw e; };
  const sha = (b) => accessCodeHash(b64u(b)); // any stable hash; the blinded request is unlinkable anyway

  const routes = [
    // The published keys. The app refuses more than MAX_KEYS, or more than one issuing key.
    ["GET", "/internal/keys", ({ claims }) => {
      gatewayOnly(claims);
      const ks = liveKeys();
      return json(200, { suite: "RSABSSA-SHA384-PSS-Randomized", keys: ks.map((k, i) => ({ ...k.publicView, issuing: i === 0, acceptUntil: day(k.acceptUntil) })) });
    }],

    // Swap an access code for a blind signature. A retry with the same blinded request
    // (the app crashed before it got the answer) gets the same signature again; a
    // different request with a used code is refused.
    ["POST", "/internal/issue", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body) || {};
      const code = parseAccessCode(r.code);
      if (!code) throw new HttpError(400, "code_invalid", "That access code isn't valid. Check it and try again.");
      const key = issuing();
      if (String(r.kid) !== key.id) throw new HttpError(409, "key_changed", "The pass key changed. Try again.");
      let blinded;
      try { blinded = unb64u(String(r.blinded || "")); } catch { throw new HttpError(400, "bad_request", "Malformed request"); }
      const h = accessCodeHash(code);
      const row = db.prepare("SELECT * FROM codes WHERE hash = ?").get(h);
      if (!row) throw new HttpError(403, "code_unknown", "This access code wasn't issued by this vault.");
      const bsha = sha(blinded);
      if (row.used_day && !(row.blinded_sha === bsha && row.kid === key.id)) throw new HttpError(409, "code_used", "This access code has already been used.");
      let sig;
      try { sig = blindSign(key, blinded); } catch (e) { passFail(e); }
      if (!row.used_day) {
        const u = db.prepare("UPDATE codes SET used_day = ?, blinded_sha = ?, kid = ? WHERE hash = ? AND used_day IS NULL").run(day(now()), bsha, key.id, h);
        if (u.changes !== 1) throw new HttpError(409, "code_used", "This access code has already been used.");
      }
      return json(200, { kid: key.id, blindSig: b64u(sig) });
    }],

    // Spend a pass, once. Returns only the spent id, so a failed registration can give it back.
    ["POST", "/internal/spend", ({ body, claims }) => {
      gatewayOnly(claims);
      const pass = (parseJson(body) || {}).pass;
      const key = liveKeys().find((k) => k.id === String(pass?.kid));
      if (!key) throw new HttpError(403, "pass_expired", "This access pass has expired or isn't from this vault.");
      if (!verifyPass(key.pub, pass)) throw new HttpError(403, "pass_invalid", "This access pass isn't valid.");
      const id = spentId(pass);
      const ins = db.prepare("INSERT OR IGNORE INTO spent (id, day) VALUES (?, ?)").run(id, day(now()));
      if (ins.changes !== 1) throw new HttpError(409, "pass_spent", "This access pass has already been used.");
      return json(200, { spent: id });
    }],

    // Live stamps: the published keys (at most two, one issuing; the app refuses a stamp key that
    // is also a pass key).
    ["GET", "/internal/stamp/keys", ({ claims }) => {
      gatewayOnly(claims);
      const ks = liveStampKeys();
      return json(200, { suite: "RSABSSA-SHA384-PSS-Randomized", keys: ks.map((k, i) => ({ ...k.publicView, issuing: i === 0, acceptUntil: day(k.acceptUntil) })) });
    }],

    // Blind-sign the stamps ONE live check approved. The gateway calls this only inside a
    // verified step-up whose signature covers these exact blinded values, so each call is one
    // check; one check may approve a few stamps for one action (deleting a conversation for
    // both is a delete and an end). Counted per day; nothing else is kept.
    ["POST", "/internal/stamp/sign", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body) || {};
      const key = liveStampKeys()[0];
      if (String(r.kid) !== key.id) throw new HttpError(409, "key_changed", "The stamp key changed. Try again.");
      const list = Array.isArray(r.blinded) ? r.blinded : [];
      if (list.length < 1 || list.length > MAX_STAMPS_PER_CHECK) throw new HttpError(400, "bad_request", `One check approves 1 to ${MAX_STAMPS_PER_CHECK} stamps`);
      const sigs = [];
      for (const b of list) {
        let blinded;
        try { blinded = unb64u(String(b || "")); } catch { throw new HttpError(400, "bad_request", "Malformed request"); }
        try { sigs.push(b64u(blindSign(key, blinded))); } catch (e) { passFail(e); }
      }
      countStamps.run(day(now()), sigs.length);
      return json(200, { kid: key.id, blindSigs: sigs });
    }],

    // How many messages a live human approved, network-wide, per day: a measure of real human
    // activity that a bot farm can't inflate, and that says nothing about anyone.
    ["GET", "/internal/stamp/stats", ({ claims }) => {
      gatewayOnly(claims);
      const rows = db.prepare("SELECT day, stamps, checks FROM stamp_days ORDER BY day DESC LIMIT 60").all();
      return json(200, { days: rows.map((x) => ({ day: x.day, stamps: Number(x.stamps), checks: Number(x.checks) })) });
    }],

    // The registration that spent it didn't go through: the pass is unspent again.
    ["POST", "/internal/refund", ({ body, claims }) => {
      gatewayOnly(claims);
      const id = String((parseJson(body) || {}).spent || "");
      if (!/^[0-9a-f]{64}$/.test(id)) throw new HttpError(400, "bad_request", "Malformed request");
      db.prepare("DELETE FROM spent WHERE id = ?").run(id);
      return json(200, { refunded: true });
    }],
  ];

  const svc = createService({ tls, name: "access", port, routes, bodyLimit: 16 * 1024, verify: (t) => verifyAssertion(internalPk, t, "access") });
  // The first key is made at start-up (4096-bit keys take a moment), not on someone's first request,
  // and never by `mint`, which may run next to a live service.
  return { ...svc, start: (...a) => { liveKeys(); liveStampKeys(); return svc.start(...a); }, mint, close: () => db.close() };
}

if (isMain(import.meta.url)) {
  const [cmd, count, batch] = process.argv.slice(2);
  if (cmd === "mint") {
    // docker compose run --rm access server.mjs mint 100 counter-2026-10
    const a = createAccess();
    const codes = a.mint(count || 1, batch);
    process.stdout.write(codes.join("\n") + "\n");
    a.close();
  } else createAccess().start();
}
