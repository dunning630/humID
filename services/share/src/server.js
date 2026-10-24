// share — share requests (docs/SHARE.md): a verifier asks a HumID holder for named facts, and
// the holder answers inside a live check on their phone.
//
// What it stores, and nothing more:
//   codes     a share code, the account it belongs to, the code's public inbox keys and salt
//             (the private halves are derived on the holder's devices from their vault-index key)
//   requests  a sealed request of the one fixed size, which code it came in on, when, the
//             verifier's poll token as a SHA3 hash, and once answered: the sealed answer, the
//             sealed note for the holder's other devices, and the ledger's receipt
//
// It holds no keys and opens nothing. It never learns who the verifier is (their name and key
// are inside the sealed request), what was asked, whether the answer was yes or no (approvals
// and denials are the same size), or any value.
//
// Every answer is released only with the holder's own step-up proof, checked here (SRV-30), and
// the ledger's signed receipt for exactly that answer, so neither the gateway alone nor a missing
// ledger record can release one.

import { createHash, randomBytes } from "node:crypto";
import { createService, serviceTlsFromEnv, openDb, env, json, parseJson, verifyAssertion, HttpError, isMain, b64u, unb64u } from "@humid/svc";
import { holderProofs, checkReceipt } from "@humid/svc/holder";
import { shareCode, parseCode, SEALED, SALT_BYTES, REQUEST_TTL_MS } from "@humid/share";

const ID_RE = /^hid_[0-9a-f]{40}$/;
const REQ_RE = /^[0-9a-f]{20}$/;
const sha3 = (s) => createHash("sha3-256").update(s).digest("hex");
const bytesOf = (v, n, what) => {
  let b;
  try { b = unb64u(String(v ?? "")); } catch { b = null; }
  if (!b || (n && b.length !== n)) throw new HttpError(400, "bad_request", `Bad ${what}`);
  return b;
};

export function createShare({
  tls = serviceTlsFromEnv(),
  port = Number(env("PORT", "8088")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  corePk = env("HUMID_CORE_STATEMENT_PK"),
  /** Active share codes one account may hold. */
  maxCodes = Number(env("HUMID_SHARE_MAX_CODES", "20")),
  /** Unanswered requests one code may hold at once: a code someone posted can't fill the server. */
  maxPendingPerCode = Number(env("HUMID_SHARE_MAX_PENDING", "20")),
  /** How long an answered request, and its sealed answer, are kept for the verifier to collect. */
  keepMs = Number(env("HUMID_SHARE_KEEP_MS", String(7 * 24 * 3600_000))),
  now = () => Date.now(),
} = {}) {
  if (!corePk) throw new Error("share needs HUMID_CORE_STATEMENT_PK (run setup again, or init on Windows)");
  const db = openDb(dataDir, "share.db", [
    `CREATE TABLE codes (code TEXT PRIMARY KEY, sub TEXT NOT NULL, kem BLOB NOT NULL, x BLOB NOT NULL, salt BLOB NOT NULL, label TEXT, created_at INTEGER NOT NULL, revoked_at INTEGER)`,
    `CREATE INDEX codes_sub ON codes (sub)`,
    `CREATE TABLE requests (id TEXT PRIMARY KEY, code TEXT NOT NULL, sub TEXT NOT NULL, sealed BLOB NOT NULL, token TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
       answered_at INTEGER, answer BLOB, note BLOB, receipt TEXT, device TEXT)`,
    `CREATE INDEX requests_sub ON requests (sub)`,
    `CREATE INDEX requests_code ON requests (code)`,
  ]);
  const q = {
    codesOf: db.prepare("SELECT code, kem, x, salt, label, created_at, revoked_at FROM codes WHERE sub = ? ORDER BY created_at"),
    activeCount: db.prepare("SELECT COUNT(*) AS n FROM codes WHERE sub = ? AND revoked_at IS NULL"),
    code: db.prepare("SELECT * FROM codes WHERE code = ?"),
    addCode: db.prepare("INSERT INTO codes (code, sub, kem, x, salt, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"),
    revoke: db.prepare("UPDATE codes SET revoked_at = ? WHERE code = ? AND sub = ? AND revoked_at IS NULL"),
    pending: db.prepare("SELECT COUNT(*) AS n FROM requests WHERE code = ? AND answered_at IS NULL AND expires_at > ?"),
    addReq: db.prepare("INSERT INTO requests (id, code, sub, sealed, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)"),
    req: db.prepare("SELECT * FROM requests WHERE id = ?"),
    inbox: db.prepare("SELECT id, code, sealed, created_at, expires_at, answered_at, note, device FROM requests WHERE sub = ? AND (answered_at IS NOT NULL OR expires_at > ?) ORDER BY created_at DESC LIMIT 100"),
    answer: db.prepare("UPDATE requests SET answered_at = ?, answer = ?, note = ?, receipt = ?, device = ? WHERE id = ? AND sub = ? AND answered_at IS NULL"),
    expire: db.prepare("DELETE FROM requests WHERE (answered_at IS NULL AND expires_at < ?) OR (answered_at IS NOT NULL AND answered_at < ?)"),
  };
  let lastExpire = 0;
  const expire = () => { const t = now(); if (t - lastExpire > 60_000) { lastExpire = t; q.expire.run(t, t - keepMs); } };

  const proofs = holderProofs({ corePk, now });
  const gatewayOnly = (claims) => { if (claims?.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
  const holder = (claims) => {
    gatewayOnly(claims);
    if (!ID_RE.test(String(claims.sub || ""))) throw new HttpError(401, "unauthenticated", "Sign in first");
    return claims.sub;
  };
  const codeView = (r) => ({ code: r.code, kemPk: b64u(r.kem), xPk: b64u(r.x), salt: b64u(r.salt), label: r.label || "", createdAt: Number(r.created_at), revoked: !!r.revoked_at });
  const activeCode = (input) => {
    const c = parseCode(input);
    const r = c && q.code.get(c);
    // a revoked code and one that never existed look the same
    if (!r || r.revoked_at) throw new HttpError(404, "unknown_code", "No HumID has that share code.");
    return r;
  };

  const routes = [
    /* ---- the holder (signed in) ---- */

    // A new share code: the app derived its inbox keys from its vault-index key and this salt.
    // The code is computed here from the keys, and the app checks it's the one it expected.
    ["POST", "/internal/codes", ({ body, claims }) => {
      const sub = holder(claims);
      const r = parseJson(body) || {};
      const kem = bytesOf(r.kemPk, 1568, "inbox key"), x = bytesOf(r.xPk, 32, "inbox key"), salt = bytesOf(r.salt, SALT_BYTES, "salt");
      const label = typeof r.label === "string" ? r.label.slice(0, 200) : null; // sealed under the index key by the app: opaque here
      if (Number(q.activeCount.get(sub).n) >= maxCodes) throw new HttpError(409, "too_many_codes", `You have ${maxCodes} share codes. Turn one off first.`);
      const code = shareCode(kem, x);
      if (q.code.get(code)) throw new HttpError(409, "code_exists", "That code exists already. Make a new one.");
      q.addCode.run(code, sub, kem, x, salt, label, now());
      return json(201, { code });
    }, { bodyLimit: 8 * 1024 }],
    ["GET", "/internal/codes", ({ claims }) => json(200, { codes: q.codesOf.all(holder(claims)).map(codeView) })],
    ["DELETE", "/internal/codes/:code", ({ params, claims }) => {
      const sub = holder(claims);
      const c = parseCode(params.code);
      if (!c || !q.revoke.run(now(), c, sub).changes) throw new HttpError(404, "not_found", "No such share code.");
      return json(200, { code: c, revoked: true });
    }],

    // Everything waiting, and what was answered, for every device of the account.
    ["GET", "/internal/inbox", ({ claims }) => {
      const sub = holder(claims);
      expire();
      const t = now();
      const list = q.inbox.all(sub, t).map((r) => ({
        id: r.id, code: r.code, sealed: b64u(r.sealed), at: Number(r.created_at), expiresAt: Number(r.expires_at),
        ...(r.answered_at ? { answeredAt: Number(r.answered_at), note: b64u(r.note), device: r.device } : {}),
      }));
      return json(200, { requests: list });
    }],

    // The answer. The holder's step-up proof (checked here, single use) and the ledger's receipt
    // for exactly this answer and this proof. Both sealed parts must be exactly their sizes.
    ["POST", "/internal/requests/:id/answer", ({ params, body, claims }) => {
      const sub = holder(claims);
      if (!REQ_RE.test(params.id)) throw new HttpError(404, "not_found", "No such request.");
      const ok = proofs.check(claims.holder, { sub, method: "POST", path: `/share/requests/${params.id}/answer`, body });
      checkReceipt(corePk, claims.receipt, { sub, type: "share.answered", want: { ref: params.id, proof: ok.proofHash } });
      const r = parseJson(body) || {};
      const answer = bytesOf(r.answer, SEALED.answer, "answer"), note = bytesOf(r.note, SEALED.note, "note");
      const row = q.req.get(params.id);
      if (!row || row.sub !== sub) throw new HttpError(404, "not_found", "No such request.");
      if (row.answered_at) throw new HttpError(409, "answered", "This request was answered already.");
      if (row.expires_at < now()) throw new HttpError(410, "expired", "This request expired.");
      q.answer.run(now(), answer, note, String(claims.receipt), ok.device, params.id, sub);
      return json(200, { id: params.id, answered: true });
    }, { bodyLimit: 32 * 1024 }],

    /* ---- the verifier (a session that never signs in: no account here) ---- */

    // A code's public inbox keys. The verifier recomputes the code from them before sealing.
    ["POST", "/internal/lookup", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = activeCode((parseJson(body) || {}).code);
      return json(200, { code: r.code, kemPk: b64u(r.kem), xPk: b64u(r.x) });
    }, { bodyLimit: 1024 }],

    // A sealed request, of the one fixed size. The answer goes to whoever holds the token, so the
    // server keeps only its hash. sub is for the gateway (to write the holder's ledger), never the verifier.
    ["POST", "/internal/requests", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body) || {};
      const code = activeCode(r.code);
      const sealed = bytesOf(r.sealed, SEALED.request, "sealed request");
      expire();
      if (Number(q.pending.get(code.code, now()).n) >= maxPendingPerCode) throw new HttpError(429, "inbox_full", "This HumID has too many requests waiting. Try again later.");
      const id = randomBytes(10).toString("hex");
      const token = randomBytes(32).toString("base64url");
      const t = now();
      q.addReq.run(id, code.code, code.sub, sealed, sha3(token), t, t + REQUEST_TTL_MS);
      return json(201, { id, token, expiresAt: t + REQUEST_TTL_MS, sub: code.sub });
    }, { bodyLimit: 32 * 1024 }],

    // The verifier collects the answer with its token. Unknown ids and wrong tokens look the same.
    ["POST", "/internal/requests/:id/result", ({ params, body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body) || {};
      const row = REQ_RE.test(params.id) ? q.req.get(params.id) : null;
      if (!row || typeof r.token !== "string" || sha3(r.token) !== row.token) throw new HttpError(404, "not_found", "No such request.");
      if (!row.answered_at) return json(200, { id: row.id, status: row.expires_at < now() ? "expired" : "waiting" });
      let receipt = null;
      // the ledger's receipt, as signed (payload.signature): the entry's place and hash, and which proof it records
      try { const p = JSON.parse(Buffer.from(String(row.receipt).split(".")[0] || "", "base64url").toString()); receipt = { seq: p.seq, hash: p.hash, proof: p.detail?.proof ?? null, at: p.iat ?? null }; } catch {}
      return json(200, { id: row.id, status: "answered", answer: b64u(row.answer), answeredAt: Number(row.answered_at), receipt });
    }, { bodyLimit: 1024 }],
  ];

  const svc = createService({ tls, name: "share", port, routes, bodyLimit: 8 * 1024, verify: (t) => verifyAssertion(internalPk, t, "share") });
  return { ...svc, close: () => db.close() };
}

if (isMain(import.meta.url)) createShare().start();
