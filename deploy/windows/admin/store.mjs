// The admin console's own records, in <root>\admin (readable and writable only by
// SYSTEM and Administrators; the HumID server's account can't open it):
//
//   admins.json     administrators' phones and the keys pinned for each
//   audit.jsonl     every sign-in, request, approval, refusal and job, hash-chained
//   history.json    one health sample a minute for the last 24 hours
//   admin.env       settings for updates (GitHub token, repository)
import { readFileSync, writeFileSync, renameSync, appendFileSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

export const adminDir = (root) => join(root, "admin");

const sha256 = (s) => createHash("sha256").update(s).digest("hex");

export function writeJsonAtomic(file, value) {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 1));
  renameSync(tmp, file);
}
export const readJson = (file, fallback = null) => {
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return fallback; }
};

export function openStore(root) {
  const dir = adminDir(root);
  for (const d of ["", "jobs", "logins", "downloads"]) mkdirSync(join(dir, d), { recursive: true });
  const files = { admins: join(dir, "admins.json"), audit: join(dir, "audit.jsonl"), history: join(dir, "history.json") };

  /* ---- administrators ---- */
  const admins = () => readJson(files.admins, []).filter((a) => a && a.device && a.deviceDsaPk);
  const saveAdmins = (list) => writeJsonAtomic(files.admins, list);

  /* ---- audit log: each line carries the hash of the line before it ---- */
  let head = "0".repeat(64), count = 0, broken = null;
  if (existsSync(files.audit)) {
    const lines = readFileSync(files.audit, "utf8").split("\n").filter(Boolean);
    for (const [i, line] of lines.entries()) {
      let o;
      try { o = JSON.parse(line); } catch { broken = broken || `line ${i + 1} can't be read`; continue; }
      if (o.prev !== head) broken = broken || `line ${i + 1} doesn't follow the line before it`;
      head = sha256(line);
      count++;
    }
  }
  function audit(type, detail = {}) {
    const line = JSON.stringify({ t: new Date().toISOString(), ...detail, type, prev: head });
    appendFileSync(files.audit, line + "\n");
    head = sha256(line);
    count++;
  }
  function recentAudit(n = 60) {
    if (!existsSync(files.audit)) return [];
    const lines = readFileSync(files.audit, "utf8").split("\n").filter(Boolean).slice(-n);
    return lines.map((l) => { try { const { prev, ...o } = JSON.parse(l); return o; } catch { return null; } }).filter(Boolean).reverse();
  }

  /* ---- history: one sample a minute, 24 hours ---- */
  let history = readJson(files.history, []);
  if (!Array.isArray(history)) history = [];
  let lastSaved = 0;
  function sample(s, now = Date.now()) {
    history.push({ t: now, ...s });
    while (history.length > 1440) history.shift();
    if (now - lastSaved > 10 * 60_000) { try { writeJsonAtomic(files.history, history); } catch {} lastSaved = now; }
  }

  /* ---- one-time sign-in links, made by `humid console` in an admin terminal ---- */
  function useLogin(token, now = Date.now()) {
    if (typeof token !== "string" || !/^[A-Za-z0-9_-]{40,64}$/.test(token)) return false;
    const file = join(dir, "logins", `${sha256(token)}.json`);
    const l = readJson(file);
    if (!l) return false;
    rmSync(file, { force: true }); // once only
    return Number(l.exp) > now;
  }
  function sweepLogins(now = Date.now()) {
    for (const f of readdirSync(join(dir, "logins"))) {
      const p = join(dir, "logins", f);
      try { if (now - statSync(p).mtimeMs > 10 * 60_000) rmSync(p, { force: true }); } catch {}
    }
  }

  return {
    dir, files, admins, saveAdmins, audit, recentAudit,
    auditState: () => ({ head, count, broken }),
    sample, history: () => history,
    useLogin, sweepLogins,
  };
}
