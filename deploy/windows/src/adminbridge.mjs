// The gateway's side of the admin console (docs/ADMIN.md). The console runs as a
// separate, more privileged program; the two meet only in one folder:
//
//   data\admin\summary.json            console → gateway: counts and alerts for admins' phones
//   data\admin\requests\<code>.json    console → gateway: a change waiting for a phone's approval
//   data\admin\approvals\<code>.json   gateway → console: the live-check proof, as signed
//
// Nothing here is trusted by the console. It re-checks every approval against the keys
// it pinned for each administrator's phone, so a server process that was taken over can
// write files here but can't approve anything.
import { readFileSync, writeFileSync, mkdirSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";

const CODE = /^[0-9A-HJKMNP-TV-Z]{12}$/;

export function adminPaths(root) {
  const dir = join(root, "data", "admin");
  return { dir, summary: join(dir, "summary.json"), requests: join(dir, "requests"), approvals: join(dir, "approvals") };
}

const readJson = (file) => {
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return null; }
};

export function createAdminBridge(root) {
  const p = adminPaths(root);
  for (const d of [p.dir, p.requests, p.approvals]) mkdirSync(d, { recursive: true });
  return {
    summary() {
      const s = readJson(p.summary);
      return s && typeof s === "object" ? s : null;
    },
    request(code) {
      if (!CODE.test(code)) return null;
      const r = readJson(join(p.requests, `${code}.json`));
      if (!r || r.code !== code || !["enrol", "action"].includes(r.kind)) return null;
      return r;
    },
    approved(code, record) {
      if (!CODE.test(code)) throw new Error("bad code");
      const file = join(p.approvals, `${code}.json`);
      if (existsSync(file)) throw new Error("already approved");
      const tmp = `${file}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(record));
      renameSync(tmp, file);
    },
  };
}
