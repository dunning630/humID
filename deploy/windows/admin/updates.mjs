// New versions of HumID Server for Windows, from the repository's GitHub releases.
//
// Only a release tagged server-win-v<version>, newer than what's installed, whose zip
// GitHub publishes a SHA-256 digest for, is offered. The download is checked against
// that digest here, and again (by the update job) right before it's installed, and
// the phone's approval covers the exact SHA-256 of the file.
import { createHash } from "node:crypto";
import { writeFileSync, renameSync, existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

export const DEFAULT_REPO = "dunning630/humID";
const TAG = /^server-win-v(\d+)\.(\d+)\.(\d+)$/;

export function parseVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(v || "").trim());
  return m ? m.slice(1, 4).map(Number) : null;
}
export function compareVersions(a, b) {
  const x = parseVersion(a), y = parseVersion(b);
  if (!x || !y) return NaN;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

const gh = (fetchImpl, token) => async (url, { accept = "application/vnd.github+json", raw = false } = {}) => {
  const headers = { accept, "user-agent": "HumID-Admin", "x-github-api-version": "2022-11-28" };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetchImpl(url, { headers, redirect: "follow", signal: AbortSignal.timeout(raw ? 300_000 : 20_000) });
  if (!res.ok) {
    const why = res.status === 404 ? (token ? "The repository or release wasn't found. Check HUMID_UPDATE_REPO and that the token can read it." : "The repository is private: add a read-only GitHub token with `humid admin token <token>`.")
      : res.status === 401 ? "GitHub refused the token. Make a new one and run `humid admin token <token>`."
      : res.status === 403 ? "GitHub refused (rate limit or token permissions). Try again later."
      : `GitHub answered ${res.status}.`;
    throw Object.assign(new Error(why), { status: res.status });
  }
  return raw ? Buffer.from(await res.arrayBuffer()) : res.json();
};

/**
 * The newest server release above `current`, or null.
 * → { version, tag, name, publishedAt, notes, asset: { id, name, size, sha256 } } | null
 */
export async function latestRelease({ repo = DEFAULT_REPO, token = "", current, fetchImpl = fetch }) {
  const get = gh(fetchImpl, token);
  const list = await get(`https://api.github.com/repos/${repo}/releases?per_page=50`);
  let best = null;
  for (const r of Array.isArray(list) ? list : []) {
    if (r.draft) continue;
    const m = TAG.exec(String(r.tag_name || ""));
    if (!m) continue;
    const version = m.slice(1, 4).join(".");
    if (!(compareVersions(version, current) > 0)) continue;
    if (best && compareVersions(version, best.version) <= 0) continue;
    const name = `HumID-Server-Windows-${version}.zip`;
    const a = (r.assets || []).find((x) => x.name === name);
    const sha256 = /^sha256:([0-9a-f]{64})$/.exec(String(a?.digest || ""))?.[1] || null;
    best = {
      version, tag: r.tag_name, name: String(r.name || r.tag_name).slice(0, 120), publishedAt: r.published_at,
      prerelease: !!r.prerelease, url: r.html_url,
      notes: String(r.body || "").slice(0, 6000),
      asset: a ? { id: a.id, name, size: a.size, sha256 } : null,
    };
  }
  return best;
}

/** Download the release zip into `dir` and check it against GitHub's digest. → { file, sha256 } */
export async function download({ repo = DEFAULT_REPO, token = "", release, dir, fetchImpl = fetch }) {
  const a = release.asset;
  if (!a) throw new Error(`Release ${release.tag} has no ${`HumID-Server-Windows-${release.version}.zip`}.`);
  if (!a.sha256) throw new Error(`GitHub publishes no SHA-256 digest for ${a.name}, so it can't be checked. Install it by hand if you trust it.`);
  const file = join(dir, a.name);
  if (existsSync(file) && sha256File(file) === a.sha256) return { file, sha256: a.sha256 };
  const bytes = await gh(fetchImpl, token)(`https://api.github.com/repos/${repo}/releases/assets/${a.id}`, { accept: "application/octet-stream", raw: true });
  const got = createHash("sha256").update(bytes).digest("hex");
  if (got !== a.sha256) throw new Error(`The download doesn't match GitHub's digest (expected ${a.sha256.slice(0, 16)}…, got ${got.slice(0, 16)}…). Nothing was installed.`);
  for (const f of readdirSync(dir)) if (f.endsWith(".zip") && f !== a.name) rmSync(join(dir, f), { force: true }); // keep one
  const tmp = `${file}.part`;
  writeFileSync(tmp, bytes);
  renameSync(tmp, file);
  return { file, sha256: got };
}

export const sha256File = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
