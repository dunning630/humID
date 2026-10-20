// Server secrets sealed at rest (server 3.0, docs/DEPLOY-VMS.md).
//
// Every long-lived secret a service keeps on disk (the gateway's HTP identity keys, the
// ledger's signing key, the recovery anchor secret, keyshare's master key, the access
// issuer keys, the internal assertion key and the role certificates' keys) is encrypted
// under one 32-byte seal key with AES-256-GCM, its file name bound in as associated data so
// sealed files can't be swapped for one another. The seal key itself never sits beside
// the data in the clear:
//
//   Windows   a DPAPI machine blob (deploy/windows/src/keyguard.mjs): only this Windows
//             installation can open it, and BitLocker with a TPM ties that to this machine
//   Docker    HUMID_SEAL_KEY_FILE: a file the operator mounts from somewhere else (a
//             Docker secret, a separate device, a KMS agent's output)
//
// Without a seal key, secrets are kept as before (plain files, owner-only), and the service
// says so in its log. A plain secret found while a seal key is set is sealed in place: the
// key material doesn't change, so a server's key id, and every phone pinned to it, stays.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, renameSync, openSync, writeSync, fsyncSync, closeSync, statSync, mkdirSync } from "node:fs";
import { dirname, basename } from "node:path";

const TAG = "humid-sealed";
const TEXT_PREFIX = "sealed:v1:";

const b64u = (b) => Buffer.from(b).toString("base64url");
const unb64u = (s) => Buffer.from(String(s), "base64url");

/** A sealer for one 32-byte key, or a pass-through when `key` is null. */
export function sealer(key) {
  if (key != null && (!(key instanceof Uint8Array) || key.length !== 32)) throw new Error("A seal key is 32 bytes");
  const k = key ? Buffer.from(key) : null;
  const aad = (name) => Buffer.from(`HUMID-SEAL-v1 ${name}`);
  const enc = (name, data) => {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", k, iv);
    c.setAAD(aad(name));
    const ct = Buffer.concat([c.update(Buffer.from(data)), c.final(), c.getAuthTag()]);
    return { iv, ct };
  };
  const dec = (name, iv, ct) => {
    if (!k) throw Object.assign(new Error(`${name} is sealed, and this server has no seal key to open it`), { code: "no_seal_key" });
    const d = createDecipheriv("aes-256-gcm", k, iv);
    d.setAAD(aad(name));
    d.setAuthTag(ct.subarray(ct.length - 16));
    try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]); }
    catch { throw Object.assign(new Error(`${name} doesn't open with this server's seal key (another machine's key, or the file was changed)`), { code: "bad_seal" }); }
  };
  return {
    on: !!k,
    /** bytes -> the sealed file's contents (JSON text) */
    seal(name, data) { const { iv, ct } = enc(name, data); return Buffer.from(JSON.stringify({ [TAG]: 1, name, iv: b64u(iv), ct: b64u(ct) })); },
    /** a file's contents -> the secret, whether sealed or (an older install) plain */
    open(name, buf) { const j = parseSealed(buf); return j ? dec(name, unb64u(j.iv), unb64u(j.ct)) : Buffer.from(buf); },
    /** a short secret kept inside another file or a database: "sealed:v1:<iv+ct>" */
    sealText(name, text) { if (!k) return text; const { iv, ct } = enc(name, Buffer.from(text, "utf8")); return TEXT_PREFIX + b64u(Buffer.concat([iv, ct])); },
    openText(name, text) { if (!isSealedText(text)) return text; const raw = unb64u(text.slice(TEXT_PREFIX.length)); return dec(name, raw.subarray(0, 12), raw.subarray(12)).toString("utf8"); },
  };
}

export const isSealedText = (t) => typeof t === "string" && t.startsWith(TEXT_PREFIX);

function parseSealed(buf) {
  const b = Buffer.from(buf);
  if (b[0] !== 0x7b) return null; // "{"
  try { const j = JSON.parse(b.toString("utf8")); return j && j[TAG] === 1 && typeof j.iv === "string" && typeof j.ct === "string" ? j : null; } catch { return null; }
}
export const isSealedFile = (path) => existsSync(path) && !!parseSealed(readFileSync(path));

/** Write a file in full or not at all: a temporary file beside it, flushed, then renamed over it. */
export function writeAtomic(path, data, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${dirname(path)}/.${basename(path)}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", mode);
  try { writeSync(fd, Buffer.from(data)); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
}

/**
 * Read a secret file, creating it with make() the first time. With a seal key, a new file is
 * written sealed and a plain one (from before 3.0, or a restored backup) is sealed in place
 * and its plain copy overwritten. Returns the secret's bytes.
 *   name   the secret's stable name ("gateway/htp-keys"), bound into the seal
 */
export function secretFile(path, { seal, name, make, log }) {
  const s = seal || sealer(null);
  if (!existsSync(path)) {
    const v = Buffer.from(make());
    writeAtomic(path, s.on ? s.seal(name, v) : v);
    return v;
  }
  const raw = readFileSync(path);
  const sealed = !!parseSealed(raw);
  const v = s.open(name, raw);
  if (!sealed && s.on) {
    // seal in place: same key material, so nothing that depends on it changes
    const size = statSync(path).size;
    try { const fd = openSync(path, "r+"); try { writeSync(fd, Buffer.alloc(size)); fsyncSync(fd); } finally { closeSync(fd); } } catch { /* best effort: the rename below replaces it anyway */ }
    writeAtomic(path, s.seal(name, v));
    log?.info?.("sealed a secret that was kept in plain", { name });
  } else if (!sealed && !s.on) log?.warn?.("secret kept unsealed: set a seal key (docs/DEPLOY-VMS.md)", { name });
  return v;
}

/**
 * The seal key a container is given: HUMID_SEAL_KEY_FILE names a file holding 32 bytes
 * (raw, hex or base64). Returns a sealer (a pass-through without one).
 */
export function sealerFromEnv(env = process.env) {
  if (globalThis.__HUMID_SEALER__) return globalThis.__HUMID_SEALER__; // set by a host that runs several services in one process
  const f = env.HUMID_SEAL_KEY_FILE;
  if (!f) return sealer(null);
  return sealer(parseKeyText(readFileSync(f)));
}

/** 32 bytes from a key file: raw, 64 hex characters, or base64/base64url. */
export function parseKeyText(buf) {
  const b = Buffer.from(buf);
  if (b.length === 32) return new Uint8Array(b);
  const t = b.toString("utf8").trim();
  if (/^[0-9a-fA-F]{64}$/.test(t)) return new Uint8Array(Buffer.from(t, "hex"));
  const d = Buffer.from(t.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (d.length === 32) return new Uint8Array(d);
  throw new Error("A seal key file holds 32 bytes: raw, 64 hex characters, or base64");
}
