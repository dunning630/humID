// What a computer backup leaves out, what it treats as sensitive, and the
// rules a restore runs under. Patterns are regular-expression sources (matched
// case-insensitively) so the policy can be stored in the repository's config
// and read the same way on Windows, macOS and Linux.
//
// Patterns run against "/" + the path relative to the backup root, with "/" as
// the separator and a trailing "/" on directories: "/Users/p/.ssh/" or
// "/Documents/tax.pdf".

/** Never backed up: OS swap and hibernation files, trash, caches, temp files. */
export const DEFAULT_EXCLUDE = Object.freeze([
  String.raw`/(pagefile|hiberfil|swapfile)\.sys$`,
  String.raw`/\$recycle\.bin/`,
  String.raw`/system volume information/`,
  String.raw`/\.trash(es|-\d+)?/`,
  String.raw`/(temp|tmp|\.cache|caches?|inetcache|code cache|gpucache)/`,
  String.raw`/(thumbs\.db|\.ds_store|desktop\.ini)$`,
  String.raw`\.(tmp|temp|swp|crdownload|part)$`,
]);

/**
 * Backed up, but marked sensitive: keys, saved passwords, browser login stores,
 * wallets, credential files. A restore leaves these out unless the person asks
 * for them in a separate step (and, once the server side lands, a second live
 * check). See docs/BACKUP.md#sensitive-files.
 */
export const DEFAULT_SENSITIVE = Object.freeze([
  String.raw`/\.(ssh|gnupg|aws|azure|kube|docker)/`,
  String.raw`/(id_rsa|id_ed25519|id_ecdsa|id_dsa)[^/]*$`,
  String.raw`\.(kdbx|pem|key|p12|pfx|ovpn|keystore|jks)$`,
  String.raw`/\.env(\.[^/]*)?$`,
  String.raw`/(\.npmrc|\.pypirc|\.netrc|\.git-credentials)$`,
  String.raw`/(login data|cookies|local state|web data)(-journal)?$`,
  String.raw`/(logins\.json|key4\.db|cert9\.db)$`,
  String.raw`/wallet\.dat$`,
  String.raw`/(wallets?|keystore)/`,
  String.raw`/library/keychains/`,
  String.raw`/microsoft/(credentials|protect|vault)/`,
]);

/**
 * Restore rules, recorded in the repository so every client applies the same
 * ones. In this provisional build the client enforces `sensitiveSeparately`;
 * the delay and device alerts need the keyshare service to hold back the vault
 * part's release (planned, docs/BACKUP.md#what-is-not-built-yet).
 */
export const DEFAULT_RESTORE = Object.freeze({
  fullRestoreDelayHours: 24, // a whole-computer restore waits, and every device can veto
  notifyDevices: true,
  sensitiveSeparately: true, // sensitive files come back only when asked for by name
});

export const DEFAULT_POLICY = Object.freeze({
  exclude: DEFAULT_EXCLUDE,
  sensitive: DEFAULT_SENSITIVE,
  restore: DEFAULT_RESTORE,
});

/** Merge a person's additions onto the defaults. Additions only add; defaults stay. */
export function makePolicy({ exclude = [], sensitive = [], restore = {} } = {}) {
  for (const p of [...exclude, ...sensitive]) new RegExp(p, "i"); // throws early on a bad pattern
  return {
    exclude: [...DEFAULT_EXCLUDE, ...exclude],
    sensitive: [...DEFAULT_SENSITIVE, ...sensitive],
    restore: { ...DEFAULT_RESTORE, ...restore },
  };
}

/** Compile a stored policy into a classifier: (path, isDir) → "exclude" | "sensitive" | "keep". */
export function classifier(policy = DEFAULT_POLICY) {
  const ex = policy.exclude.map((p) => new RegExp(p, "i"));
  const se = policy.sensitive.map((p) => new RegExp(p, "i"));
  return (path, isDir = false) => {
    const probe = "/" + path + (isDir ? "/" : "");
    if (ex.some((r) => r.test(probe))) return "exclude";
    if (se.some((r) => r.test(probe))) return "sensitive";
    return "keep";
  };
}

/**
 * Normalise a relative path to the stored form ("a/b/c"), or throw. Refuses
 * absolute paths, drive letters, "..", empty segments and control characters,
 * so a tampered snapshot can never write outside the restore folder.
 */
export function safePath(p) {
  const s = String(p ?? "").replace(/\\/g, "/");
  if (!s || s.startsWith("/") || /^[a-z]:/i.test(s) || /[\u0000-\u001f]/.test(s)) throw new Error(`Unsafe path in backup: ${JSON.stringify(p)}`);
  const parts = s.split("/");
  if (parts.some((x) => x === "" || x === "." || x === "..")) throw new Error(`Unsafe path in backup: ${JSON.stringify(p)}`);
  return parts.join("/");
}
