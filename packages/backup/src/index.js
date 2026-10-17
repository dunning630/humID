// @humid/backup — HumID 3.0 (provisional). Whole-computer backups that HumID
// gates without becoming the only way back in. See docs/BACKUP.md.
//
// Platform-neutral: storage, the files being backed up and the restore target
// are passed in. Node folder adapters live in "@humid/backup/fs".

export {
  FORMAT, FORMAT_VERSION, DEFAULT_CHUNK,
  memoryStore, createRepo, describe, vaultPartEnvelope, unlock, replaceParts,
  backup, readSnapshot, listSnapshots, restore, unusedChunks,
} from "./repo.js";

export {
  KEY_BYTES, PART, PART_KINDS, THRESHOLD, VAULT_PART_TYPE, SHEET_PREFIX,
  newBackupKey, splitBackupKey, combineParts, formatSheet, parseSheet,
  encodeContactPart, decodeContactPart, sealVaultPart, openVaultPart, wrapKey, unwrapKey, wipe,
} from "./keys.js";

export {
  DEFAULT_EXCLUDE, DEFAULT_SENSITIVE, DEFAULT_RESTORE, DEFAULT_POLICY,
  makePolicy, classifier, safePath,
} from "./policy.js";
