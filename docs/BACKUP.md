# Computer backup (HumID 3.0, provisional)

> **Status:** 3.0 track, on branch `v3/pc-backup`. Not part of the 2.0
> releases. The format and key design are built and tested
> (`packages/backup`, `tests/backup.test.js`); the app screens and the server
> side are not. Merge into `main` once 2.0 is complete.

Back up a whole computer's files, sealed so that HumID decides who opens them,
and restore them on a new computer. The design goal: **losing any one thing
never loses the backup**, including the old computer, the printed sheet, your
HumID account, or HumID itself.

## The idea in one paragraph

Files are cut into pieces, each sealed with AES-256-GCM under a key derived
from one random **backup key**. The backup key is stored only wrapped, under a
**part key** that is never stored anywhere. The part key is split into three
parts, and any two rebuild it:

| Part | Where it lives | What opening it takes |
|---|---|---|
| **HumID** (vault part) | in the backup, as `vault-part.humid` | a live biometric check (the HUMID-PQ1 identity keys) **and** a per-backup key from the keyshare service, released inside that check |
| **Sheet** | printed, kept offline: `HUMIDBK-XXXXXX-…` (nine groups of six) | typing it in |
| **Contact** | given to someone you trust, or a safe | asking them for it |

| Two parts | When |
|---|---|
| HumID + sheet | the normal restore on a new computer |
| HumID + contact | the sheet is lost |
| sheet + contact | HumID is unavailable: account lost, or the service gone. The backup outlives the company. |

One part alone reveals nothing (Shamir 2-of-3 over GF(256), the same code
`@humid/recovery` uses for recovery contacts).

## Why it doesn't depend on the old computer

The vault part is sealed to the person's HumID **identity**, not to the
computer. On a new computer, the identity comes back through the existing
two-proof recovery ([CONTINUITY.md](CONTINUITY.md)) with the **same seed**, so
the vault part opens there. The biometric check gates the key's release; it is
never the key itself (biometrics aren't secrets).

## Backing up without anyone present

Scheduled backups need the backup key on the computer being backed up. The app
keeps it in that computer's secure storage (TPM/DPAPI on Windows, Keychain on
macOS, Secret Service on Linux), set there during a live check. This gives that
computer nothing it doesn't already have: it holds the files themselves. A
**new** computer has no such key and must unlock with two parts. The dev CLI
mimics this with `<repo>.dev/device-key.bin`.

## What the storage host learns

Only how many pieces and snapshots there are, and their sizes. Not file names,
folders, individual file sizes, or whether you have a particular file: piece
ids are a **keyed** hash (HMAC-SHA3-256 under a key from the backup key), so two
people's identical files get different ids and the host can't test for a known
file. The same folder backed up again stores nothing new.

## Sensitive files

Keys, saved passwords, browser login stores, password managers' databases and
crypto wallets are backed up but **marked sensitive**
(`DEFAULT_SENSITIVE` in `packages/backup/src/policy.js`). A restore holds them
back and lists them; they come back only when asked for, by name or all
together. Once the server side lands, that second step needs a second live
check. Swap, hibernation, trash, caches and temp files are left out entirely.
People can add patterns; the defaults always apply.

## Restoring safely

- Every piece is checked twice: the AEAD tag, then its keyed id. A changed piece
  or a snapshot moved from another backup fails loudly.
- Paths in a snapshot are validated: no absolute paths, drive letters, `..` or
  control characters, so a tampered snapshot can't write outside the restore
  folder. Links are restored last.
- An optional **scan hook** sees each file before it's written and can
  quarantine it (the place for a malware scanner; a natural Malwarebytes
  integration point).
- A restore refuses to overwrite existing files unless told to.

## Replacing parts

A lost sheet, a contact you no longer trust, or a move to a new HumID account:
`replaceParts` makes a new part key that wraps the **same** backup key, issues a
new sheet, contact part and vault part, and the old parts stop opening the
backup. No data is re-encrypted. (A copy of the backup taken before the change
still opens with the old parts; that is unavoidable for any design.)

## Format v1

```
config.json          format, repo id, chunk size, policy, wrapped backup key, key check
vault-part.humid     HUMID-PQ1 envelope (split-key inner layer) holding the vault part
chunks/ab/<id>       nonce ‖ AES-256-GCM(HKDF(B, "chunk-key", id), piece), AAD binds the id
snapshots/<id>       nonce ‖ AES-256-GCM(HKDF(B, "snapshot"), snapshot JSON), AAD binds repo + id
```

Keys: HKDF-SHA3-256 from the backup key with labels `HUMID-BACKUP-v1 …`. Fixed
1 MiB pieces (64 KiB to 16 MiB allowed). Any store with
`put/get/has/list` works: a folder, a USB drive, the HumID vault, S3.

## Trying it

The development CLI that stood in for the app (`tools/humid-backup.mjs`, a demo
identity in place of a live check) was removed for HumID 5.0. The format and its
rules are exercised by `tests/backup.test.js`; `@humid/backup` (`createRepo`,
`backup`, `restore`, with `@humid/backup/fs` for a folder) is the API it used.

## What is not built yet

1. **App screens:** set up a backup (live check, print the sheet, send the
   contact part the way recovery shares are sent), schedule, browse snapshots,
   restore on a new computer.
2. **Keyshare release rules for backups:** hold back the vault part for a whole
   computer restore (`fullRestoreDelayHours`, default 24 h), alert every device
   with a veto, and require a second check for sensitive files. Today the
   client enforces only "sensitive files separately".
3. **Duress:** a duress unlock should refuse backup releases, as it slows
   recoveries today.
4. **Upload to the HumID vault** as a store (today: any folder or drive).
5. **Open files on Windows** (Volume Shadow Copy) and locked databases.
6. **Content-defined chunking** for better deduplication when bytes are inserted
   mid-file (format v2).
7. **Retention and pruning** from the CLI or app (`unusedChunks` finds the
   pieces to delete).
8. **Bare-metal images** (whole-disk restore): deliberately out of scope; file
   restores move across hardware far better.
9. **Independent security review**, as for the rest of HumID.
