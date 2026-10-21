# Server administration: HumID Admin

HumID Server for Windows (2.0.0 and later) installs an admin console beside the
server. It shows how the server and the computer are doing, and it installs
HumID updates, Windows updates and Defender definitions, makes backups, and
restarts things. **Nothing changes until an administrator approves it on their
phone with a live face or fingerprint check**, and the console checks that
approval itself.

```
                 this computer only                               your phone (HumID app)
┌───────────────────────────────────────────────┐               ┌──────────────────────────┐
│ browser ──► HumID Admin (SYSTEM, 127.0.0.1:8490)              │ You ▸ Manage this server │
│               │  writes a request (code + digest)             │ ▸ scan the code          │
│               ▼                                               │ ▸ live check             │
│   data\admin\requests ──► gateway ◄────── HTP/1 over the tunnel ──────────┘              │
│   data\admin\approvals ◄── (LOCAL SERVICE)  step-up proof, written as signed             │
│               │                                                                          │
│               ▼  console re-checks the ML-DSA-87 and chip signatures                     │
│          against the keys pinned for that phone, then queues the job                    │
│               ▼                                                                          │
│       HumID Admin Job (SYSTEM) ── humid.ps1 job-run: update / backup / Windows Update    │
└───────────────────────────────────────────────┘
```

## Using it

1. **Open it.** In Terminal (Admin) on the server PC: `humid console`. It opens
   a sign-in link in your browser that works once, for two minutes. The console
   is at `http://127.0.0.1:8490` and nowhere else.
2. **Add your phone** (once). On the console, **Administrators ▸ Add a phone**
   shows a QR code and a 12-character code. In HumID on your phone (signed in to
   this server): **You ▸ Manage this server**, scan or type the code, check
   the short check matches, approve with your biometric. Your phone then shows an
   **admin check**; the console shows one too. If they're the same, choose
   **They match**. If not, someone is in the middle: choose **They don't match**.
3. **Make a change.** Click what you want (Update, Install selected Windows
   updates, Back up now, Restart…). The console shows a code; approve it the same
   way. The console verifies the approval, then runs the job and shows each step.
   Administrators also see **This server** on their You tab, with the
   server's health and what's waiting to install.

For HumID updates from a private repository, give the console a read-only token:
make a fine-grained GitHub token with access to the HumID repository only and
**Contents: Read-only**, then `humid admin token github_pat_…`. (`humid admin repo
owner/name` changes where updates come from.)

## What it watches

| Area | What | Alert when |
|---|---|---|
| HumID server | each service's health and response time, the edge, memory, CPU, event-loop delay, sessions, data sizes, errors and warnings of the last hour | not answering, a service unhealthy, ≥5 errors in an hour, slow |
| Network | the public address's `/healthz` and its TLS certificate | unreachable; certificate expiring within 14 days |
| Computer | CPU, memory, every fixed drive, uptime, the three background tasks, the tunnel's service | a drive under 10 GB / 10% free (bad under 2 GB / 5%), memory over 92% |
| Protection | Microsoft Defender (on, real-time, definitions age), Windows Firewall per profile, BitLocker on the system drive, pending restart | Defender or the firewall off, definitions older than 3 days, the system drive not encrypted |
| Updates | newer `server-win-v*` releases on GitHub; Windows Update (every 6 hours, the first 10 minutes after start) | security updates waiting (bad after a week), a HumID update |
| Backups | `C:\ProgramData\HumID\backups`, the backup key, where keyshare's half goes | no backup key (bad: backups wait for one); keyshare's half on the same disk as the rest; old unencrypted backups left over; none, or the newest older than a week |
| Console | administrator phones, its own audit log | no phone enrolled; the audit chain broken |

The server reports its side every 15 seconds in `C:\ProgramData\HumID\server-status.json`
(health and counts only; no account, document or key). The console keeps a
sample a minute for 24 hours.

## What each change does

| Change | How |
|---|---|
| **Update HumID Server** | Downloads the release zip and its signature (`.sig`). The zip must be signed by a HumID release key the console pins, for exactly that file name and version (see *Signed releases* below), and match the SHA-256 that GitHub publishes for it; the phone approves that exact SHA-256. The job checks the SHA-256 and the signature again right before it unpacks the zip, checks the zip's version and contents, takes a local rollback copy of the data (and, with a backup key set, an encrypted backup; see *Backups*), keeps the current version in `C:\Program Files\HumID Server.previous`, installs, and checks the server comes up healthy **with the same server key id** (phones refuse a changed one). Otherwise it reinstalls the previous version by itself, and if that doesn't come up either, restores the data from the rollback copy it just took. Once the update has worked, the rollback copy is deleted. |
| **Roll back** | The same, the other way; the version you left is kept, so you can roll forward again. Only to 2.0.0 or later (older versions have no console). |
| **Install Windows updates** | The ones you tick from the last scan; their titles are in what the phone approves. Windows Update downloads and installs them (accepting their licence terms); a restart is a separate approval. |
| **Restart this computer** | `shutdown /r` 60 seconds after approval. HumID starts again by itself. |
| **Update Defender** | `Update-MpSignature`. |
| **Back up now** | Needs a backup key (`humid backup-key new`). Stops the server for a few seconds and writes two files, both encrypted to the backup key: settings, server keys and every sealed document into `backups\`, and keyshare's half (`share-key.bin` and its database) into the keyshare folder. Keeps the newest 10 of each. Copy them somewhere offline now and then, on different disks: a backup on the same disk doesn't survive the disk. |
| **Restart the server** | Stops and starts the HumID Server task. |
| **Remove an administrator phone** | Approved by any administrator phone, including the one being removed. |

## Backups

Every backup is encrypted to **the backup key**, and keyshare's data goes to a
file of its own. A backup used to be one plain zip on the server's own disk: the
vault, keyshare's `share-key.bin` and every server key together, exactly what
split keys keep apart ([SECURITY.md](SECURITY.md), *A compromised phone*).

1. **Make the backup key** (once), in Terminal (Admin), onto a USB drive:
   `humid backup-key new -Path E:\humid-backup.key`. The private key goes only
   into that file; the server keeps the public key (in `admin\admin.env`). It
   refuses to write inside `C:\ProgramData\HumID` or the program folder, and
   never overwrites a file. Keep the file, and a second copy, off this computer.
   HumID never uses passwords or PINs, so there's no passphrase: whoever holds
   the file and a backup can read the backup. A new key (`-Replace`) doesn't
   re-encrypt older backups; keep the old file while you still need them.
2. **Keep keyshare's half elsewhere.** The console writes it to
   `backups\keyshare` unless you choose another disk:
   `humid backup-key keyshare D:\HumID-keyshare` (a folder only administrators
   can change). The console warns while both go to the same disk, and so does
   `humid backup`.
3. **Back up** from the console (**Back up now**), or in Terminal (Admin):
   `humid backup [-Path F:\HumID-backup.humidbak] [-KeysharePath G:\HumID-keyshare.humidbak]`.
4. **Restore** needs both files and the key file:
   `humid restore -Path <HumID-backup-….humidbak> -KeysharePath <HumID-keyshare-….humidbak> -Key E:\humid-backup.key`.
   Every piece is checked as it's unpacked (into a new folder only SYSTEM and
   Administrators can open); a wrong key, the keyshare file of another backup, or
   a file that was changed or cut short, and nothing is restored. Backups made by
   2.1.0 and earlier (`.zip`, unencrypted) still restore; delete them once you
   have an encrypted backup (the console lists how many are left).

How it's sealed: each file has a random 256-bit file key, sealed to the backup
key with HUMID-PQ1, the suite every HumID document uses (ML-KEM-1024 + X25519,
HKDF-SHA3-256, AES-256-GCM); the contents are AES-256-GCM in 1 MiB pieces bound
to their position and to the file's header, so pieces can't be dropped, reordered,
cut short or moved between backups. Format: `deploy/windows/admin/backups.mjs`.

**Without a backup key, nothing makes a backup**: the console shows *Backups
aren't encrypted: set up a backup key*, **Back up now** asks for one, and
`humid backup` refuses. Updates still work, because of the one exception:

**The local rollback copy.** Before an update or a rollback the job takes a copy
of `humid.env` and `data\` that it can put back by itself if neither version comes
up. The job can't use the backup key (it's off the computer), so this copy is
**not** encrypted to it. It's kept in `admin\rollback` (SYSTEM and Administrators
only, like the console's own records), never in `backups\`, and it's deleted as
soon as the update or rollback has worked; after one that failed, it stays (so you
can restore it with `humid restore -Path <file>`) until the next update or
rollback replaces it. With a backup key set, the same stop also writes an
encrypted backup that's kept.

## Why you can trust an approval

- **The phone signs exactly this change.** The console describes each change in
  one canonical JSON object (this server's key id, the code, the change, its
  arguments and when it asked) and takes its SHA3-256: the *digest*. The phone
  approves `{ digest }` with an ordinary HTP/1 step-up: an ML-DSA-87 signature by
  its device key over the session, the request and the body, and on phones with a
  secure chip, the chip's P-256 liveness signature made during the live check
  ([PROTOCOL.md](PROTOCOL.md)). Both screens show the first 8 characters of the
  digest so you can see they agree.
- **The console doesn't trust the server.** The HumID server is the part that
  faces the internet. It relays requests and approvals through
  `data\admin\`: it reads the requests and drops approvals into
  `approvals\`. So the console re-checks every approval
  itself: the signature against the device key **it pinned** for that phone at
  enrolment, the chip signature against the pinned liveness key, the path naming
  this code, the body naming this digest, and the time (signed after the request
  was made, at most 2 minutes old). A taken-over server process can make up
  approvals, but can't sign them as your phone (`tests/e2e/admin-console.test.js`
  writes exactly such a forgery and checks it's refused).
- **Enrolment is checked by a person.** When a phone enrols, its keys arrive with
  its approval. Before the console pins them, you compare the admin check: a code
  the phone computes from its own device key and the console computes from the key
  it received (`HUMID-ADMIN-v1`, the same scheme as device-link codes). A server
  that swapped in its own key would show a different code.
- **Only this computer can open it.** The console listens on 127.0.0.1 on its own
  port, which the tunnel never forwards (the settings refuse the same port). It
  answers only to the Host `127.0.0.1:<port>` or `localhost:<port>`, so a web page
  can't reach it by DNS tricks. Sign-in is a one-time link that only an
  administrator can make (`humid console`); the session is an HttpOnly,
  SameSite=Strict cookie, 30 minutes idle and 12 hours at most; every change also
  needs a custom header and the console's own origin. The page runs under a
  strict content security policy with a fresh nonce.
- **Duress counts here too.** Approving is a sensitive change in the gateway, so
  after a duress signal it fails the way a busy server does.
- **Every step is recorded twice.** The approval goes into the administrator's
  own HumID ledger first (`admin.approved`; if the ledger can't record it, the
  approval is refused), and the console keeps a hash-chained audit log of
  sign-ins, requests, approvals, refusals and jobs in
  `C:\ProgramData\HumID\admin\audit.jsonl`. If a line is edited the console says so.
- **Separate rights.** The console and its jobs run as SYSTEM, because installing
  updates needs it. The HumID server still runs as LOCAL SERVICE, and can't open
  `C:\ProgramData\HumID\admin` or `backups` (SYSTEM and Administrators only).
  Everywhere else under `C:\ProgramData\HumID` it can read, but it changes only
  its own databases and keys (`data\<service>`), its log (`logs\`), its two
  status files (`server.json`, `server-status.json`), and new files in the
  approvals drop box (`data\admin\approvals`, where it can't make folders). It
  can't change `humid.env`, what the console writes, or any folder SYSTEM reads,
  writes or unpacks into, so it can't plant a junction there to redirect SYSTEM.
  On top of that, SYSTEM refuses to follow a link: the console won't read
  approvals through a junction or symbolic link (it says so under alerts), jobs
  check every folder from the data root down before they read or write, backups
  refuse a link anywhere in the data, and a restore unpacks into a new folder
  under `admin\` and is checked before it's swapped in. Installing (or updating)
  re-applies these permissions, makes Administrators the owner of what SYSTEM
  uses, and removes any junction or symbolic link under the data root (only the
  link, never what it points to), so installs of 2.1.0 and earlier, where the
  server's account could write everywhere, are put right.

## Signed releases

GitHub's digest proves only that a file was uploaded to a release; anyone who
could create a `server-win-v*` release could otherwise make every console install
their zip as SYSTEM. So the console also requires a signature by **the HumID
release key**, an ML-DSA-87 key the maintainer keeps offline, never in GitHub or
CI. Its public key is pinned in the console itself
(`deploy/windows/admin/release-keys.mjs`, one or two keys while rotating).

- The signature (`HumID-Server-Windows-<version>.zip.sig`) covers the label
  `HUMID-SERVER-RELEASE-v1`, the file name, the version, the size, and the
  zip's SHA-256 and SHA3-512. A signature for another file or version, or one
  made for anything but a server release, doesn't count.
- The console checks it before anything else: no `.sig`, a bad one, a key it
  doesn't pin, or a version that doesn't match the release tag, and nothing is
  downloaded or offered for approval. The update job checks it again (as
  SYSTEM, with the installed console's keys) right before it unpacks the zip.
- Drafts are never offered. Releases marked pre-release are offered only with
  `humid set HUMID_UPDATE_PRERELEASES=on` (off by default), and must be signed
  all the same.
- **While no key is pinned, the console refuses every update** and says so under
  Updates; install releases by hand. A console learns a new key only from a
  release installed by hand or signed by a key it already pins. How the
  maintainer makes, uses and rotates the key: [RELEASING.md](../RELEASING.md).

## Break-glass

- **The server is down.** Your phone can't reach a server that's down, so after
  30 seconds of no answer the console offers **Restart the server now** without a
  phone. It's the only change that doesn't wait for one, and it's logged as
  break-glass. (Windows also restarts the task by itself within a minute.)
- **Lost the only administrator phone.** `humid admin reset` in Terminal (Admin)
  forgets every administrator phone (logged); then add a new one. Anyone who is
  an administrator of Windows on this computer can do this, as they could also
  run any `humid` command: the console adds a phone's approval on top of Windows'
  own administrator rights, it doesn't replace them.

## Files

| Where | What |
|---|---|
| `C:\Program Files\HumID Server\humid-admin.mjs` | the console (one file, its page inside) |
| `C:\ProgramData\HumID\admin\` | `admins.json` (pinned phones), `audit.jsonl`, `history.json`, `admin.env` (token, repository), `jobs\`, `downloads\`, `os-updates.json`, `logins\` — SYSTEM and Administrators only |
| `C:\ProgramData\HumID\data\admin\` | the shared folder: `requests\`, `summary.json` (the console writes, the server reads), `approvals\` (the server drops files in, the console reads) |
| `C:\ProgramData\HumID\server-status.json` | the server's own report, every 15 s |
| `C:\ProgramData\HumID\backups\` | backups (`HumID-backup-….humidbak`, encrypted to the backup key), newest 10 kept; `keyshare\`: keyshare's half of each, unless `humid backup-key keyshare` chose another folder |
| `C:\ProgramData\HumID\admin\rollback\` | the local rollback copy during an update or rollback (deleted once it has worked) |
| `HUMID_BACKUP_KEY`, `HUMID_BACKUP_KEYSHARE_DIR` in `admin\admin.env` | the backup key's public half; where keyshare's half goes |
| `C:\ProgramData\HumID\admin\logs\humid-admin.log` | the console's log (in 2.1.0 and earlier it was in `logs\`, which the server writes) |
| `HUMID_ADMIN_PORT` in `humid.env` | the console's port (8490) |

## Trying it without Windows

`HUMID_DEV_ADMIN=1 npm run dev` starts the console beside the dev server on a
simulated Windows, at `http://127.0.0.1:5174` (the sign-in link is printed). Make
a HumID in the browser at `http://localhost:5173`, then **You ▸ Manage this
server**. `node tests/browser/admin.mjs` walks the whole thing in Chromium.

## Not yet

- Docker / Linux deployments: the gateway routes are there, but no console runs
  beside the containers yet.
- Notifications leave the console only through the HumID app (the **This server**
  card); there's no push or email (the same gap as in [SECURITY.md](SECURITY.md)).
- The release key is a single offline key with no threshold: whoever holds it can
  sign an update every console accepts. Two-of-three signing, or a transparency
  log of release signatures, would remove that single point.
