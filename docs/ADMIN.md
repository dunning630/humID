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
| Backups | `C:\ProgramData\HumID\backups` | none, or the newest older than a week |
| Console | administrator phones, its own audit log | no phone enrolled; the audit chain broken |

The server reports its side every 15 seconds in `C:\ProgramData\HumID\server-status.json`
(health and counts only; no account, document or key). The console keeps a
sample a minute for 24 hours.

## What each change does

| Change | How |
|---|---|
| **Update HumID Server** | Downloads the release zip; it must match the SHA-256 that GitHub publishes for it, and the phone approves that exact SHA-256. The job checks it again, checks the zip's version and contents, takes a backup (`backups\pre-update-…zip`), keeps the current version in `C:\Program Files\HumID Server.previous`, installs, and checks the server comes up healthy **with the same server key id** (phones refuse a changed one). Otherwise it reinstalls the previous version by itself, and if that doesn't come up either, restores the data from the backup it just took. |
| **Roll back** | The same, the other way; the version you left is kept, so you can roll forward again. Only to 2.0.0 or later (older versions have no console). |
| **Install Windows updates** | The ones you tick from the last scan; their titles are in what the phone approves. Windows Update downloads and installs them (accepting their licence terms); a restart is a separate approval. |
| **Restart this computer** | `shutdown /r` 60 seconds after approval. HumID starts again by itself. |
| **Update Defender** | `Update-MpSignature`. |
| **Back up now** | Stops the server for a few seconds, zips settings, keys and every sealed document into `backups\`, keeps the newest 10. Copy one somewhere offline now and then: a backup on the same disk doesn't survive the disk. |
| **Restart the server** | Stops and starts the HumID Server task. |
| **Remove an administrator phone** | Approved by any administrator phone, including the one being removed. |

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
  `data\admin\`, which it can write. So the console re-checks every approval
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
| `C:\ProgramData\HumID\data\admin\` | the shared folder: `requests\`, `approvals\`, `summary.json` |
| `C:\ProgramData\HumID\server-status.json` | the server's own report, every 15 s |
| `C:\ProgramData\HumID\backups\` | backups, newest 10 kept |
| `C:\ProgramData\HumID\logs\humid-admin.log` | the console's log |
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
- Release zips are checked against GitHub's digest, not against a HumID signing key
  of their own; a compromised GitHub account could publish a release. Signing
  releases with a key the console pins is the next step.
