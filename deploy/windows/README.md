# HumID Server for Windows

The HumID vault server for one Windows 10 or 11 PC (for example a Dell
laptop), without Docker. The person installing it double-clicks
`Install HumID Server.cmd`; step-by-step instructions for them are in
[`scripts/README.txt`](scripts/README.txt), which ships inside the zip.

## Build

```bash
node deploy/windows/build.mjs --zip
# -> deploy/windows/out/HumID-Server-Windows-<version>.zip  (about 0.5 MB)
```

CI builds the same zip on every change that touches a service, installs it on
a Windows runner exactly as a person would, runs the deployment smoke test
against it under both device policies, backs up, restores, updates in place,
tests the admin console and its jobs (`tests/windows/admin-console.ps1`: an
update that can't start is put back by itself, a good one keeps the server
key, rollback) and uninstalls. The zip is attached to the run as `HumID-Server-Windows`.

## What's in the package

| File | |
|---|---|
| `humid-server.mjs` | The seven services (identity, vault, ledger, recovery, access, keyshare, gateway) and a local edge, bundled into one file. The same service code as the Docker images. |
| `app/` | The web app the edge serves (release build: no demo mode). |
| `humid-admin.mjs` | HumID Admin, the admin console ([docs/ADMIN.md](../../docs/ADMIN.md)), with its page inside. |
| `humid.ps1` | Install, update, start / stop, status, logs, settings, backup / restore, expose, console, admin, uninstall; and the Windows side of the console (`probe`, `job-run`). Windows PowerShell 5.1 compatible. |
| `Install HumID Server.cmd`, `Uninstall HumID Server.cmd` | Double-click launchers that ask for administrator rights. |
| `README.txt` | Instructions for the person installing it. |

The installer downloads the official Node.js 22 runtime from nodejs.org and
checks it against nodejs.org's SHA-256 list before installing it.

## How it runs

```
phone ──https──► Tailscale Funnel or Cloudflare Tunnel ──► 127.0.0.1:8480  edge (web app, /htp proxy)
                 (TLS ends here; HTP/1 inside stays                          │
                  end-to-end encrypted, post-quantum)                         ▼
                                                     gateway ─► identity, vault, ledger, recovery
                                                     (each on 127.0.0.1, random port, own data folder)
```

- **One process, one background task.** A scheduled task named *HumID
  Server* starts `node.exe humid-server.mjs run --service` at boot, before
  anyone signs in, as the low-privilege **LOCAL SERVICE** account, and
  restarts it if it stops. It runs on battery too.
- **Nothing listens on the network.** Every port is bound to 127.0.0.1, so no
  firewall rule is needed and nothing on the LAN can reach it. Phones arrive
  through a tunnel that connects outward: Tailscale Funnel (free, an address
  like `https://dell-laptop.tail1234.ts.net`) or Cloudflare Tunnel (your own
  domain, which must use Cloudflare DNS).
- **Files.** Program in `C:\Program Files\HumID Server`; settings, keys,
  databases and logs in `C:\ProgramData\HumID`, which only SYSTEM,
  Administrators and LOCAL SERVICE can open.
- **The admin console** is a second task, *HumID Admin*, run as SYSTEM on
  127.0.0.1:8490 (`HUMID_ADMIN_PORT`), with a third, *HumID Admin Job*, that
  runs what an administrator approved on their phone: HumID updates with
  automatic rollback, Windows updates, backups, restarts. See
  [docs/ADMIN.md](../../docs/ADMIN.md).
- **Settings** live in `C:\ProgramData\HumID\humid.env` and are changed with
  `humid set KEY=VALUE`, which validates them and restarts the server. The
  same variables as the Docker deployment ([../README.md](../README.md)),
  plus `HUMID_PORT` (8480) and `HUMID_PUBLIC_URL` (set by `humid expose`).

## Compared with the Docker deployment

| | Docker (`deploy/`) | Windows |
|---|---|---|
| Isolation between services | separate read-only containers on an internal network | one process; services talk over 127.0.0.1 |
| TLS | Caddy on the server, automatic certificates | the tunnel |
| Client address for rate limits | Caddy's `X-Forwarded-For` | the edge trusts only the local tunnel's last hop (`CF-Connecting-IP` or the last `X-Forwarded-For` entry) |
| Updates | `docker compose pull` per service | from the admin console (approved on a phone, automatic rollback), or unzip and run the installer again |

The service code, the device policy, the attestation checks and the data
formats are the same, so a backup can move between the two deployments.

## Two-proof recovery and the public log

Put country signing certificates (CSCA, PEM or DER) for the passports you want
to accept in `C:\ProgramData\HumID\csca` and restart (`humid restart`). Make
an account a verification station with
`humid set HUMID_STATION_ACCOUNTS=hid_…`. The public log is at
`https://<your tunnel>/tlog/v1/checkpoint`. Every setting is in `humid.env`
with an explanation; see [../../docs/CONTINUITY.md](../../docs/CONTINUITY.md).

## Selling access (anonymous payment)

A new HumID needs an access pass unless you `humid set HUMID_REGISTRATION=open`.
Print access codes to sell, for cash or through an online store that delivers
license keys, with `humid mint 100 counter-2026-10` (one code per line; the
batch name is for your records). `humid set HUMID_PASS_BUY_URL=https://…` makes
the app link to your shop. How it stays anonymous:
[docs/ANONYMITY.md](../../docs/ANONYMITY.md).

## Check-in

`humid set HUMID_CHECKIN=on` lets holders arm Check-in: their vault is erased
for good unless they check in every hour or two
([docs/CHECKIN.md](../../docs/CHECKIN.md)). The keys of an armed vault live in
the server's memory only, so **anything that stops the server erases every
armed vault**: `humid restart`, an update, a backup, restarting Windows, a
crash. `humid status` shows how many are armed. The admin console says so
before you approve any of those, and `humid stop`, `restart`, `set`, `backup`,
`restore`, `expose`, `uninstall` and an update say so and go on only once you
type ERASE (with `-Quiet`, they go on after the warning). It's off by default
until push reminders exist.

## Limits

- The laptop has to be on, awake and online. The installer offers to keep it
  awake while plugged in (lid closed included).
- Everything runs in one process as one account, so a flaw in one service
  exposes the others' memory. That's acceptable for a single-machine pilot,
  not for real customer data (see [docs/SECURITY.md](../../docs/SECURITY.md)).
- The tunnel provider sees encrypted HTP/1 traffic and connection metadata,
  not documents or keys.
