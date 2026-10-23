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
tests the admin console and its jobs (`tests/windows/admin-console.ps1`: the
server's account writes only its own data, planted junctions are refused and
removed, backups are encrypted with keyshare's half apart, unsigned or wrongly
signed updates are refused, an update that can't start is put back by itself, a
good one keeps the server key, rollback) and uninstalls. The zip is attached to the run as `HumID-Server-Windows`.

## What's in the package

| File | |
|---|---|
| `humid-server.mjs` | The seven services (identity, vault, ledger, recovery, access, keyshare, gateway) and a local edge, bundled into one file. The same service code as the Docker images. |
| `app/` | The web app the edge serves (release build: no demo mode). |
| `humid-admin.mjs` | HumID Admin, the admin console ([docs/ADMIN.md](../../docs/ADMIN.md)), with its page inside. |
| `humid-selftest.mjs` | The deployment smoke test as one file (`humid selftest`). |
| `humid.ps1` | Install, update, start / stop, status, logs, settings, backup / restore / backup-key, pki, selftest, expose, console, admin, uninstall, test instances (`-Instance`); and the Windows side of the console (`probe`, `job-run`). Windows PowerShell 5.1 compatible. |
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
  Administrators and LOCAL SERVICE can open. LOCAL SERVICE reads it but writes
  only its own data (`data\<service>`, `logs\`, its status files and the
  approvals drop box), never where the SYSTEM console and its jobs read or
  write ([docs/ADMIN.md](../../docs/ADMIN.md), "Separate rights").
- **The admin console** is a second task, *HumID Admin*, run as SYSTEM on
  127.0.0.1:8490 (`HUMID_ADMIN_PORT`), with a third, *HumID Admin Job*, that
  runs what an administrator approved on their phone: HumID updates with
  automatic rollback, Windows updates, backups, restarts. See
  [docs/ADMIN.md](../../docs/ADMIN.md).
- **Backups** are encrypted to a backup key whose private half you keep off the
  computer (`humid backup-key new -Path E:\humid-backup.key`), with keyshare's
  data in a separate file you can put on another disk; restoring needs the key
  file. Without a key, backups wait ([docs/ADMIN.md](../../docs/ADMIN.md), "Backups").
- **Settings** live in `C:\ProgramData\HumID\humid.env` and are changed with
  `humid set KEY=VALUE`, which validates them and restarts the server. The
  same variables as the Docker deployment ([../README.md](../README.md)),
  plus `HUMID_PORT` (8480) and `HUMID_PUBLIC_URL` (set by `humid expose`).

## Compared with the Docker deployment

| | Docker (`deploy/`) | Windows |
|---|---|---|
| Isolation between services | separate read-only containers on an internal network | one process; services talk over 127.0.0.1 |
| TLS | Caddy on the server, automatic certificates | the tunnel |
| Client address for rate limits | Caddy's `X-Forwarded-For` | `HUMID_TRUST_FORWARDED`, set by `humid expose`: `cloudflare` believes Cloudflare's `CF-Connecting-IP`; `off` (Tailscale Funnel, and the default) believes no header, so every visitor shares the tunnel's address and the per-address limits apply to all of them together; `xff` only for a tunnel you know appends the visitor's address |
| Rate limits behind Tailscale Funnel | per visitor address | **shared**: see *Rate limits behind a tunnel* below |
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

## Rate limits behind a tunnel

The gateway limits handshakes and failed sign-ins per visitor address. Behind
**Cloudflare Tunnel** it knows the address (`HUMID_TRUST_FORWARDED=cloudflare`,
which `humid expose cloudflare` sets). Behind **Tailscale Funnel**, with the
default `HUMID_TRUST_FORWARDED=off`, it doesn't: every visitor arrives from the
tunnel's own 127.0.0.1, so a per-address limit would be one bucket for everyone
and one visitor could keep every holder from connecting. So when the address is
unknown:

- **Handshakes** share one server-wide ceiling, `HUMID_SHARED_HELLO_PER_MIN`
  (600 a minute by default), instead of 30 per address. One busy visitor can
  still spend it; it takes 10 handshakes a second to do so.
- **A holder who has signed in before always gets through.** Each sign-in hands
  the app a one-use *hello pass* inside the encrypted session; its next
  handshake presents it and skips every handshake limit. So unlocking, and
  checking in when Check-in is armed, never fails because strangers used up the
  shared ceiling. A pass works once, opens nothing, and a new one comes with
  each sign-in. Passes are kept in memory: right after the server restarts,
  a holder's first handshake goes through the shared ceiling like anyone's.
- **Failed sign-ins** are counted per HumID and server-wide, not per address.
- Once a session is open, its own per-session limits apply as everywhere.

What you give up with `off`: one visitor can still spend the shared ceiling and
keep **new** visitors (people setting up HumID, or a phone whose app data was
cleared) from connecting while they keep at it, and a new holder's phone has no
pass until its first sign-in. If you can, use Cloudflare Tunnel, or put the
server where the visitor's address is known.

Whether Tailscale Funnel passes the visitor's address on: Tailscale's
documentation doesn't say. Tailscale's Serve code reportedly *replaces*
`X-Forwarded-For` with the connection's source, and for Funnel that source is the
visitor, which would make `HUMID_TRUST_FORWARDED=xff` correct behind Funnel. That
is not confirmed, and if it's wrong `xff` lets anyone name their own address, so
the default stays `off`. To check on your server: open the app from a phone off
your tailnet (mobile data), send a request with a made-up `X-Forwarded-For`
(`curl -H "X-Forwarded-For: 1.2.3.4" https://<your funnel address>/htp/v1/keys`)
and look at what reached the edge. If the made-up value never arrives and your
phone's public address does, `humid set HUMID_TRUST_FORWARDED=xff`.

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
