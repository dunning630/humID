# Running a HumID vault server

Two ways:

- **On one Windows PC, no Docker:** [windows/README.md](windows/README.md).
- **On VMs and shared storage (server 3.0):** [../docs/DEPLOY-VMS.md](../docs/DEPLOY-VMS.md): front, core and keys on separate VMs over mutual TLS, secrets sealed under a TPM-bound key, encrypted backups.
  Unzip, double-click the installer, then give it an https address with
  Tailscale Funnel. Good for a pilot on a laptop.
- **On a Linux server with Docker** (this page).

Eight small containers: **edge** (Caddy, the only one on the internet),
**gateway**, **identity**, **vault**, **ledger**, **recovery**, **access** and **keyshare**. They run on
a private network with no route to the internet, read-only, as non-root.

## What you need

- A Linux machine with Docker and the compose plugin. 1 vCPU and 1 GB of RAM
  is plenty for a POC (a ~$6/month cloud server works).
- A domain name pointing at it, e.g. `vault.humidsecure.ai` (DNS A record).
- Ports 80 and 443 open. Caddy gets the TLS certificate automatically.

## First start

```bash
git clone https://github.com/dunning630/humID.git && cd humID/deploy
./setup.sh vault.humidsecure.ai
```

`setup.sh` generates the internal service keys into `deploy/.env` (kept out
of git; keep it secret), builds and starts the stack, and prints the server's
fingerprint plus the two values to pin it in the apps:

```
HUMID_SERVER_URL = https://vault.humidsecure.ai
HUMID_SERVER_KID = 64 hex characters
```

Set those as repository variables on GitHub (Settings → Secrets and variables
→ Actions → Variables), then run **Actions → Release apps**. The built apps
connect to this server only.

The web app is served at the same address, but a browser can't prove a live
face or fingerprint check, so it only points people to the iPhone and
Android apps.

## Settings (`deploy/.env`)

| Variable | Default | Meaning |
|---|---|---|
| `HUMID_DOMAIN` | (required) | The server's domain. |
| `HUMID_INTERNAL_SK`, `HUMID_INTERNAL_PK` | (generated) | Key pair the gateway uses to sign calls to the other services. |
| `HUMID_DEVICE_POLICY` | `attested` | Which devices may join and sign in. `attested`: phones whose secure chip proves every live face or fingerprint check. `biometric`: also biometric-only desktops (Touch ID, fingerprint readers), which can't prove it. `demo`: local testing only. No policy accepts a PIN or password. |
| `HUMID_IOS_APP_ID` | (empty) | `<Apple Team ID>.app.humid.vault`. Needed to accept iPhones (App Attest). `setup.sh` asks for the Team ID. |
| `HUMID_APP_ATTEST_ENV` | `production` | `development` only for Xcode debug builds. |
| `HUMID_ANDROID_PACKAGES` | `app.humid.vault` | Android package names accepted in key attestation. |
| `HUMID_ANDROID_CERT_DIGESTS` | (empty = any) | SHA-256 of your release / Play signing certificate, comma-separated. Set it so only your signed app can join. |
| `HUMID_REQUIRE_LOCKED_BOOT` | `1` | Refuse Android phones with an unlocked bootloader or failed verified boot. |
| `RECOVERY_DELAY_MS` | `259200000` (72 h) | How long a card or contacts recovery waits before release. |
| `VAULT_QUOTA_BYTES` | `262144000` (250 MB) | Storage per account. |
| `HUMID_CHECKIN` | `off` | `on` lets holders arm Check-in: their vault is erased for good unless they check in every hour or two ([docs/CHECKIN.md](../docs/CHECKIN.md)). Its keys live in keyshare's memory only, so **restarting or updating keyshare erases every armed vault**. Off until push reminders exist. |
| `HUMID_REGISTRY`, `HUMID_VERSION` | `ghcr.io/dunning630`, `latest` | Where to pull images from, and which version. |

## Updating

Images are published to GitHub's container registry on every merge to
`main`, one per service, and only for the services a change touched.

```bash
cd deploy
docker compose pull            # everything that changed
docker compose up -d
# or one service at a time:
docker compose pull vault && docker compose up -d vault
```

Pulling private images needs a one-time `docker login ghcr.io` with a GitHub
token that can read packages. Without it, `docker compose up -d --build`
builds from the checked-out source instead.

## Keep these safe

| Volume | Holds | If lost |
|---|---|---|
| `gateway-data` | `htp-keys.json`, the server's identity | Every app that pinned this server refuses to connect. Back it up. |
| `vault-data` | sealed documents | Documents are gone (they stay unreadable to anyone either way). |
| `identity-data` | accounts and device public keys | Nobody can sign in. |
| `ledger-data` | access history and the ledger signing key | History is gone; new history starts. |
| `recovery-data` | seal-card pieces, witnesses' pieces, ID-anchor parts and `anchor-secret.bin` | Recovery stops working; devices still do. Without `anchor-secret.bin` no ID anchor opens. |
| `keyshare-data` | each split document's key, and `share-key.bin` | **Every split document becomes unopenable, for good.** Back it up with the same care as the vault, but keep it on different storage from `vault-data`. |
| `access-data` | access-code hashes, pass signing keys, spent passes | Unsold and unswapped codes stop working, and passes not yet spent are refused. |

Back up all seven volumes, encrypted, and test a restore. Keep `keyshare-data`'s
backups apart from `vault-data`'s: together they're what split keys keep apart.

## Selling access (anonymous payment)

By default a new HumID needs an access pass (`HUMID_REGISTRATION=pass`). People
buy an **access code**, the app swaps it for a pass the server signs blind, and
registration spends the pass, so the payment can't be linked to the account.
How it works and what it doesn't hide: [docs/ANONYMITY.md](../docs/ANONYMITY.md).

```bash
docker compose run --rm access server.mjs mint 100 counter-2026-10   # 100 codes, one per line
```

Sell them for cash (printed cards) or through any online store that delivers
license keys. Set `HUMID_PASS_BUY_URL=https://…` in `deploy/.env` and the app
links to your shop. For a private server, `HUMID_REGISTRATION=open` turns
payment off.

## Two-proof recovery, stations, the public log

| Setting | What it does |
|---|---|
| `deploy/csca/` (mounted at `/csca`) | Country signing certificates (CSCA) for passport and ID chips. Empty = ID anchors off. See [csca/README.md](csca/README.md). |
| `HUMID_STATION_ACCOUNTS` | `hid_…` accounts (comma-separated) that run in-person verification stations. |
| `HUMID_DURESS_COOLOFF_MS` | How long it must be calm after a duress signal before the owner can lift the lockdown (default 24 h). |
| `HUMID_TLOG_COSIGNERS` | `name=key,…` independent cosigners of the public log. They run `node tools/tlog-cosign.mjs run https://your-server <name> <keyfile>` on a schedule; `keygen` makes the key. Build the apps with the same value (`HUMID_TLOG_COSIGNERS` when running `build.mjs`): phones count only cosigners built into them, never a list the server sends. |
| `RECOVERY_DELAY_MS` | The base wait (72 h). Station = ⅓, witnesses = 1×, card + chip = 7⁄3; doubled after a duress signal. |

The edge serves the public log at `/tlog/v1/checkpoint`, `/tlog/v1/consistency`
and `/tlog/v1/cosign`. See [../docs/CONTINUITY.md](../docs/CONTINUITY.md).

## Checking it

```bash
curl https://vault.humidsecure.ai/healthz          # ok
docker compose ps                                   # all healthy
docker compose logs gateway | grep "server identity"
node ../tests/smoke.mjs https://vault.humidsecure.ai   # see below
```

The smoke test has no phone, so it enrols as a biometric-only desktop. On the
default `attested` policy it checks that the server **refuses** it
(`device_not_proven`). With `HUMID_DEVICE_POLICY=biometric` it runs the full
flow (account, seal, card, second device, open, ledger).
