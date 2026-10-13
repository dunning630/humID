# Running a HumID vault server

Two ways:

- **On one Windows PC, no Docker:** [windows/README.md](windows/README.md).
  Unzip, double-click the installer, then give it an https address with
  Tailscale Funnel. Good for a pilot on a laptop.
- **On a Linux server with Docker** (this page).

Six small containers: **edge** (Caddy, the only one on the internet),
**gateway**, **identity**, **vault**, **ledger** and **recovery**. They run on
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
| `recovery-data` | card backups, contacts' pieces | Recovery cards and contacts stop working; devices still do. |

Back up all five volumes together, encrypted, and test a restore.

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
