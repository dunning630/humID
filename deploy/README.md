# Running a HumID vault server

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

The web app is served at the same address, so `https://vault.humidsecure.ai`
also works in a phone browser and can be added to the home screen.

## Settings (`deploy/.env`)

| Variable | Default | Meaning |
|---|---|---|
| `HUMID_DOMAIN` | (required) | The server's domain. |
| `HUMID_INTERNAL_SK`, `HUMID_INTERNAL_PK` | (generated) | Key pair the gateway uses to sign calls to the other services. |
| `HUMID_MIN_ASSURANCE` | `none` | Weakest biometric gate accepted: `none` (demo mode allowed), `os`, or `hardware`. Use `hardware` for anything beyond a demo. |
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
node ../tests/smoke.mjs https://vault.humidsecure.ai   # account, seal, card, second device, open, ledger
```

The smoke test signs in as a demo device. On a server with
`HUMID_MIN_ASSURANCE=hardware`, run it with `SMOKE_ASSURANCE=hardware`.
