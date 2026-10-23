#!/usr/bin/env bash
# First-time setup for a HumID server. Needs Docker with the compose plugin.
#   ./setup.sh vault.humidsecure.ai
# Point the domain's DNS A record at this machine and open ports 80 and 443 first.
set -euo pipefail
cd "$(dirname "$0")"

domain="${1:-${HUMID_DOMAIN:-}}"
if [ -z "$domain" ]; then read -rp "Domain for this server (e.g. vault.humidsecure.ai): " domain; fi

if [ ! -f .env ]; then
  echo "Generating internal service keys…"
  X="HUMID_CORE_STATEMENT_PK=x HUMID_KEYS_STATEMENT_PK=x HUMID_CORE_STATEMENT_SK=x HUMID_KEYS_STATEMENT_SK=x"
  env HUMID_DOMAIN="$domain" HUMID_INTERNAL_SK=x HUMID_INTERNAL_PK=x $X docker compose build gateway >/dev/null
  keys="$(env HUMID_DOMAIN="$domain" HUMID_INTERNAL_SK=x HUMID_INTERNAL_PK=x $X docker compose run --rm --no-deps gateway server.mjs keygen)"
  umask 077
  team="${HUMID_APPLE_TEAM_ID:-}"
  if [ -z "$team" ]; then read -rp "Apple Developer Team ID for the iPhone app (10 characters; Enter to skip iPhones for now): " team; fi
  { echo "HUMID_DOMAIN=$domain"; echo "$keys"; [ -n "$team" ] && echo "HUMID_IOS_APP_ID=$team.app.humid.vault"; } > .env
  echo "Wrote deploy/.env (keep it secret; it is not in git)."
fi

# 4.1.x (SRV-30): statement keys, so the gateway's internal key alone can't release or delete
# anything. Added to an existing .env once; the gateway never gets the private halves.
if ! grep -q '^HUMID_CORE_STATEMENT_PK=' .env; then
  echo "Adding statement keys…"
  X="HUMID_CORE_STATEMENT_PK=x HUMID_KEYS_STATEMENT_PK=x HUMID_CORE_STATEMENT_SK=x HUMID_KEYS_STATEMENT_SK=x"
  st="$(env HUMID_DOMAIN="$domain" HUMID_INTERNAL_SK=x HUMID_INTERNAL_PK=x $X docker compose run --rm --no-deps gateway server.mjs keygen statements | grep '_STATEMENT_')"
  umask 077
  echo "$st" >> .env
fi

docker compose up -d --build
echo "Waiting for the gateway…"
for _ in $(seq 1 30); do
  line="$(docker compose logs gateway 2>/dev/null | grep '"server identity"' | tail -1)"
  [ -n "$line" ] && break; sleep 2
done
fp="$(echo "$line" | grep -o '"fingerprint":"[^"]*"' | cut -d'"' -f4)"
kid="$(echo "$line" | grep -o '"kid":"[^"]*"' | cut -d'"' -f4)"
echo
echo "HumID is running at https://$domain"
echo "Device policy: ${HUMID_DEVICE_POLICY:-attested} (phones whose secure chip proves every face or fingerprint check)"
grep -q '^HUMID_IOS_APP_ID=' .env || echo "iPhones: not enabled yet. Add HUMID_IOS_APP_ID=<TeamID>.app.humid.vault to deploy/.env and run docker compose up -d."
echo "Server fingerprint: ${fp:-see 'docker compose logs gateway'}"
echo
echo "To build apps that trust only this server, set these repository variables on GitHub"
echo "(Settings > Secrets and variables > Actions > Variables), then run Actions > Release apps:"
echo "  HUMID_SERVER_URL = https://$domain"
echo "  HUMID_SERVER_KID = ${kid:-<64-hex kid from 'docker compose logs gateway'>}"
