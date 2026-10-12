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
  HUMID_DOMAIN="$domain" HUMID_INTERNAL_SK=x HUMID_INTERNAL_PK=x docker compose build gateway >/dev/null
  keys="$(HUMID_DOMAIN="$domain" HUMID_INTERNAL_SK=x HUMID_INTERNAL_PK=x docker compose run --rm --no-deps gateway server.mjs keygen)"
  umask 077
  { echo "HUMID_DOMAIN=$domain"; echo "$keys"; } > .env
  echo "Wrote deploy/.env (keep it secret; it is not in git)."
fi

docker compose up -d --build
echo "Waiting for the gateway…"
for _ in $(seq 1 30); do
  fp="$(docker compose logs gateway 2>/dev/null | grep -o '"fingerprint":"[^"]*"' | tail -1 | cut -d'"' -f4)"
  [ -n "$fp" ] && break; sleep 2
done
echo
echo "HumID is running at https://$domain"
echo "Server fingerprint: ${fp:-see 'docker compose logs gateway'}"
echo "Pin this fingerprint in the app build (HUMID_SERVER_KID) for production."
