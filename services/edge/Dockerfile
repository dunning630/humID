# Edge: Caddy (TLS 1.3, auto HTTPS, PQ-hybrid key exchange) + the web app.
# Runs as an unprivileged user with no capabilities (PC-21; compose lets it bind 80/443).
#
# TODO(PC-21): pin both base images by digest (FROM image:tag@sha256:…, as
# services/Dockerfile notes). The registries weren't reachable when this was
# written; Dependabot (docker ecosystem) keeps digests current once they're set.
FROM node:24-alpine AS app
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps/mobile ./apps/mobile
COPY services ./services
# the app build checks the native plugins' contract versions
COPY plugins/humid-gate/Cargo.toml ./plugins/humid-gate/Cargo.toml
COPY plugins/humid-nfc/Cargo.toml ./plugins/humid-nfc/Cargo.toml
COPY plugins/humid-docscan/Cargo.toml ./plugins/humid-docscan/Cargo.toml
RUN npm ci --ignore-scripts --no-audit --no-fund --workspaces --include-workspace-root \
 && HUMID_PRECOMPRESS=1 npm run build -w @humid/mobile

FROM caddy:2-alpine
COPY services/edge/Caddyfile /etc/caddy/Caddyfile
COPY --from=app /src/apps/mobile/dist /srv/app
# Caddy's state (certificates, ACME account) on volumes the unprivileged user owns.
# The image gives the binary a file capability (cap_net_bind_service); with cap_drop ALL
# the kernel refuses to exec a binary whose file capabilities it can't grant, and none is
# needed (see the sysctl in docker-compose.yml), so the binary is copied without it (a
# plain copy drops the xattr).
RUN set -eu; mkdir -p /data/caddy /config/caddy; chown -R 65532:65532 /data /config; \
    install -m 0755 /usr/bin/caddy /usr/bin/caddy.nocap; mv /usr/bin/caddy.nocap /usr/bin/caddy
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
USER 65532:65532
EXPOSE 80 443 443/udp
