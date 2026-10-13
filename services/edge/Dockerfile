# Edge: Caddy (TLS 1.3, auto HTTPS, PQ-hybrid key exchange) + the web app.
FROM node:22-alpine AS app
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps/mobile ./apps/mobile
COPY services ./services
# the app build checks the native plugin's contract version
COPY plugins/humid-gate/Cargo.toml ./plugins/humid-gate/Cargo.toml
RUN npm ci --ignore-scripts --no-audit --no-fund --workspaces --include-workspace-root \
 && npm run build -w @humid/mobile

FROM caddy:2-alpine
COPY services/edge/Caddyfile /etc/caddy/Caddyfile
COPY --from=app /src/apps/mobile/dist /srv/app
