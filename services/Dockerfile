# One Dockerfile for every Node service:
#   docker build -f services/Dockerfile --build-arg SERVICE=vault -t humid-vault .
#
# Final image: distroless Node 22 (no shell, no package manager), non-root,
# one bundled JavaScript file. Roughly 60 MB, most of it the Node runtime.

# TODO(PC-21): pin both base images by digest (FROM node:22-alpine@sha256:…,
# gcr.io/distroless/nodejs22-debian12:nonroot@sha256:…). The registries weren't
# reachable when this was written; Dependabot's docker updates keep a pinned digest
# current. Until then a tag can move under a rebuild.
FROM node:25-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages ./packages
COPY services ./services
COPY apps/mobile/package.json ./apps/mobile/package.json
RUN npm ci --ignore-scripts --no-audit --no-fund --workspaces --include-workspace-root
ARG SERVICE
RUN test -n "$SERVICE" && node services/build-service.mjs "$SERVICE" \
 && mkdir -p /out/data && cp "services/$SERVICE/dist/server.mjs" /out/server.mjs

FROM gcr.io/distroless/nodejs22-debian12:nonroot
ARG SERVICE
LABEL org.opencontainers.image.title="humid-${SERVICE}" \
      org.opencontainers.image.source="https://github.com/dunning630/humID"
WORKDIR /app
COPY --from=build /out/server.mjs /app/server.mjs
COPY --from=build --chown=65532:65532 /out/data /data
ENV NODE_ENV=production NODE_NO_WARNINGS=1 DATA_DIR=/data
USER nonroot
CMD ["server.mjs"]
