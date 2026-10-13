# Releasing HumID without forklift upgrades

Every change ships as the smallest possible release, and nothing a person
already has (identities, sealed documents, recovery cards) ever needs a bulk
conversion.

## 1. Seams that make small releases possible

| Seam | Rule | What it allows |
|---|---|---|
| **Packages** (`packages/*`) | Own semver and CHANGELOG; talk only through exported interfaces. | Fix recovery codes without touching crypto. |
| **Contracts** (`"humid": {provides, requires}`) | The app build fails on a mismatch. | Packages release independently, safely. |
| **Services** (`services/*`) | Talk only over HTTP behind the gateway; each owns its database and migrates it at start-up. | Replace one container: `docker compose pull vault && docker compose up -d vault`. |
| **HTP/1** (`packages/htp`) | Version and suite are checked on every handshake. A change to any primitive or label is a new version. | Servers can accept two versions during a migration. |
| **Envelope format v1** (`@humid/codec`) | Frozen. A new layout gets a new version byte and a new parse branch. | Documents sealed today open in every future build. |
| **Sealing suites** (`@humid/crypto`) | A suite is frozen once released. New primitives mean a new suite id beside HUMID-PQ1. | New seals use the new suite; old documents still open. |
| **Gate contract v2** (`@humid/gate`) | Adapters implement probe / enroll / release / forget; enroll and release take a `challenge` (and `attest` when a device is added) and return the liveness signature. | Add a gate as one file. |
| **Native plugin** (`plugins/humid-gate`) | Command names and request / response shapes are its API; its major version is the contract (`humid-gate@2`), read from `Cargo.toml` by the app build. Platform code is one file per OS. | A Windows fingerprint fix rebuilds Windows only. |
| **Identity record** (`@humid/store`) | Records carry `schema`; one migration step per bump, run on read. Never edit a released step. | On-device data upgrades lazily, per record. |

## 2. Day-to-day flow

1. Change the package, service or app that owns the behaviour.
2. `npx changeset`: tick only what you changed; choose patch / minor / major.
3. Open a PR. CI runs every test, then builds only the affected app platforms
   and service images, boots the stack with docker compose and runs the smoke
   test (`node tools/affected.mjs origin/main` shows what it will build).
4. Merge. Changed service images are published to
   `ghcr.io/dunning630/humid-<service>:latest` and `:<commit>`.
   `npm run version-modules` bumps the changed packages and writes their
   CHANGELOG entries.

### What a change costs

| You changed | Images rebuilt | Apps rebuilt |
|---|---|---|
| `services/vault/**` | vault | none |
| `services/recovery/**` | recovery | none |
| `packages/recovery/**` | recovery, edge | all |
| `packages/htp/**` | every Node service, edge | all |
| `apps/mobile/src/**` | edge (web app) | all |
| `plugins/humid-gate/src/desktop/windows.rs` | none | Windows |
| `plugins/humid-gate/android/**` | none | Android |
| docs, tests | none | none |

## 3. Shipping apps

- Set repository variables `HUMID_SERVER_URL` and `HUMID_SERVER_KID` (printed
  by `deploy/setup.sh`) so the apps pin your server.
- **One or a few platforms:** Actions → *Release apps* → platforms: `android`
  (or `ios,android`, or `all`).
- **Everything:** bump `apps/mobile/package.json`, tag `app-vX.Y.Z`; a draft
  GitHub release collects every platform's installers.
- Each app embeds `modules.json` listing the package versions inside it, so a
  bug report pins the exact combination.

Signing secrets are listed at the top of `.github/workflows/release.yml`.
Without them you still get an installable Android test APK (debug-signed) and
Linux packages.

**Live-check proof needs these on the server side** (`deploy/.env`):

- **iPhone:** enable the *App Attest* capability on the `app.humid.vault` App
  ID in your Apple Developer account. The release workflow adds the
  `com.apple.developer.devicecheck.appattest-environment = production`
  entitlement. Set `HUMID_IOS_APP_ID=<Team ID>.app.humid.vault` on the server.
  TestFlight and App Store builds use App Attest's production environment;
  Xcode debug builds use development (`HUMID_APP_ATTEST_ENV=development` on a
  test server).
- **Android:** the app needs Android 11 (API 30) or later. Set
  `HUMID_ANDROID_CERT_DIGESTS` to the SHA-256 of your release signing
  certificate (Play App Signing: the app-signing key's certificate) so only
  your build can join. The debug-signed test APK works while it's empty.

## 4. Shipping the server

```bash
cd deploy && docker compose pull && docker compose up -d
```

Pin a version with `HUMID_VERSION=<commit>` in `deploy/.env` to roll back.

**HumID Server for Windows** (`deploy/windows/`) ships as a zip on the
repository's Releases page, one release per version:

1. Bump `deploy/windows/package.json` and add an entry to
   `deploy/windows/CHANGELOG.md`.
2. Tag the commit and push the tag:
   `git tag server-win-v1.0.1 && git push origin server-win-v1.0.1`

*Release HumID Server for Windows* builds the zip on Windows, installs it and
runs the smoke test there, then creates the release with the zip and the
changelog entry. The tag must match the version. To update a laptop,
download the new zip and run its installer; settings and data are kept.

## 5. Breaking changes, safely

- **New envelope layout:** add a codec branch, keep v1 parsing forever.
- **New crypto:** add a suite file and a registry line, then switch the
  default. Never modify a released suite.
- **New protocol version:** run HTP/1 and HTP/2 side by side on the gateway;
  ship apps that speak HTP/2; retire HTP/1 when no app pins it.
- **New identity fields:** add a migration step and bump `IDENTITY_SCHEMA`.
  Older apps refuse newer records with a clear "update HumID" message instead
  of corrupting them.
- **Native plugin major:** bump `plugins/humid-gate/Cargo.toml`, tag
  `humid-gate-vX.Y.Z`, and update `@humid/gate`'s `requires.native-plugin`.
