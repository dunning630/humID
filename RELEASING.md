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

Every *Release apps* run also leaves one download, `HumID-<version>-<server>`:
a `HumID <version>` folder with a folder per app (Android, iPhone, Mac,
Windows, Linux, Windows Server), a README naming the server the apps are
pinned to, and SHA-256 checksums (`tools/bundle-release.mjs`).

- Set repository variables `HUMID_SERVER_URL` and `HUMID_SERVER_KID` (printed
  by `deploy/setup.sh`) so the apps pin your server.
- **One or a few platforms:** Actions → *Release apps* → platforms: `android`
  (or `ios,android`, or `all`).
- **Desktop apps are paused** (2026-10-17, see [docs/SECURITY.md](docs/SECURITY.md)):
  a publishing run leaves macOS, Windows and Linux out with a warning (they can
  still be built, unpublished, to test). Set the repository variable
  `HUMID_DESKTOP_RELEASES=on` to publish them again. HumID Server for Windows
  is a server, not a desktop app, and isn't affected.
- **Everything:** bump `apps/mobile/package.json`, tag `app-vX.Y.Z`; a draft
  GitHub release collects every platform's installers.
- Each app embeds `modules.json` listing the package versions inside it, so a
  bug report pins the exact combination.

Signing secrets are listed at the top of `.github/workflows/release.yml`.
**Android needs its release key** (`ANDROID_KEYSTORE`, `ANDROID_KEYSTORE_PASSWORD`,
`ANDROID_KEY_ALIAS`): without it there is no Android build. HumID never ships a
debug build, which would be debuggable, remotely inspectable and signed with a
key anyone could get. The workflow checks the APK is signed with the HumID key
and not debuggable, and prints the certificate's SHA-256 for the server.

**Live-check proof needs these on the server side** (`deploy/.env`):

- **iPhone:** enable the *App Attest* capability on the `app.humid.vault` App
  ID in your Apple Developer account. The release workflow adds the
  `com.apple.developer.devicecheck.appattest-environment = production`
  entitlement. Set `HUMID_IOS_APP_ID=<Team ID>.app.humid.vault` on the server.
  TestFlight and App Store builds use App Attest's production environment;
  Xcode debug builds use development (`HUMID_APP_ATTEST_ENV=development` on a
  test server).
- **Android:** the app needs Android 11 (API 30) or later. Servers accept only
  apps signed with the official HumID release certificate
  (`HUMID_ANDROID_RELEASE_CERT` in `packages/attest/src/roots.js`), so a
  re-signed or rebuilt copy can't join. If you build and sign your own, add your
  certificate's SHA-256 with `HUMID_ANDROID_CERT_DIGESTS` (Play App Signing: the
  app-signing key's certificate). `HUMID_ANDROID_ALLOW_ANY_SIGNER=1` accepts any
  signer, for a test server only.
- **Android, optional:** `HUMID_ANDROID_MIN_PATCH=YYYYMM` refuses phones on an
  older security patch. Google's attestation revocation list is fetched every
  6 hours (`HUMID_ATTESTATION_STATUS_URL`; `HUMID_ATTESTATION_STATUS_REQUIRED=1`
  refuses phones until a copy has been fetched).

## 4. Shipping the server

```bash
cd deploy && docker compose pull && docker compose up -d
```

Pin a version with `HUMID_VERSION=<commit>` in `deploy/.env` to roll back.

**HumID Server for Windows** (`deploy/windows/`) ships as a zip on the
repository's Releases page, one release per version. The admin console installs
an update as SYSTEM, so it takes only a zip signed with **the HumID release key**:
an ML-DSA-87 key the maintainer keeps offline, whose public key is pinned in
[`deploy/windows/admin/release-keys.mjs`](deploy/windows/admin/release-keys.mjs).
CI never holds it, so CI makes a draft and the maintainer signs and publishes it.

**Once, before the first signed release** (and again only to rotate the key):

1. On a computer that's offline, with a checkout of this repository:
   `node tools/release-key.mjs keygen --out E:\humid-release.key` (a USB drive).
   It refuses to overwrite a file, writes the secret key readable only by you,
   and prints the public key and its fingerprint.
2. Paste the public key into `RELEASE_KEYS` in `release-keys.mjs` (with the
   fingerprint and date in a comment) and commit it. A console only trusts keys
   its installed version pins, so servers learn the key from the first release
   that pins it. Consoles of 2.1.0 and earlier still check only GitHub's digest,
   so that release reaches them as updates did before (from the console, or by
   hand); from then on every update must be signed.
3. Keep the key file offline, with a second copy somewhere safe. Never put it in
   the repository, a GitHub secret or a server. Losing it means servers must be
   updated by hand to a release that pins a new key.

To rotate: add the new public key beside the old one (at most two), release that
signed with the old key, then sign with the new key and drop the old one later.

**Every release:**

1. Bump `deploy/windows/package.json` and add an entry to
   `deploy/windows/CHANGELOG.md`.
2. Either click **Actions → Release apps → Run workflow**, pick the branch,
   set platforms to `server-windows` and tick the publish box, or tag the
   commit yourself: `git tag server-win-v1.0.1 && git push origin server-win-v1.0.1`
3. *Release HumID Server for Windows* refuses to start while `release-keys.mjs`
   pins no key. It builds the zip on Windows, installs it and runs the smoke
   test there, then creates a **draft** release with the zip and the changelog
   entry. The tag must match the version.
4. Download `HumID-Server-Windows-<version>.zip` from the draft to the offline
   computer and run
   `node tools/release-key.mjs sign HumID-Server-Windows-<version>.zip --key E:\humid-release.key`.
   It writes `HumID-Server-Windows-<version>.zip.sig` and warns if that key isn't
   the one pinned in your checkout.
5. Upload the `.sig` to the draft beside the zip, then **Publish release**
   (leave "pre-release" unticked: consoles skip pre-releases unless
   `HUMID_UPDATE_PRERELEASES=on`). Check it with
   `node tools/release-key.mjs verify HumID-Server-Windows-<version>.zip`.

Consoles never see drafts, and refuse a zip without a valid `.sig`. To update a
laptop by hand, download the new zip and run its installer; settings and data are
kept.

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
