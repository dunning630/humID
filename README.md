# HumID — safe, secure, simple personal-data vault (POC v2)

Your documents are sealed on your phone with post-quantum encryption, stored
on a vault server that can't read them, and opened again only after a live
face or fingerprint check. Three parts:

| Part | Where | What |
|---|---|---|
| **App** | `apps/mobile` | iOS and Android (Tauri 2), plus an installable web app. Brand: humidsecure.ai. |
| **Transit** | `packages/htp` | HTP/1: hybrid ML-KEM-1024 + X25519 handshake, AES-256-GCM frames, biometric step-up proofs, inside TLS 1.3. |
| **Server** | `services/` | Six small services: edge, gateway, identity, vault, ledger, recovery. Docker compose. |

Start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Then
[docs/PROTOCOL.md](docs/PROTOCOL.md) (the wire protocol),
[docs/RECOVERY.md](docs/RECOVERY.md) (devices and getting your vault back),
[docs/SECURITY.md](docs/SECURITY.md) (what it protects against, and what it
doesn't yet), and [deploy/README.md](deploy/README.md) (running a server).

## Try it on your machine

Needs Node 22.

```bash
npm install
npm test && npm run test:e2e   # crypto, protocol, every service end to end
npm run build:app
npm run dev                    # whole stack, no Docker → http://localhost:5173
```

Open http://localhost:5173 in a normal and a private window to try two
devices: create a HumID in one, then choose *I already have HumID* in the
other. (Browsers allow the app's encryption only on `localhost` or HTTPS, so
to use a phone, deploy a server or put the dev server behind an HTTPS tunnel.)
Without a fingerprint sensor, use demo mode (press and hold). Locally, card
and contact recovery waits 2 minutes instead of 72 hours.

## What you can do in the app

- **Create** a HumID: bind it to your face or fingerprint, get a recovery card.
- **Seal** photos, PDFs and files; search and sort them by category. The
  server never learns their names.
- **Open** a document with a fresh biometric check each time. Every access is
  in your **Activity** log, which your phone verifies for itself.
- **Add devices** with a 12-character code; **remove** a lost one.
- **Recover** on a new phone with another device, your recovery card, or your
  recovery contacts (any majority of 2–5 people). Card and contact recoveries
  wait 72 hours and alert your devices, which can cancel.

## Layout

```
apps/mobile/         the app (Preact) + Tauri project for iOS/Android/desktop
packages/            independently versioned modules
  codec crypto gate store io       envelope format, HUMID-PQ1, biometric gates, storage, files
  htp api recovery audit svc       transit protocol, API client, recovery crypto, ledger checks, service kit
plugins/humid-gate/  native biometric gate (Swift, Kotlin, Rust)
services/            edge (Caddy) · gateway · identity · vault · ledger · recovery
deploy/              docker compose + setup.sh for a real server
tests/               unit, protocol, end-to-end and smoke tests
tools/               dev server, change detection for CI
```

## Builds and releases

- **Every push:** tests, then only the apps and service images the change
  touches (`node tools/affected.mjs` shows what it decided). CI also boots the
  full stack with docker compose and runs the smoke test over TLS.
- **Server images:** published to `ghcr.io/dunning630/humid-<service>` on merge
  to `main`, again only the ones that changed.
- **Apps:** Actions → *Release apps* → choose platforms. Set
  `HUMID_SERVER_URL` and `HUMID_SERVER_KID` repository variables first so the
  apps pin your server. Without signing secrets you still get an installable
  Android APK and a Linux build; iOS needs an Apple Developer account.

Details: [RELEASING.md](RELEASING.md).

## Status

A working proof of concept, not a product yet. The cryptography uses
standard, audited primitives, but HumID's protocol and recovery design need an
independent review before real customer data goes in.
[docs/SECURITY.md](docs/SECURITY.md) lists what's left.

Private and patent pending. Not for redistribution.
