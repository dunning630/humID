# HumID — safe, secure, simple personal-data vault (POC v2)

Your documents are sealed on your phone with post-quantum encryption, stored
on a vault server that can't read them, and opened again only after a live
face or fingerprint check. Three parts:

| Part | Where | What |
|---|---|---|
| **App** | `apps/mobile` | iOS and Android (Tauri 2), plus an installable web app. Brand: humidsecure.ai. |
| **Transit** | `packages/htp` | HTP/1: hybrid ML-KEM-1024 + X25519 handshake, AES-256-GCM frames, biometric step-up proofs, inside TLS 1.3. |
| **Server** | `services/` | Eight small services: edge, gateway, identity, vault, ledger, recovery, access, keyshare. Docker compose. |

Start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Then
[docs/CONTINUITY.md](docs/CONTINUITY.md) (proving it's the same person: two-proof recovery, duress, the public log),
[docs/PROTOCOL.md](docs/PROTOCOL.md) (the wire protocol),
[docs/RECOVERY.md](docs/RECOVERY.md) (devices and getting your vault back),
[docs/ANONYMITY.md](docs/ANONYMITY.md) (paying without being identified, and who can know what),
[docs/SECURITY.md](docs/SECURITY.md) (what it protects against, and what it
doesn't yet), [deploy/README.md](deploy/README.md) (running a server, on Linux with Docker or on a Windows PC), and
[docs/ADMIN.md](docs/ADMIN.md) (the Windows server's admin console: health, updates and backups, each change approved on an administrator's phone), and
[docs/CHECKIN.md](docs/CHECKIN.md) (Check-in: a timer that erases your vault for good unless you check in).

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
The dev server runs a development build with demo mode (press and hold in
place of a sensor) and a server policy that accepts it. Real builds accept only
a live face or fingerprint, never a PIN or password, and real servers accept
only phones whose secure chip proves each check. Locally, the base recovery
wait is 2 minutes instead of 72 hours, every account can act as a verification
station, "Use a demo passport" gives you an ID chip to anchor and recover with,
and "Use a demo access code" pays for a new HumID.

## What you can do in the app

- **Pay anonymously:** an access code (bought for cash, or online) becomes a
  pass the server signs blind, so it can't link the payment to your account.
  No name, email or phone number anywhere.
- **Create** a HumID: bind it to your face or fingerprint, get a seal card.
  Every check is live: your phone's secure chip signs each one, and the server
  verifies it. A PIN or password never unlocks anything.
- **Split keys:** every new document also needs its own key from a separate
  service, released one document at a time inside a live check, so spyware
  that copies your keys off the phone still opens nothing on its own.
- **Seal** photos, PDFs and files; search and sort them by category. The
  server never learns their names.
- **Scan an ID:** photograph a driver's license, passport or ID card and
  HumID reads it on the phone (the license barcode, the passport's
  machine-readable lines, and the chip over NFC with its photo), lets you
  check the details, and seals one record with its photos. The vault shows
  when each ID expires. See [docs/ID-SCANNING.md](docs/ID-SCANNING.md).
- **Open** a document with a fresh biometric check each time. Every access is
  in your **Activity** log, which your phone verifies for itself.
- **Add devices** by scanning a QR code or typing a 12-character code;
  **remove** a lost one.
- **Recover** on a new phone with any **two** of three proofs: your witnesses
  (a majority of 2–5 people), your passport or ID chip (read with the phone's
  NFC, or a USB card reader on a computer), your seal card. The
  wait depends on the evidence (24 h with an in-person station check, 72 h
  with witnesses, 7 days otherwise); every surviving device is alerted and can
  veto. See [docs/CONTINUITY.md](docs/CONTINUITY.md).
- **Duress gesture:** unlock into a decoy view while the server silently locks
  sensitive changes and slows recoveries. Which gesture it is stays sealed on
  the phone until a live check.
- **Check-in:** before a high-stakes situation, arm a timer and check in with
  a live check every hour or two. Miss one and the vault locks; miss the grace
  period, or unlock with the duress gesture, and its documents' keys are
  destroyed for good. See [docs/CHECKIN.md](docs/CHECKIN.md).
- **Offline, read only:** with no connection, the same live check still
  opens your document list, Activity and Security as of the last sync.
  Documents themselves open only with the vault. See
  [docs/SECURITY.md](docs/SECURITY.md#offline).
- **Continuity:** your ledger is published in a public append-only log that
  your phone and independent cosigners check.

## Layout

```
apps/mobile/         the app (Preact) + Tauri project for iOS/Android/desktop
packages/            independently versioned modules
  codec crypto gate store io       envelope format, HUMID-PQ1, biometric gates, storage, files
  htp api recovery audit svc       transit protocol, API client, recovery crypto, ledger + public-log checks, service kit
  attest anchor                    phone attestation; passport / ID chip checks (server side)
  pass                             anonymous access passes (RFC 9474 blind signatures), access codes
  emrtd                            reads passport / ID chips: BAC, PACE, secure messaging, Active Authentication
  idscan                           reads IDs into one vault record: MRZ (OCR-tolerant), license barcodes (AAMVA), chip data
  cards                            payment cards: number checks, camera (both sides) + contactless capture, sealed record (no PIN, no back photo)
  wallet                           Apple Wallet passes: bounded unzip, manifest hashes, issuer signature through Apple's pinned roots
plugins/humid-gate/  native biometric gate (Swift, Kotlin, Rust)
plugins/humid-nfc/   native chip reader transport (Core NFC, Android IsoDep, PC/SC)
services/            edge (Caddy) · gateway · identity · vault · ledger · recovery · access · keyshare
deploy/              docker compose + setup.sh for a real server; windows/ = HumID Server for Windows
tests/               unit, protocol, end-to-end and smoke tests
tools/               dev server (with demo passports), change detection for CI, public-log cosigner
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
