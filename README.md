# HumID — safe, secure, simple personal-data vault (3.0)

Your documents are sealed on your phone with post-quantum encryption, stored
on a vault server that can't read them, and opened again only after a live
face or fingerprint check. Three parts:

| Part | Where | What |
|---|---|---|
| **App** | `apps/mobile` | iOS and Android (Tauri 2), plus an installable web app. Brand: humidsecure.ai. |
| **Transit** | `packages/htp` | HTP/1: hybrid ML-KEM-1024 + X25519 handshake, AES-256-GCM frames, biometric step-up proofs, inside TLS 1.3. |
| **Server** | `services/` | Eight small services: edge, gateway, identity, vault, ledger, recovery, access, keyshare. Docker compose. |

Start with [docs/V3.md](docs/V3.md) (the 3.0 app: its shape, the brand as meaning, what changed for the person, the security and weight changes, the communication boundary), then [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Then
[docs/CONTINUITY.md](docs/CONTINUITY.md) (proving it's the same person: two-proof recovery, duress, the public log),
[docs/PROTOCOL.md](docs/PROTOCOL.md) (the wire protocol),
[docs/RECOVERY.md](docs/RECOVERY.md) (devices and getting your vault back),
[docs/ANONYMITY.md](docs/ANONYMITY.md) (paying without being identified, and who can know what),
[docs/SECURITY.md](docs/SECURITY.md) (what it protects against, and what it
doesn't yet), [deploy/README.md](deploy/README.md) (running a server, on Linux with Docker or on a Windows PC), [docs/DEPLOY-VMS.md](docs/DEPLOY-VMS.md) (server 3.0 on VMs and shared storage: roles on separate machines over mutual TLS, sealed secrets, encrypted backups),
[docs/ADMIN.md](docs/ADMIN.md) (the Windows server's admin console: health, updates and backups, each change approved on an administrator's phone),
[docs/CHECKIN.md](docs/CHECKIN.md) (Check-in: a timer that erases your vault for good unless you check in),
[docs/BACKUP.md](docs/BACKUP.md) (HumID 3.0, provisional: whole-computer backups),
[docs/MESSAGING.md](docs/MESSAGING.md) (HumID 4.0, provisional: person to person, known only by an ID), and
[docs/CREDENTIALS.md](docs/CREDENTIALS.md) (HumID 4.0, provisional: asking for and checking mobile licenses, digital IDs, passports; what an SSN check can and can't be).

The next build is specified in [docs/V5.md](docs/V5.md) (HumID 5.0: post-quantum from the ground up, keys made by the device's secure hardware inside every live check).

## Try it on your machine

Needs Node 24 (LTS).

```bash
npm install
npm test && npm run test:e2e   # crypto, protocol, every service end to end
npm run build:app
npm run dev                    # whole stack, no Docker → http://localhost:5173 (this computer only; HOST=0.0.0.0 to share it)
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

- **Message people you've approved** (4.0, provisional): each of you knows the other only by
  an ID made for the two of you; post-quantum end-to-end encryption; and nobody interacts
  without a live check: inviting, asking, approving, every message, and reading. A
  conversation shows "Both here" only while both people's checks are fresh. See
  [docs/MESSAGING.md](docs/MESSAGING.md).
- **Pay anonymously:** an access code (bought for cash, or online) becomes a
  pass the server signs blind, so it can't link the payment to your account.
  No name, email or phone number anywhere.
- **Create** a HumID: choose how you'd get back in if you lost every device
  (*only my own devices*, or *two proofs, a wait and a veto*), bind it to your
  face or fingerprint, and, with recovery on, get a recovery card. Every check
  is a live biometric match: on an iPhone or Android phone its secure chip
  signs each one and the server verifies it. HumID relies on the phone's own
  matcher and anti-spoofing; it doesn't do liveness detection of its own, and
  it proves a face or finger enrolled on that phone was matched, not whose
  ([SECURITY.md](docs/SECURITY.md#what-it-does-not-protect-against-yet)).
  Computers can't prove their checks this way, and the default server policy
  accepts phones only. A PIN or password never unlocks anything.
- **Split keys:** every new document also needs its own key from a separate
  service, released one document at a time inside a live check, so spyware
  that copies your account keys off the phone can't open documents with them
  alone. (Spyware that watches the phone while you open a document sees it, as
  with any app.)
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
- **Recover** on a new phone, if you chose recovery, with any **two** of four
  proofs: your witnesses (a majority of 2–5 people), your passport or ID chip
  (read with the phone's NFC, or a USB card reader on a computer), your
  recovery card, your security key. The wait depends on the evidence (24 h with
  an in-person station check, 72 h with witnesses, 7 days otherwise); every
  surviving device is alerted and can veto. With *only my own devices* there
  is no recovery at all: lose every device and the vault is gone. See
  [docs/RECOVERY.md](docs/RECOVERY.md#two-recovery-modes) for what each mode
  trusts the server operator with, and [docs/CONTINUITY.md](docs/CONTINUITY.md).
- **Duress gesture:** unlock into a decoy view while the server silently locks
  sensitive changes and slows recoveries. Which gesture it is stays sealed on
  the phone until a live check. The decoy view is meant to look like a calm,
  ordinary account; someone who knows HumID well may still suspect one exists.
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
  backup                           (3.0, provisional) computer backups: sealed pieces, 2-of-3 key parts (HumID, sheet, contact)
  msg                              (4.0, provisional) person to person: persona IDs, PQ double ratchet, live stamps, relay rules
  mdoc                             mobile IDs (ISO 18013-5/-7): in person and online (Digital Credentials API, HPKE), issuer + device authentication
  sdjwt                            (4.0, provisional) SD-JWT VC with key binding, JOSE, token status lists (revocation)
  creds                            (4.0, provisional) one request and one verifier for public credentials; minimised claims; SSN (eCBSV)
plugins/humid-gate/  native biometric gate (Swift, Kotlin, Rust)
plugins/humid-nfc/   native chip reader transport (Core NFC, Android IsoDep, PC/SC)
services/            edge (Caddy) · gateway · identity · vault · ledger · recovery · access · keyshare
deploy/              docker compose + setup.sh for a real server; windows/ = HumID Server for Windows
tests/               unit, protocol, end-to-end and smoke tests
tools/               dev server (with demo passports), public-log cosigner, release helpers
```

## Builds and releases

- **Every push:** tests and Rust checks; the iPhone and Android apps compile
  when app or plugin code changed, and the service images are rebuilt and the
  full stack booted with docker compose (smoke test over TLS) when server code
  changed (`changes` job in `.github/workflows/ci.yml`).
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
