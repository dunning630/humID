# HumID architecture (POC v2)

HumID is a personal-data vault. Documents are encrypted on the phone, stored
on the server as ciphertext, and opened again only after a live biometric
check on one of the holder's devices. Three parts:

```
┌──────────────── 1. App (iOS · Android · PWA) ────────────────┐
│  apps/mobile   Preact UI · @humid/api · crypto · recovery     │
│  keys sealed behind Face ID / fingerprint; released per use   │
└───────────────────────────┬───────────────────────────────────┘
                            │  2. HTP/1 inside TLS 1.3
                            │     (docs/PROTOCOL.md)
┌───────────────────────────▼──── 3. Server (services/) ────────┐
│  edge       Caddy: TLS 1.3 + PQ hybrid, static app, headers   │
│   │                                                           │
│  gateway    only service reachable from the edge              │
│   │         HTP termination · routing whitelist · rate limits │
│   │         step-up verification · fail-closed audit          │
│   ├──► identity   accounts, devices, public keys  (SQLite)    │
│   ├──► vault      sealed envelopes + index    (SQLite+blobs)  │
│   ├──► ledger     signed hash-chained log         (SQLite)    │
│   └──► recovery   device links, card + contact    (SQLite)    │
│                   backups, timed releases                     │
│       internal network: no internet egress                   │
└───────────────────────────────────────────────────────────────┘
```

## 1. The app — `apps/mobile`

One codebase, built three ways from the same `dist/` bundle (about 195 KB of
JavaScript before compression):

| Target | How | Live biometric gate (never a PIN or password) |
|---|---|---|
| iOS | Tauri 2 → WKWebView | Face ID / Touch ID. Secret in the Keychain (`.biometryCurrentSet`); liveness key in the Secure Enclave, proven with App Attest |
| Android | Tauri 2 → Android WebView | Class 3 face or fingerprint. Liveness key in the Keystore (StrongBox where present), per use, proven with key attestation |
| macOS | Tauri 2 | Touch ID (Keychain `.biometryCurrentSet`); no hardware proof |
| Windows | Tauri 2 | Fingerprint through the Windows Biometric Framework (not Hello, which allows a PIN); no hardware proof |
| Linux | Tauri 2 | Fingerprint through fprintd; no hardware proof |
| Web / PWA | served by the edge | None: a browser can't prove a live check, so it points people to the app |

Servers accept proven phones by default (`HUMID_DEVICE_POLICY=attested`);
`biometric` also admits the desktops. See [SECURITY.md](SECURITY.md#live-biometric-checks).

**Screens.** Welcome → *Create my HumID* (connect · bind · recovery card) or
*I already have HumID* (connect · choose: another device, recovery card,
recovery contacts · bind · wait) → Lock → Vault (search, categories, add,
open, rename, sealed copy, delete) → Activity (verified ledger) → Security
(recovery alerts, devices, recovery card and contacts, being someone's
contact, helping someone recover, connection, lock, close & erase).

**Keys on a device.** Each device holds two seeds behind one biometric
secret: the **account seed**, shared by all of the holder's devices, and its
own **device seed**. The account keys seal and open documents, encrypt the
index and authorise new devices. The device key signs sign-ins and step-up
proofs, so a lost device can be removed alone. Details:
[RECOVERY.md](RECOVERY.md).

**Key handling** (`src/core/controller.js`): seeds exist only inside
`withKeys()`, which runs one biometric interrupt, derives the keys, runs one
operation, and zeroes seeds and secret keys in `finally`. The interrupt is
given its challenge before the prompt opens (the sign-in challenge, a
step-up ticket from `withStepUp()`, or a sealed file's hash) so the phone's
liveness key signs exactly what the check approves. The index key is
derived during the unlock interrupt and held in memory while unlocked. The
app locks after 5 minutes idle and when it goes to the background.

**Modules** (`packages/`), each versioned on its own:

| Package | Role |
|---|---|
| `@humid/codec` | `.humid` envelope framing (format v1) |
| `@humid/crypto` | sealing suite HUMID-PQ1; vault-index encryption |
| `@humid/gate` | live-biometric gate contract (v2) + native adapter; demo adapter in development builds only |
| `@humid/store` | on-device identity record with per-record migrations (schema 4) |
| `@humid/io` | save dialog / download |
| `@humid/htp` | HTP/1 client and server, proofs |
| `@humid/recovery` | key codes, recovery cards, Shamir sharing over GF(2⁸) |
| `@humid/api` | typed client for the HumID API over HTP; checks every typed code |
| `@humid/audit` | ledger hash-chain verification (shared by app and ledger service) |
| `@humid/svc` | tiny service kit: HTTP, internal assertions, SQLite |
| `@humid/attest` | server only: verifies Android key attestation and Apple App Attest against pinned roots |
| `@humid/emrtd` | reads passport and ID card chips (ICAO 9303) over any APDU transport: BAC, PACE, secure messaging, Active Authentication; the DG2 photo only for the holder's own vault copy |
| `@humid/idscan` | reads ID documents into one record: MRZ (OCR-tolerant), AAMVA license barcodes, chip data groups and SOD hashes ([ID-SCANNING.md](ID-SCANNING.md)) |

Each package declares what it `provides` and `requires` in `package.json`
under `"humid"`. The app build refuses an incompatible combination.

## 2. Transit — HTP/1

A one-round-trip hybrid handshake (ML-KEM-1024 + X25519), then one
AES-256-GCM frame per call, carried as HTTPS POSTs inside TLS 1.3. Sessions are
bound to one device of an account; sensitive requests need a per-request
biometric proof. Full specification: [PROTOCOL.md](PROTOCOL.md).

## 3. Server — `services/`

Each service is a few hundred lines of plain Node 22 with its own SQLite
database (`node:sqlite`). esbuild bundles each into one file of 115–175 KB.
Each runs as a distroless, non-root, read-only container with all Linux
capabilities dropped.

| Service | Reachable from | Stores | Knows |
|---|---|---|---|
| **edge** | internet :443 | nothing | TLS only; HTP frames are opaque to it |
| **gateway** | edge | its HTP key pair | session keys, which account and device are signed in |
| **identity** | gateway | account and device public keys, gate method, liveness keys and their verified proof | public keys only |
| **vault** | gateway | sealed envelopes, encrypted index blobs | sizes, timestamps, object ids. No names, no content. |
| **ledger** | gateway | per-account hash chain, signed heads | event types and proof hashes |
| **recovery** | gateway | sealed seeds for new devices, card-locked backups, contacts' sealed pieces, recovery requests | who protects whom (account ids), when a recovery releases. Never a usable key. |

**Internal trust.** The gateway signs a short-lived Ed25519 assertion (30 s,
audience-bound) for every internal call, naming the account, the device,
key fingerprints and any step-up. Identity, vault, ledger and recovery verify
it and accept nothing else, so a compromised edge can reach them on the
network but cannot get them to do anything.

**Zero knowledge in the vault.** The vault checks each upload's ML-DSA-87
signature, that the signer is the signed-in account, and that the recipient
is the account's own KEM key. It cannot decrypt anything. Item names and
types are in an index blob encrypted with a key derived from the account seed.
Returning a document's bytes needs a step-up made in the last 60 seconds.

**Recovery without a master key.** The recovery service holds only things it
cannot open: an account seed sealed to a new device's keys, a backup locked
by the holder's recovery card, and Shamir pieces each sealed to one recovery
contact. Its job is the rules: a code must match the keys behind it, a card
or contact recovery is released only after a delay (72 hours by default) and
can be cancelled from any signed-in device, and every step is in the
account's ledger.

**Audit that cannot be skipped.** Opening and deleting a document, and
approving a new device, are recorded in the ledger *before* the response is
released. If the ledger is down, the gateway refuses (503
`audit_unavailable`). Each account's log is a SHA3 hash chain; the ledger
signs the head with ML-DSA-87. Each time it shows Activity, the app
re-verifies every link it receives (the latest 300 events) and the signature
on the head.

## Releasing one piece at a time

`tools/affected.mjs` maps changed files to the app platforms and service
images they affect. CI builds and tests only those. Examples:

| Change | Rebuilds |
|---|---|
| `services/vault/**` | `humid-vault` image only |
| `services/recovery/**` | `humid-recovery` image only |
| `packages/audit/**` | ledger image + edge (web app) + all apps |
| `packages/recovery/**` | recovery image + edge + all apps |
| `plugins/humid-gate/ios/**` | iOS app only |
| `docs/**` | nothing |

Services talk only through HTTP contracts, so each image is replaced on its
own: `docker compose pull vault && docker compose up -d vault`. Schemas
migrate per service at start-up.
