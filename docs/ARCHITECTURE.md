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
│   ├──► recovery   device links, card + contact    (SQLite)    │
│   │               backups, timed releases                     │
│   ├──► access     access codes, blind-signed      (SQLite)    │
│   │               passes, spent passes: no accounts           │
│   └──► keyshare   each split document's second    (SQLite)    │
│                   key; never sees envelopes                   │
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

**Screens.** Welcome → *Create my HumID* (connect · access pass · the first
check · your recovery card · you're in) or *I already have HumID* (connect ·
choose: another device, or prove it's you with two proofs · the first check ·
wait) → Lock → three tabs. **Vault** (search; a chip row of the *kinds* that
exist: All · IDs · Cards · Passes · Photos · Files, with a secondary tag row
once any item carries a tag; one **Add** flow, camera first: the photo routes
itself to the ID flow, the card review or the photo review, with File, Type a
card and Tap a card on the camera's own bar and "It's something else" for the
picker; every kind then goes through one shared *Review* (name, kind, the kind's
fields, tags, location stamp, Seal). Tapping a row pushes the **Item** screen:
the preview first (one Open = one check), the facts, and a ··· menu with Rename
· Pin · Show in decoy · Export sealed · Delete; Save a copy lives in the opened
Viewer). **Activity** (the access record, checked on the phone). **You**
(`screens/you.jsx`: the protection checklist, devices, recovery — witnesses · ID
chip · recovery card — duress with its decoy picker, helping others and the
station, preferences, a collapsed "About this HumID" with the identity, device
and connection diagnostics, then lock and close & erase).

`main.jsx` routes `S.view` → the tab in `S.tab` → one global `S.sheet`
(`{ type, … }`; each type is rendered by exactly one file, see
tests/ia.test.js). Two of those types render full-screen *pushed* screens
rather than bottom sheets: `add` (`screens/add.jsx`, whose steps are the camera,
the picker, the ID flow in `ids.jsx`, the card flow in `cards.jsx` and the
photo / file / pass reviews) and `item` (`screens/vault.jsx`). `core/back.js`
sends Android Back to the top `[data-back]` control: the camera, then an open
document, then the top sheet (or the step inside it), then the step inside a
pushed screen, so Add and the item step back one level before they close.

**Kinds and tags** (`core/categories.js`). Every item's encrypted index entry
carries `kind` ∈ id · card · pass · photo · file. Entries sealed before 2.0 have
none and are classified on read (ID summary → id, card summary → card, pass
summary → pass, image type → photo, else file); the inferred kind is written back
only when the entry is next re-sealed for a rename or a pin, never in bulk. The
1.x category survives as an optional `tags` list with the same ids (identity ·
health · money · home · personal), suggested from the name on add. The identity
record itself is unchanged (schema 4): item meta is per entry, not part of it.

The words people read follow one vocabulary: *check* for the biometric prompt
(the "biological interrupt" of this document), *seal* for encrypt-and-store,
*recovery card*, *witnesses*, *ID chip* (the identity anchor), *your vault
server*; the security facts are in one shared `HowProtected` sheet
(`ui.jsx`).

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
| `@humid/mdoc` | mobile IDs (ISO/IEC 18013-5/-7): reader session, Digital Credentials API requests (Annex C, HPKE; OpenID4VP transcripts), issuer data authentication against IACA roots, device authentication, VICAL ([CREDENTIALS.md](CREDENTIALS.md)) |
| `@humid/sdjwt` | 4.0, provisional: SD-JWT VC with key binding, JWS/x5c/JWE, IETF Token Status List ([CREDENTIALS.md](CREDENTIALS.md)) |
| `@humid/creds` | 4.0, provisional: one request and one verifier for public credentials, assurance levels, revocation, minimised claims, SSN via eCBSV for permitted entities; `/server` for passport chips and ICAO master lists ([CREDENTIALS.md](CREDENTIALS.md)) |
| `@humid/cards` | the holder's payment cards: number checks and networks, camera (front and back) and contactless (read-only EMV) capture, the sealed card record ([CARDS.md](CARDS.md)) |
| `@humid/wallet` | Apple Wallet passes: bounded unzip, manifest hashes, the issuer's CMS signature through Apple's pinned roots ([WALLET-PASSES.md](WALLET-PASSES.md)) |
| `@humid/pass` | anonymous access passes: RFC 9474 blind signatures (app side; `/issuer` for the server), access codes |

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
| **keyshare** | gateway | one encrypted 256-bit key per split document, under `share-key.bin`; while Check-in is armed, under a per-account fuse key held in memory only | which documents exist and when each was opened; who has Check-in armed and until when. Never an envelope, name or account key. See [SECURITY.md](SECURITY.md#a-compromised-phone) and [CHECKIN.md](CHECKIN.md). |
| **access** | gateway | access-code hashes, pass keys, spent-pass hashes, all dated by day | which codes were used, and how many passes were spent. Never an account. See [ANONYMITY.md](ANONYMITY.md). |

**Internal trust.** The gateway signs a short-lived Ed25519 assertion (30 s,
audience-bound) for every internal call, naming the account, the device,
key fingerprints and any step-up. Identity, vault, ledger and recovery verify
it and accept nothing else, so a compromised edge can reach them on the
network but cannot get them to do anything.

**Split keys.** Since split keys, each document also needs its own key from
keyshare, released inside the same live step-up that releases its envelope. A
copy of the account keys opens nothing alone ([SECURITY.md](SECURITY.md#a-compromised-phone)).

**Offline.** The app keeps a read-only copy of what it shows (the sealed index entries,
devices, recovery and duress status, the verified ledger), sealed under a key derived
from the account seed. With no connection, a live check opens that copy instead of
signing in; nothing that needs the vault works until it reconnects ([SECURITY.md](SECURITY.md#offline)).

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
