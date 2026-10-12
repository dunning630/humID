# HumID architecture (POC v2)

HumID is a personal-data vault. Documents are encrypted on the phone, stored
on the server as ciphertext, and opened again only after a live biometric
check on the holder's device. Three parts:

```
┌──────────────── 1. App (iOS · Android · PWA) ────────────────┐
│  apps/mobile   Preact UI · @humid/api · @humid/crypto · gate  │
│  keys live in the Secure Enclave / Keystore; released per use │
└───────────────────────────┬───────────────────────────────────┘
                            │  2. HTP/1 inside TLS 1.3
                            │     (docs/PROTOCOL.md)
┌───────────────────────────▼──── 3. Server (services/) ────────┐
│  edge       Caddy: TLS 1.3 + PQ hybrid, static app, headers   │
│   │                                                           │
│  gateway    only service reachable from the edge              │
│   │         HTP termination · routing whitelist · rate limits │
│   │         step-up verification · fail-closed audit          │
│   ├──► identity   public keys + devices        (SQLite)       │
│   ├──► vault      sealed envelopes + index     (SQLite+blobs) │
│   └──► ledger     signed hash-chained log      (SQLite)       │
│       internal network: no internet egress                   │
└───────────────────────────────────────────────────────────────┘
```

## 1. The app — `apps/mobile`

One codebase, built three ways from the same `dist/` bundle (~150 KB of
JavaScript, 52 KB gzipped):

| Target | How | Biometric gate |
|---|---|---|
| iOS | Tauri 2 → WKWebView | Keychain item bound to `.biometryCurrentSet` (Secure Enclave), no passcode fallback |
| Android | Tauri 2 → Android WebView | Keystore AES key, `BIOMETRIC_STRONG`, auth per use (StrongBox where present) |
| Web / PWA | served by the edge | WebAuthn platform authenticator + PRF |

The desktop builds (macOS, Windows, Linux) come from the same Tauri project.

**Screens:** Welcome → Enroll (connect · bind face/fingerprint · ready) →
Lock → Vault (search, categories, add, open, rename, sealed copy, delete) →
Activity (verified ledger) → Security (identity, device, connection, session,
lock, close & erase).

**Key handling** (`src/core/controller.js`): the identity seed exists only
inside `withKeys()`, which runs one biometric interrupt, derives the keys,
runs one operation, and zeroes the seed and secret keys in `finally`. The
vault-index key is derived during the unlock interrupt and held in memory
while unlocked. The app locks after 5 minutes idle and when it goes to the
background.

**Modules** (`packages/`), each versioned on its own:

| Package | Role |
|---|---|
| `@humid/codec` | `.humid` envelope framing (format v1) |
| `@humid/crypto` | sealing suite HUMID-PQ1; vault-index encryption (1.1.0) |
| `@humid/gate` | biometric gate contract + native / WebAuthn / demo adapters |
| `@humid/store` | on-device identity record with per-record migrations |
| `@humid/io` | save dialog / download |
| `@humid/htp` | HTP/1 client and server |
| `@humid/api` | typed client for the HumID API over HTP |
| `@humid/audit` | ledger hash-chain verification (shared by app and ledger service) |
| `@humid/svc` | tiny service kit: HTTP, internal assertions, SQLite |

Each package declares what it `provides` and `requires` in `package.json`
under `"humid"`. The app build refuses an incompatible combination.

## 2. Transit — HTP/1

A one-round-trip hybrid handshake (ML-KEM-1024 + X25519), then one
AES-256-GCM frame per call, carried as HTTPS POSTs inside TLS 1.3. Sessions are
bound to the holder's ML-DSA-87 key; opening or deleting a document needs a
per-request biometric proof. Full specification: [PROTOCOL.md](PROTOCOL.md).

## 3. Server — `services/`

Each service is a few hundred lines of plain Node 22 with its own SQLite
database (`node:sqlite`). esbuild bundles each into one file of 115–160 KB.
Each runs as a distroless, non-root, read-only container with all Linux
capabilities dropped.

| Service | Reachable from | Stores | Knows |
|---|---|---|---|
| **edge** | internet :443 | nothing | TLS only; HTP frames are opaque to it |
| **gateway** | edge | its HTP key pair | session keys, which identity is signed in |
| **identity** | gateway | public keys, devices, gate method | public keys only |
| **vault** | gateway | sealed envelopes, encrypted index blobs | sizes, timestamps, object ids. No names, no content. |
| **ledger** | gateway | per-holder hash chain, signed heads | event types and proof hashes |

**Internal trust.** The gateway signs a short-lived Ed25519 assertion (30 s,
audience-bound) for every internal call, naming the holder, their key
fingerprints and any step-up. Identity, vault and ledger verify it and accept
nothing else, so a compromised edge can reach them on the network but cannot
get them to do anything.

**Zero knowledge in the vault.** The vault checks each upload's ML-DSA-87
signature, that the signer is the signed-in holder, and that the recipient is
the holder's own KEM key. It cannot decrypt anything. Item names and types
are in an index blob encrypted with a key derived from the holder's seed.
Returning a document's bytes needs a step-up made in the last 60 seconds.

**Audit that cannot be skipped.** Opening and deleting a document are
recorded in the ledger *before* the response is released. If the ledger is
down, the gateway refuses the access (503 `audit_unavailable`). Each holder's
log is a SHA3 hash chain; the ledger signs the head with ML-DSA-87. Each time
it shows Activity, the app re-verifies every link it receives (the latest 200
events) and the signature on the head.

## Releasing one piece at a time

`tools/affected.mjs` maps changed files to the app platforms and service
images they affect. CI builds and tests only those. Examples:

| Change | Rebuilds |
|---|---|
| `services/vault/**` | `humid-vault` image only |
| `packages/audit/**` | ledger image + edge (web app) + all apps |
| `plugins/humid-gate/ios/**` | iOS app only |
| `docs/**` | nothing |

Services talk only through HTTP contracts, so each image is replaced on its
own: `docker compose pull vault && docker compose up -d vault`. Schemas
migrate per service at start-up.
