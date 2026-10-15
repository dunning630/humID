# HumID Server for Windows

## 1.2.0

- **Anonymous payment for new accounts.** A new HumID needs an access pass, bought with an access code and signed blind, so no one, HumID included, can link the payment to the account. Print codes to sell with `humid mint 50 batch-name`; `humid set HUMID_PASS_BUY_URL=https://…` links the app to your shop; `humid set HUMID_REGISTRATION=open` turns payment off. See docs/ANONYMITY.md.
- A sixth service, **access**, runs in the same background task with its own database (`data\access`): access-code hashes, pass keys and spent passes, dated by day, with no accounts.
- **Upgrading from 1.1.0:** `humid install` adds the new settings with payment **on**. Mint codes before you tell anyone to sign up, or set `HUMID_REGISTRATION=open`.
- The web app it serves is HumID 1.4.0, with **Scan an ID**: driver's license barcodes, passport and ID card MRZs, and chip copies with the photo, sealed as one vault record. See docs/ID-SCANNING.md.
- The local edge allows WebAssembly (`'wasm-unsafe-eval'` in the content security policy) for the document scanners, and serves `.wasm` as `application/wasm`.

## 1.1.0

- Two-proof recovery: witnesses, ID chip anchor and seal card; any two, with waits set by the evidence (24 h with a station, 72 h with witnesses, 7 days for card + chip; doubled after a duress signal).
- ID chip checks (ICAO 9303 passive and active authentication). Put country signing certificates in `C:\ProgramData\HumID\csca`.
- Verification stations (`HUMID_STATION_ACCOUNTS`), duress lockdown (`HUMID_DURESS_COOLOFF_MS`), and the public transparency log at `/tlog/v1/*` with optional cosigners (`HUMID_TLOG_COSIGNERS`).

## 1.0.0

- The five HumID services and a local edge in one background task (scheduled task at startup, LOCAL SERVICE account, restarted if it stops), bound to 127.0.0.1.
- Double-click installer; official Node.js 22 downloaded from nodejs.org and checksum verified.
- `humid` command: install / update, start, stop, restart, status, logs, set, show, backup, restore, expose (Tailscale Funnel or Cloudflare Tunnel), uninstall.
- Offers to keep a laptop awake while plugged in.
