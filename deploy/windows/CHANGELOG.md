# HumID Server for Windows

## 1.7.0

- **Check-in** (docs/CHECKIN.md), off by default: `humid set HUMID_CHECKIN=on` lets holders arm a timer that erases their vault for good unless they check in every hour or two. The keys of an armed vault live in the server's memory only, so anything that stops the server (a restart, an update, a backup, restarting Windows) erases every armed vault.
- The admin console says how many vaults are armed on every change that stops the server, before you approve it; `server-status.json` carries the count (a number, nothing more).
- The web app it serves is HumID 1.14.0.

## 1.6.0

- **HumID Admin, the admin console** (docs/ADMIN.md). A second background task, run as SYSTEM, at `http://127.0.0.1:8490` on this computer only. Open it with `humid console` in Terminal (Admin): a sign-in link that works once.
  - **Watches** the server (every service, response times, errors, sessions), the public address and its certificate, CPU, memory, drives, Microsoft Defender, Windows Firewall, BitLocker, pending restarts, backups, and new HumID and Windows updates.
  - **Changes** (update HumID with automatic rollback, roll back, install Windows updates, update Defender, back up, restart the server or the computer) **each wait for an administrator's phone**: a code on the console, **Security ▸ Manage this server** in HumID 1.13.0, a live check. The console checks the phone's signatures itself against keys it pinned when the phone was added, so even a taken-over server process can't approve anything.
  - HumID updates come from the repository's releases, checked against GitHub's SHA-256 digest; for a private repository run `humid admin token <read-only token>`.
  - Break-glass: while the server is down, the console can restart it without a phone (logged); `humid admin reset` forgets lost administrator phones.
- The server writes how it's doing to `C:\ProgramData\HumID\server-status.json` every 15 seconds (health and counts only).
- Backups the console makes go to `C:\ProgramData\HumID\backups` (administrators only; the newest 10 are kept).
- The web app it serves is HumID 1.13.0.
- **Installing over 1.5.0** keeps all data and settings, adds the two admin tasks and `HUMID_ADMIN_PORT=8490`. Nothing can be changed from the console until you add your phone.

## 1.5.0

- **Security hardening.** The web app it serves is HumID 1.8.0, and the server checks more:
  - **Approvals sign the action.** Each approval is a single-use, 60-second approval for one action on one device, signed by the phone's secure chip. **Update every phone and computer to HumID 1.8.0**: older apps can sign in and read, but can't approve anything on this server.
  - **Android phones:** both attestation levels must be TEE or StrongBox; Google's revoked-key list is checked every 6 hours (`humid set HUMID_ATTESTATION_STATUS_REQUIRED=1` refuses phones until it has been fetched); `humid set HUMID_ANDROID_MIN_PATCH=202501` sets a minimum security patch. The official HumID app's signing certificate is built in, so test builds signed with another key can't join. An attestation must be under 5 minutes old and enrols one device.
  - **ID chips:** passive authentication now requires one country throughout (the country signing certificate, the document signer and the passport's issuer), a document-signing certificate named by the chip, and the MRZ's overall check digit. A chip that can prove it's present must, at stations too.
  - **Logs** record each request's route (`/links/:code`), never the codes or ids in it.
- No data changes: installing over 1.4.0 keeps all data and settings.

## 1.4.0

- The web app it serves is HumID 1.6.0: setup buttons stay on screen on small phones, the seal card is checked by typing back part of it (and can be printed), and the vault shows what's left to protect a new HumID, with a button for each step.
- No server changes: installing over 1.3.0 keeps all data and settings.

## 1.3.0

- **Split keys**, against spyware that reads a phone's memory during a face or fingerprint check. Every new document also needs its own key, kept by a seventh service, **keyshare** (`data\keyshare`), and released one document at a time inside the same live check that opens it. Copied account keys open nothing on their own. See docs/SECURITY.md, "A compromised phone".
- `humid set HUMID_SHARE_RELEASES_PER_HOUR=120` caps how many documents one account can open per hour.
- The web app it serves is HumID 1.5.0.
- **Back up `data\keyshare` with the vault** (`humid backup` includes it): without it, split documents can't be opened. On one PC both halves sit on the same disk; the Docker deployment can keep them apart.
- Documents sealed before this version keep opening as before; they aren't split.

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
