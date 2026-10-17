# HumID Server for Windows

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
