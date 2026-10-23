# HumID Server for Windows

## Unreleased

- **One visitor can't lock everyone out behind Tailscale Funnel** (V76-03). With `HUMID_TRUST_FORWARDED=off` every visitor shares the tunnel's address, so the 30-a-minute handshake limit was one bucket for all. Now an unknown address shares a server-wide ceiling (`HUMID_SHARED_HELLO_PER_MIN`, 600), failed sign-ins count per HumID and server-wide, and a holder who signed in before carries a one-use hello pass past every handshake limit, so unlocking and checking in always get through (README, *Rate limits behind a tunnel*).
- **Revocation fails closed** (PC-14 / LIVE-02). New installs get `HUMID_ATTESTATION_STATUS_REQUIRED=1`: with the attested policy an Android phone is refused while Google's revoked-key list hasn't been fetched or is over 48 hours old, instead of being let in unchecked. The server needs outbound HTTPS to `android.googleapis.com` (a PC with internet has it; on split roles, the core machine: docs/DEPLOY-VMS.md). An existing install keeps the `0` it was given: `humid set HUMID_ATTESTATION_STATUS_REQUIRED=1` to switch.
- **The live-human posture at every start** (LIVE-04). Identity logs one line with the device policy, locked-boot rule, app signer rule, App Attest environment and revocation state, as a warning naming each setting that weakens it. `HUMID_ANDROID_ALLOW_ANY_SIGNER=1` (test servers only) is now listed in `humid.env` and refused with the attested policy unless `HUMID_INSECURE_TEST=1` is set too.

- **Rate limits can't be dodged with a made-up address** (SRV-31). The edge used to believe `CF-Connecting-IP` or `X-Forwarded-For` from whatever came through the tunnel; behind Tailscale Funnel nothing overwrites them, so a visitor could name a new address on every request and reset every per-address limit. A new setting, `HUMID_TRUST_FORWARDED`, says which header to believe: `humid expose cloudflare` sets `cloudflare` (Cloudflare's edge overwrites `CF-Connecting-IP`), `humid expose tailscale` and `none` set `off`. With `off`, the default, all visitors through the tunnel share one address for the limits. An install that already uses Cloudflare Tunnel: run `humid set HUMID_TRUST_FORWARDED=cloudflare` (or `humid expose cloudflare` again).

## 3.2.0 (preview, non-production)

Paired with **HumID 4.1 preview**. Installing over 3.1.0 keeps all data, settings and the server's identity, and changes nothing until you turn messaging on.

- **Person to person, off by default.** `humid set HUMID_MESSAGING=on` starts the messaging relay beside the other services (data in `data\relay`, internal port base+7 on split roles) and the app shows Messages. Every contact request, approval and message needs a live check, and messages open only within 5 minutes of the reader's own check (docs/MESSAGING.md). Keep it off on anything holding real data until the independent review.
- The relay keeps fixed-size ciphertext in random, daily-rotating mailboxes for at most 14 days. It stores no account and no address, and is reached only from app sessions that never sign in. Each network (an IPv4 address or an IPv6 /48) may deposit 48 MiB a day.
- The access service gains a separate key for live stamps (never the pass key) and keeps only per-day totals.

## 3.1.0

Server 3.0 (sealed secrets, split roles, test instances, `humid selftest`) with the pre-certification audit's Windows fixes on top. 3.0.0 was never released on its own; both are in this release. Installing over 2.1.0 keeps all data, settings and the server's identity.

From 3.0:

- **Secrets sealed at rest.** Every server secret (the server's identity keys, the log key, keyshare's `share-key.bin`, the recovery anchor secret, the access issuer keys, the internal key in `humid.env`, the role certificates' keys) is sealed under a seal key kept as a DPAPI machine blob (`keys\seal.dpapi`): a copied data folder or a pulled disk opens nothing. Secrets kept in plain by 2.x are sealed in place; the key id doesn't change. `humid status` shows *Secrets sealed (DPAPI)*; `humid-server.mjs seal-status` lists them.
- **Roles on separate machines** (front, core, keys) with mutual TLS between them: `humid pki init | issue | import | status`, `HUMID_ROLES` (docs/DEPLOY-VMS.md).
- **Test instances** beside the live server (`install -Instance test`), each with its own folders, data, ports and tasks; **`humid selftest`** runs the end-to-end flow against this server.
- Windows PowerShell 5.1 started from PowerShell 7 can load its own built-in commands again.

The audit's fixes:

- **Updates must be signed by the HumID release key** (PC-07). The admin console installs a HumID update only if its zip carries a signature (`.sig`) by an ML-DSA-87 key the maintainer keeps offline and the console pins, for exactly that file name and version; GitHub's digest is checked as well. The update job checks the signature again, as SYSTEM, right before it unpacks the zip. Pre-releases are skipped unless `humid set HUMID_UPDATE_PRERELEASES=on`. A release can only be built once the maintainer has pinned the release key (RELEASING.md); a build without one (such as a CI artifact) refuses every update.
- **The server's account can no longer redirect SYSTEM** (PC-09). LOCAL SERVICE used to have Modify on all of `C:\ProgramData\HumID`, including the folders the SYSTEM console and its jobs read, write and unpack into, so it could plant a junction there. Now it reads the data root but writes only `data\<service>`, `logs\`, its two status files and new files in `data\admin\approvals`. The console won't read approvals through a junction or symbolic link, jobs check every folder they use, and a restore unpacks into a new folder only SYSTEM and Administrators can open before it's swapped in. Installing applies the new permissions, makes Administrators the owner of what SYSTEM uses, and removes any junction or symbolic link under the data root (the link only). The console's log moves to `admin\logs\humid-admin.log`. Because the server can't change `humid.env`, the installer (and a restore) seals its internal key there.
- **Backups the server can't open, keyshare's half kept apart** (PC-10). 2.x wrote one plain zip of everything, both halves of every split key included; 3.0 test builds encrypted backups but kept the key that opens them on the server (DPAPI-sealed in `backup-key\`). Now every backup is encrypted to a **backup key**: `humid backup-key new -Path E:\humid-backup.key` writes its private key to a file you keep off the computer (never inside the data or program folders; no passphrase), and the server keeps only the public key. Installing 3.1 removes 3.0's on-server backup key. Keyshare's data (`share-key.bin` and its database) goes to a separate file (`humid backup -KeysharePath`, and `humid backup-key keyshare D:\HumID-keyshare` for the console's copies); the console and `humid backup` warn while both are on one disk. The server's seal key travels only inside the encrypted files, so `humid restore -Path <backup> -KeysharePath <keyshare file> -Key <key file>` brings the same server back on a new computer (sealed again under its DPAPI). A refused restore (wrong key, mismatched or changed files) changes nothing; otherwise the current data moves to `before-restore-<date>`, and the opened backup never stays behind. `-KeysharePath` with `-Key` alone restores keyshare's half on a keys machine. **Until you make a backup key, backups wait**: the console says *Backups aren't encrypted: set up a backup key*. Updates and rollbacks keep working: they take a local rollback copy in `admin\` (administrators only), deleted once the update has worked (docs/ADMIN.md, *Backups*). Old `.zip` backups still restore; 3.0 test builds' `-main`/`-keys` backups don't (make a new one after installing).

## 2.1.0

Security hardening from the October 18 2026 audit, paired with **HumID 2.1.0**. Installing over 2.0.0 keeps all data and settings.

- **A malformed request can no longer stop the server.** A request such as `GET //` used to exit a service, and on Windows all services share one process. A bad request line now gets a 400, and an unexpected error in one request is a 500 for that request only.
- **Size limits before sign-in.** An anonymous request is limited to 512 KiB (`GATEWAY_MAX_ANON_CALL_BYTES`); only a signed-in session can send up to `GATEWAY_MAX_CALL_BYTES` (64 MiB, for vault uploads). Each address can have 16 uploads in flight and the server 1,024.
- **Sign-in attempts and Check-in.** Only failed proofs count toward the limits (10 per account, 20 per address, 200 for the server, per 5 minutes); a valid proof from the real holder always signs in. A refused sign-in can never erase an armed vault (docs/CHECKIN.md).
- Recovery, identity and ledger answer 400 to a JSON body that isn't an object (it used to be 500).
- The web app it serves is **HumID 2.1.0**: the camera opens only after you choose what you're adding; a faster scanner that says what it is doing; a passport chip that fails its check is no longer treated as verified; a crafted passport name line can no longer freeze the app. A document's Sealed time now comes from this server's clock, not the phone's.
- **Compatibility.** Apps 1.8.0 and later keep working with this server.
- Not changed here: the audit's larger design findings are listed in docs/HARDENING.md.

## 2.0.0

Paired with **HumID 2.0.0**, the apps' new layout (Vault · Activity · You). 1.6.0 and 1.7.0 were never released on their own; both are in this release.

- **HumID Admin, the admin console** (docs/ADMIN.md). A second background task, run as SYSTEM, at `http://127.0.0.1:8490` on this computer only. Open it with `humid console` in Terminal (Admin): a sign-in link that works once.
  - **Watches** the server (every service, response times, errors, sessions), the public address and its certificate, CPU, memory, drives, Microsoft Defender, Windows Firewall, BitLocker, pending restarts, backups, and new HumID and Windows updates.
  - **Changes** (update HumID with automatic rollback, roll back, install Windows updates, update Defender, back up, restart the server or the computer) **each wait for an administrator's phone**: a code on the console, then **You ▸ Manage this server** in HumID 2.0 and a face or fingerprint check. The console checks the phone's signatures itself against keys it pinned when the phone was added, so even a taken-over server process can't approve anything.
  - HumID updates come from the repository's releases, checked against GitHub's SHA-256 digest; for a private repository run `humid admin token <read-only token>`.
  - Break-glass: while the server is down, the console can restart it without a phone (logged); `humid admin reset` forgets lost administrator phones.
  - The server writes how it's doing to `C:\ProgramData\HumID\server-status.json` every 15 seconds (health and counts only). Backups the console makes go to `C:\ProgramData\HumID\backups` (administrators only; the newest 10 are kept).
- **Check-in** (docs/CHECKIN.md), **off by default**: `humid set HUMID_CHECKIN=on` lets holders arm a timer (You ▸ Check-in) that erases their vault for good unless they check in every hour or two. The keys of an armed vault live in the server's memory only, so anything that stops the server (a restart, an update, a backup, restarting Windows) erases every armed vault.
  - The admin console says how many vaults are armed on every change that stops the server, before you approve it; `server-status.json` carries the count (a number, nothing more).
  - So do the `humid` commands that stop the server (`stop`, `restart`, `set`, `backup`, `restore`, `expose`, `uninstall`, and `install` over an existing install): with vaults armed they go on only once you type ERASE (`-Quiet` goes on after the warning). `humid status` shows the count while Check-in is on.
- The web app it serves is **HumID 2.0.0**.
- **Compatibility.** Apps 1.8.0 and later keep working with this server. Manage this server and Check-in need HumID 2.0.0.
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
