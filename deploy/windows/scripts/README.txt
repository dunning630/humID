HumID Server for Windows __HUMID_SERVER_VERSION__
=================================================

Runs the HumID vault server on this Windows 10 or 11 PC: all seven HumID
services in one background task that starts with Windows, even when nobody
is signed in. It listens on this computer only (127.0.0.1). Phones reach it
through a secure tunnel, so you don't open anything on your router.


1. INSTALL  (about 2 minutes)
-----------------------------
  a. Right-click the zip > Properties > tick "Unblock" > OK. Then Extract All.
  b. In the extracted HumID-Server folder, double-click
       Install HumID Server.cmd
     and click Yes when Windows asks for administrator rights.

  It downloads the official Node.js runtime from nodejs.org (checksum
  checked), installs to C:\Program Files\HumID Server, keeps its data in
  C:\ProgramData\HumID, and starts the server. Answer Y when it offers to
  keep the laptop awake while plugged in: a sleeping laptop can't answer
  phones.

  At the end it prints the server's fingerprint and key id. You can see them
  again any time with "humid status". A new install also prints its backup
  key once: write it down (see BACKUPS ARE ENCRYPTED below).


2. GIVE IT A PUBLIC HTTPS ADDRESS  (Tailscale Funnel, free)
-----------------------------------------------------------
  a. Install Tailscale:   winget install --id Tailscale.Tailscale
     (or download from https://tailscale.com/download/windows) and sign in.
  b. Tailscale icon in the taskbar > Preferences > turn on "Run unattended",
     so the address keeps working when nobody is signed in to Windows.
  c. Open Terminal (Admin) and run:
       humid expose tailscale
     If Tailscale shows a link to allow Funnel for your account, open it,
     approve, and the command carries on.

  You get an address like  https://dell-laptop.tail1234.ts.net
  Tailscale provides the certificate. The HumID connection inside it is
  encrypted end to end (HTP/1, post-quantum), so Tailscale only carries
  sealed traffic.

  Your own domain instead (e.g. https://vault.humidsecure.com) works with a
  Cloudflare Tunnel if the domain's DNS is on Cloudflare:
       humid expose cloudflare
  prints the steps.


3. ALLOW IPHONES
----------------
  iPhones prove each Face ID check with Apple App Attest, which needs your
  Apple Developer Team ID (10 letters and digits, Apple Developer > Membership):
       humid set HUMID_IOS_APP_ID=ABCDE12345.app.humid.vault
  Android phones (Android 11 or later) work without extra settings.


4. BUILD THE PHONE APPS FOR THIS SERVER
---------------------------------------
  "humid status" prints two values. On GitHub, in the humID repository:
  Settings > Secrets and variables > Actions > Variables, set
       HUMID_SERVER_URL = your https address from step 2
       HUMID_SERVER_KID = the key id
  then run Actions > Release apps. The apps will talk to this server only.


EVERYDAY COMMANDS  (Terminal (Admin))
-------------------------------------
  humid status            is it running, its address, fingerprint, key id
  humid logs [-Follow]    the server log
  humid restart           restart the background task
  humid show              settings (the secret key is hidden)
  humid set KEY=VALUE     change a setting and restart
  humid backup            stop, write two encrypted files to C:\ProgramData\HumID\backups, start
  humid restore -Path <main file>,<keys file>
  humid backup-key        the backup key, to write down and keep offline
  humid selftest          run the end-to-end self-test against this server
  humid console           open the admin console (see below)

  Settings worth knowing (humid set ...):
    HUMID_DEVICE_POLICY   attested (default): only phones whose secure chip
                          proves every live face or fingerprint check.
                          biometric: also fingerprint / Touch ID desktops.
                          demo: testing only. No setting ever accepts a PIN.
    HUMID_PORT            local port the tunnel forwards to (8480).


THE ADMIN CONSOLE
-----------------
  HumID Admin shows how the server and this computer are doing, and installs
  HumID updates, Windows updates and backups. It's at http://127.0.0.1:8490,
  on this computer only.

  1. In Terminal (Admin):  humid console
     Your browser opens a sign-in link (it works once, for two minutes).
  2. Add your phone: Administrators > Add a phone. In HumID on your phone:
     You > Manage this server, scan the code, approve with your face or
     fingerprint. Compare the admin check on both screens; if it's the same,
     choose "They match".
  3. Every change (an update, a restart, a backup) shows a code. Approve it
     the same way on your phone. Nothing changes until you do.

  For HumID updates from a private GitHub repository, make a fine-grained
  token (that repository only, Contents: read-only), then:
       humid admin token github_pat_...
  Lost your phone?   humid admin reset   then add a new one.


BACKUPS ARE ENCRYPTED
---------------------
  "humid backup" stops the server for a moment and writes two files, both
  encrypted with this server's backup key:
       HumID-backup-<date>-main.humidbak   settings, accounts, sealed documents
       HumID-backup-<date>-keys.humidbak   the key-share data (the second half
                                           of every document key)
  to C:\ProgramData\HumID\backups (or: humid backup -Path D:\some\folder).
  Keep the -keys file somewhere other than the -main file (a different
  drive, or offline): together they open documents, apart they don't.

  The backup key:   humid backup-key
  Write it down and keep it offline, apart from the backups. Anyone with the
  key AND a backup file can read the backup.

  Restore on this server:
       humid restore -Path <main file>,<keys file>
  Restore on a new or rebuilt computer (install first, then):
       humid restore -Path <main file>,<keys file> -BackupKey HBK-XXXX-...
  The current data moves aside to C:\ProgramData\HumID\before-restore-<date>,
  and nothing changes if the key is wrong or a file is damaged. A backup
  .zip from HumID 2.x still restores: humid restore -Path <backup.zip>


SEALED SECRETS
--------------
  The server's own keys (its identity, the log key, the key-share key) are
  sealed with Windows DPAPI: only this Windows installation can open them,
  so a copied data folder or a pulled disk opens nothing. Turn on BitLocker
  with the TPM for the system drive too: then only this machine can.
  "humid status" shows "Secrets  sealed (DPAPI)". HUMID_SEAL=off turns
  sealing off (not recommended).


TRY 3.0 BESIDE A RUNNING SERVER  (a test instance)
--------------------------------------------------
  A test instance has its own folders, data, ports and tasks, and never
  touches the live server. From the unzipped HumID-Server folder, in
  Terminal (Admin):
       .\humid.ps1 install -Instance test -Port 8580 -DevicePolicy biometric
       & "C:\Program Files\HumID Server (test)\humid.cmd" status
       & "C:\Program Files\HumID Server (test)\humid.cmd" selftest
  selftest runs the whole flow (an account, a sealed document, a second
  device, a live check, the log) and says whether it passed. When done:
       & "C:\Program Files\HumID Server (test)\humid.cmd" uninstall -RemoveData
  Plain "humid" keeps meaning the live server. Don't point Tailscale Funnel
  at a test instance: the computer has one Funnel address, and the live
  server uses it.


RUNNING ROLES ON SEPARATE MACHINES
----------------------------------
  The front (edge and gateway), core and keys roles can each run on their
  own machine or VM, with mutual TLS between them: docs/DEPLOY-VMS.md.
  On the front machine:
       humid pki init
       humid pki issue keys -Path C:\transfer\keys     (and/or core)
  On the keys machine, after installing as usual:
       humid pki import -Path C:\transfer\keys
       humid set HUMID_ROLES=keys HUMID_INTERNAL_BIND=<its internal address>
  Then on the front machine:
       humid set HUMID_ROLES=front,core HUMID_KEYS_HOST=<that address>
  Delete the transfer folders: they hold a private key until imported.


UPDATING
--------
  From the admin console: Updates > Update (approved on your phone). It backs
  up first and goes back to the old version by itself if the new one fails.
  Or by hand: unzip the new version and run "Install HumID Server.cmd" again.
  Settings, accounts, documents and the server's identity are kept.


UNINSTALLING
------------
  Run "Uninstall HumID Server.cmd" (or: humid uninstall).
  Data stays in C:\ProgramData\HumID unless you run:  humid uninstall -RemoveData


GOOD TO KNOW
------------
  * The laptop must be on, awake and online for phones to reach the vault.
    After a Windows update restarts it, the server starts again by itself.
  * Back up C:\ProgramData\HumID (humid backup). It holds the server's
    identity: lose it and every app pinned to this server refuses to
    connect. Copy the backup files off this computer, and keep the backup
    key offline.
  * Only administrators and the server itself (LOCAL SERVICE account) can
    read C:\ProgramData\HumID.
  * This is a proof of concept. Don't put real customer data in it before
    the independent security review in docs/SECURITY.md.
