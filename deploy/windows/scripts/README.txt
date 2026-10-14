HumID Server for Windows __HUMID_SERVER_VERSION__
=================================================

Runs the HumID vault server on this Windows 10 or 11 PC: all five HumID
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
  again any time with "humid status".


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
  humid backup            stop, copy everything to Documents\HumID-backup-<date>.zip, start
  humid restore -Path <zip>

  Settings worth knowing (humid set ...):
    HUMID_DEVICE_POLICY   attested (default): only phones whose secure chip
                          proves every live face or fingerprint check.
                          biometric: also fingerprint / Touch ID desktops.
                          demo: testing only. No setting ever accepts a PIN.
    HUMID_PORT            local port the tunnel forwards to (8480).


UPDATING
--------
  Unzip the new version and run "Install HumID Server.cmd" again.
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
    connect. The backup holds keys, so keep it offline.
  * Only administrators and the server itself (LOCAL SERVICE account) can
    read C:\ProgramData\HumID.
  * This is a proof of concept. Don't put real customer data in it before
    the independent security review in docs/SECURITY.md.
