HumID Server for Linux __HUMID_SERVER_VERSION__
=============================================

The HumID vault server on one Linux machine: the seven HumID services and a local edge in one
systemd service that starts at boot. It listens on 127.0.0.1 only; phones reach it through a
secure tunnel, so nothing on your router or firewall needs to change. The same server as
HumID Server for Windows, so backups move between the two.

Needs: x86_64 or arm64, systemd, curl, tar and xz. Ubuntu 24.04 or Debian 12 or later is
best (systemd 250+ seals the server's key with the machine's TPM). 1 GB of RAM is plenty
for a pilot.


1. INSTALL  (about 2 minutes)
-----------------------------
    tar -xzf HumID-Server-Linux-__HUMID_SERVER_VERSION__.tar.gz
    cd humid-server
    sudo ./bin/humid install

  It downloads the official Node.js 22 runtime from nodejs.org (checksum checked), installs
  to /opt/humid, keeps its data in /var/lib/humid (readable only by the "humid" system user),
  makes the seal key (sealed to the TPM where there is one), and starts the service.
  Options: --policy attested|biometric|demo  --apple-team-id ABCDE12345  --port 8480

  At the end it prints the server's key id. See it again any time: sudo humid status


2. GIVE IT A PUBLIC HTTPS ADDRESS  (Tailscale Funnel, free)
-----------------------------------------------------------
    curl -fsSL https://tailscale.com/install.sh | sh
    sudo tailscale up
    sudo humid expose tailscale

  You get an address like https://webserver1.tail1234.ts.net. If Tailscale shows a link to
  allow Funnel for your tailnet, open it, approve, and run the last command again.


3. THE BACKUP KEY  (once, onto a USB drive)
-------------------------------------------
    sudo humid backup-key new /media/<usb>/humid-backup.key

  Its private key goes only to that file; this machine keeps only the public key, so it can
  make backups but never open them. Keep the file, and a second copy, off this machine.
    sudo humid backup [/some/folder]     two encrypted files: the backup and keyshare's half
                                         (put keyshare's half on a different disk)
    sudo humid restore <backup> <keyshare> <key file>
  A backup from HumID Server for Windows restores here too, with the same server identity.


4. POINT THE APPS AT IT
-----------------------
  "sudo humid status" prints the public address and the key id. On GitHub, in the humID
  repository, Settings > Secrets and variables > Actions > Variables:
       HUMID_SERVER_URL = the public address
       HUMID_SERVER_KID = the key id
  then Actions > Release apps. The apps will talk to this server only.


EVERYDAY COMMANDS
-----------------
  sudo humid status | start | stop | restart | logs [-f]
  sudo humid set KEY=VALUE ...      change a setting and restart (settings: README.md in deploy/)
  sudo humid show                   settings (secret keys hidden)
  sudo humid mint 50 [batch]        access codes to sell
  sudo humid selftest               the end-to-end self-test against this server
  sudo humid uninstall [--remove-data]

  iPhones:  sudo humid set HUMID_IOS_APP_ID=ABCDE12345.app.humid.vault
  No admin console on Linux: update by unpacking a newer package and running
  sudo ./bin/humid install again (data, settings and the server's identity are kept).

Proof of concept: don't store real customer data before the independent security review.
