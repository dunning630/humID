# Running HumID on VMs and shared storage (server 3.0)

HumID's promise doesn't depend on the hardware: documents are sealed on the person's phone to keys that never leave it, so no server, disk or hypervisor alone opens a vault. What the hardware can still reach is everything else the server holds (its identity key, its log-signing key, the key-share service's master key, metadata) and the traffic between its parts. Server 3.0 limits what each piece of hardware holds, encrypts what it keeps, and authenticates every hop. This guide is how to lay it out.

Design and threat model: the "HumID Server 3.0 — VM deployment design spec" doc. Security model: [SECURITY.md](SECURITY.md).

## The three roles

| Role | Runs | Holds | Reached by |
|---|---|---|---|
| **front** | the edge (TLS to phones, the web app) and the gateway | the server's HTP identity key (its kid), the internal signing key | phones, through a tunnel or a reverse proxy |
| **core** | identity, vault, ledger, recovery, access | sealed envelopes, the encrypted index, the log and its signing key, recovery records, pass issuer keys | the gateway only, mutual TLS |
| **keys** | keyshare | the second half of every split document key, sealed under its master key | the gateway only, mutual TLS |

`HUMID_ROLES` picks what a machine runs (default: all three, as on one PC). Keeping **keys** on its own VM and storage is what makes a copied phone useless: the document keys it would need live somewhere else, released only on a live check.

## Reference layout

| VM | Role | vCPU / RAM | Storage | Network |
|---|---|---|---|---|
| `humid-front` | front | 2 / 4 GB | 20 GB system, no data of note | DMZ VLAN: 443 in (or a tunnel out); to core 8501–8505 and keys 8506 only |
| `humid-core` | core | 4 / 8 GB | pool **A**: the vault (≈ 250 MB per account at the default quota) | internal VLAN: from front only |
| `humid-keys` | keys | 2 / 2 GB | pool **B**, a different array or host from pool A | keys VLAN: from front only |
| backups | — | — | pool **C**, off the cluster (NAS, tape, cloud bucket) | management VLAN |

Firewall, deny by default:

| From | To | Ports | Why |
|---|---|---|---|
| internet / tunnel | front | 443 (or none, with an outbound tunnel) | phones |
| front | core | 8501–8505 (`HUMID_INTERNAL_PORT_BASE` + 1…5) | gateway → identity, vault, ledger, recovery, access |
| front | keys | 8506 (base + 6) | gateway → keyshare |
| management | each VM | RDP/SSH from a jump host only | administration |
| anything else | anything | — | refused |

Core and keys never call each other or the internet. Front never stores documents.

## What each layer must do

1. **Disks encrypted.** BitLocker with the TPM protector on Windows VMs (a vTPM per VM), LUKS with a TPM2 or network-bound key on Linux, or self-encrypting drives on the arrays. A pulled drive must be noise.
2. **Secrets sealed.** HumID seals its own secrets under a seal key the machine protects: DPAPI on Windows (with BitLocker's TPM protector, only that VM opens it), a TPM2-encrypted systemd credential on Linux (below). `humid status` shows "Secrets sealed".
3. **Mutual TLS between roles.** Each role has a certificate from the server's own CA (`humid pki`). Core and keys admit only `humid-front`; the gateway admits only the role it meant to reach. Names are checked, not addresses. The key exchange is the hybrid X25519 + ML-KEM-768 group only (`X25519MLKEM768`), so a recording of the links between machines (split-key shares, anchor parts, ID-chip fields) can't be opened later by a quantum computer; a role that can't do it is refused, and a machine whose Node lacks it (OpenSSL older than 3.5) won't start a split role. The certificates are still Ed25519: forging one needs a quantum computer at the time of the connection, not later.
4. **Statement keys apart from the gateway.** The core role's statement key (identity and ledger) and the keys role's (keyshare) let them vouch for what the gateway can't make up: which device keys an account has, what the ledger recorded, what Check-in erased. `humid pki issue core|keys` carries each to its own machine (sealed on import); the front keeps only the public halves, so the gateway's internal key alone releases and deletes nothing (SRV-30). After a split, clear the moved private key on the front (`humid` warns at start-up while one is still there).
5. **Every internal request bound and single-use.** The gateway's assertion names the service, method, path, query and body hash, and each service accepts its id once (SEC-S-01, fixed in 3.0).
6. **No snapshots of `humid-keys`.** A snapshot copies the document keys that Heartbeat and deletion are meant to destroy. Exclude the VM from snapshot schedules and replication; back it up with `humid backup` instead.
7. **Backups encrypted, and apart.** `humid backup` writes a backup file and keyshare's half (`HumID-keyshare-….humidbak`), both encrypted to the backup key (`humid backup-key new -Path E:\humid-backup.key`: its private key goes only to that file, and the server can't open its own backups). Store the two files in different places, and the backup key file offline, apart from both.
8. **Hypervisor access minimal.** Whoever controls the hypervisor can read VM memory. Few administrators, hardware-key sign-in, management on its own network. Where the CPUs support it, run front and keys as confidential VMs (AMD SEV-SNP or Intel TDX) so the hypervisor can't read their memory either.
8. **Physical access logged.** A locked rack or cage, access logged, cameras on the room.

## Setting it up (Windows VMs)

On each VM, install HumID Server for Windows as usual (`humid install`, Terminal as Administrator). Then:

On **humid-front**:

```
humid pki init
humid pki issue core -Path C:\transfer\core
humid pki issue keys -Path C:\transfer\keys
```

Carry each folder to its VM (it holds that role's private key until it is imported), then on **humid-core** and **humid-keys** respectively:

```
humid pki import -Path C:\transfer\core          (or \keys on humid-keys)
humid set HUMID_ROLES=core HUMID_INTERNAL_BIND=10.0.1.12      (the VM's internal address)
```

```
humid set HUMID_ROLES=keys HUMID_INTERNAL_BIND=10.0.2.20
```

Delete the transfer folders. Back on **humid-front**:

```
humid set HUMID_ROLES=front HUMID_CORE_HOST=10.0.1.12 HUMID_KEYS_HOST=10.0.2.20
humid status
humid selftest
```

`humid status` on each VM shows its roles, whether its secrets are sealed, and (on core and keys) the addresses it listens on. Certificates last about two years (`humid pki status` shows the days left); issue and import new ones before then.

To split an existing single-PC install, run the steps above on the PC as front, then move the key-share data: `humid backup` on the PC, restore keyshare's half alone on humid-keys with `humid restore -KeysharePath <HumID-keyshare-….humidbak> -Key <backup key file>`, and only then set the PC's roles to `front,core`.

## Setting it up (Linux VMs)

The same program runs on Linux (it is what the test suite runs). With the HumID Server package unzipped to `/opt/humid` and Node.js 22:

```
# a seal key, encrypted to this VM's TPM, readable only by systemd for this service
head -c 32 /dev/urandom | systemd-creds encrypt --with-key=tpm2 --name=seal - /etc/humid/seal.cred
```

`/etc/systemd/system/humid.service`:

```
[Unit]
Description=HumID server
After=network-online.target

[Service]
User=humid
Environment=HUMID_SEAL=file
Environment=HUMID_SEAL_KEY_FILE=%d/seal
LoadCredentialEncrypted=seal:/etc/humid/seal.cred
ExecStart=/usr/bin/node /opt/humid/humid-server.mjs run --service --root /var/lib/humid
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/humid
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Then `node /opt/humid/humid-server.mjs init --root /var/lib/humid` (with the same two environment variables), the `pki` commands as above (`pki issue keys --out DIR`, `pki import --from DIR`), and `set` for the roles. The seal key never sits on disk in the clear: systemd decrypts it with the TPM into a private in-memory file for the service only.

## Patching and restarts

- Patch one VM at a time. Core and keys restarts interrupt service for seconds; the app retries.
- **Heartbeat:** while anyone has Heartbeat armed, restarting the **keys** VM erases their vault, because its fuse keys live only in memory (docs/CHECKIN.md). `HUMID_CHECKIN` stays `off` until reminders exist; if it's on, `humid` asks for a typed ERASE before anything that stops keys.
- Updating: update all three VMs to the same version together. A 3.0 service refuses the unbound assertions of an older gateway, so mixed versions don't talk.

## Trying it on one Windows machine

A test instance installs beside a live server with its own folder, data, ports and tasks, and never touches the live one:

```
.\humid.ps1 install -Instance test -Port 8580 -DevicePolicy biometric
& "C:\Program Files\HumID Server (test)\humid.cmd" status
& "C:\Program Files\HumID Server (test)\humid.cmd" selftest
```

`selftest` runs the whole flow (account, seal, second device, open with a live check, log, close) against the test instance. The split can be tried on the same machine with a second instance as the keys role (`-Instance keys`, `pki issue keys` from the test instance, `pki import` in the keys instance, `HUMID_INTERNAL_BIND=127.0.0.1`). Remove them with `uninstall -RemoveData` from each instance's own `humid.cmd`.

## Limits of this release

- Each role is one process: this layout separates and protects, it does not yet scale out. One front holds up to 50,000 sessions; more needs the shared-session work (next).
- One server per CA. Dedicated servers per organisation each have their own CA, keys and kid, and today's apps are built for one server; joining a server by scanning its setup QR code is the planned way past that.
- The hypervisor can read memory unless the VMs are confidential. HumID doesn't detect a hostile hypervisor.
