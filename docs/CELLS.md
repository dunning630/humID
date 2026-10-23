# Holder cells: one small VM per HumID holder (server 5.0 preview)

**Status: preview, off by default (`HUMID_CELLS=off`).** Built and tested against an
in-process stand-in for Hyper-V; the Hyper-V driver and the guest image have not yet run on
a real host. Don't turn it on for real data before that and the independent review.

## What it does

Every new HumID gets its own small Hyper-V virtual machine, a **cell**, that holds that
person's sealed documents and nothing else. All of a holder's phones share their one cell:
adding a second phone, or recovering onto a new one, uses the cell they already have.

Today every holder's envelopes sit in one vault database on one disk. With cells:

- A bug that mixed up two holders' requests can't reach across: a cell is bound to one
  account when it is handed out and refuses every other account, forever.
- One holder's storage, load or a corrupted database stays in their cell.
- Capacity grows by adding cells, and later by adding Hyper-V hosts; the gateway doesn't
  care which host a cell is on.

## What moves into a cell, and what stays

| Service | Where | Why |
|---|---|---|
| **vault** (sealed envelopes, encrypted index) | **the holder's cell** | Per holder, and the bulk of the data (up to 250 MB each). |
| keyshare (second half of every split key) | stays on the **keys** role | Split keys only protect if their two halves are on different machines. Putting keyshare in the cell would put both halves in one VM. |
| ledger (access history and the public log) | stays on **core** | The public log is one append-only log for the whole server; cosigners and phones check its consistency. |
| identity, recovery, access, relay | stay on **core** | Shared by design: sign-in routing, anonymous recovery requests, blind passes, mailboxes with no accounts. |
| edge, gateway | stay on **front** | The only thing phones reach. |

## How it works

```
phone ──► edge ──► gateway ──┬──► identity, ledger, recovery, access, relay   (core)
                             ├──► keyshare                                    (keys)
                             └──► vault in this holder's cell  ─ mutual TLS ─► cell VM 10.77.0.x
                                  (shared vault if they have none)
```

### Warm pool

Booting a VM takes tens of seconds, too long to make someone wait at sign-up. The
**cell controller** keeps `HUMID_CELLS_WARM` cells (default 2) booted and unbound. When an
account is created, the gateway takes one from the pool at once and binds it; the controller
then starts another to refill the pool, up to `HUMID_CELLS_MAX` cells in all (default 25).

When the pool is empty (the cap is reached, the host is short of memory, or Hyper-V is down),
sign-up still works: the account uses the shared vault, as every account does today, and
`humid cells status` counts it. Moving such an account into a cell later is a follow-up
(below).

### Who may do what

| Part | Runs as | Can | Cannot |
|---|---|---|---|
| **Cell controller** (`humid-server.mjs cells run`, scheduled task *HumID Cells*) | SYSTEM | Create, start, stop and remove cell VMs; issue each cell's certificate from the server's CA. Its state and the seeds sit in `cells\private` (SYSTEM and Administrators only) | Be reached from the network (it listens on nothing) |
| **Gateway** | LOCAL SERVICE | Take a ready cell from the pool and bind it; mark a closed account's cell for retirement | Create or remove VMs; retire a cell that still holds documents |
| **Cell** (vault in the VM) | `humid` user in the guest | Store and return one holder's envelopes | Serve any other account; take calls from anything but `humid-front` |

- **Sign-up can't exhaust the host.** The gateway only takes cells that already exist; the
  controller alone creates them, never past `HUMID_CELLS_MAX`, and never when the host's free
  memory would fall below `HUMID_CELLS_RESERVE_MB` (default 4096). Each sign-up also costs an
  access pass by default.
- **Binding is one-way.** The gateway's first call to a new cell names its account
  (`POST /internal/cell/bind`). The cell writes that to its own disk and from then on refuses
  any request for another account (`wrong_cell`), even one the gateway signed.
- **Names, not addresses.** Each cell's certificate is issued by the server's own CA to
  `humid-cell-<id>`. The gateway accepts a cell's TLS only under the exact name the pool lists
  for it, so one cell can't answer for another, and an address change can't redirect a holder.
  Key exchange is the same hybrid `X25519MLKEM768` as between the other roles.
- **Retirement needs an empty cell.** When a holder closes their HumID (a live check erases
  their vault first), the gateway marks their cell for retirement. The controller asks the cell
  itself how many documents it holds and removes the VM and its disks only at zero. A gateway
  taken over can't destroy a vault this way.

### The VM

| | |
|---|---|
| Hypervisor | Hyper-V, Generation 2, Secure Boot (Microsoft UEFI CA template) |
| Guest | Debian 13 cloud image (Hyper-V drivers, a shim signed for Secure Boot) with the official Node 22 build (OpenSSL 3.5, for the hybrid key exchange) and the vault bundle. No SSH, no cloud-init, root locked, no console login. The vault runs as its own user under a strict systemd sandbox. Built by `tools/cells/build-image.sh` (Actions › Cell image). |
| Memory | 256 MB at start, dynamic up to 512 MB |
| CPU | 1 virtual processor |
| Disks | OS: a differencing disk on the shared base image (replaced on update) · data: its own dynamic VHDX, up to 1 GB (`HUMID_CELLS_DISK_MB`) · seed: a small disk with the cell's settings and certificate, detached and deleted once the cell is up |
| Network | Internal switch `HumID-Cells` only: the host is 10.77.0.1, cells 10.77.0.10 upward. No route to the internet or your LAN, no forwarding on the host. The guest firewall accepts port 8502 from 10.77.0.1 only and starts no outbound connection; the host's firewall takes nothing inbound from cells. |
| Checkpoints | Off. A checkpoint would copy what a later deletion is meant to destroy. |

On a 32 GB machine with the 4 GB reserve, about 50 cells fit at their 512 MB ceiling;
idle cells use far less.

### Updating

The OS disk carries no data. To update the vault code, the controller builds the new base
image's differencing disk for each cell in turn, stops the cell, swaps the OS disk, and starts
it again. The data disk and the cell's binding stay. (Rolling update is part of the follow-up
work; this preview creates new cells from the current base image only.)

## Turning it on (Windows, Terminal as Administrator)

```
humid pki init                                   # once, if this server has no CA yet
humid cells image -Path C:\path\humid-cell.vhdx  # the base image (built by CI: Actions › Cell image)
humid cells enable                               # Hyper-V check, the internal switch, the HumID Cells task
humid set HUMID_CELLS=hyperv
humid cells status
```

Hyper-V needs Windows 10/11 Pro, Enterprise or Education with virtualisation on in the
firmware (`humid cells enable` checks both and says what's missing).

## Settings

| Setting | Default | |
|---|---|---|
| `HUMID_CELLS` | `off` | `hyperv` = new HumIDs get a cell · `off` = everyone uses the shared vault |
| `HUMID_CELLS_WARM` | `2` | Cells kept booted and unbound, ready for the next sign-ups |
| `HUMID_CELLS_MAX` | `25` | Cells in all, bound and warm |
| `HUMID_CELLS_RESERVE_MB` | `4096` | Free memory the host keeps; no new cell below it |
| `HUMID_CELLS_DISK_MB` | `1024` | Each cell's data disk (the vault quota plus room for its database) |
| `HUMID_CELLS_IMAGE` | `<root>\cells\base\humid-cell.vhdx` | Base image (set by `humid cells image`) |

## Not done yet

- **Backups of cells.** `humid backup` covers the shared vault but not cell data disks yet.
  Until it does, don't put real data in a cell.
- **Moving an account between the shared vault and a cell**, and between hosts.
- **Rolling update** of running cells to a new base image.
- **More than one Hyper-V host.** The pool format already carries each cell's address; the
  controller manages only the machine it runs on.
- **Encryption inside the guest.** The data disk relies on the host's BitLocker. LUKS with a
  key held by the controller is the next step, so a copied VHDX alone opens nothing.
- **Running on real Hyper-V and building the image in CI.** Neither has run yet.
