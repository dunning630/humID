# Check-in: erase the vault unless you check in

Before a high-stakes situation (a border crossing, a protest, a hostile
negotiation, travel where your phone may be taken), turn on **Check-in**.
While it's on, you check in with a live face or fingerprint check before each
deadline. Miss one and your vault **locks**: it opens nothing until you check
in. Miss the grace period too, or unlock with your duress gesture, and your
vault is **erased for good**: the keys to its documents are destroyed, so
nobody can open them again. Not you, not your witnesses, not HumID.

This first version erases **vault data only**: your HumID, its devices and its
recovery stay, so you come back to an empty vault (plus your decoy documents)
without setting up again. Closing the whole HumID on a missed check-in is a
possible later setting.

The server must offer it (`HUMID_CHECKIN=on`). It's **off by default** until
HumID can send push reminders; until then the app can only warn you while
it's open, so set an alarm for each check-in.

## Using it

You ▸ **Check-in** ▸ Set up:

| Setting | Choices | Default |
|---|---|---|
| Check in every | 1, 2, 4, 8 or 24 hours | 2 hours |
| Longest single window | up to 24 hours: when you check in you can choose a longer next window (say, for the night), up to this | 8 hours |
| Grace after a missed check-in | none, 15, 30 or 60 minutes: the vault is locked meanwhile; checking in opens it again | 15 minutes |

One live check turns it on. Then every tab shows when the next check-in is
due, with a **Check in** button (amber in the last half hour, red once missed);
the lock screen never shows it, since anyone holding the phone would see it.
The app warns you 30, 10 and 2 minutes before a deadline while it's open.
Changing the settings is a live check too, and counts as a check-in. Turning
it off is a live check.

What else changes while it's on:

- **Your duress gesture erases at once.** Unlock with it and the vault is
  erased the moment the unlock reaches the server, with no grace (right after
  the server answers, so the answer looks and takes the same as an ordinary
  unlock). The duress session looks like Check-in is on and working: checking
  in "works", the timer moves, and your decoy documents open.
- **Decoy documents stay.** Documents marked *Show in decoy view* when you turn
  Check-in on (or change its settings) are kept out of the erase, so a forced
  unlock still shows a lived-in vault.
- **Nothing is kept on the phone.** The offline copy is deleted and none is
  written, so a phone held offline (in a Faraday bag, say) shows nothing, and
  HumID doesn't open offline. Your other devices drop their copies the next
  time they connect: until then, one kept offline still shows its old list of
  names (never a document).
- **Every document must be split.** Documents sealed before split keys (apps
  before 1.5.0) have no second key on the server, so erasing them couldn't be
  final. Check-in refuses until you re-seal them (save a copy, add it again,
  delete the old one) or delete them.

After an erase, Activity shows **Vault erased by Check-in**, with no reason
(a missed deadline and a duress signal look the same), and the Vault says what
happened for a week.

## How it works

Split keys make this possible. Every split document is encrypted under its own
256-bit key that only the keyshare service holds (docs/SECURITY.md). Deleting
files from a server doesn't make them gone (backups, replicas, snapshots and
SSD wear-levelling keep copies); destroying the keys does. NIST SP 800-88 calls
this cryptographic erase.

```
                       keyshare (in memory only)
                       ┌──────────────────────────┐
  arm (live check) ──► │ fuse key F (per account) │──► every split key re-sealed under
                       │ deadline, grace          │    HKDF(share-key ‖ F, account)
  check in ─────────►  │ next deadline (monotonic │
  (live check)         │ clock)                   │
                       └────────────┬─────────────┘
              deadline passes │ locked: no key released (423 checkin_missed)
          + grace, duress, or │
          a keyshare restart  ▼
                       F destroyed ──► every copy of those keys, live or in any backup
                                       made since arming, is unreadable
                              │
              gateway sweep   ▼  (every 10 s; retried until done)
          vault drops the envelopes and index entries (keeping decoys and anything
          sealed since), then the ledger records checkin.erased
```

- **keyshare holds the clock.** The countdown runs inside keyshare on the
  monotonic clock, so stopping the gateway or changing the wall clock can't
  stretch it. Deadlines are settled on every request and every second.
- **The fuse key lives in memory only.** It's never written to disk or to a
  backup. That's what makes a backup of keyshare (database and `share-key.bin`
  together) useless for an armed account. The cost: **a restart of keyshare
  erases every armed vault** (fail-deadly). Updating, backing up or restarting
  the server, or restarting the computer, counts. On Windows, the admin console
  says how many vaults are armed before you approve any change that stops the
  server, and the `humid` commands that stop it (`stop`, `restart`, `set`,
  `backup`, `restore`, `expose`, an update, `uninstall`) go on only once you
  type ERASE.
- **The erase never waits.** Normal deletes are written to the ledger first
  and refused if it's down. An erase can't be: a ledger outage (or an attacker
  who causes one) would stop it. The keys go first; the vault and the ledger
  catch up on the next sweep. The ledger gets exactly one `checkin.erased` per
  erase, with the number of keys destroyed, however many sweeps it takes; the
  sweep never removes a document uploaded after the erase.
- **A sign-in lockout can't cause an erase, and can't keep you from checking
  in.** Only three things destroy a fuse key: a missed deadline plus grace
  inside keyshare, a duress sign-in, and a restart of keyshare. A refused
  sign-in is none of them. Sign-in throttling counts failed proofs only and
  never refuses a request before its proof is checked, so someone who knows
  your account id (it isn't secret) cannot use up your allowance: your valid
  sign-in always works, and a check-in needs nothing but that sign-in.
- **No heartbeat in the public log.** The ledger records `checkin.armed`,
  `checkin.disarmed` and `checkin.erased`, never a check-in: an hourly entry in
  the public transparency log would tell anyone watching that an account is
  armed.
- **A duress session looks the same.** Every unlock asks keyshare where
  Check-in stands, so a duress unlock takes the same time and returns the same
  answer; the erase runs after the reply. The duress session is shown a copy of
  Check-in as it was, which its own check-ins move.

### Routes

| Route (inside HTP/1) | Step-up | What |
|---|---|---|
| `GET /checkin` | no | `{ state: off \| armed \| locked \| erased, deadline, erasesAt, windowMs, maxWindowMs, graceMs, armedAt, erasedAt }` |
| `POST /checkin/arm` | yes | `{ windowMs, maxWindowMs, graceMs, keep: [decoy ids] }`; 409 `unsplit_items` lists documents to re-seal first |
| `POST /checkin/check` | yes | `{ nextWindowMs? }` (up to the maximum) |
| `POST /checkin/disarm` | yes | every key back under the service key |

The server's policy hint carries `checkin: { windowsH, graceMin }` when it's on;
apps hide Check-in when it's absent.

## What it doesn't do (yet)

- **It's a server rule.** Whoever runs the server (you, if you host it; HumID
  for hosted accounts) could change keyshare to keep fuse keys. A later option:
  split each fuse key with an independent cosigner (like the public log's), so
  the data dies if either side forgets its half.
- **Backups made before you armed.** They hold the keys of documents sealed
  before arming, under the service key alone. A backup made since arming is
  useless; one made before isn't. Arm well before you need it, and keep
  backups short-lived.
- **Item names in vault backups.** Names, types and categories are in each
  document's index entry, sealed under a key from the account seed. Erased
  entries are overwritten in the live database, but a vault backup plus your
  recovered account seed (two of your three recovery proofs) would still show
  the names of erased documents, never their contents.
- **What already left.** Copies saved or exported from the viewer, screenshots.
- **A server seized while running**, before the deadline, could have its
  memory read. An HSM narrows this.
- **Losing your phone means losing the vault**, unless another of your phones
  can check in: recovery takes 24 hours to 7 days and can't beat a deadline.
- **Accidents are permanent:** a dead battery, no signal, sleeping through a
  window, a server restart. Warnings, the grace period and the night window
  reduce the risk; nothing undoes an erase.
- **No push reminders yet.** Until they exist, servers keep it off by default.
- **The law.** Erasing data an operator has been asked to preserve (a legal
  hold or a preservation request) is a question for counsel before launch.
- **Not in the simulation build.** Its in-app server doesn't offer Check-in.

## Settings

| Variable | Default | |
|---|---|---|
| `HUMID_CHECKIN` | `off` | `on` offers Check-in. The gateway reads it; keyshare always supports it. Local development (`npm run dev`) turns it on. |
