# HumID 5.0 server — design

Status: **draft for review, 23 October 2026.** Branch `v5-server`. Code: [`server/humid-server`](../../server/humid-server).
Inputs: [V5.md](../V5.md) ("Servers and trust", "Recovery", "Messaging", "The live check"), the 5.0 server
audit (findings H1, H2, M1–M5, L1–L10, the 9 → 4 unit plan, unbounded tables, phone battery), the independent
verification of that audit, the messaging/relay audit (H-2, H-3, M-5, M-10), and the 4.x services in `services/*`
for behaviour. Crypto: [`crates/humid-pq2`](../../crates/humid-pq2) ([PQ2.md](PQ2.md)), used by path.

Owner decisions this design follows: Rust; a clean break from 4.x (fresh schemas, no migrations from 4.x, no 4.x
compatibility routes); four units — **front**, **core**, **keys**, **anon**; the owner's own Linux hardware at two
sites with a live standby (the Windows box behind Tailscale Funnel is temporary and dev/pilot only).

The one rule everything below serves:

> **Every unit verifies the holder's own live proof itself. Nothing happens on another unit's word that the holder
> could have signed for.** Where a unit must rely on another unit (keys on core for "this device is still enrolled
> and this open was logged"), it relies on a *signed statement* from that unit's HSM key, never on the network
> position of the caller.

---

## 1. Units and what each owns

```
                internet (TLS 1.3, X25519MLKEM768 required; SecP384r1MLKEM1024 offered)
                   │
          ┌────────▼────────┐   holds: HTP session keys (memory), rate-limit sketches (memory)
          │      front      │   owns:  no database, no long-lived secret except its TLS key
          │  edge + gateway │   knows: which sessions exist; never a document key, never a share
          └──┬───────────┬──┘
   mTLS PQ   │           │  mTLS PQ           (internal TLS: TLS 1.3, SecP384r1MLKEM1024 only,
   (core)    │           │  (anon)             ML-DSA-87 certificates, even on one host)
   ┌─────────▼──────┐  ┌─▼──────────────┐
   │      core      │  │      anon      │  owns: access codes, pass/post-token keys, spent ids,
   │ identity+vault │  │ access + relay │        relay objects, push buckets. No account ids, ever.
   │ +ledger        │  └────────────────┘
   │ +recovery      │  owns: accounts, devices, sessions, nonces, documents, the ledger and public log,
   └────────┬───────┘        recovery. One Postgres database: "logged before release" is one transaction.
   mTLS PQ  │ (keys)
   ┌────────▼───────┐  owns: one wrapped key share per document, Check-in fuses (memory only), used-proof
   │      keys      │        ledger. Kept apart on purpose: it is the split. Its own database cluster,
   └────────────────┘        its own host in production, a second operator later (§6).
```

| Unit | Merges (4.x) | Owns | Never holds | Called by |
| --- | --- | --- | --- | --- |
| **front** | edge, gateway | outer TLS; HTP/2 termination; socket-address rate limits; route allow-list; content-free push fan-out to anon | a document key, a share, a device key's private half, any database | the internet |
| **core** | identity, vault, ledger, recovery | `accounts`, `devices`, `sessions`, `nonces`, `objects`, `ledger_entries`, `tlog_*`, `recovery_*`, `links` | a share; an account or device private key; a passport secret | front only |
| **keys** | keyshare | `shares` (wrapped by the HSM KEK), `used_proofs`, `checkin`; fuse keys in memory | an envelope, a document name, an account key | core only |
| **anon** | access, relay | `access_codes`, `blind_keys`, `spent`, `relay_objects`, `push_subs` | any account id or device id | front only |

Why these lines (from the audit's §3): core's four services already shared one role, one statement key and one
machine; merging them turns vouch statements, ledger receipts, `created` statements and the gateway's write-first
dance into function calls inside one transaction, which fixes **H1** and **M3** structurally. keys must stay apart:
it *is* the split. access and relay know no accounts and keep only days.

One library crate (`humid-server`), four binaries (`humid-server-front`, `-core`, `-keys`, `-anon`). Each binary
links only its own unit module and the shared plumbing; a test (`units_do_not_import_each_other`) fails the build
if one unit's module names another's. One process per unit in production, one per unit in development too (the
4.x "everything in one Node process" mode does not come back).

## 2. Proofs: what each unit checks itself

Formats are proposals for humid-core and HTP/2 to confirm (§13 open questions); the server code keeps every one
behind `proofs.rs` so a format change is one file.

### 2.1 Keys and ids

| Thing | Encoding | Id |
| --- | --- | --- |
| Account root key | HUMID-PQ2 ML-DSA-87 verifying key (2605 B) | `account_id = key_id(vk)` (32 B, hex in JSON) |
| Account KEM key | HUMID-PQ2 hybrid KEM public key (1613 B) | — |
| Device key | ML-DSA-87 verifying key | `device_id = key_id(vk)` |
| Live key(s) | P-256 SPKI (every phone) and, where the chip allows, ML-DSA-87 (iOS 26 Secure Enclave, Android 17 Keystore) | stored per device with its algorithm list |

Because the account id *is* the hash of the account key, any unit can check a claimed account key against an
account id without asking anyone (keys uses this, §2.4).

### 2.2 The device certificate (account-signed)

A device belongs to an account only if the **account key** signed it:

```
device_cert_msg = lp(account_id, device_id, device_vk, live_p256_spki, live_mldsa_vk | "", enrol_th)
device_cert_sig = AccountKey.sign("HUMID-PQ2 device-cert", device_cert_msg)
```

Core stores both. Keys re-verifies both on every release, so a compromised core alone cannot invent a device for
an account. It can with a **copied account seed**: the attacker signs a certificate for its own phone and the
compromised core vouches for it (review M-2; §11). Keys keeping its own device set is tracked in §12.

### 2.3 Live proofs

```
ticket     = lp(METHOD, path, th, u64 seq, device_id, nonce, u64 at_ms, u8 mode)
live_p256  = ECDSA-P256-SHA256 over H("HUMID-PQ2 live", [ticket])        (secure chip, inside the biometric)
live_mldsa = LiveMlDsa.sign("HUMID-PQ2 live", ticket)                     (where supported)
device_sig = DeviceKey.sign("HUMID-PQ2 step-up", lp(ticket, SHA3-512(body)))
login_sig  = DeviceKey.sign("HUMID-PQ2 login",   lp(th, account_id, device_id, challenge, u8 duress))
live_login = ECDSA-P256-SHA256 over H("HUMID-PQ2 live-login", [lp(th, account_id, device_id, challenge)])
challenge  = u64 issued_at ‖ 16 random ‖ KMAC(HSM session key, "HUMID-PQ2 login-challenge", [account, device, issued_at ‖ random])
```

`mode` is humid-core's session mode (CORE.md §8–9): `0x00` normal, `0x01` duress. It is inside the ticket, so both
the device key and the chip sign it, and every unit reads it from the holder's own proof. Core requires a session's
proofs to carry that session's mode; keys refuses any write (store, delete, close, Check-in) whose proof carries
`0x01`, even if core relays it.

**Sign-in challenges are stateless** (review H-3): a MAC under the HSM `session` key, good for 2 minutes, so asking
for one stores nothing and nobody can use up another device's challenges. A challenge that signs someone in is
recorded (`used_challenges`), so it signs in once. Throttling never refuses a valid proof: the proof is checked
first; junk (no valid challenge) counts against the network only; only a valid challenge with signatures that
don't verify counts against the identity, and even then a valid proof is never refused.

The secure chip signs the *ticket* (known before the prompt opens); the device key, released by the same check,
also covers the body (which may only exist after the check: a seed sealed to a new device). The duress bit is only
in `login_sig`: which gesture means duress opens inside the check, so the chip's challenge cannot carry it.

A proof is accepted when, checked **by the unit acting on it**:

- `METHOD`, `path` match the action the unit is about to take, and SHA3-512 of the body it received matches;
- `at` is ≤ 60 s old and ≤ 5 s in the future; `nonce` was issued by core for this session and device and is
  unused (core consumes it in the action's transaction), and the proof hash was not seen before (keys and anon
  keep their own used-proof table);
- `device_sig` verifies under the device key, `live_p256` under the live key, and `live_mldsa` under the device's
  ML-DSA live key when it has one; a P-256-only device is refused after the policy's `p256_only_until` date;
- the device is active (not removed), its account is active, and the account is not in a lockdown that forbids
  this action;
- (iOS) the App Attest assertion for this check verifies with a strictly increasing counter — *stubbed: see §12*.

`proof_hash = H("HUMID-PQ2 proof-hash", [device_sig])[0..32]` is what the ledger records.

### 2.4 Statements between units

A unit statement is `body ‖ ML-DSA-87.sign("HUMID-PQ2 unit-statement", body)` with the unit's **statement key in
its HSM**. The body is JSON with `kind`, `exp` (≤ 120 s) and the facts; the verifier checks the exact signed
bytes, then parses. Public statement keys are in the signed policy (§7).

| Statement | From → to | Says | Why it can't be forged by front |
| --- | --- | --- | --- |
| `release` | core → keys | account, object, device cert (+ account vk), proof hash, ledger seq + hash of the `object.opened` entry | core's HSM key; and keys re-checks the holder proof and device cert itself |
| `upload` | core → keys | account, object, device cert, proof hash, envelope and manifest hashes (`object.sealed` is appended after keys stores the share, in the same transaction) | same |
| `delete`, `close`, `checkin` | core → keys | as above for those actions | same |
| `duress` | core → keys | account, device cert, the duress sign-in itself | keys re-verifies the duress sign-in signature |
| `live-check` | core → anon (via front) | *no account id*: action, body hash, proof hash, exp | core's HSM key; anon learns only that a live check approved these blinded values |
| `spent` | anon → core (via front) | a pass was spent: spent id, day | anon's HSM key |

### 2.5 Route table

Who may call: the mTLS client certificate's role (`front`, `core`, …). "Session" means a core-issued session token
bound to the HTP transcript hash `th` (core verified the login itself; a compromised front reaches only accounts
that sign in while it is compromised). "Step-up" means a live proof (§2.3) checked by that unit.

**front (public, internet)**

| Route | Who | Checks itself |
| --- | --- | --- |
| `GET /htp/v2/keys` | anyone | — serves the signed policy and the current HTP KEM key with its certificate |
| `POST /htp/v2/hello`, `POST /htp/v2/call` | anyone | HTP/2 handshake and frames: **stubbed** (HTP/2 not yet specified, §12) |
| `GET /tlog/v2/checkpoint`, `/tlog/v2/consistency` | anyone | rate limited per network (L8); forwarded to core |
| `POST /tlog/v2/cosign` | a cosigner | forwarded; core checks the cosignature against the policy's cosigner keys |
| `GET /healthz` | anyone | — |

Inner routes (inside an HTP/2 frame once it lands) map one-to-one onto the core and anon routes below; anything
not in the allow-list is a 404 before any unit sees it (`front::routes::resolve`).

**core (caller: front)**

| Route | Session | Proof core checks itself | Writes in the same transaction |
| --- | --- | --- | --- |
| `POST /v1/auth/register` | anonymous | account-key PoP over `lp(th, account_vk, kem_pk)`; device cert; device PoP; live P-256 over the cert; attestation (stub); anon `spent` statement when registration needs a pass | account, device, `account.created` (logs the account-key binding into the public log), `device.added` |
| `POST /v1/auth/challenge` | anonymous | — (stateless HSM MAC, 2 min; nothing stored; an unknown account gets the same answer) | — |
| `POST /v1/auth/login` | anonymous | the challenge's MAC and age, then `login_sig` + `live_login`, *before any limit*; revocation of the device; P-256-only date | session, nonce pool, used challenge; on duress: lockdown, every recovery wait doubled (waiting ones too), the session's frozen copy of Check-in, `session.duress` (deferred while a duress session is live), and a `duress_pending` row that a worker delivers to keys **after the reply**, retried until keys acts on it. Every sign-in asks keys where Check-in stands, so answer and timing are the same. A duress session then changes nothing real (§2.6) |
| `POST /v1/auth/logout` | session | — | session revoked |
| `POST /v1/auth/nonces` | session | — (tops the pool up to 8; also returned in every signed-in reply) | nonces |
| `POST /v1/links` | anonymous | humid-core's self-signed join request (`0x0108`, CORE.md §5.3): signature, account, device key, join key; 64 open links per IPv4 /24 or IPv6 /48, 10,000 in all; per-network rate | link (request, binding, 100-bit code) |
| `GET /v1/links/:code` | session of the account the request names | — (any other account: `unknown_code`) | — |
| `POST /v1/links/:code/approve` | session of that account | step-up on an existing device over the request's **binding** | link approved for exactly this request, `device.link_approved` |
| `GET /v1/links/:code/result` | anonymous | — (the 100-bit code is the capability; 10 min) | — |
| `POST /v1/devices` | anonymous | device cert, device PoP, live signature, attestation (stub), **and the evidence**: an approved link for this device key or a released recovery for this account, consumed in the same transaction (**H1**) | device, `device.added` with its evidence, link consumed / recovery completed |
| `DELETE /v1/devices/:id` | session | step-up | device revoked, `device.removed` |
| `GET /v1/me` | session | — | — |
| `DELETE /v1/me` | session | step-up | account closed, devices revoked, `account.closed`; then `close` statement to keys |
| `POST /v1/objects` | session | step-up whose body carries the envelope, manifest and sealed-share hashes (**H2**) | object, `object.sealed`; keys stores the share before commit |
| `POST /v1/objects/:id/open` | session | step-up whose body carries humid-core's share request (account, document, manifest hash, one-time key) | **`object.opened` committed before anything leaves**; then the `release` statement to keys; download ticket (4 at once per session). In a duress session every refusal reads `not_available` |
| `GET /v1/objects/:id/chunks/:n` | session | the download ticket from that open (60 s, this session) | — |
| `PATCH /v1/objects/:id` | session | step-up (**L3**) | index entry, `object.updated` |
| `DELETE /v1/objects/:id` | session | step-up | object deleted, tombstone, `object.deleted`; `delete` statement to keys |
| `POST /v1/sync` | session | — | — (returns deltas since the phone's versions, plus nonces) |
| `GET /v1/ledger/events?since=` | session | — | — |
| `GET /v1/ledger/inclusion?seq=` | session | — | — |
| `PUT /v1/recovery/mode` | session | step-up + the account key's signed, chained mode statement | mode, `recovery.mode_set` |
| `PUT` / `DELETE /v1/recovery/card` | session | step-up | card tag (server-keyed), `recovery.card_set` / `_removed` |
| `PUT` / `DELETE /v1/recovery/witnesses` | session | step-up | witness set, `recovery.witnesses_set` / `_removed` |
| `POST /v1/recovery/requests` | anonymous | — (global cap on unbound requests; per-account cap once bound, M4) | request |
| `GET /v1/recovery/requests/:id` | anonymous | — (the 128-bit id is the capability) | — |
| `POST /v1/recovery/requests/:id/card` | anonymous | the card's server-keyed tag | evidence, `recovery.evidence` |
| `GET` / `POST /v1/recovery/help/:code` | the witness's own session | POST: the witness's step-up, and that they are one of this account's witnesses | their piece re-sealed to the new device, `recovery.helped` (witness's ledger) and `recovery.evidence` |
| `POST /v1/recovery/requests/:id/anchor`, `/key` | anonymous | **stubbed**: passport (needs the second share operator) and FIDO | — |
| `GET /v1/recovery/alerts` | session | — | — |
| `POST /v1/recovery/alerts/:ref/cancel` | session (not a duress one) | step-up (the veto) | request cancelled, `recovery.cancelled` |
| `POST /v1/duress/clear` | session (not a duress one) | step-up, after the cool-off | lockdown cleared, `duress.cleared` (deferred while a duress session is live) |
| `GET /v1/checkin` | session | — (asked of keys; a duress session is answered from its own copy) | — |
| `POST /v1/checkin/arm`, `/check`, `/disarm` | session | step-up (and keys checks it again) | keys first, then `checkin.armed` / `checkin.disarmed` (never one per check-in). A duress session's are simulated on its own copy |
| `POST /v1/live/attest` | session (not a duress one) | step-up; 32 per account per day | — (returns the account-free `live-check` statement for anon) |

### 2.6 A duress session (review H-1, H-2)

A duress sign-in answers exactly as an ordinary one, and the session it opens **changes nothing real and learns
nothing that names duress**:

- Upload, delete, index changes, device links and removals, recovery setup, help and veto, closing the account,
  clearing a lockdown and post tokens answer `busy`. Keys refuses any write whose proof carries mode `0x01`,
  whatever core says.
- Check-in looks on and working: the session is shown Check-in as it stood at the duress sign-in (stored with the
  session) and its own arm / check / disarm move only that copy. Keys is never told, so a coerced arm can't erase
  the vault later.
- Ledger entries that would give it away (`session.duress`, `duress.cleared`, `access.denied`, `checkin.erased`)
  are held in `deferred_entries` while a duress session of the account is live and appended once none is (the
  holder's own devices then see them); older ones are left out of what a duress session reads. A refused open
  reads `not_available`, never `vault_erased`.
- The erase request reaches keys after the reply, from `duress_pending`, retried with back-off until keys acts on
  it (or says it already did).
- Opens follow the owner's decision on duress releases (§13): today, as an ordinary open.

`tests/review95_more.rs` tries every step-up route in `front::routes::ROUTES` from a duress session and checks both
databases row by row.
| `GET /tlog/checkpoint`, `/tlog/consistency`; `POST /tlog/cosign` | front (public) | cosignature | cosignature |

There is **no route** by which front writes a ledger entry (**M3**), marks a link or recovery used (**H1**), sets
a lockdown (**M2**), or undoes an upload or an enrolment (**L1**): core does each of those itself, inside the
transaction of the action the holder signed.

**keys (caller: core)**

| Route | Checks itself |
| --- | --- |
| `GET /v1/kem-key` | — (also in the policy) |
| `POST /v1/shares` (store) | core `upload` statement; account vk hashes to the account id; device cert under the account key; holder proof for `POST /v1/objects` whose signed body names this object, this envelope hash, this manifest hash and this sealed share's hash; opens the share (direction *upload*, binding = manifest hash) with its KEM key |
| `POST /v1/shares/:id/release` | core `release` statement; device cert; holder proof for `POST /v1/objects/:id/open`; the proof hash in the statement equals the proof's; the share request (and so the one-time key and binding) taken from the signed body; hourly cap per account; Check-in not locked/erased; proof never seen before |
| `POST /v1/shares/:id/delete` | core `delete` statement + holder proof for `DELETE /v1/objects/:id` |
| `POST /v1/accounts/:id/close` | core `close` statement + holder proof for `DELETE /v1/me` |
| `POST /v1/checkin/{status,arm,check,disarm}` | core `checkin` statement + holder proof for the matching app route |
| `POST /v1/duress` | core `duress` statement + the duress sign-in (`login_sig` with the duress bit, `live_login`), each one acted on once |

**anon (caller: front)**

| Route | Checks itself |
| --- | --- |
| `GET /v1/pass/keys`, `POST /v1/pass/issue` | the access code (the code is the payment); RFC 9474 blind signature |
| `POST /v1/pass/spend` | the pass's signature; once; returns the `spent` statement core needs |
| `POST /v1/post-tokens` | core's account-free `live-check` statement for `POST /v1/post-tokens` over exactly these blinded values; proof hash unseen; ≤ 16 tokens per check (**M1**, M-10) |
| `POST /v1/stamps` | the same statement; **issuance stubbed** (partially blind RSA with epoch metadata pending, §12) |
| `POST /v1/relay/deposit` | post tokens (once each), one per 16 KiB of the wire size class; box caps before any token is spent; the relay total in SQL (`relay_usage`) |
| `POST /v1/relay/tick` | — fixed-size request (16 prefix slots, each with a cursor), fixed-size padded reply; reads, never deletes. An object too big for the reply comes back as a stub (id, box, size), so nothing blocks a prefix |
| `POST /v1/relay/fetch` | — one stubbed object by id and box (never deletes) |
| `POST /v1/relay/ack` | the ack token whose hash the sender stored with the object; deletes only then (**H-3**) |
| `POST /v1/relay/retract` | the retract token |
| `POST /v1/push/subscribe` | a post token; stores a push token against coarse prefix buckets (sender stubbed) |

## 3. The key share, both directions (H2)

The formats are humid-core's (CORE.md §6.3); `tests/core_formats.rs` checks the server parses and binds exactly
what `crates/humid-core` emits.

```
UPLOAD                                                       RELEASE (open)
phone (inside one live check):                               phone (inside one live check):
  share_ks ← random 32 B                                       (eph_sk, eph_pk) ← one-time hybrid KEM key
  sealed = seal_share(Upload, keys_kem_pk, account,             request = header(0x0012) ‖ account ‖ doc ‖ manifest_hash ‖ eph_pk
           object, binding = manifest_hash, share_ks)           body = { object, share_request: request }
  body = { object, envelope_hash, manifest_hash,                proof = step-up(POST /v1/objects/:id/open, body)
           sealed_hash = H(sealed), index }
           + envelope + sealed
  proof = step-up(POST /v1/objects, body)
front: forwards ciphertext only                              front: forwards
core:  verifies proof; stores envelope; appends              core:  verifies proof; the request names this account,
       object.sealed; calls keys with the `upload`                  document and stored manifest hash; consumes the
       statement + proof + sealed; commits only if                  nonce; appends object.opened and COMMITS (synchronously
       keys stored it                                               replicated); then calls keys with `release` + proof
keys:  verifies statement, device cert, proof (its body      keys:  verifies statement, device cert, proof, that
       names this sealed share's and manifest's hash);              proof_hash matches; cap; Check-in; once; HSM-unwraps;
       open_share(Upload, kem_sk, …, manifest_hash);                seal_share(Release, eph_pk, account, object,
       HSM-wraps it at rest; forgets it                             binding = H("HUMID-PQ2 share-request", [request]), share)
                                                             core → front → phone: envelope chunks + sealed share
```

The share is **never in the clear outside the phone and the keys unit's memory for the duration of one call**.
Front sees ciphertext in both directions; core sees ciphertext in both directions. The audit's H2 scenario
(a compromised gateway collects every new share) no longer works: front never had it, core never had it.

Keys' KEM key is software (ML-KEM decapsulation in today's HSMs is not available on the hardware we can buy),
generated at start-up, held in memory, certified by keys' HSM statement key and published in the policy; it is
rotated at least monthly and the previous key kept for one day to finish in-flight uploads.

## 4. Database: PostgreSQL

**Choice: PostgreSQL 16+ (one cluster per unit that stores anything: core, keys, anon), streaming replication to
a hot standby at the second site with `synchronous_commit = remote_apply` for core and keys.** Front has no
database.

| | PostgreSQL + streaming replication | SQLite + Litestream / LiteFS |
| --- | --- | --- |
| Live standby at site 2 | Built in: hot standby, `pg_promote()`, `pg_rewind` to bring the old primary back | Litestream is backup (async to object storage), not a standby; LiteFS needs FUSE and a lease service and is in maintenance mode |
| "Logged before release" across a site loss | `remote_apply`: the `object.opened` entry is on **both** sites before the share is released. RPO 0 for the ledger | Async: a failover can lose the last seconds of ledger after the share went out — exactly the property the ledger promises |
| Concurrency inside one unit | Row locks, `SELECT … FOR UPDATE`, advisory locks | One writer; WAL helps readers only |
| Always-rollback transactions | `tokio_postgres::Transaction` rolls back on drop unless committed | Possible, hand-rolled |
| Operations for one owner | One more daemon per unit; `pg_basebackup`, `pg_dump`, `pg_checksums`, standard monitoring | Nothing to run, but replication is the hard part and it is bolted on |
| Retention | `DELETE … WHERE` in batches + autovacuum reclaims space | `VACUUM` / `auto_vacuum=INCREMENTAL` needed (4.x relay file never shrank) |

SQLite would be simpler on one box, and it was the right call for 4.x. It stops being simpler the moment there are
two sites and a standby, and the ledger's guarantee depends on synchronous replication. So: Postgres, kept boring
— no extensions, no stored procedures except one function for the tlog append, plain SQL migrations, `bytea` for
binary, `bigint` epoch milliseconds for time.

Topology per unit (production): primary at site A, synchronous hot standby at site B, an asynchronous third
copy (the N+1) at site A on separate disks; promote by hand (`humid-server-core db promote` documents the steps).
Connections: Unix socket on the same host (no network hop to protect); replication over TLS 1.3 with a PQ group
(PostgreSQL 18 `ssl_groups`, OpenSSL ≥ 3.5) — see §13.

Migrations: `migrations/<unit>/NNNN_name.sql`, from empty, applied in order inside one transaction each, recorded
in `schema_migrations(unit, version, applied_at, sha3)`. A changed migration file is refused (hash mismatch). No
4.x import.

## 5. Retention and caps (closes the unbounded tables)

One retention job per unit (`retention::run`), every 10 minutes for short-lived rows and daily for the rest, in
batches of 10,000, each batch its own transaction. Every table has a rule; every in-memory map has a cap.

**core**

| Table | Rule | Cap |
| --- | --- | --- |
| `accounts` | kept while active; closed accounts kept (public keys for old proofs) | — |
| `devices` | kept; revoked rows kept with the account (old proofs) | 16 active per account |
| `sessions` | deleted 1 day after `expires_at` (8 h absolute, 15 min idle) or revocation | 16 live per account (LRU revoked) |
| `nonces` | deleted at expiry (pool 15 min); used ones at once | 8 unused per session |
| `used_challenges` | deleted at expiry (sign-in challenges are stateless; only used ones are kept, 3 min) | — |
| `duress_pending`, `deferred_entries` | until delivered to keys / appended to the ledger | — |
| `erase_sweeps` | 30 days | one per erase |
| `live_check_days` | 2 days | 32 live checks for post tokens per account per day |
| `policy_seen` | one row | — |
| `objects` | until deleted by the holder or Check-in | per-account byte quota (policy) |
| `object_tombstones` | 30 days (`/sync` older than that gets `resync: true`) | — |
| `download_tickets` | deleted at expiry (60 s) | 4 per session |
| `links` | 1 day after expiry or use | 64 open per IPv4 /24 or IPv6 /48; 10,000 in all |
| `recovery_requests` | 30 days after close (the ledger keeps the record); an unbound one lives 1 hour | 3 open per account; 32 unbound per /24 or /48; 10,000 unbound |
| `recovery_evidence`, `recovery_approvals` | with their request | — |
| `recovery_cards`, `recovery_witnesses`, `recovery_mode` | until replaced or account close | 1 card, 1 witness set |
| `duress` | 14 days after the last signal; at account close | — |
| `ledger_entries` | append-only; bodies of closed accounts redacted after 7 years, hashes kept | — |
| `tlog_nodes`, `tlog_state` | append-only (they *are* the log) | — |
| `tlog_checkpoints` | the latest, every cosigned one, and one per day; others after 1 h | — |
| `tlog_cosigs` | with their checkpoint | 1 per cosigner per checkpoint |
| `rate_buckets` | in memory, LRU | 100,000 keys |

**keys**

| Table | Rule | Cap |
| --- | --- | --- |
| `shares` | until deleted, account close, or Check-in erase | — |
| `releases` | 1 hour (the hourly cap's window) | per-account hourly cap (policy) |
| `used_proofs` | 10 minutes (proofs live 60 s) | — |
| `checkin` | erased rows 7 days after erase (the app shows it for a week); off rows deleted | 1 per account |
| `duress_used` | 8 hours (a session's lifetime; replaces the 4.x forever table) | — |

**anon**

| Table | Rule | Cap |
| --- | --- | --- |
| `access_codes` | used codes 400 days after use; unused until their batch expires | — |
| `blind_keys` | private half erased when issuing ends; row deleted at `accept_until` | 2 live per purpose |
| `spent` | carries `kid`; deleted at that key's `accept_until` (4.x kept them forever) | — |
| `relay_objects` | 14 days, or at acknowledgement | 500 / 64 MiB per box, 2 GiB in all |
| `push_subs` | 30 days without a refresh | 1 per push token |
| `day_counts` | 400 days | — |

## 6. HSM key hierarchy

Behind a PKCS#11-style trait (`hsm::Hsm`): keys are referenced by label, are non-extractable, and the trait
offers only the operations PKCS#11 v3.2 defines mechanisms for — ML-DSA sign (`CKM_ML_DSA` with a context
string), SLH-DSA sign (`CKM_SLH_DSA`), AES key wrap with padding (`CKM_AES_KEY_WRAP_KWP`) with associated data
bound by deriving a per-record KEK, and HMAC/KMAC for keyed tags.

| Key (label) | Unit | Algorithm | Used for |
| --- | --- | --- | --- |
| `identity-root` | offline / ceremony | ML-DSA-87 + SLH-DSA-SHA2-256s | signs the policy (which certifies every other public key); apps pin it |
| `core-statement` | core | ML-DSA-87 | unit statements; HTP KEM key certificate (daily) |
| `ledger` | core | ML-DSA-87 + SLH-DSA-SHA2-256s | tlog checkpoints, at a fixed cadence (60 s), never per request |
| `card-tag` | core | KMAC256 key | server-keyed recovery-card lookup tags |
| `session` | core | KMAC256 key | stateless sign-in challenges (§2.3) |
| `session` | core | KMAC256 key | session token MACs |
| `keys-statement` | keys | ML-DSA-87 | certifies keys' KEM key |
| `share-kek` | keys | AES-256 (KWP) | wraps every share; unwrapped inside the HSM per release |
| `anon-statement` | anon | ML-DSA-87 | `spent` statements |
| `seal` | every unit | AES-256 | anything else at rest (software key files) |
| `tls-ca` | ceremony | ML-DSA-87 | internal CA (≤ 2 years), leaves ≤ 90 days |

Software keys certified by the HSM keep it off the hot path: the HTP KEM key (daily), keys' KEM key (monthly),
mTLS leaves, blind-signature keys.

`hsm::soft::SoftHsm` implements the trait in software for development, from a key file in the unit's data
directory. It is **refused in production mode** at start-up (`Mode::Production` + a software HSM = exit with
an error naming the problem). `hsm::pkcs11` is the production path; it is a typed stub until the HSM model is
chosen (§13). No unit starts in production without its `seal` key.

## 7. Signed, forward-only policy

Every security setting that 4.x read from environment variables in several services (device policy,
registration, station lists, check-in lists, cosigners, keyshare key) is one file, `policy.json`, with a detached
dual signature `policy.json.sig` by `identity-root` over the **exact file bytes**
(`DualSigningKey.sign("HUMID-PQ2 server-policy", lp(bytes))`). No canonicalisation step to get wrong.

- `version` must not be lower than the highest version this unit has accepted, and the same version must have
  the same bytes. The high-water mark is kept in the unit's replicated database (`policy_seen`, core, keys and
  anon) **and** in `<data_dir>/policy.state` (front has no database); either one refuses a rollback, so a wiped or
  restored data directory alone can't bring back an older policy (review M-7). There is no reload path yet: a new
  policy takes a restart.
- A build with the identity root pinned (`HUMID_IDENTITY_ROOT_ID` at build time) accepts **only** that root, in
  every mode, so the unsigned `server.toml` can't point a production build at another root that signs a
  development policy. A build without a pin runs development policies only.
- Unknown fields are refused (`serde(deny_unknown_fields)`).
- The same bytes and signature are served at `GET /htp/v2/keys`, so the app checks exactly what the servers enforce
  and warns on unsafe modes (`mode != production`, `registration: open`, `p256_only_until` in the future, no
  cosigners).
- `server.toml` (unsigned) holds only *where* things are: listen addresses, database URL, certificate paths, HSM
  module path, data directory, unit endpoints. Nothing in it can weaken a check.

Fields: `version`, `issued_at`, `mode` (`development` | `production`), `registration` (`pass` | `open`),
`device_policy` (`attested_proofs`, `p256_only_until`, `android_min_patch`), `stations`, `cosigners`,
`unit_keys` (core/keys/anon statement public keys), `keys_kem_pk`, `checkin` (windows, graces),
`limits` (quota, share releases per hour, rate limits), `messaging` (epoch minutes, prefix bits, tick slots and
size, post tokens per check), `recovery` (base delay, duress window, count passport only with a second operator).

## 8. Internal TLS

- TLS 1.3 only, one key exchange group: **SecP384r1MLKEM1024** (codepoint `0x11ED`, draft-kwiatkowski-tls-ecdhe-mlkem; ECDH share first),
  implemented as a rustls `SupportedKxGroup` over aws-lc-rs's P-384 and ML-KEM-1024 (rustls ships only the 768
  hybrids). A peer that offers anything else fails the handshake: no downgrade.
- ML-DSA-87 certificates (rustls + aws-lc-rs verify them; rcgen issues them), one internal CA ≤ 2 years, leaves
  ≤ 90 days; each leaf's DNS SAN names its role (`core.unit.humid.internal`); the server maps the verified client
  certificate to a role and each route lists the roles it accepts.
- Always on, loopback included. There is no plain-HTTP listener in the code at all.
- Outer TLS (front): TLS 1.3, `X25519MLKEM768` required, `SecP384r1MLKEM1024` offered first; a classical-only
  client fails. Certificates for the public name stay classical (ECDSA P-384) until browsers and app platforms
  verify ML-DSA chains.

## 9. Rate limits on a verified address

On the owner's hardware front terminates TLS itself, so the client address is the **socket's peer address**.
There is no `X-Forwarded-For`, no `TRUST_FORWARDED` mode, no shared bucket, no loopback special case (all of them
deleted, audit §3). Keys: IPv4 address, IPv6 /64. Front sends the key to units in `x-humid-client-net` over mTLS;
units use it only for limits (availability), never for authorisation.

Limits: handshakes 30/min per network; calls `limits.calls_per_minute` per session (core enforces it until HTP/2
front does); step-up actions 600/hour per account; sign-in failures 20 per network per 5 minutes and, only for a
valid challenge whose signatures don't verify, 10 per identity (a valid proof is never refused, §2.3); recovery
starts per network, unbound requests per /24 or /48, and per account once bound; open links per /24 or /48 (**M4**,
review M-5: no global bucket a handful of networks can fill); relay deposits by post token rather than address
(**M-10**), weighted by size, with live checks for tokens capped per account per day (review M-6). Sketches have
fixed memory (count-min, as 4.x) or LRU caps; none wipes everything when full (**L4**).

In production a call that reaches core without `x-humid-client-net` is refused (`no_client_network`), so a front
that forgets it can't put every caller into one bucket (review M-4). The temporary Funnel deployment cannot see
client addresses; it runs in `development` mode only, where such calls share `dev:unknown` and per-account limits
do the work.

## 10. Phone battery: API changes from the audit

| Change | Where |
| --- | --- |
| **One delta `POST /v1/sync {since}`** replacing the ~13-request unlock: items changed since the phone's object revision (index entries only), tombstones, ledger entries since its head, devices/recovery digests, and a nonce pool top-up | core `sync` |
| **Step-up nonce pool**: login and every signed-in reply carry up to 8 single-use nonces (15 min), so a sensitive action is one round trip, not two. Freshness comes from `at` (≤ 60 s) and single use, not from a fresh nonce round trip | core `nonces` |
| **Binary chunked frames**: a document is served in 1 MiB chunks under one approval with a 60 s download ticket; a dropped connection resumes from the next chunk without a new live check. Proofs travel as binary fields, not base64 in JSON (once HTP/2 lands; internal APIs use JSON with base64url until then) | core `objects`, front HTP/2 |
| **Content-free push**: the phone registers a push token (anonymously, with a post token) against coarse prefix buckets; a deposit into a bucket queues one batched, jittered "check now" wake. No polling in the background | anon `push` (sender stubbed) |
| **Constant-rate messaging check**: one fixed-size `tick` per interval covering every prefix the phone follows, with a fixed-size padded reply; the same request is the cover traffic | anon `relay::tick` |
| **Relay deletes only after acknowledgement**: tick only reads (per-prefix cursors, so a prefix shared with strangers hides nothing from them); `ack` with the per-object ack token (whose SHA3 the sender stored at deposit; only the recipient can derive it from the box key) deletes; unacked objects stay until their 14-day TTL | anon `relay` |
| Cached key bundle; challenge folded into the hello reply; ledger fetched `since` the stored head; checkpoints fetched only when their size changes | front, core |

## 11. What a compromised unit can and cannot do

| Compromised | Can | Cannot |
| --- | --- | --- |
| front | deny service; see which sessions exist and when; act as an account that signs in while compromised, within that session's rights (reads, nothing that needs a step-up) | open a document, see a share, enrol a device (H1), write or forge a ledger entry (M3), lock an account down (M2), mint stamps or post tokens (M1), undo anything (L1) |
| core | read envelopes (ciphertext), refuse service, lie by omission in `/sync` (caught by the public log), vouch for a revoked device; **with a copied account seed, add a device** (the attacker signs a certificate for its own phone; core vouches for it; keys then releases shares for that phone's genuine live proofs, and a phone that trusts core's device list wraps new documents for it) | release a share without a live proof from a device the account key certified (keys checks both), invent a device without the account seed, relay a coerced change from a duress session (keys reads the signed mode), see a share. Documents sealed before the compromise stay behind each device's own `HW_doc` |
| keys | refuse or destroy shares (denial) | open anything (no envelope), release a share that a phone can use without core's envelope |
| anon | refuse service, see message sizes and times by prefix | link anything to an account (it never sees one) |

## 12. Implemented vs stubbed (this branch)

Stubs never panic: they return `Error::NotImplemented { what, waiting_on }` → HTTP 501 `not_implemented`, and a
production-mode start refuses while any required stub is in the path.

| Area | State | Waiting on |
| --- | --- | --- |
| Units, routing, mTLS with SecP384r1MLKEM1024 + ML-DSA-87 certs, roles per route | implemented | — |
| Policy load, dual-signature check, forward-only version | implemented | — |
| HSM trait, `SoftHsm`, production refusal | implemented | — |
| `Pkcs11Hsm` | stub | HSM model (§13) |
| Postgres schema per unit, migrations from empty, retention jobs | implemented | — |
| Core: register, challenge, login (incl. duress), logout, nonce pool, links, enrolment with evidence (H1), device removal, close | implemented | — |
| Core: objects upload / open (log before release) / chunks / patch / delete; `/sync` | implemented (envelope bytes stored opaque; size and hash checks only) | humid-core envelope v2, to verify the account signature server-side |
| Core: ledger hash chain, tlog leaves, inclusion/consistency proofs, dual-signed checkpoints, cosignatures | implemented | — |
| Core: recovery mode, card tags, witness sets, requests, card evidence, witness approvals, wait + veto, release for enrolment | implemented | — |
| Recovery passport anchor and FIDO security-key evidence | stub | second share operator; Rust ICAO passive auth and CTAP verification |
| Device attestation (Android key attestation, App Attest) and per-check App Attest assertions | stub (development accepts `none`) | port of `packages/attest` |
| Keys: sealed share store / release / delete / close, used proofs, hourly cap, Check-in arm / check / disarm / erase on duress | implemented | — |
| Anon: access codes, RFC 9474 passes, spend statements, post tokens behind core's live-check statement, relay deposit / tick / ack / retract, push subscriptions | implemented | — |
| Anon: live stamps | stub | partially blind RSA with epoch metadata (stamp v2 design) |
| Push sender (APNs / FCM) | stub | provider accounts |
| Front: outer TLS, rate limits, allow-list, key bundle, internal client | implemented | — |
| Front: HTP/2 handshake and frames | stub | HTP/2 specification (KEM handshake over PQ2 §5, TransitSealer frames, binary TLV) |
| `humid-server-core dev-setup <dir>`: CA, leaves, dev identity root, signed dev policy, soft HSMs, four `*.toml` | implemented (development only) | — |

Tests (`cargo test -p humid-server`; Postgres from `HUMID_TEST_DATABASE_URL`, one schema per test; CI runs them
against a PostgreSQL 16 service): 48 unit tests; `tests/flows.rs` (10 end-to-end flows over real internal TLS);
`tests/compromised_front.rs` (10: front's certificate and sessions in the attacker's hands, plus a copied seed);
`tests/retention.rs` (2); `tests/startup.rs` (2: policy tampering and rollback at start-up, outer TLS requires a PQ
group); `tests/core_formats.rs` (3: share requests and join requests cross-checked against `crates/humid-core`);
`tests/review95.rs` (6) and `tests/review95_more.rs` (16): the PR #95 review's probes, each turned into a
regression that failed before its fix, plus the every-route duress test.

### Tracked from the PR #95 review

Fixed on this branch: H-1, H-2, H-3, M-1, M-3, M-4, M-5, M-6, M-7 (the database high-water mark and the root pin
in every mode), and lows L-1, L-2, L-3, L-6, L-7, L-8, L-10, L-11, L-12, L-13, L-14, L-16, L-17, L-18, L-19.
M-2 is documented (§2.2, §11). Still open:

| # | What | Plan |
| --- | --- | --- |
| M-2 | Keys trusts core's word for which devices an account has; a copied seed plus a compromised core adds one | keys keeps its own per-account device set: the first device from the registration PoP (relayed in a core statement), later ones only with an endorsement keys checks itself (the approving device's step-up over the new request's binding, or the released recovery's evidence hash); the app checks its device list against signed `device.added` entries, not `/sync` |
| M-7 | Units don't compare policy versions; statements carry none; `issued_at` has no staleness bound; no reload path | put the policy version in every statement and refuse older ones; a reload endpoint behind the operator's key |
| L-4 | Uncosigned checkpoints are served as latest; front has no `POST /tlog/v2/cosign` | add the front route (HTP/2 work touches front); serve `final` only when cosigned |
| L-5 | `keys_kem_pk` isn't in the policy; keys' KEM key isn't rotated | certify it in the policy, rotate monthly with an overlap |
| L-9 | A share stored by keys whose core commit then fails is orphaned | keys sweeps shares no core object names (core signs the list), or two-phase store |
| L-15 | Statements have no audience or id; `spent` single use is keyed on statement bytes | add `aud`, `jti` and the policy version; key single use on `facts.spent` |

## 13. Open questions for the owner

1. **HTP/2.** Front can't carry app traffic until HTP/2 is specified (handshake, binary frames, proofs as TLV).
   Who writes it, and does it live in PQ2.md or its own doc?
2. **Proof formats.** Shares and join requests now follow CORE.md §5.3 and §6.3 exactly (tested against
   humid-core). The step-up ticket now carries humid-core's session mode byte (§2.3). The rest of the step-up,
   sign-in and enrolment proofs are still this server's proposal: CORE.md §9 has per-action live labels
   (`live-open`, `live-seal`, `live-grant`, …) over `[challenge, …, mode]`, while the server checks one ticket shape
   for every route plus the ML-DSA device signature over the body. Proposal: the chip signs
   `H(live-<action>, [ticket, binding…, mode])` with CORE.md's labels and `ticket` (§2.3) as the challenge;
   `proofs.rs` is the one file to change. The server-side attestation check that the new device's key is the
   request's (CORE.md §5.3, "attested model") lands with the attestation port (§12): today the enrolment
   certificate must certify exactly the request's device key, and the attestation itself is a stub.
3. **Type codes**: the server uses `0x0200`–`0x0202` for its own at-rest boxes (shares, fused shares, soft-HSM
   key file). Please add a `0x02xx` server block to the PQ2.md registry.
4. **HSM model** (PKCS#11 v3.2 with ML-DSA and SLH-DSA mechanisms): which device, one per site?
5. **Postgres replication TLS**: PostgreSQL 18 + OpenSSL ≥ 3.5 for a PQ group on the replication link, or a
   WireGuard tunnel between sites in the meantime?
6. **Keys' KEM key in software** (§3): acceptable, given HSMs don't do ML-KEM decapsulation yet?
7. **Second key-share operator** for the passport piece: same `keys` binary at a partner; until then the passport
   doesn't count as an independent proof (policy `recovery.passport_counts = false`).
8. **CI**: done here: the `rust` job has a PostgreSQL 16 service, so `cargo test --workspace` runs the server
   tests. The image is pinned by tag only (Docker Hub couldn't be reached to look up a digest); please pin it by
   digest.
9. **Branch and workspace.** This branch is `v5-server` (git refuses `v5/server` beside a branch named `v5`). The
   crate is a member of the root workspace (its lints and profiles); it depends on `crates/humid-pq2` (and, for
   tests, `crates/humid-core`) by path from `v5-core`, merged in.
10. **Rust version.** Built and tested with stable 1.97; `rust-toolchain.toml` pins 1.99.1, which this box can't
    download. Nothing here needs more than 1.85.
11. **Duress releases.** CORE.md §8 leaves it to the owner: when a live proof carries `mode = 0x01`, does keys
   release real shares, refuse ("not available right now"), or serve decoy content? The server reads the mode and
   already refuses every write; releases are unchanged until you decide (an armed vault is already erased by the
   duress sign-in, so only decoy-marked documents still open).
12. **Duress and the ledger.** Entries that would show a duress session what happened are held back while one is
   live and appended afterwards, so the holder's chain stays complete, and a duress session reads its chain with
   those entries left out (the phone's core knows it is in a decoy session). Alternative: label them in the public
   log by hash only and never serve them to any session. Which do you want?
