# HTP/2 — HumID Transit Protocol, version 2

Status: **draft for review, 24 October 2026; revised after the PR #97 review (§14).** Branch `v5-htp2`. Reference implementation:
[`crates/humid-htp`](../../crates/humid-htp) (sans-io client and server), the server side in
[`server/humid-server/src/htp.rs`](../../server/humid-server/src/htp.rs) and
[`src/front`](../../server/humid-server/src/front/mod.rs), the app core's client in
[`crates/humid-link`](../../crates/humid-link). Built on [HUMID-PQ2](PQ2.md) (§5 hybrid KEM, §4.2 KDF,
§7.4 transit records). Replaces HTP/1 ([PROTOCOL.md](../PROTOCOL.md)); nothing of HTP/1 is accepted.
Inputs: [V5.md](../V5.md) ("The live check", "Servers and trust"), [SERVER.md](SERVER.md) §2, §10, §13.1,
[CORE.md](CORE.md) §9, the 5.0 server audit (phone battery), the messaging audit (metadata).

This document is meant to be enough to write a second, interoperating implementation. Where it and the
code disagree, one of them has a bug.

## 1. What HTP/2 is for

HTP/2 carries every app request between the phone's Rust core and the server unit that acts on it
(**core**, or **anon** for anonymous sessions). It runs inside the outer TLS that **front** terminates and
ends *inside* core or anon, not in front.

| Goal | How |
| --- | --- |
| Front sees routing metadata only | Each frame has a 32-byte cleartext header (version, kind, unit, size class, session id, counter). Everything else is in AES-256-GCM records under keys front never holds. |
| Post-quantum, and authenticated to the server the app pins | Hybrid ML-KEM-1024 + X25519 (PQ2 §5) to the unit's KEM key. That key is certified by the unit's HSM statement key, which the dual-signed policy names, which the identity root signs. The app pins the root. |
| Forward secrecy | A second KEM to the phone's one-time key, discarded after the handshake. |
| No nonce reuse, ever | Keys come only from `transit_channel` (PQ2 §7.4): one key per session *and* per direction, the direction also in the nonce, `seq` only grows, a session secret is consumed once. Two sealers can never share a key. |
| A live proof binds one exact request | The proof names method, path, body hash, session transcript, request id (as `seq`), device, single-use nonce, time and session mode (SERVER.md §2.3, V5.md "The live check"). HTP/2 checks the `seq` against the request carrying it before the unit sees it; the unit checks the rest. |
| Phone battery (audit, SERVER.md §10) | Resumption on unlock (no certificate fetch, no sign-in); one delta `/v1/sync`; the step-up nonce pool (one round trip per sensitive action); binary bodies and proofs (no base64); 1 MiB chunks, resumable both ways. |
| Metadata hygiene | Six size classes with zero padding inside the record; an optional minimum class for cover. |
| Typed errors | One 16-bit code registry (§9), authenticated whenever a session exists. |

Not goals: hiding *that* a phone talks to HumID, or when (front and the network see that); hiding which
unit a session goes to (the routing byte); anonymity from core for signed-in traffic (core knows the
account it serves). Anonymous messaging uses anon sessions that never sign in (§7.3).

Notation is PQ2.md §1's: `‖` concatenation, big-endian `u16/u32/u64`, `lp(a, b, …)` length-prefixed parts,
`H(label, [parts])` = PQ2 §4.3's labelled SHA3-512, `KDF(label, [keys], [context], n)` = PQ2 §4.2.

## 2. Server keys and the key bundle

### 2.1 Trust chain

```
identity root (dual: ML-DSA-87 + SLH-DSA-SHA2-256s)       pinned in the app at build time
  └─ policy.json, dual-signed over the exact file bytes   SERVER.md §7; names unit_keys.core / .anon
       └─ unit statement key (ML-DSA-87, in the unit's HSM)
            └─ KEM certificate (below): 24 h valid (the format allows at most 3 days), rotated at 12 h
                 └─ the unit's HTP/2 KEM key (hybrid, software, in the unit's memory)
```

The KEM key is software because HSMs we can buy don't do ML-KEM decapsulation (SERVER.md §13.6). It never
leaves the unit's process. A restart makes a new one, which ends every session and makes every ticket
useless (the phone does one full handshake).

### 2.2 KEM certificate (type `0x0300`)

```
cert = header(0x0300) ‖ u8 unit ‖ u64 not_before ‖ u64 not_after ‖ kem_pk (1613) ‖ sig (4640)   (6297 bytes)
sig  = ML-DSA-87(statement key, ctx = SUITE ‖ u16 0x0004 ‖ "HUMID-PQ2 htp2-kem-cert",
                 M = every byte before sig)                                     (an encoded PQ2 signature)
kid  = key_id(kem_pk)                                                           (PQ2 §4.3, 32 bytes)
unit = 1 core, 2 anon
```

A decoder refuses another header, an unknown unit, `not_after ≤ not_before`, a validity over 3 days, a KEM
key that fails FIPS 203's check, and trailing bytes. The client accepts a certificate when the signature
verifies under the statement key the verified policy names for that unit and
`not_before − 10 min ≤ now ≤ not_after + 10 min`. The client checks the dates again **every** time it
uses a cached certificate (`Handshake::full` refuses one outside them with `bad_cert`), and fetches the
bundle again once the certificate is past half its life, so a stolen KEM key is useful only until its
certificate ends.

### 2.3 Key bundle (type `0x0301`), `GET /htp/v2/keys`

```
bundle = header(0x0301) ‖ lp(policy.json) ‖ lp(policy.json.sig) ‖ u8 n (1..4) ‖ lp(cert)×n
```

Front builds it from the policy file it verified at start-up (the same bytes and signature, unchanged) and
each unit's `GET /htp/v2/cert`, and caches it for 10 minutes. The policy is at most 256 KiB; its signature
is PQ2 §6.3's dual signature over `lp(file bytes)` with label `HUMID-PQ2 server-policy`. The app fetches
the bundle when it has no usable certificate (none, past half its life, or expired), or when a hello is
refused with `key_unknown` or `bad_cert`. A bundle whose signature doesn't verify under the pinned root is
a **hard stop**: the app shows its warning screen and sends nothing. An answer that isn't a bundle at all
(front's error while a unit restarts) is only `Offline`.

The policy is **forward-only on the phone too**: the link keeps the highest version it accepted (and the
SHA3-512 of its bytes; the app persists both) and refuses a lower version, or the same version with other
bytes (`PolicyRollback`). It also surfaces the policy's mode, and the app warns on a server that isn't in
production mode.

## 3. Frames: what front sees

Every HTP/2 message travels in a frame, and a call (one HTTPS `POST /htp/v2/call`, body
`application/vnd.humid.htp2`) carries one or more frames back to back.

```
frame   = header (32) ‖ payload                    total length = CLASSES[class], exactly
header  = "HT" ‖ u8 v ‖ u8 kind ‖ u8 unit ‖ u8 class ‖ 00 00 ‖ sid (16) ‖ u64 seq
CLASSES = 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB + 8 KiB          (class 0..5)
```

| `v` | `1` (this document). Any other value: `version_unsupported`. No negotiation exists, so nothing can be downgraded: a v2 endpoint never speaks v1. |
| --- | --- |
| `kind` | `1` HELLO, `2` RESUME (client → server, cleartext); `3` REPLY (server → client, cleartext); `4` RECORD (encrypted); `5` ERROR (cleartext, unauthenticated) |
| `unit` | `1` core, `2` anon: the one byte front routes on |
| `class` | index into CLASSES |
| `sid` | zero in HELLO/RESUME; the new session's id in REPLY; the session in RECORD; zero or the session in ERROR |
| `seq` | the record counter in RECORD (the sender's `transit_channel` seq); zero otherwise |

Cleartext payload: `u32 len ‖ body ‖ zeros` to the frame's end. Record payload: AES-256-GCM over
`u32 len ‖ msg ‖ zeros` (to `frame length − 32 − 16`), tag appended. The record's associated data is the
whole 32-byte header, inside PQ2 §7.4's `A`. Padding must be all zeros after decryption. The sender picks
the smallest class that fits, or a higher one for cover.

**Front's check** (`frame::route`) before forwarding: every header is well formed, every frame is exactly
its class's length, a call has at most 64 frames, and the call is either one HELLO/RESUME or records of a
single session and unit. Front then rate-limits: handshakes per client network and per IPv6 /48;
records (counted per frame, not per call) per session and per client network. It forwards the bytes
unchanged to that unit's internal `POST /htp/v2/call`, and reads at most 96 MiB back. For core it sets
`x-humid-client-net` from the verified socket (SERVER.md §9). Anon never learns a client address. Front
never holds a key that opens them.

**Cover classes are capped.** A sender pads small messages up to at most class 2 (16 KiB). Bigger frames
are only as big as their content needs, so a client can't make the server seal a small answer in a 1 MiB
frame.

## 4. Handshake

### 4.1 Full handshake (one round trip)

```
Phone                                                    Unit (KEM key K, certified)
(ek_c, dk_c) ← fresh hybrid KEM key pair (one-time)
(ct_s, ss_s) ← Encaps(K)
HELLO  kid (32) ‖ ct_s (1613) ‖ ek_c (1613) ‖ nonce_c (32) ‖ u64 time_c     ─────►
                                    refuse: unknown or expired kid (key_unknown);
                                            |time_c − now| > 5 min (stale_hello);
                                            nonce_c seen in the last 10 min (replay)
                                    ss_s ← Decaps(K, ct_s);  (ct_c, ss_e) ← Encaps(ek_c)
                                    sid ← 16 random bytes;   nonce_s ← 32 random bytes
◄─────  REPLY  u8 mode=0 ‖ u32 gen=0 ‖ ct_c (1613) ‖ nonce_s (32) ‖ u64 time_s ‖ confirm (32)
        RECORD TICKET (§4.3), in the same call
ss_e ← Decaps(dk_c, ct_c); check confirm in constant time; dk_c is dropped
```

```
th      = H("HUMID-PQ2 htp2-transcript", [v ‖ unit, kid, ct_s, ek_c, nonce_c, u64 time_c,
                                          sid, u8 mode, u32 gen, ct_c, nonce_s, u64 time_s])     (64)
master  = KDF("HUMID-PQ2 htp2-master",     [ss_s, ss_e], [th], 32)
confirm = KDF("HUMID-PQ2 htp2-confirm",    [master],     [th], 32)
session = KDF("HUMID-PQ2 htp2-session",    [master],     [th], 32)
res     = KDF("HUMID-PQ2 htp2-resumption", [master],     [th], 32)
(tx, rx) = transit_channel(session, channel = "HTP2" ‖ u8 unit ‖ sid, role)   phone: Initiator, unit: Responder
```

- **Server authentication.** Only the holder of `K`'s secret computes `ss_s`, so only it produces `confirm`
  and opens or seals records. `K` is pinned through the chain in §2.1.
- **Forward secrecy.** `ss_e` comes from the phone's one-time key. Stealing `K` later doesn't open recorded
  sessions, because each needs `dk_c` too.
- **Hybrid.** Both KEMs are PQ2 §5 hybrids, so each secret holds if ML-KEM-1024 *or* X25519 holds.
- **Transcript binding.** Every field of both messages is in `th`. `th` salts every key, is what sign-ins
  and live proofs name (`x-humid-th` to the unit), and is what core binds a session token to.
- The client isn't authenticated by the handshake. A person is authenticated *inside* the session (sign-in,
  live proofs), bound to `th`.

### 4.2 Resumption (one round trip, no certificate, no sign-in)

When the app locks it drops the session keys, the token and the nonce pool, and keeps the ticket (§8).
The next unlock resumes:

```
RESUME  lp(ticket) (≤ 1024) ‖ ek_c (1613) ‖ nonce_c (32) ‖ u64 time_c                         ─────►
                                    open the ticket (§4.3): unit matches, not expired, chain not too old,
                                    ticket unused (a used ticket is remembered until it expires)
                                    (ct_c, ss_e) ← Encaps(ek_c)
◄─────  REPLY  u8 mode=1 ‖ u32 gen ‖ ct_c ‖ nonce_s ‖ u64 time_s ‖ confirm,   + RECORD TICKET (the next one)

th_r    = H("HUMID-PQ2 htp2-transcript-resume", [v ‖ unit, RESUME body, sid, u8 mode, u32 gen,
                                                 ct_c, nonce_s, u64 time_s])
master  = KDF("HUMID-PQ2 htp2-resume-master", [res, ss_e], [th_r], 32)
confirm, session, res' as in §4.1 with th_r;   channel = "HTP2" ‖ unit ‖ sid (the new sid)
```

- A resumed session gets **fresh keys** (a new ephemeral KEM, a new `sid`, `seq` from 0). Nothing from an
  earlier session's records can be replayed into it.
- The **chain transcript** carries over: the unit hands the unit-level request the *first* full handshake's
  `th`, so a sign-in made in it stays valid (core binds tokens to it). Its session limits still apply
  (15 min idle, 8 h absolute; SERVER.md §5).
- `gen` counts sessions in a chain: 0 for the full handshake, +1 per resumption. A live proof's `seq` is
  `u64(gen) << 32 | rid` (§6.2), so a proof made in one session of a chain never matches a request in
  another. `REPLY` with `mode = 0` must have `gen = 0` and vice versa.
- A ticket also says whether the chain has signed in. After a sign-in the unit sends a new ticket in the
  same session, and the client keeps it in place of the old one, so the next session may carry large
  bodies at once (§5.1).
- Tickets are single use and a chain ends 8 hours after its full handshake. After that, or after a unit
  restart, the phone does a full handshake (and the core signs in again).
- **There is no 0-RTT data.** Early data under a resumption secret would be replayable. One round trip is
  the price, paid once per unlock.

### 4.3 The ticket (server-private, type `0x0302`)

```
ticket = seal_at_rest(ticket_key, 0x0302, [u8 unit],
                      u8 unit ‖ u8 signed_in ‖ u32 gen_next ‖ u64 chain_start ‖ u64 expires_at
                      ‖ chain_th (64) ‖ res (32))
```

`ticket_key` is 32 random bytes in the unit's memory (PQ2 §7.1: AES-256-GCM-SIV, random nonce). The ticket
travels to the phone inside an authenticated record, so front never sees it:

```
TICKET  14 ‖ u64 expires_at ‖ lp(ticket)
```

`expires_at = min(chain_start + 8 h, now + 8 h)`. The phone keeps `res` wiped on drop, next to the ticket.

## 5. Messages inside records

One message per record. Every decoder checks every length before reading, refuses trailing bytes and unknown
types, and refuses a message travelling the wrong way.

```
REQUEST  01 ‖ u32 rid ‖ u8 method ‖ u8 enc ‖ u8 nh ‖ (u8 name ‖ lp(value ≤ 64))×nh ‖ lp(path ≤ 1024)
            ‖ u64 body_len ‖ body_hash (64) ‖ lp(chunk 0)                                   phone → unit
BODY     02 ‖ u32 rid ‖ u32 index (≥ 1) ‖ lp(chunk)                                           both ways
PULL     03 ‖ u32 rid ‖ u32 from                                                              phone → unit
RESPONSE 11 ‖ u32 rid ‖ u16 status ‖ u8 ctype ‖ u64 body_len ‖ body_hash (64) ‖ lp(chunk 0)   unit → phone
ACK      12 ‖ u32 rid ‖ u32 next                                                              unit → phone
ERROR    13 ‖ u32 rid ‖ u16 code                                                              unit → phone
TICKET   14 ‖ u64 expires_at ‖ lp(ticket ≤ 1024)                                              unit → phone
```

| Field | Rule |
| --- | --- |
| `rid` | ≥ 1, unique in the session; the phone counts up from 1, and may reserve ids ahead (§6.2). The unit keeps a 16,384-id window above a floor that moves only when an id beyond the window arrives, so an id reserved during a long prompt survives a burst of newer requests. A reused id is `rid_reused`, also when it names a kept answer to another request (the unit compares the head's hash). |
| `method` | 1 GET, 2 POST, 3 PUT, 4 PATCH, 5 DELETE |
| `enc` | 0 raw (the unit's JSON, or empty); 1 typed parts (§6) |
| header names | `1` session token (≤ 64 bytes), `2` download ticket. Ascending, each at most once. Nothing else can be expressed, and in particular not the transcript or the client network, which the unit sets itself. |
| `path` | printable ASCII, starts with `/`, query allowed |
| bodies | requests ≤ 72 MiB, responses ≤ 80 MiB; `body_hash = SHA3-512(body)`; checked after assembly (`body_mismatch`) |
| `ctype` | 0 JSON, 1 bytes |
| `status` | 100–599, the unit's own HTTP status |

### 5.1 Chunks (1 MiB, resumable both ways)

A body of `L` bytes is `n = max(1, ⌈L / 1 MiB⌉)` chunks: every one full except the last, chunk 0 inside the
REQUEST/RESPONSE, chunks 1… in BODY messages. A full chunk fills one top-class (1 MiB + 8 KiB) frame. A
call carries at most 7 MiB of chunks (64 frames in all).

- **Upload.** The unit acknowledges every request still being assembled in the call with
  `ACK(rid, next missing)`. A phone whose call was cut sends the request from `next`. Chunks the unit holds
  are ignored; a REQUEST head sent again identical is accepted and nothing runs twice. Before any of a body
  is buffered, its **head** must pass the unit's admission check (§5.2: route, session rule, size).
  Buffers are bounded:
  - at most 4 requests assemble per session;
  - a session that hasn't signed in holds at most 1 MiB (anon's 8 MiB, for relay deposits);
  - a signed-in session holds at most one largest body;
  - one client network holds at most two largest bodies;
  - all sessions together hold at most 512 MiB.

  Past any of these the answer is `busy`. An assembly that gets no chunk for 2 minutes, or isn't complete
  10 minutes after its head, is dropped, whatever other records the session sends.
- **Download.** The unit keeps each answer for 60 s (8 per session, 4 MiB per session, a quarter of the
  buffer cap in all). Each frame of an answer is in the smallest class that fits it, raised to the
  request's cover class (at most class 2). A phone whose answer was cut sends `PULL(rid, from)` and gets
  the RESPONSE again (`from = 0`) or BODY chunks from `from`. One call re-sends a kept answer at most once,
  however many pulls or repeated heads name it, and draws at most 8 MiB out of kept answers in all; past
  that it gets `in_progress` and pulls again in its next call. This needs no new request and no new live check. A pull for an
  answer still being made is `in_progress`; for one not kept, `rid_unknown`, and the phone repeats the
  request if the route is idempotent. Documents also keep core's own per-chunk route
  (`GET /v1/objects/:id/chunks/:n` under the open's 60 s download ticket, SERVER.md §10), so a download
  cut at any point resumes from the next chunk with no new live check.

### 5.2 Dispatch at the unit

For each request **head**, before any of its body is buffered, the unit's endpoint:

1. checks method and path against the route allow-list (`front::routes`, SERVER.md §2.5): `route_not_found`
   otherwise, including any route of another unit;
2. refuses a session-token header on an anon route that must never sign in (`auth_not_allowed`);
3. refuses a body larger than the route allows: 256 KiB before the session has signed in, one document
   envelope after (`too_large`).

At most 16 requests complete per call; the rest are refused `too_many_in_flight`. For each complete
request, before the unit's code sees it, the endpoint:

4. checks a typed body parses, and that a live proof made in this session names this request's `seq`
   (`proof_mismatch`);
5. builds the internal request. It sets `x-humid-th` to the chain transcript and `x-humid-seq` to the
   request's `seq`, which core compares with the proof's own `seq` in `check_step_up`. It adds
   `authorization: Session <token>` from header 1, `x-humid-ticket` from header 2, and (core only)
   `x-humid-client-net` from front. Then the JSON body (§6.3);
6. calls the unit's own router **in process**, and seals its status, content type and body as the RESPONSE.
   A successful sign-in, or a request the session token authorised, marks the session signed in.

The unit's `/v1/…` routes answer only requests the endpoint dispatched. Over the network, front's
certificate reaches only `/htp/v2/call`, `/htp/v2/cert`, `/tlog/*` and `/healthz`. So even a front in the
attacker's hands cannot name a transcript, add a token, or send a body: it has no session.

## 6. Typed bodies and live proofs

### 6.1 Parts

```
parts = u8 n (≤ 16) ‖ part×n
part  = 01 ‖ lp(json object ≤ 256 KiB)               at most one
      | 02 ‖ lp(name: [a-z_]{1,32}) ‖ lp(bytes)       names unique (envelope, sealed_share, …)
      | 03 ‖ lp(proof)                                at most one
```

Binary fields travel as bytes: no base64 (the audit's ×1.33 and 6.2 KB per proof).

### 6.2 The live proof (type `0x0303`) and what it binds

```
proof = header(0x0303) ‖ lp(method) ‖ lp(path) ‖ th (64) ‖ u64 seq ‖ device (32) ‖ nonce (32) ‖ u64 at
        ‖ u8 mode ‖ lp(device_sig) ‖ lp(live_p256) ‖ lp(live_mldsa | "") ‖ lp(signed body ≤ 256 KiB)
```

The phone makes it inside one biometric prompt, over SERVER.md §2.3's ticket:

```
ticket     = lp(METHOD, path, th, u64 seq, device_id, nonce, u64 at_ms, u8 mode)
live_p256  = ECDSA-P256-SHA256 over H("HUMID-PQ2 live", [ticket])          secure chip (+ ML-DSA-87 where present)
device_sig = DeviceKey.sign("HUMID-PQ2 step-up", lp(ticket, SHA3-512(signed body)))
```

| V5.md "bound to one exact request" | Where it is bound | Who checks |
| --- | --- | --- |
| method, path | ticket | the unit (it knows the action it is about to take); the endpoint's allow-list first |
| body | `SHA3-512(signed body)` under the device key; the unit parses the signed body only after checking it, and the upload/open bodies name the hashes of the envelope, manifest and sealed share beside them | the unit (core; keys again on release) |
| session | `th` = the chain transcript; core also refuses a proof whose `th` isn't the session's (`session_changed`) | endpoint and unit |
| sequence | `seq = u64(gen) << 32 ‖ rid` (as a 64-bit number) of the request that carries it | endpoint, then core against `x-humid-seq` (`proof_mismatch`) |
| device | `device_id`, the device key, the chip key in the account-signed certificate | the unit (and keys) |
| single-use nonce | from the session's pool (§7.2), consumed in the action's transaction (`step_up_used`); keys and anon keep a used-proof table | the unit |
| 60 s | `at`: at most 60 s old, 5 s ahead | the unit |
| session mode | the signed `mode` must be the session's (a duress session's proofs carry 1) | core; keys reads it from the proof itself |

**Request ids are reserved before the prompt.** The prompt must know what it approves, but the body may
only exist afterwards (CORE.md §9). The client therefore reserves a request id (`Session::reserve`), so it
knows `seq`, takes a nonce from the pool, opens the prompt, and then sends the request under that id.
Reserved ids may be sent in any order. A proof whose request fails at the endpoint can't be used again,
because its `rid` is spent. The app asks for a new check.

### 6.3 What the unit receives

The endpoint turns a typed body into the JSON the unit already reads (SERVER.md §2.5 bodies): the JSON part's
fields, each byte field as unpadded base64url under its name, and the proof as
`"signed": { "proof": {…}, "body": … }`. A proof travels only as a typed proof part. The endpoint refuses
(`bad_frame`) a raw body that isn't empty or a JSON object, since serde would read an array as a struct.
It also refuses a raw body or a JSON part that carries `signed` itself. Even so, core checks `seq` itself
against `x-humid-seq`, so the binding doesn't depend on the endpoint seeing the proof.

## 7. Sessions, sign-in, the nonce pool, `/sync`

### 7.1 Signed-in sessions (core)

1. Handshake (§4).
2. `POST /v1/auth/challenge` → a stateless, single-use 56-byte challenge (SERVER.md §2.5).
3. `POST /v1/auth/login` with SERVER.md §2.3's sign-in signed over `th` → a session token, bound by core to
   `th`, and **8 step-up nonces**. The token travels as header 1 on every request; core refuses it in any
   other transcript.

### 7.2 The step-up nonce pool

Sign-in, `/v1/sync` and `/v1/auth/nonces` each return the session's unused nonces, topped up to 8 (15 min
each). A sensitive action therefore takes **one round trip**: reserve an id, take a nonce, prompt, send.
HTP/1's extra `/auth/step-up` round trip is gone.

### 7.3 Anonymous sessions (anon)

Messaging, passes and post tokens use anon sessions that never sign in. A request with a session token to
one of their routes is refused by the endpoint (`auth_not_allowed`), so a phone can't link a mailbox to an
account by mistake. The relay's tick is a fixed-size request and reply (SERVER.md §10); with size classes
both always fill the same frames. A phone may keep one anon session for all its conversations and resume it.

### 7.4 One delta `/v1/sync`

`POST /v1/sync {object_rev, ledger_seq, devices_rev}` returns everything changed since (index entries,
tombstones, ledger entries, devices) plus the nonce pool (SERVER.md §10). An unlock is: RESUME, then `/sync`.
That is two round trips, against 4.x's thirteen.

## 8. The app's client (`crates/humid-link`)

- One `Link` per unit, over a platform `Transport` (HTTPS POST to `/htp/v2/call`, GET `/htp/v2/keys`).
- Pins the identity root. It verifies the bundle and caches the certificate, using it only within its
  dates. It refetches past half life, or on `key_unknown` / `bad_cert`.
- Failures: a signature that fails is `IdentityChanged` (hard stop); an older policy is `PolicyRollback`;
  an answer that isn't a bundle is `Offline`. It keeps the policy floor (`policy_seen` /
  `set_policy_floor`) and the server's mode (`server_is_production`).
- `connect`: resume if a ticket is held, else a full handshake; a RESUME that got no answer keeps its
  ticket. `lock`: drop the session, the token and the nonces, and keep the ticket. `forget`: drop the
  ticket too.
- `step_up` reserves `(rid, seq, th, nonce)`; `call(Some(rid), …)` sends the request the proof names.
- Cut uploads continue from the unit's ACK; cut answers are PULLed.
- An unauthenticated error is never believed at once. The link sends an authenticated `PULL(rid, 0)`, up to
  twice. If an authenticated answer comes back, the session is alive and that is the answer. Only if the
  error stands does the link open a new session. Then it sends a GET again; a non-idempotent request comes
  back as `Unknown` (it may have run; the app re-reads its state). A request carrying a proof is never sent
  again. So a forged `session_unknown` can't make a request run twice.
- Holds the HTP/2 session keys (inside humid-htp, wiped on drop) and the session token (wiped on drop). It
  never holds a document key, a share or a seed: humid-core hands it opaque bytes (sealed envelopes, sealed
  shares, share requests) and receives opaque bytes back.

## 9. Errors

Session-level codes (`0x00xx`) may arrive in an unauthenticated ERROR frame (anyone on the path could send
one). Such a frame never changes the client's state: the client treats it as a hint and proves it with its
next call. Request-level codes (`0x01xx`) arrive inside an authenticated ERROR message. A unit's own
refusals (`bad_proof`, `step_up_used`, `session_changed`, `busy`, …) come back as authenticated RESPONSEs
with their status and JSON code, unchanged.

| Code | Name | HTTP | Meaning |
| --- | --- | --- | --- |
| `0x0001` | `bad_frame` | 400 | not an HTP/2 message |
| `0x0002` | `version_unsupported` | 400 | another `v` |
| `0x0003` | `unit_unknown` | 404 | unit byte not served here |
| `0x0004` | `session_unknown` | 404 | no such session: handshake again |
| `0x0005` | `replay` | 409 | record or hello already accepted, or `seq` older than the window |
| `0x0006` | `bad_record` | 400 | didn't authenticate (tampered, truncated, wrong session) |
| `0x0007` | `too_large` | 413 | over a size cap |
| `0x0008` | `rate_limited` | 429 | over a limit at front |
| `0x0009` | `busy` | 503 | endpoint full |
| `0x000A` | `stale_hello` | 400 | hello time ±5 min |
| `0x000B` | `key_unknown` | 404 | fetch the bundle again |
| `0x000C` | `ticket_unknown` | 404 | full handshake |
| `0x000D` | `handshake_failed` | 400 | bad key agreement or confirmation |
| `0x000E` | `bad_cert` | 400 | certificate or bundle doesn't verify |
| `0x0101` | `rid_reused` | 409 | request id used for another request |
| `0x0102` | `rid_unknown` | 404 | no such request (or its answer wasn't kept) |
| `0x0103` | `route_not_found` | 404 | not on the unit's allow-list |
| `0x0104` | `body_mismatch` | 400 | body ≠ announced hash |
| `0x0105` | `auth_not_allowed` | 403 | session token on a never-signed-in route |
| `0x0106` | `too_many_in_flight` | 429 | over 4 assembling requests, or 16 completed in one call |
| `0x0107` | `unit_unavailable` | 503 | the unit didn't answer front |
| `0x0108` | `internal` | 500 | bug |
| `0x010A` | `in_progress` | 409 | answer not ready; pull again |
| `0x010B` | `proof_mismatch` | 403 | a proof for another request (also core's own code when `x-humid-seq` differs) |

## 10. Versioning

`v = 1` is in every header and in both transcripts. Any change to a layout, label, constant or rule is
`v = 2`. A unit may serve several versions during a migration, but each session is one version, chosen by
the client's first frame and bound into its keys. The client pins exactly one, so there is nothing to
downgrade. HUMID-PQ2's own `{suite, v}` is inside every KDF, hash, AAD and signature context; a new suite
version is a new HTP/2 version.

## 11. Threat model

| Adversary | Can | Cannot |
| --- | --- | --- |
| **Network / anything before front** | see TLS traffic sizes and times | anything below the outer TLS 1.3 (X25519MLKEM768 required) |
| **front** (its TLS key, its internal certificate, every byte it relays) | see per call: unit, kind, size class, session id, record counter, and when; link calls of one session; delay, drop, reorder, replay, or cut calls; send unauthenticated ERROR frames; see the KEM ciphertexts and public keys of handshakes; refuse service | read or change a request, a body, a path, a method, a token, a proof or a response (AEAD under keys from two KEM secrets it has neither of); replay a record (window) or a hello (nonce table); move a record to another session (`sid` in the key, the channel and the AAD); make the endpoint run a request twice; reach the units' app routes with its own certificate; open a recorded session after stealing a unit's KEM key (ephemeral KEM); downgrade the version |
| **A thief of a unit's KEM key** (memory dump of core) | impersonate that unit to phones until its certificate expires (24 h; phones check the dates on every use and refetch at half life); see its sessions from then on | open past sessions; mint a certificate for its own key (needs the HSM statement key); act as the holder (needs the device and the biometric) |
| **core itself** | sees the signed-in requests it serves (it is their endpoint) | everything SERVER.md §11 already rules out (keys re-checks every proof) |
| **A quantum attacker with recorded traffic** | — | break either session secret (ML-KEM-1024 in both, AES-256, SHA3/KMAC) |
| **Malware on the phone, once** | use the HTP/2 session and token while it runs | make a live proof without the biometric; reuse one (seq, nonce, 60 s); use a ticket after the chain ends (8 h) |

What front learns, precisely: that some phone at an address (it terminates TLS) opened a session to core or
anon, and then for each call how many frames of which classes went each way and when. Size classes blur
request types, but don't hide them: a 2.5 MiB upload is three top-class frames. Cover padding
(`Session::set_min_class`) and the fixed-size tick narrow this for messaging. Hiding the address needs a
mixnet or Tor transport (V5.md Messaging, not in this version).

Residual risks, stated plainly:

- **A compromised front sees session ids**, so it can count a phone's actions and time them. A mitigation
  would be to rotate the `sid` per call. It isn't in v1.
- **The KEM key is software** (§2.1). Its certificate lifetime (24 h, enforced on the phone) bounds what a
  thief of it can do.
- **Unauthenticated errors** can delay a phone (it checks each with an authenticated pull) and, if they
  persist, make it handshake again: denial only, never a repeated request.
- **Endpoint capacity.** A hello never evicts a session that has sent an authenticated record, or one made
  in the last 30 s. Past the global cap (50,000) or a network's cap (64 sessions, 4,096 remembered hellos),
  new hellos are refused `busy`. Expiry runs on time-ordered queues, not scans. A determined attacker with
  many networks can still fill the endpoint for newcomers until sessions idle out (15 min); front's
  per-network and per-/48 limits make that slow.
- Resumption reuses the chain transcript, so a session token stolen by phone malware stays good for the
  chain's 8 hours (as in HTP/1, and bounded by core's idle limit).

## 12. Tests and fuzzing

- `crates/humid-htp`: unit tests per module, and `tests/props.rs` (property tests over the client/server
  pair): round trip, any flipped bit refused without burning the record, truncation, replay and reorder,
  a record moved to another session or an unknown one, downgrade and version bytes, a forged reply, an
  unknown kid, a replayed or stale hello, unauthenticated errors leave the session alone, resumption (chain
  transcript, generation, single-use tickets, chain lifetime), 1 MiB chunks with a cut upload resumed from
  the ACK and a cut download pulled, size classes, and buffer and in-flight bounds. Internal tests cover a
  body that doesn't match its hash, a proof for another request id, request-id reuse past the window, the
  kept-answer bound, and client messages travelling the wrong way.
- Fuzz targets (`crates/humid-htp/fuzz`, cargo-fuzz, one per decoder plus both state machines): `frames`,
  `messages`, `handshake_bodies`, `parts`, `certs`, `server_calls`, `client_answers`, and `sealed_messages`.
  `sealed_messages` seals fuzzer-chosen messages under a genuine session's keys in sequences of calls
  against one long-lived server, so it reaches assembly, pulls, kept answers and admission. It checks the
  per-call output, buffer and kept bounds. Each decoder target also checks that whatever decodes
  re-encodes to the same bytes.
- `tests/review97.rs` in humid-htp, humid-link and humid-server holds one regression test per finding of
  the PR #97 review. Each test failed against 932d464 and passes now (§14).
- `server/humid-server`: every flow test (`tests/flows.rs`, `review95*.rs`, `retention.rs`) runs over real
  HTP/2: the simulated phone talks to a real front on outer TLS, through `humid-link`.
  `tests/compromised_front.rs` adds: front sees no body, token, proof, id, transcript, route or JSON field
  name; altered, moved and replayed records never reach core; the app routes refuse front's certificate; a
  token on an anon route is refused; an unlock resumes the session and the sign-in holds.
  `tests/app_link.rs` has humid-core seal a 2.5 MiB document and open it again from what came back over
  HTP/2.

## 13. Open questions for the owner

1. **Session ids visible to front.** Rotating the `sid` per call (derived from the session and a counter,
   with the unit keeping a short map) would stop front linking a phone's calls. It costs a lookup and some
   complexity. Worth it in v1?
2. **Resumption lifetime.** Chains end 8 h after the full handshake (core's absolute session limit). Shorter,
   e.g. one day of unlocks but a new sign-in each time, would trade battery for exposure. Keep 8 h?
3. **Cover traffic.** `min_class` exists but the app doesn't use it yet. Should signed-in calls default to
   class 1 (4 KiB), so a sync, a sign-in and a small step-up look alike? It costs ~3 KiB per call.
4. **The software KEM key.** The certificate lifetime is 3 days and keys rotate at 12 h (half of 24 h
   validity). Shorter, if the HSM signing load allows?
5. **Registry.** Please add the `0x03xx` HTP/2 block (`0x0300` KEM certificate, `0x0301` key bundle,
   `0x0302` ticket, `0x0303` live proof) to PQ2.md's type registry, beside the server's `0x02xx`.
6. **Formal model.** V5.md asks for Tamarin/ProVerif models of the messaging handshake. This handshake
   (KEM-only, server-authenticated, with resumption) should be modelled too, before freeze.
7. **Proof shape** (SERVER.md §13.2): when the chip moves to per-action labels (`live-open`, …), only
   `proofs.rs` and §6.2 change; the wire proof already carries every field, `mode` included.
8. **Large answers kept for pulls.** Answers over 4 MiB per session aren't kept. Downloads use core's
   per-chunk route, so this only affects a future large response on another route. Is that acceptable?
9. **Endpoint capacity under a wide attacker** (§11): per-network caps assume front's network key (IPv4
   address, IPv6 /64). Should the endpoint also cap by /48, or admit new sessions only with a cheap
   proof-of-work when it is nearly full?

## 14. Changes after the PR #97 review

| Finding | Fix | Regression test |
| --- | --- | --- |
| H-1 answer amplification | answers in the class that fits, cover ≤ class 2 both ways; one re-send per kept answer per call; 8 MiB answer budget per call; ≤ 64 frames per call; front reads ≤ 96 MiB back | humid-htp `h1_answers_are_not_amplified`, `h1_output_per_call_is_bounded` |
| M-1 proof `seq` bypass | endpoint passes `x-humid-seq`, core checks it in `check_step_up` (`Expect.seq`); raw bodies must be objects without `signed`; JSON parts may not carry `signed` | humid-server `m1_a_proof_is_bound_to_its_request_in_every_body_shape`, `m1_core_checks_seq_itself`; `htp::tests::a_proof_cannot_be_smuggled_past_the_seq_check` |
| M-2 buffer squatting | head-time admission (route, session rule, size); per-session, pre-sign-in, per-network and global byte caps; assemblies dropped after 2 min idle / 10 min total | humid-htp `m2_unknown_routes_buffer_nothing`, `m2_assembly_buffer_squatting_is_bounded`; `htp::tests::admission_runs_on_the_head` |
| M-3 eviction, replay tables | never evict a session that sent a record or is < 30 s old; per-network session and hello caps; time-ordered expiry; front limits handshakes per /48 | humid-htp `m3_hellos_do_not_evict_live_sessions`, `m3_a_fresh_session_is_not_evicted_by_a_hello_flood` |
| M-4 per-call rate limit | front counts frames, per session and per network; ≤ 16 requests dispatched per call | humid-htp `m4_requests_per_call_are_capped` |
| M-5 forged `session_unknown` | authenticated pull before believing it; only GETs re-sent; others `Unknown` | humid-link `m5_a_forged_session_unknown_never_runs_a_request_twice` |
| M-6 expired certificate | `Handshake::full` checks the dates; link refetches at half life | humid-htp `m6_an_expired_certificate_is_refused_by_the_client`; humid-link `m6_the_link_refetches_and_never_uses_an_expired_certificate` |
| L-1 policy rollback, mode | link keeps a policy floor, refuses older; surfaces production mode | humid-link `l1_policy_is_forward_only` |
| L-2 client network | passed through only when present; never to anon | humid-server `l2_anon_gets_no_client_address` |
| L-3 link errors | non-bundle answer is `Offline`; RESUME without an answer keeps the ticket | humid-link `l3_a_transient_error_is_not_identity_changed`, `l3_offline_during_resume_keeps_the_ticket` |
| L-4 fuzz depth | `sealed_messages` target; world set up once | (fuzz) |
| L-5 request ids | head hash compared before replaying a kept answer; 16,384-id window | humid-htp `l5_request_id_edge_cases` |
| L-6 size-class leaks | ERROR and ACK in the request's (capped) class | humid-htp `l6_refusals_use_the_requests_class` |
| L-7 doc mismatches | this revision | — |
