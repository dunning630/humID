# HTP/1 — HumID Transit Protocol

Status: **POC, version 1**. Reference implementation: `packages/htp`.
Tests: `tests/htp.test.js`. Needs an independent cryptographic review before it carries real customer data.

## Why a protocol on top of TLS

TLS 1.3 protects the connection to the edge, and the edge negotiates the
post-quantum hybrid group `X25519MLKEM768` with clients that support it. TLS
alone has three gaps for a personal-data vault:

1. **TLS ends at the edge.** Anything that terminates TLS (a load balancer, a
   CDN, a misconfigured proxy) sees plaintext. HTP frames are opaque to all of
   them. Only the gateway service holds HTP session keys.
2. **The app cannot pin the server through the platform TLS stack** in a
   webview. HTP authenticates the server by a key id the app pins at build time
   or on first enrolment, independent of the certificate chain.
3. **TLS has no notion of a person.** HTP binds a session to a holder's
   ML-DSA-87 identity key, and binds every sensitive request to a fresh
   biometric check (a *step-up proof*).

HTP composes standard primitives only: ML-KEM-1024 (FIPS 203), ML-DSA-87
(FIPS 204), X25519 (RFC 7748), HKDF (RFC 5869) with SHA3-256 (FIPS 202),
HMAC-SHA3-256 and AES-256-GCM. Libraries: `@noble/post-quantum`,
`@noble/curves`, `@noble/hashes`, WebCrypto.

## Transport

Three HTTPS endpoints, all on the gateway:

| Endpoint | Body | Purpose |
|---|---|---|
| `GET /htp/v1/keys` | JSON | Server's static public keys and key id. Never cached. |
| `POST /htp/v1/hello` | JSON ClientHello → JSON ServerHello | Handshake (one round trip). |
| `POST /htp/v1/call` | `application/vnd.humid.htp` frame → frame | Every API call after the handshake. |

Proxies and CDNs see only POSTs of opaque bytes to `/htp/v1/call`. Method,
path, headers, status and body of the inner request are all encrypted.

## Server identity

The server holds a static key set: ML-KEM-1024 (`kemPk`), X25519 (`xPk`) and
ML-DSA-87 (`dsaPk`). Its key id binds all three:

```
kid = SHA3-256("HTP/1 server key" || lp(kemPk, xPk, dsaPk))
fingerprint = first 16 bytes of kid, hex, groups of 4  (e.g. 7A3F-91C2-…)
```

`lp(a, b, …)` is length-prefixed concatenation: `u32(len a) || a || u32(len b) || b …`,
so no two field lists encode to the same bytes.

The app accepts a server only if `kid` matches its pin:

- **Build-time pin** — `HUMID_SERVER_KID` is compiled into the app. Production setting.
- **Trust on first use** — with no build-time pin, the app records the kid at
  enrolment and refuses any other kid afterwards.

A changed key is never accepted silently. The client raises
`server_identity_changed` and the app stops on a warning screen.

## Handshake

```
Client                                               Server (static KEM_S, X_S)
ekC, dkC  <- ML-KEM-1024.KeyGen()      (ephemeral)
xC        <- X25519 ephemeral
ctS, ssS  <- ML-KEM-1024.Encaps(KEM_S.pk)

ClientHello { v, suite, kid, nC, ts, ekC, xC, ctS }  ------>
                                                      check v, suite, kid, |now - ts| <= 5 min
                                                      ssS       <- Decaps(KEM_S.sk, ctS)
                                                      ctC, ssE  <- Encaps(ekC)
                                                      xS        <- X25519 ephemeral
                                                      ssXS      <- X25519(X_S.sk, xC)
                                                      ssXE      <- X25519(xS.sk, xC)
                         <------  ServerHello { v, sid, nS, exp, ctC, xS, confirm }
ssE <- Decaps(dkC, ctC); ssXS <- X25519(xC.sk, X_S.pk); ssXE <- X25519(xC.sk, xS)
```

Key schedule, identical on both sides:

```
th      = SHA3-256("HTP/1 handshake" || lp(kid, nC, u64 ts, ekC, xC, ctS, sid, nS, u64 exp, ctC, xS))
ikm     = ssS || ssE || ssXS || ssXE
kC2S    = HKDF-SHA3-256(ikm, salt = th, info = "HTP/1 c2s key",     32)
kS2C    = HKDF-SHA3-256(ikm, salt = th, info = "HTP/1 s2c key",     32)
kConf   = HKDF-SHA3-256(ikm, salt = th, info = "HTP/1 confirm key", 32)
confirm = HMAC-SHA3-256(kConf, "HTP/1 server confirm" || th)
```

The client checks `confirm` in constant time and aborts on mismatch. Field
sizes are fixed and checked: `ekC` and `ct*` 1568 bytes, `x*` 32, nonces 32,
`sid` 16, `kid` 32. Suite string: `HTP1-MLKEM1024+X25519-HKDF-SHA3-256-AES256GCM`.

What this gives:

| Property | How |
|---|---|
| Hybrid security | Session keys depend on both ML-KEM-1024 and X25519 secrets. An attacker must break both. |
| Server authentication | Only the holder of `KEM_S.sk` and `X_S.sk` can compute `ssS` and `ssXS`, so only it can produce `confirm`. |
| Forward secrecy | `ssE` and `ssXE` come from ephemerals discarded after the handshake. Stealing the server's static keys later does not decrypt recorded sessions. |
| Transcript binding | Every field of both hellos is in `th`, which salts the key schedule and is signed into every proof. |

Ephemeral secrets and the input keying material are zeroed after use.

## Frames

Every call after the handshake is exactly one request frame and one response frame.

```
header (37 bytes)   "HTP" 0x01 | dir (1 = request, 2 = response) | sid (16) | seq (u64) | ts (u64 ms)
nonce               0x00000000 || u64 seq
ciphertext          AES-256-GCM(key = dir == 1 ? kC2S : kS2C, nonce, plaintext, aad = header)
plaintext           u32 metaLength || meta JSON || body bytes

request meta        { m: method, p: path, h?: headers, proof?: { at, sig, interrupt, live? } }
response meta       { s: status, h?: headers }
```

- The header is authenticated as associated data. Changing session, direction,
  sequence or time breaks the tag.
- The client increments `seq` per request. The response reuses the request's
  `seq` under the other direction's key, so no (key, nonce) pair repeats.
- The server keeps a 256-entry sliding replay window per session. A `seq` is
  processed at most once, and anything older than the window is refused.
- Frames with `ts` more than 2 minutes from server time are refused.
- The meta JSON is at most 64 KiB (`bad_frame` otherwise). A frame from a
  session that hasn't signed in is at most 512 KiB; a signed-in session's frame
  may be as large as a vault upload, but once it is open the gateway holds the
  body to the route's own cap before anything parses it (`413 too_large`):
  64 KiB for JSON and control routes, a few hundred KiB for recovery routes
  that carry envelopes or ID-chip reads, and the full frame cap only for
  `POST /vault/objects`.
- Sessions expire after 15 minutes idle and 8 hours absolute. Logout, closing
  the identity and expiry all erase the session keys on the server.

## Binding a person to the session

A HumID account has an **account key** and one **device key** per device
(see [RECOVERY.md](RECOVERY.md)). Both are ML-DSA-87 keys derived from seeds
that a device releases only after a live biometric check (Secure Enclave or
Keystore on mobile). Every proof below is made during that check.

Phones also hold a **liveness key**: P-256 in the Secure Enclave or Android
Keystore, usable only right after a live face or fingerprint match, never
with a PIN or passcode. It signs the same check's challenge, so the server
can verify a live check approved each action (ECDSA-SHA256, DER; the key is
sent as SubjectPublicKeyInfo).

```
account id    = "hid_" || hex(SHA3-256(account dsaPk))[0:40]
device id     = "dev_" || hex(SHA3-256(device dsaPk))[0:24]

register      account key over "HTP/1 register" || lp(th, SHA3-256(kemPk), SHA3-256(dsaPk), xPk, commit)
device        account key AND device key over "HTP/1 device" || lp(th, account id, SHA3-256(device dsaPk))
login         device key over "HTP/1 login"   || lp(th, "<account id>/<device id>", challenge)   challenge: 32 random bytes, single use
step-up       device key over "HTP/1 step-up" || lp(th, u64 seq, METHOD, path, SHA3-256(body), u64 at)

liveness key (phones):
device        same "HTP/1 device" bytes, plus the key's attestation made for th
login         same "HTP/1 login" bytes
step-up       "HTP/1 live" || lp(th, u64 seq, METHOD, path, u64 at)        known before the body, see tickets
seal          "HUMID-SEAL-v1" || SHA3-512(envelope ciphertext)             carried in the envelope's interrupt.live
```

**Attestation** (sent once, with the `device` statement):

- Android: `{ kind: "android-key", chain: [DER…] }`, the Keystore certificate
  chain. The server verifies it to a pinned Google root, then requires a
  hardware key (TEE or StrongBox), EC P-256, `userAuthType` biometric only
  (no password bit), auth per use, not valid while on-body, a locked
  bootloader with verified boot, the HumID package (and signing-cert digest if
  configured), and `attestationChallenge = th`. The leaf's key must be the
  liveness key.
- iPhone: `{ kind: "apple-app-attest", object }`. The server verifies it to
  Apple's App Attestation Root and checks the app id, environment, counter 0,
  key id, and `clientDataHash = SHA-256(th || liveness key SPKI)`.

The verified proof (`android-tee`, `android-strongbox`, `apple-secure-enclave`)
is stored with the device. After that, the device's login, step-ups and
seals must carry valid liveness signatures (`bad_live_proof`,
`no_live_seal`). The server's **device policy** (`/htp/v1/keys` →
`policy.devicePolicy`) decides who may join: `attested` (proven phones only,
the default), `biometric` (also biometric-only desktops, which have no
liveness key), or `demo` (development).

**Tickets.** The biometric prompt has to know what it is approving before it
opens, but the request body may only exist afterwards (a decrypted key to
re-seal, say). So the client first reserves the request's slot, a ticket
`{ sid, seq, at, METHOD, path }`, and the liveness key signs the ticket's
`HTP/1 live` bytes. The device key's step-up signature, made in the same
check, still covers the body. The replay window accepts the reserved `seq`
even if other calls went first.

- **Register** creates the account. It is proof of possession: the server
  stores the account's public keys only if the holder can sign with them, in
  this session. The first device is added in the same call with a `device`
  statement.
- **Device** adds a device. It needs two signatures over the same bytes: the
  account key's (only a holder of the account seed can authorise a device)
  and the new device key's (proof of possession). How a new device gets the
  account seed is in [RECOVERY.md](RECOVERY.md).
- **Login** answers a fresh single-use server challenge, signed by one device
  key. A removed device's key is refused. Sign-in attempts are rate-limited
  per account.
- **Step-up** is required for opening, deleting or exporting a document,
  approving a new device, removing one, changing recovery settings, helping
  someone recover, cancelling a recovery, and closing the account. It names
  the exact request (sequence number, method, path, body hash), is at most 60
  seconds old, and is bound to this session through `th`. A captured proof
  cannot be reused for another request, another session, or later.

The gateway records `SHA3-256(sig)[0:16]` of each proof in the ledger as
evidence that a biometric check preceded the action.

## Key codes

When one screen must tell another about public keys (a new device, a
recovery contact, a recovery request), it shows a 12-character code:

```
code = Crockford-base32( SHA3-256(label || lp(public keys…)) )[0:12]      60 bits
```

The device that types the code recomputes it from the keys the server
returns and refuses to continue on a mismatch (`code_mismatch`), so a server
that substitutes its own keys is caught before anything is sealed. Labels:
`HUMID-LINK-v1`, `HUMID-CONTACT-v1`, `HUMID-RECOVER-v1`.

## Errors

The client surfaces these codes:

| Code | Meaning |
|---|---|
| `server_identity_changed` | Server's kid differs from the pin. Hard stop. |
| `server_unreachable` | Keys or hello endpoint unavailable. |
| `session_expired` / `session_unknown` | Server no longer knows the session. The client drops its keys and the app asks for a new biometric sign-in. |
| `replay` / `stale_frame` | Sequence number reused, or frame time outside the window. |
| `step_up_required` / `step_up_stale` / `bad_proof` | Sensitive request without a valid, fresh proof. Rejected proofs are logged as `access.denied`. |
| `rate_limited` | 30 handshakes per minute per IP, 600 calls per minute per session, failed sign-in proofs: 10 per 5 minutes per identity, 20 per address, 200 in all (past the budget a failure is `rate_limited`; a valid proof is never refused). Frames: 512 KiB before sign-in, an unknown session `session_unknown` from the header alone. |
| `too_large` | A body over the frame cap, or over the route's own cap once the frame is open. |
| `audit_unavailable` | The ledger could not record an access, so the access was refused (fail closed). |
| `device_removed` | This device was removed from the account. |
| `device_not_proven` | The device can't prove a live check the way the server's device policy requires. |
| `bad_live_proof` | The liveness key's signature is missing or wrong. Logged as `access.denied` (`no_live_biometric`). |
| `no_live_seal` | A phone uploaded an envelope its liveness key didn't sign. |
| `wrong_challenge` / `software_key` / `no_biometric` / `pin_allowed` / `not_per_use` / `unlocked_device` / `wrong_app` / `untrusted_root` / `bad_attestation` | Android key attestation refused, and why. |
| `wrong_environment` / `not_configured` | App Attest refused: development object on a production server, or the server has no iOS app id. |
| `session_changed` / `ticket_mismatch` | A ticket was used in another session or for another request. |
| `code_mismatch` | A typed code doesn't match the keys the server returned. Hard stop. |

## Versioning

`v` and `suite` are checked on every hello. Any change to a primitive, label
or layout is a new version. Servers may accept several versions during a
migration. Clients pin exactly one.
