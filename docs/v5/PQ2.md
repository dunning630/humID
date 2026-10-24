# HUMID-PQ2 — suite specification, version 1

Status: **draft for review, 23 October 2026.** Frozen once 5.0 ships: any change to a primitive,
label, constant or layout is a new version (`v = 2`), never an edit.
Reference implementation: [`crates/humid-pq2`](../../crates/humid-pq2). Design context:
[V5.md](../V5.md), "One crypto suite: HUMID-PQ2". The core that uses it: [CORE.md](CORE.md).

This document is meant to be enough to write a second, interoperating implementation. Where it
and the code disagree, that is a bug in one of them; the known-answer and cross-check vectors in
§11 decide which.

## 1. Primitives

| Job | Primitive | Standard | Sizes (bytes) |
| --- | --- | --- | --- |
| Key encapsulation, post-quantum leg | ML-KEM-1024 | FIPS 203 | ek 1568, ct 1568, ss 32, seed `d‖z` 64 |
| Key agreement, classical leg | X25519 | RFC 7748 | pk 32, scalar 32, shared 32 |
| Everyday signature | ML-DSA-87, **hedged**, pure, external interface with context | FIPS 204 | pk 2592, sig 4627, seed ξ 32 |
| Hash-based signature (roots) | SLH-DSA-SHA2-256s, hedged, pure, external with context | FIPS 205 | pk 64, sig 29792, seed 96 |
| Encryption at rest | AES-256-GCM-SIV | RFC 8452 | key 32, nonce 12, tag 16 |
| Encryption in transit | AES-256-GCM | SP 800-38D | key 32, nonce 12, tag 16 |
| Key derivation | KMAC256 | SP 800-185 | any output length 1–8192 |
| Hash / XOF | SHA3-512, SHAKE256 | FIPS 202 | 64 / any |
| Randomness | platform CSPRNG only (`getrandom`: `getrandom(2)`, `SecRandomCopyBytes`, `BCryptGenRandom`) | | |

Not in version 1: HQC-256 for the vault root (added as `v = 2` once NIST's standard is final);
the TLS layers (V5.md's TLS rows are transport configuration, not this suite).

Notation. `‖` is concatenation. `u16(x)`, `u32(x)`, `u64(x)` are big-endian. `"…"` is the ASCII
bytes of the string, no terminator. `[a, b, …]` is a list of byte strings.

```
lp(a, b, …) = u32(len a) ‖ a ‖ u32(len b) ‖ b ‖ …       every part < 2^32 bytes
```

`lp` of the empty list is the empty string; `lp("")` is `00 00 00 00`. Two different lists never
have the same `lp`.

## 2. `{suite, v}` and object headers

```
SUITE  = "HUMID-PQ2" ‖ u16(1)                     = 48 55 4D 49 44 2D 50 51 32 00 01   (11 bytes)
header(type) = SUITE ‖ u16(type)                  (13 bytes)
```

Every stand-alone encoding starts with `header(type)`; every KDF input, AAD, labelled hash and
signature context contains `SUITE`. A decoder checks the full 13 bytes and refuses any other
suite, version or type, and refuses trailing bytes.

### Type codes

One registry for all of HumID 5.0. `0x00xx` are suite objects (this document); `0x01xx` are
humid-core records (CORE.md).

| Code | Object | Code | Object |
| --- | --- | --- | --- |
| `0x0001` | hybrid KEM public key | `0x0100` | device wrap `W_n` |
| `0x0002` | hybrid KEM ciphertext | `0x0101` | document manifest |
| `0x0003` | ML-DSA-87 verifying key | `0x0102` | document chunk (AAD only) |
| `0x0004` | ML-DSA-87 signature | `0x0103` | document signed statement (signature context) |
| `0x0005` | SLH-DSA-SHA2-256s verifying key | `0x0104` | document device slot |
| `0x0006` | SLH-DSA-SHA2-256s signature | `0x0110` | index entry |
| `0x0007` | dual verifying key | `0x0111` | settings |
| `0x0008` | dual signature | `0x0112` | offline copy |
| `0x0009` | generic at-rest box | `0x0113` | record revisions |
| `0x000A` | generic sealed box | `0x0114` | message store |
| `0x0010` | share, phone → key service | | |
| `0x0011` | share, key service → phone | | |
| `0x0020` | transit record (AAD only) | | |

## 3. Labels

A label is `"HUMID-PQ2 "` followed by 1–48 characters from `a–z 0–9 -`. Implementations refuse
anything else. Labels used by the suite itself:

| Label | Use |
| --- | --- |
| `HUMID-PQ2 hybrid-kem` | the KEM combiner (§5) |
| `HUMID-PQ2 sealed-box` | key of a box sealed to a public key (§7.2) |
| `HUMID-PQ2 key-id` | key ids (§4) |

humid-core's labels (`HUMID-PQ2 device-wrap`, `HUMID-PQ2 doc`, …) are listed in CORE.md.

## 4. KDF, labelled hash, key id

### 4.1 KMAC256

As SP 800-185 §4.3, with `N = "KMAC"`:

```
KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) ‖ X ‖ right_encode(L), L, "KMAC", S)
```

`L` is in bits. `left_encode`, `right_encode`, `encode_string` and `bytepad` are SP 800-185 §2.3.

### 4.2 KDF

```
KDF(label, key = [k1, …, km], context = [c1, …, cn], len) =
    KMAC256(K = lp(k1, …, km), X = SUITE ‖ lp(c1, …, cn), L = 8·len, S = label)
```

Secret inputs go in `key`; public inputs (ids, ciphertexts, public keys, counters) in `context`.
`len` is 1–8192 bytes; KMAC's `L` makes outputs of different lengths unrelated.

### 4.3 Labelled hash and key id

```
H(label, [p1, …, pn])  = SHA3-512(SUITE ‖ lp(label, p1, …, pn))
key_id(encoding)       = first 32 bytes of H("HUMID-PQ2 key-id", [encoding])
```

`encoding` is a key's full stand-alone encoding, header included, so a KEM key and a signing key
with equal bytes still get different ids.

## 5. Hybrid KEM (ML-KEM-1024 + X25519)

### Keys

```
secret seed (96)   = d (32) ‖ z (32) ‖ x (32)
ML-KEM             = ML-KEM.KeyGen_internal(d, z)               → ek (1568), dk
X25519             = scalar x (clamped as RFC 7748), X = X25519(x, 9)
public key (1613)  = header(0x0001) ‖ ek ‖ X
```

Decoding a public key runs FIPS 203's encapsulation-key check (§7.2: `ByteEncode12(ByteDecode12(ek)) = ek`)
and refuses keys that fail it. A secret key is stored only as its 96-byte seed, and only sealed.

### Encapsulation to (ek, X)

```
m     ← 32 random bytes;   (ct_k, ss_k) = ML-KEM.Encaps_internal(ek, m)
e     ← 32 random bytes;   E = X25519(e, 9);   ss_x = X25519(e, X)
refuse if ss_x is all zero (X a low-order point)
ss    = KDF("HUMID-PQ2 hybrid-kem", key = [ss_k, ss_x], context = [ct_k, E, ek, X], 32)
ciphertext (1613) = header(0x0002) ‖ ct_k (1568) ‖ E (32)
```

### Decapsulation with (dk, x)

```
ss_k = ML-KEM.Decaps(dk, ct_k)       (implicit rejection: a bad ct gives an unrelated ss_k)
ss_x = X25519(x, E);  refuse if all zero
ss   = KDF("HUMID-PQ2 hybrid-kem", [ss_k, ss_x], [ct_k, E, ek, X], 32)
```

One combiner binds **both secrets, both ciphertexts and both public keys**: `ss` is pseudo-random
if either ML-KEM-1024 or X25519 holds (it is a KDF keyed by both secrets), a ciphertext can't be
re-targeted to another key or recombined with half of another ciphertext (both halves and both
public keys are in the context). X-Wing leaves ML-KEM's ciphertext and key out of its combiner
and relies on ML-KEM's own binding properties; HUMID-PQ2 includes them, at the cost of one more
KMAC block, so it relies on nothing beyond "ML-KEM-1024 is IND-CCA2 or X25519 is gap-DH".
Encapsulation and decapsulation errors never say which half failed.

## 6. Signatures

All signatures use the FIPS 204 / FIPS 205 **pure** signing interface with a context string
(`M' = 0x00 ‖ u8(|ctx|) ‖ ctx ‖ M`, done by the algorithms themselves):

```
ctx(type, label) = SUITE ‖ u16(type) ‖ label            (≤ 71 bytes)
```

`type` is the signature's own type code: `0x0004` for a stand-alone ML-DSA-87 signature,
`0x0006` for a stand-alone SLH-DSA signature, `0x0008` for both halves of a dual signature, and a
humid-core type for core statements (for example `0x0103` for a document). So a signature made
for one purpose never verifies for another, and half of a dual signature never verifies as a
stand-alone one.

### 6.1 ML-DSA-87 (everyday)

```
keys              ML-DSA.KeyGen_internal(ξ), ξ = 32-byte seed (store only ξ, sealed)
sign (hedged)     rnd ← 32 random bytes;  σ = ML-DSA.Sign_internal(sk, M', rnd)     (FIPS 204 §3.4)
verifying key     header(0x0003) ‖ pk (2592)              = 2605 bytes
signature         header(0x0004) ‖ σ (4627)               = 4640 bytes
```

Inside larger structures the raw `pk` / `σ` (without header) may appear when the structure's own
header already names them.

### 6.2 SLH-DSA-SHA2-256s

```
keys              slh_keygen_internal(SK.seed, SK.prf, PK.seed) from a 96-byte seed in that order
sign (hedged)     opt_rand ← 32 random bytes;  slh_sign_internal(M', opt_rand)
verifying key     header(0x0005) ‖ PK.seed ‖ PK.root (64) = 77 bytes
signature         header(0x0006) ‖ sig (29792)            = 29805 bytes
```

### 6.3 Dual signature (long-lived roots)

For ledger and log checkpoints, the release key, server identity and account-root changes.

```
verifying key     header(0x0007) ‖ ML-DSA pk (2592) ‖ SLH-DSA pk (64)          = 2669 bytes
signature         header(0x0008) ‖ ML-DSA σ (4627) ‖ SLH-DSA sig (29792)        = 34432 bytes
both halves sign the same M with ctx = SUITE ‖ u16(0x0008) ‖ label
valid             only if BOTH halves verify
```

## 7. Symmetric encryption

### 7.1 At rest: AES-256-GCM-SIV

```
box(type, key, aad_parts, pt) = header(type) ‖ nonce (12) ‖ AES-256-GCM-SIV(key, nonce, A, pt) ‖ tag (16)
A     = header(type) ‖ lp(aad_parts…)
nonce ← 12 random bytes
```

Overhead 41 bytes. `aad_parts` binds a record to what it describes (item id, revision, device,
counter); a record type uses one fixed list shape. Plaintext ≤ 64 MiB per box (larger data is
chunked by the caller, CORE.md §6). GCM-SIV is used everywhere at rest because keys there live a
long time and a repeated random nonce must not be catastrophic.

### 7.2 Sealed to a public key

```
(kem_ct, ss) = Encaps(recipient)                            (§5; kem_ct = ct_k ‖ E, 1600 bytes)
k     = KDF("HUMID-PQ2 sealed-box", [ss], [header(type), kem_ct, key_id(recipient)], 32)
A     = header(type) ‖ lp(aad_parts…)
box   = header(type) ‖ kem_ct (1600) ‖ AES-256-GCM-SIV(k, nonce = 0^12, A, pt) ‖ tag (16)
```

Overhead 1629 bytes. `k` is used for exactly one message, so the fixed zero nonce is safe.

### 7.3 Shares (both directions)

A document's 32-byte key share `share_ks` is a sealed box (§7.2):

| Direction | Type | Recipient | `aad_parts` |
| --- | --- | --- | --- |
| phone → key service | `0x0010` | key service's pinned hybrid KEM key | `[account id, document id, binding]` |
| key service → phone | `0x0011` | a one-time hybrid KEM key the phone made for this open | `[account id, document id, binding]` |

`binding` is the manifest hash for an upload and the hash of the signed open request for a
release. A sealed share is always 1661 bytes; anything else is refused before decryption.

### 7.4 In transit: AES-256-GCM with counter nonces

One key per direction (from the session's handshake, outside this suite version's scope; the
handshake uses §5 and §4.2).

```
nonce(seq) = 00 00 00 00 ‖ u64(seq)
A          = header(0x0020) ‖ lp(channel, u64(seq), extra_aad)
record     = AES-256-GCM(key, nonce(seq), A, pt) ‖ tag (16)        seq sent alongside
```

The sender's `seq` starts at 0 and only increases; it stops at 2^64−1. The receiver keeps the
highest accepted `seq` and a 256-record window; it accepts a record only after its tag verifies,
and each `seq` at most once; a `seq` older than the window is refused. A record that fails to
verify doesn't consume its `seq`.

## 8. Hashes

`SHA3-512` for content and transcript hashes; `SHAKE256` where an XOF is needed. SHA3-256 and
SHA-256 are not used by HUMID-PQ2's own formats (they remain where an external standard demands
them: App Attest, FIDO, X.509).

## 9. Implementation rules

1. Secrets (`ss`, seeds, AEAD keys, KDF outputs, plaintexts) live in wiping containers, have no
   printable form, and are compared in constant time.
2. Decoders check every length before reading, refuse trailing bytes and never panic.
3. Failure doesn't say why: one error for "didn't authenticate", one for "didn't verify".
4. Randomness only from the platform CSPRNG. ML-DSA and SLH-DSA always sign hedged in production;
   deterministic signing exists only for the known-answer tests.
5. At start, run the power-on self-test (`humid_pq2::self_test`: FIPS 202, SP 800-185, RFC 8452
   and NIST keyGen answers, a randomness check, and pairwise KEM and signature checks) and refuse to
   run if it fails.

## 10. Sizes at a glance

| Object | Bytes |
| --- | --- |
| hybrid public key / ciphertext | 1613 / 1613 |
| ML-DSA-87 verifying key / signature (encoded) | 2605 / 4640 |
| SLH-DSA-SHA2-256s verifying key / signature (encoded) | 77 / 29805 |
| dual verifying key / signature | 2669 / 34432 |
| at-rest box overhead | 41 |
| sealed box overhead / sealed share | 1629 / 1661 |
| transit record overhead | 16 (+ `seq` on the wire) |

## 11. Test vectors

| What | Source | Where |
| --- | --- | --- |
| ML-KEM-1024 keyGen, encaps, decaps (incl. malformed ct), ek/dk checks | NIST ACVP-Server `975de31e` | `tests/fixtures/acvp/` (shared with the 4.x JS KATs) |
| ML-DSA-87 keyGen, sigGen (deterministic + hedged, pure external with context), sigVer | NIST ACVP | `tests/fixtures/acvp/` |
| SLH-DSA-SHA2-256s keyGen, sigGen (deterministic + hedged), sigVer (every failure reason) | NIST ACVP | `tests/fixtures/acvp-pq2/` |
| KMAC-256 (AFT and MVT, XOF and fixed, text and hex customization) | NIST ACVP | `tests/fixtures/acvp-pq2/` |
| KMAC256 / KMACXOF256 samples 4–6 | NIST SP 800-185 examples | in `kat.rs` |
| SHA3-512 (AFT + Monte Carlo), SHAKE-256 (AFT + variable output) | NIST ACVP | `tests/fixtures/acvp-pq2/` |
| AES-256-GCM-SIV | RFC 8452 C.2 and C.3 (re-checked with OpenSSL) | `crates/humid-pq2/tests/vectors/` |
| AES-256-GCM | NIST CAVS gcmEncryptExtIV256 (re-checked with OpenSSL) | `crates/humid-pq2/tests/vectors/` |
| X25519 | RFC 7748 §5.2, §6.1 | `crates/humid-pq2/tests/vectors/` |
| Cross-check with the 4.x JS (@noble): ML-KEM, ML-DSA hedged with given `rnd`, X25519, SLH-DSA keys, **and HUMID-PQ2's KDF, combiner, key id, at-rest and sealed boxes computed in JS from this document** | `tools/pq2-noble-vectors.mjs` | `crates/humid-pq2/tests/vectors/noble-interop.json` |

Refresh: `node tools/acvp-vectors.mjs <ACVP json-files dir> <commit> --pq2`,
`python3 -I tools/pq2-rfc-vectors.py <cargo registry src> crates/humid-pq2/tests/vectors`,
`node tools/pq2-noble-vectors.mjs`.
