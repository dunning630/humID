# humid-core — design

Status: **draft for review, 24 October 2026; revised after the independent review of PR #94
(findings H1–H3, M1–M7, L1–L8, each with a regression test in `crates/humid-core/tests/review94.rs`
or the crate's unit tests).** Skeleton implemented in
[`crates/humid-core`](../../crates/humid-core) against a software stand-in for the hardware; no
platform code yet. Built on [HUMID-PQ2](PQ2.md). Requirements: [V5.md](../V5.md) ("The device
key", "Opening a document", "App architecture"); findings: audit area 1 (crypto) and its
independent verification.

Owner decisions this design assumes: clean break from 4.x (no 4.x format is read); iOS 26+ and
Android 17+ only; a Tauri app whose Rust core holds every key, with a web UI that holds none.

## 0. What changes from 4.x, in one table

| 4.x | 5.0 core |
| --- | --- |
| The gate releases a stored 32-byte secret, as base64, into the WebView (audit H2) | The hardware computes a fresh output per unlock inside the biometric check; the bytes go to Rust only and are wiped |
| `wrapped` never changes after enrolment | `W_n → W_{n+1}` on every unlock; the old wrap's hardware key is deleted |
| Seeds and four session keys in the JS heap | Seeds and keys only in the core, in wiping containers; the UI gets results |
| Two-key documents: inner AES under the share, outer envelope to the account | Three-key documents (`ss_acct`, `HW_doc`, `share_ks`), one layer of chunked GCM-SIV |
| Share in plaintext at the gateway on upload (H1) | Share sealed phone → key service and key service → phone |
| Index v1 fallback, unbound labels (M2) | One AAD shape per record type, revisions that only grow |
| 2 prompts per check on Android | 1 prompt per action is a hard requirement (§5) |

## 1. The API the UI may call

The web UI talks to the core through Tauri commands. The rule: **opaque handles in, results
out.** Nothing that crosses the bridge is a key, a seed, a hardware output or a share, and the
only plaintext that crosses is what the screen shows (a document's name and type, and its bytes
streamed into a viewer sink that renders and forgets them).

| Call | UI gives | UI gets | Prompts |
| --- | --- | --- | --- |
| `enroll(prompt, challenge)` | server challenge | public identity, live proof | 1 |
| `unlock(prompt, challenge)` | server challenge | public identity, live proof, wrap counter | 1 |
| `lock()` | | | 0 |
| `enter_decoy()` | | | 0 |
| `identity()` | | public identity | 0 |
| `seal_document(prompt, meta, input, out, key_service_pk, challenge)` | a byte source (file picker / camera), an upload sink | receipt: doc id, manifest hash, envelope hash, size, this device's slot, sealed share, live proof | 1 |
| `begin_open(prompt, slot, challenge)` | the slot the vault listed | open handle, share request, live proof, adopted slot (if any) | 1 |
| `finish_open(handle, sealed_share, envelope, viewer)` | what the servers returned, a viewer sink | name, type, size | 0 |
| `begin_join(account_id)` (new device) | the account to join | self-signed join request, the **code to show** | 0 |
| `grant_device(prompt, request, typed_code, slots, challenge)` (old device) | the request, the code the person typed, the slots | grant (sealed) and pending slots, binding, live proof | 1 (see §5.3) |
| `finish_join(prompt, grant, challenge)` (new device) | what the old device sent | public identity, live proof | 1 |
| `pending_adoptions()` | | how many granted documents still wait for a first open | 0 |
| `seal_index_entry(id, current, entry)` / `open_index_entry(id, blob)` | the vault's current blob (if any), entry text / blob | blob / entry text | 0 |
| `reset_records()` | after telling the person | | 0 |
| `set_setting(name, value)` / `setting(name)` | names `[a-z0-9-]{1,64}` | | 0 |

Rules the bridge keeps:

- Every secret-holding type in the core has no `Debug`, `Serialize` or `Clone`; the Tauri command
  layer can only return the result structs above, which hold public bytes (plaintext the screen
  shows comes back in `Zeroizing` buffers).
- The core owns the `HardwareGate` and the `DeviceStore` and hands neither out: whoever can call
  `authorize` or read the wrap files can compute `HW_n` and the seeds (review M1). The accessors
  the tests use exist only under `cfg(test)` or the `software-gate` feature, which no release
  build enables.
- A handle is a random 64-bit id, single use, and dies at `lock()`.
- The `viewer` and `out` sinks are Rust objects the plugin layer owns (a file in the app's
  protected container, or the native viewer); the web view gets a URL to view, not the bytes,
  wherever the platform viewer allows.
- Every call made while locked returns `Locked`; every write made in a decoy session returns
  `Decoy` and writes nothing (§8).
- Errors carry no secret data and say what to do next (V5.md UX rule 5); the UI maps them.

## 2. Keys

One device wrap holds two 32-byte seeds: the **account seed** (shared by every device of the
account, never on a server) and this **device's seed**. Everything else is derived, in the core,
when needed:

| Key | Derivation (HUMID-PQ2 KDF, §4.2 of PQ2.md) | Use |
| --- | --- | --- |
| account hybrid KEM | `KemSecretKey::from_seed(KDF("HUMID-PQ2 account-kem", [account], [], 96))` | documents are encapsulated to it (`ss_acct`) |
| account ML-DSA-87 | `ξ = KDF("HUMID-PQ2 account-dsa", [account], [], 32)` | signs every document; pinned; its key id is the account id |
| device ML-DSA-87 | `ξ = KDF("HUMID-PQ2 device-dsa", [device], [], 32)` | sign-in, step-ups; its key id is the device id |
| index key | `KDF("HUMID-PQ2 index", [account], [], 32)` | vault index entries (synced) |
| device records key | `KDF("HUMID-PQ2 device-records", [device], [], 32)` | settings, revisions, the join key, offline copy (this device only) |
| join KEM key | random, per join (§5.3) | the grant and pending slots are sealed to it; destroyed once every granted document is adopted |

The 5.0 hardware liveness keys (P-256, and ML-DSA-87 where the platform has it) stay in the
secure hardware and sign inside the same prompt (§3).

## 3. `HardwareGate`: the per-platform operation

```rust
pub trait HardwareGate {
    fn info(&self) -> GateInfo;                                   // platform, max ops per prompt
    fn target(&mut self, kind: TargetKind) -> Result<HwTarget, GateError>;      // no prompt
    fn authorize(&mut self, prompt: &Prompt, ops: &[HwOp]) -> Result<Vec<HwOutput>, GateError>;
    fn retire(&mut self, input: &[u8]);                           // delete the key behind an input
}
pub enum HwOp { Derive(Vec<u8>), SignLive(Vec<u8>) }
pub struct HwTarget { pub input: Vec<u8>, pub value: Option<Secret32> }
```

Contract: `authorize` shows **exactly one** live-biometric prompt (no passcode fallback, no reuse
window) and runs every op inside it, or none; a `Derive` on an input the hardware doesn't know
(retired, or another device's) returns `HwOutput::Unavailable` without failing the other ops, so
the core can try fallback wraps in the same prompt; `target` never prompts; outputs are bytes,
wiped by the adapter; a liveness signature that was asked for and is missing fails the whole call
(fixes audit L1).

`GateInfo::max_ops` is how many ops one prompt can carry. The core plans for it (review M3):
enrolment refuses a gate that couldn't unlock in one prompt (an unlock needs `HW_n` and the live
signature, plus `HW_{n+1}` when the platform can't know it in advance), and a grant puts the live
signature in the first prompt and spreads the documents' derives over as many prompts as needed,
even with `max_ops = 1`.

`HW(input)` is the 32-byte hardware output for an opaque input. Per platform:

| | `target()` (no prompt) | `Derive(input)` inside the prompt | `retire(input)` |
| --- | --- | --- | --- |
| **iOS 26+** | encapsulate to the Secure Enclave ML-KEM-1024 public key, and make a P-256 ephemeral against the SE P-256 agreement key; `input` = both ciphertexts; `value` = KDF(ML-KEM ss, ECDH ss) **known now** | SE decapsulation + SE P-256 key agreement in one `LAContext` (`.biometryCurrentSet`, `interactionNotAllowed` off, no reuse duration); same KDF | rotate the SE KEM key per wrap target (a new SE key per `W_{n+1}`, delete the old one) |
| **Android 17+** (StrongBox, else TEE) | see §5: proposal A imports a fresh per-use HMAC key whose bytes the core picked (`value` known); otherwise `input` = alias ‖ 32 random bytes and `value = None` | `HMAC-SHA256(Keystore key, message)` under a `CryptoObject` for that per-use, `AUTH_BIOMETRIC_STRONG`, unlocked-device-required, invalidated-by-enrolment, attested key | delete the imported key (proposal A); otherwise nothing (the rollback floor covers it) |

`KDF` here is `KDF("HUMID-PQ2 hw-ios", [ss_kem, ss_ecdh], [input], 32)` and
`KDF("HUMID-PQ2 hw-android", [hmac], [input], 32)`; the adapters return the KDF output, never the
raw secrets. "Verify on device that iOS 26 Secure Enclave ML-KEM keys accept biometric access
control" (V5.md) remains the first iOS check (§10).

## 4. The device wrap and its per-unlock ratchet

```
K_wrap = KDF("HUMID-PQ2 device-wrap", [HW_n, ss_soft], [account_id, device_id, u64 n, hw_input], 32)
W_n    = header(0x0100) ‖ u64 n ‖ account_id (32) ‖ device_id (32) ‖ lp(hw_input)
         ‖ nonce (12) ‖ AES-256-GCM-SIV(K_wrap, nonce, A, account seed ‖ device seed) ‖ tag (16)
A      = header(0x0100) ‖ lp(account_id, device_id, u64 n, hw_input)
```

`ss_soft` is V5.md's optional software ML-KEM-1024 + X25519 leg; HUMID-PQ2/1 passes the empty
string (a future version can add it without changing the layout). The `device` and `n` of V5.md's
formula are here, plus the account id and the hardware input.

**One unlock** (`Core::unlock`, one prompt):

1. Read the two slots `wrap-0`, `wrap-1` (`W_n` lives in slot `n mod 2`; an undecodable slot is
   ignored) and the store's **rollback floor**. The candidates are the wraps with `n ≥ floor`,
   highest first (`ratchet::plan`). A wrap below the floor is a restored backup or image: refused
   (`Rollback`).
2. `t = gate.target(Wrap)`: the input for `n+1`, made without a prompt.
3. One `authorize`: `Derive` for each candidate (as many as fit), `Derive(t.input)` only if
   `t.value` is unknown, and
   `SignLive(H("HUMID-PQ2 live-unlock", [challenge, account_id, device_id, u64 n]))`.
4. Open the highest candidate that opens and whose keys match its account and device ids: that is
   `W_n`. A planted or damaged higher wrap is skipped (review H2).
5. Seal the same seeds as `W_{n+1}` under `HW_{n+1}`, write it to the other slot, **read it back
   and open it in software**. Only a `W_{n+1}` that is on disk and opens counts as written: a
   write may report an error and still have landed, or report success and not have.
6. Retire the inputs of wraps lower than `W_n`, raise the floor to `n+1` (stored where a file
   restore can't reach: iOS `ThisDeviceOnly` Keychain item, Android Keystore-bound record), then
   retire `W_n`'s hardware input and delete its slot.

Crash and storage-failure cases (each has a test in `tests/lifecycle.rs` or `tests/review94.rs`):

| What happened | State left | Next unlock |
| --- | --- | --- |
| prompt cancelled, `W_n` didn't open | `W_n`; the fresh target is retired | opens `W_n` |
| write failed and `W_{n+1}` isn't on disk | `W_n`; target retired | opens `W_n`, steps again |
| write reported an error but landed | read back: treated as written, step completes | opens `W_{n+1}` |
| outcome unknown (read-back failed) | `W_n`; target **kept** | opens whichever is there |
| crash between 5 and the floor raise | `W_n` and `W_{n+1}`, floor `n` | opens `W_{n+1}`, finishes the step, retires both old inputs |
| a junk or planted wrap with a higher `n` | it, and `W_n` | skips it, opens `W_n` |

Nothing is retired until a higher wrap has actually opened or been verified on disk, so a storage
fault can't strand the seeds behind a retired key.

What the ratchet buys: a copy of the wrap file, taken at any time, opens nothing once the phone
has unlocked again. On iOS and on Android with proposal A (§5) the hardware key behind the old
wrap is gone, so even the person's own finger can't reopen it; on Android without proposal A the
rollback floor is what refuses it (the hardware HMAC key itself is long-lived).

## 5. The open hardware question: one prompt on Android

**The problem (audit 2b, risk 1).** A `BiometricPrompt` `CryptoObject` authorises one Keystore
operation on one key. 4.x already shows **two prompts** per check on Android (the liveness
`Signature`, then the secret `Cipher`). A naive ratchet adds the per-unlock HMAC: three. UX rule 1
is one prompt per action. The format must not freeze until a design is **proven on real phones**
(Pixel with StrongBox, a Samsung with StrongBox, one TEE-only phone, all on Android 17).

The core is built so the platform can choose: `authorize` takes a list of ops for one prompt, and
`target` may return the next value without hardware (`value: Some`). So the core never needs
`HW_{n+1}` from the hardware inside the prompt, and a platform that can't do more than one op per
prompt sets `max_ops` and the core plans for it.

**Proposals, in order of preference:**

**A. One per-use key, one HMAC: liveness and `HW_n` from the same operation.**
- Each wrap target imports a fresh 256-bit HMAC key into Keystore (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`, StrongBox, unlocked-device-required, invalidated by enrolment). The core picked the key bytes, so `HW_{n+1}` is known at once and no prompt is needed (`value: Some`).
- The core then wipes the key bytes; from then on only Keystore holds them.
- At unlock, one `CryptoObject(Mac)` on key `n` computes `HMAC(k_n, H(challenge ‖ …))`.
- The output feeds `K_wrap`, so opening `W_n` proves the hardware op happened inside a biometric auth.
- For the **server**, the live proof becomes `HMAC` under a key whose attestation (an imported key's attestation carries `origin = IMPORTED`) the server can't verify the output of. So proposal A covers the local unlock only. For step-ups to the server, the P-256 liveness signature stays.
- Result: **unlocks are 1 prompt; actions that need a server-verifiable proof are still 2.** Not enough alone.

**B. `CryptoObject` with an operation handle covering several keys (API 35+ `BiometricPrompt.CryptoObject(long operationHandle)`).**
- Begin both Keystore operations (the liveness `Signature` and the HMAC `Mac`).
- Authorise both with one prompt by binding them to the same auth token, using keys created with `setUserAuthenticationParameters(timeout = 0, …)` and the operation-handle `CryptoObject`.
- Whether one auth token can unlock two per-use operations is exactly what must be tested; Keystore 2's documentation suggests a per-operation challenge.
- If it works: 1 prompt for everything, and the format above stands unchanged.

**C. A short-timeout key for the second operation.**
- The liveness key stays per-use, under a `CryptoObject(Signature)`.
- The HMAC key gets `setUserAuthenticationParameters(timeout = 1 s, AUTH_BIOMETRIC_STRONG)`: the same prompt's authentication unlocks it for one second, with no second prompt.
- Weaker: any HMAC in that second is allowed. The core makes exactly the ops it planned, and the window is tiny.
- V5.md says "per-use key, no time window". This proposal relaxes that for the HMAC only, and needs the owner's sign-off.

**D. Liveness signature as the hardware factor.**
- If ML-DSA-87 is available in Android 17 Keystore with deterministic signing, the signature over a fixed per-wrap message is a hardware-made, per-use, biometric-bound value.
- Feed `SHA3(signature)` into `K_wrap` as `HW_n`. One prompt, one operation, also server-verifiable.
- Breaks for hedged or randomised signatures (ECDSA, hedged ML-DSA) because the value must be reproducible. So it hinges on a deterministic mode Keystore may not offer.

**Recommendation.**
- Build the Android adapter to try **B** first. Fall back to **A + C** (A for wraps, C for the HMAC alongside the liveness signature). Use **D** only if the platform offers deterministic ML-DSA.
- Ship nothing that shows two prompts.
- The device-lab run on the three phones above is the gate before the wrap format freezes. It must cover cancel, lockout, a new enrolment invalidating keys, StrongBox busy, a reboot between steps 5 and 6, and timing (the extra Keystore op should cost under 50 ms).
- iOS needs no workaround: one `LAContext` authorises the SE decapsulation, the SE agreement and the SE signature together.

### 5.3 Adding a device (risk 2)

**Authenticating the new device (review H1).** The old device seals the account seed to whatever
key the join request names, so that key must be the new device's and no one else's. V5.md: a
device joins only with "a live approval on an existing device (attested model + a code bound to
both devices' keys)". In the core:

```
request = header(0x0108) ‖ account_id ‖ device ML-DSA-87 pk ‖ join KEM pk ‖ nonce (32)
          ‖ ML-DSA-87(device key, ctx SUITE ‖ 0x0108 ‖ "HUMID-PQ2 join-request", body)
code    = Crockford-base32(first 100 bits of H("HUMID-PQ2 join-code", [body]))   e.g. 7K2Q-…
binding = H("HUMID-PQ2 join-binding", [body])
```

1. The new device (`begin_join(account_id)`) makes its device seed and a **one-time join KEM
   key**, signs the request with its device key, and **shows the code**.
2. The person types the code on the approving device. `grant_device` refuses unless the request's
   signature verifies, it names this account, and the typed code matches (`CodeMismatch`). The
   live proof covers `H("HUMID-PQ2 live-grant", [challenge, account_id, binding])`, so the server
   records which request the person approved. The server also checks the new device's attestation
   against the request's device key (the "attested model" half).
3. The grant (the account seed and the list of granted document ids) is sealed to the join key,
   bound to `[account_id, device_id, binding]`; the new device opens it only for its own request.

A relay that swaps the join key has to re-sign with a device key of its own, which changes the
code. To match the code the person reads on the real screen, it would need a second preimage of
100 bits. The account side is bound too: a grant from another account's device doesn't open
(`finish_join` checks that the account seed derives the account id the request named).

**Moving documents.** `HW_doc` is device-bound, so a new device can't reuse the old one's slots.
In this design each document has a random `r_doc` (32 bytes) reached through one slot per device:

- **Old device** (`grant_device`, unlocked): one authorization derives `HW_doc` for each of its
  slots, opens `r_doc`, and seals it **in software** to the request's join key as a *pending
  slot* (type `0x0105`, §6.4). It also seals the grant to that key (`0x0106`).
  N documents need N derives: with `max_ops` per prompt that is `ceil((N+1)/max_ops)` prompts.
  `Grant::prompts` reports it; the UI must say so before starting ("Approving 240 documents
  takes 2 checks").
- **New device** (`finish_join`, one prompt): writes its first wrap, and keeps the join key (in
  a `0x0109` record under its device records key) with the list of granted documents. On the
  **first open** of each document it opens the pending slot with the join key and, in the same
  prompt, seals `r_doc` under its own hardware, returning the new slot to upload in place of the
  pending one. When the last granted document is adopted, the **join key is deleted** (review L5).
  From then on a captured pending slot opens with nothing on the device. Before that, a pending
  slot is protected by the join key, which sits under the hardware-wrapped seeds.

So the new device's prompts are the ones it was going to show anyway. The old device's cost
depends on how many `Derive` ops one prompt can carry:

| Platform | One prompt carries | 240 documents |
| --- | --- | --- |
| iOS | many SE ops in one `LAContext` | 1 prompt |
| Android, proposal B | many ops | 1 prompt |
| Android, proposal A/C | 1 HMAC (+ a 1 s window under C) | many |

On Android with proposal A or C the old device would show many prompts. Two ways out:

- (a) Make document slots on Android **public-key targets**, as wraps are under proposal A. `target(Document)` imports a fresh per-document HMAC key whose bytes the core picked and then wiped, so `HW_doc` is known at seal time; opening still needs the hardware. The cost is one Keystore key per document; StrongBox has key-count limits, so test with 10,000 keys.
- (b) Accept a slow, resumable "re-wrap in batches" screen.

Recommend (a) where the key count holds. **Decide before the format freezes.**

Pending slots are the one place a document's per-device secret sits under a software key (the join
key, which is reachable only through the hardware-wrapped seeds). They live only until first open:
the new device converts them, the server deletes a pending slot once its replacement is uploaded,
and the join key goes when the last one is adopted. The residual risk is a document that is
never opened on the new device. Its pending slot stays openable by the join key until it is
adopted. The UI should offer "make all documents ready on this phone", which adopts them in
batches.

## 6. Documents: three keys, one streaming layer

### 6.1 The key

```
K_doc = KDF("HUMID-PQ2 doc", key = [ss_acct, HW_doc, share_ks], context = [doc_id, manifest_hash], 32)
```

`HW_doc` in V5.md's formula is realised as `r_doc`: 32 random bytes reachable only through this
device's hardware slot (§6.2). The three inputs:

| Input | Comes from | Who can't produce it |
| --- | --- | --- |
| `ss_acct` | hybrid KEM (ML-KEM-1024 + X25519) to the account key | the servers, a thief, a quantum attacker |
| `HW_doc` (`r_doc`) | a hardware op on this device, inside the live check | anyone without this device and the person's biometric |
| `share_ks` | the key-share service, after a fresh live proof for this document, sealed to a one-time key | malware with a copied seed; the vault |

### 6.2 Envelope

```
envelope      = manifest ‖ signature ‖ u32 len ‖ meta box ‖ chunk_0 ‖ … ‖ chunk_last
manifest      = header(0x0101) ‖ doc_id (32) ‖ account_id (32) ‖ ML-KEM ct (1568) ‖ X25519 eph (32)
                ‖ u32 chunk_size                                                    (1681 bytes)
manifest_hash = H("HUMID-PQ2 manifest", [manifest])
signature     = ML-DSA-87(account key, ctx = SUITE ‖ u16 0x0103 ‖ "HUMID-PQ2 doc", manifest)  (4627)
meta box      = AES-256-GCM-SIV(KDF("HUMID-PQ2 doc-meta", [K_doc], [], 32), 0¹²,
                header(0x0107) ‖ lp(manifest_hash), pad64(lp(lp(name, media type))))
chunk_i       = u32(len | last·2³¹) ‖ AES-256-GCM-SIV(K_doc, u64 i ‖ u32 last,
                header(0x0102) ‖ lp(manifest_hash, u64 i), plaintext_i)
```

- One layer of encryption (no inner/outer double pass). Chunks are 64 KiB by default (≤ 1 MiB
  accepted). Every chunk but the last is full. The last carries the flag in its length word and
  in its nonce, and may be empty.
- Sealing and opening stream: peak memory is about two chunks. The SHA3-512 of the whole
  envelope is computed on the way out, in the same pass, so the live proof can name it. There is
  no other hash pass.
- Each `K_doc` is fresh, so the counter nonces never repeat under a key. The misuse-resistant AEAD
  is defence in depth.
- The signer is named by a 32-byte account id in the manifest, not a 2,592-byte public key. It is
  checked against the account's **pinned** ML-DSA key before anything is decrypted, which closes
  "anyone with the public keys can seal to you".
- Truncation, extension, dropping, reordering or duplicating a chunk, or moving one between
  documents, fails authentication. Nothing reaches the viewer from a chunk that didn't
  authenticate. A failure mid-stream means "discard what was shown", and the viewer sink must
  support that.
- Name and media type are inside the document, padded to 64 bytes. The index (§7) holds only what
  the list shows. 4.x's `plainHash` and GPS `place` (audit M6) move inside the document as
  ordinary metadata fields when the viewer needs them.

### 6.3 Shares, both directions

- **Seal**: the phone draws `share_ks` and seals it to the key service's pinned hybrid KEM key
  (`seal_share(Upload, …, binding = manifest_hash)`, type `0x0010`). The gateway forwards 1661
  opaque bytes. This closes audit H1 and verify #1.
- **Open**: the phone makes a one-time hybrid KEM key and a *share request*
  (`header(0x0012) ‖ account_id ‖ doc_id ‖ manifest_hash ‖ one_time public key`). The liveness
  key signs `H("HUMID-PQ2 live-open", [challenge, binding])` in the same prompt that derives
  `HW_doc`, where `binding = H("HUMID-PQ2 share-request", [request])`. The key service checks the
  live proof itself, then seals the share to the one-time key (type `0x0011`) under that binding.
  The one-time key dies with the open handle.

### 6.4 Device and pending slots

```
device slot  = header(0x0104) ‖ doc_id ‖ device_id ‖ manifest_hash ‖ lp(hw_input)
               ‖ GCM-SIV(k, 0¹², A, r_doc) ‖ tag        k = KDF("HUMID-PQ2 doc-slot", [HW(hw_input)],
                                                             [doc_id, device_id, manifest_hash, hw_input], 32)
pending slot = header(0x0105) ‖ doc_id ‖ device_id ‖ manifest_hash
               ‖ seal_to(join KEM key, 0x0105, [doc_id, device_id, manifest_hash], r_doc)
```

The vault stores one slot per (document, device). It can withhold slots but can't open or move
them: a slot for another document, device or manifest doesn't open.

## 7. Local records

The core owns a small store (`DeviceStore`: atomic file writes plus the rollback floor). On iOS
the files are `NSFileProtectionComplete` and excluded from backup; on Android they sit in the
no-backup directory. IndexedDB keeps only non-secret UI cache.

| Record | Format | Key |
| --- | --- | --- |
| index entry (synced) | `u64 rev ‖ writer (32) ‖ box(0x0110, [account_id, item_id, u64 rev, writer], pad64(lp(entry)))` | index key |
| revisions | `u64 c ‖ box(0x0113, [device_id, u64 c], (lp(id) ‖ u64 rev ‖ writer)*)` | device records key |
| setting | `box(0x0111, [device_id, name], lp(value))`, file `setting-<name>`, name `[a-z0-9-]{1,64}` | device records key |
| join key | `box(0x0109, [device_id], seed (96) ‖ u32 n ‖ n × doc_id)` | device records key |
| offline copy (next) | `box(0x0112, [device_id, u64 rev], …)` | device records key |
| message store key (next) | per V5.md Messaging: hardware-derived per conversation, rotated per save | through a slot, as documents |

One AAD shape per type, no fallback, so a server can't move an entry onto another item (audit M2).

**Synced versions (review M7).** The index is shared by every device of the account, so an entry's
version is `(rev, writer device id)`, compared lexicographically. A device writing an entry passes
the blob the vault holds now (`seal_index_entry(id, current, entry)`); the new `rev` is one more
than the highest of that and anything this device has seen. Two devices writing at the same time
get the same `rev`, but the writer id still orders them, so every device converges on the same
"newest" and refuses the other as older.

**Rollback of the revisions themselves (review M2).** The revisions record carries a counter `c`
that the store also keeps outside the files (with the wrap floor). A copy whose `c` is below the
store's, a missing file once `c > 0`, or a damaged one, means synced records can't be checked.
The unlock still succeeds (`Unlocked::records_ok = false`), but index entries refuse to open
(`RecordsUnavailable`) until the UI has told the person and called `reset_records()`. Then the
device starts its history afresh from what the vault serves next. A copy whose `c` is above the
store's (the counter write was lost) is accepted and the counter catches up.
`rev` only grows. The device keeps the highest it has seen per id, sealed in the revisions record
and checked on every open. An older entry the vault serves back is refused (`Rollback`), across
lock and restart.

## 8. Session, decoy and lock

- **Session**: after `unlock` the core holds the derived keys (§2) and the revisions. Open handles
  hold one document's `r_doc` and one-time key until `finish_open`. A join in progress holds the
  new device's seed.
- **Decoy** (`enter_decoy`, one way until lock): every write, seal and grant returns `Decoy` and
  touches no storage or hardware key. A pending slot is opened without being adopted (no new
  hardware key, no slot to upload; review M4). Every live proof made in the session carries the
  session mode (`0x00` normal, `0x01` duress) inside the signed message (§9). The person and the
  coercer can't tell, but the key-share service can: it decides whether to release real shares,
  refuse ("this document isn't available right now"), or serve decoy content.

  **Owner decision needed:** which of these the key service does under duress. The core's part is
  done either way. Reading local decoy-marked items and index entries still works and leaves no
  trace.
- **Lock means gone**: `lock()` drops the session, every open handle and any join in progress.
  Every secret type zeroizes on drop: `Secret<N>` boxes, the RustCrypto keys' `ZeroizeOnDrop`, and
  plaintext in `Zeroizing<Vec<u8>>`. `held_secrets()` is 0 afterwards, which the tests assert.
  The platform layer also closes viewers and drops secret-holding drafts on lock (V5.md). Each
  unlock starts by locking, so a failed unlock leaves nothing behind.
- Not yet done: `mlock` of the secret pages where the OS allows (Android `mlock` limits, iOS
  doesn't page app memory to disk), and a test that reads freed memory. Both belong with the
  platform crates.

## 9. Live proofs

Each prompt's liveness signature covers `H(label, [challenge, …])` with a label per action:
`live-enroll` (account id, device id), `live-unlock` (account id, device id, `n`), `live-seal`
(doc id, manifest hash, envelope hash, mode), `live-open` (share-request binding, mode),
`live-grant` (account id, join-request binding). `mode` is one byte: `0x00` normal, `0x01` duress
(§8). The
server's own challenge (HTP's ticket) is the first part, so a proof stands for one request only.
P-256 plus ML-DSA-87 where the platform has it (`LiveAlg`). App Attest assertions per check
(iOS) ride alongside the signature.

## 10. Open questions

0. **Duress policy at the key service** (§8): release, refuse or serve decoy shares when a live
   proof carries `mode = 0x01`.

1. **Android one prompt** (§5): which of B, A + C or D works on Android 17 StrongBox and TEE.
   Prove it on three phones before the wrap format freezes.
2. **Adding a device on Android** (§5.3): per-document imported keys (StrongBox key-count limits)
   or batched approvals.
3. **iOS 26 Secure Enclave ML-KEM with biometric access control** (V5.md): confirm
   `SecureEnclave.MLKEM1024` keys accept `.biometryCurrentSet` access control in one `LAContext`
   with the P-256 agreement and signature keys.
4. **Proposal C relaxes "no time window"** for the HMAC key only. Needs the owner's decision.
5. **`ss_soft`**: whether to turn on the optional software KEM leg in `K_wrap`. It is empty in
   HUMID-PQ2/1.
6. **Recovery** (hardened mode) needs its own path into `finish_join` (the account seed from 2 of
   N proofs). Not in this skeleton.
7. **The vault index** keeps only list fields. Exactly which fields, and whether the index key
   moves behind the ratchet as well (audit M6), is still to be decided.
8. **FFI shape**: Tauri commands over a global `Core` behind a mutex, or a dedicated thread owning
   it (V5.md: "one owner and a stop on every exit path"). The latter is recommended.

## 11. Tracked: crypto backends (review L8)

The suite runs today on pure-Rust RustCrypto and dalek crates. Several are pre-1.0 or release
candidates and haven't been independently audited: `ml-kem 0.3.3`, `ml-dsa =0.1.1` and
`slh-dsa =0.2.0-rc.5`. V5.md wants native constant-time backends wherever available (CryptoKit on
iOS 26, BoringSSL/Conscrypt on Android, AWS-LC or OpenSSL 3.5 on servers), with others only as
checked fallbacks.

The plan:

- **A backend table in the core.** One `Backend` per primitive, chosen at start. Every backend
  passes `self_test()` and is cross-checked against the RustCrypto one on the same inputs before
  it is used.
- **Server first.** `aws-lc-rs` already has ML-KEM, AES-GCM(-SIV) and SHA-3 and builds for
  Linux. It replaces the RustCrypto backends for those primitives once it passes the same KATs.
  ML-DSA and SLH-DSA stay RustCrypto until aws-lc's are stable.
- **Phones next.** CryptoKit (iOS 26 has ML-KEM and ML-DSA) and Conscrypt behind the same table,
  through the gate plugins.
- **Until then.** Pin exact versions of the pre-1.0 crates. CI runs cargo-deny (advisories,
  licences, sources) on every PR, and the external crypto review (V5.md roadmap) covers these
  crates explicitly.
