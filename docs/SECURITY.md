# HumID security model (POC v2)

**Status: proof of concept.** The building blocks are standard (ML-KEM-1024,
ML-DSA-87, X25519, AES-256-GCM, SHA-3, from audited libraries), but the way
HumID composes them (HTP/1, the envelope format, the recovery flows) has not
had an independent cryptographic review. Don't store real customer data in
it until that review and the items under *Before real data* are done.

## What it protects against

| Threat | What stops it |
|---|---|
| **The server is breached, or an insider looks** | The vault holds only envelopes sealed on the phone to the account's ML-KEM-1024 + X25519 key, and index entries encrypted with a key derived from the account seed. No service holds a key that opens either. |
| **Someone on the network, or a proxy that ends TLS** | HTP/1 runs inside TLS 1.3. Its frames are encrypted end to end between app and gateway with keys from a hybrid ML-KEM-1024 + X25519 handshake. The app pins the server's key and refuses any other. |
| **Harvest now, decrypt later** | Transit and stored documents both use a hybrid of ML-KEM-1024 and X25519. An attacker must break both. Signatures are ML-DSA-87. |
| **A stolen or lost phone** | Keys are released only by a live biometric check in the Secure Enclave or Android Keystore. Remove the device from any other device: its sessions end and the server refuses it. |
| **A stolen session or a replayed request** | Opening, deleting, exporting, adding or removing devices, changing recovery, and closing the account each need a fresh biometric signature over that exact request, bound to the session, at most 60 seconds old. Frames carry sequence numbers checked against a replay window. |
| **A stolen recovery card** | A card recovery waits 72 hours and alerts every signed-in device, any of which can cancel it. The card alone opens nothing without that wait. |
| **A rogue recovery contact** | A majority of contacts must approve, each with their own biometric. Fewer pieces reveal nothing (Shamir sharing). Then the same 72-hour wait and cancel apply. |
| **The server substituting keys while you add a device or contact** | Every code you type is a hash of the public keys behind it. The app recomputes it from what the server returns and stops on a mismatch. |
| **Tampering with your access history** | Each account's ledger is a SHA-3 hash chain with an ML-DSA-87-signed head, verified on the phone. Opening or deleting a document is refused if the ledger can't record it first. |
| **Brute force** | Sign-ins are rate-limited per account, handshakes per IP, calls per session. |

## What it does not protect against yet

- **Unreviewed composition.** See the status note above.
- **The app reports its own gate strength.** The server records whether a
  device said its biometric was hardware-backed, OS-enforced or demo, and
  `HUMID_MIN_ASSURANCE` refuses weaker claims. Without device attestation
  (Apple App Attest, Google Play Integrity) a modified app could claim
  "hardware". Attestation is the follow-up.
- **Windows Hello accepts a PIN**, and Linux fingerprint checks are enforced
  by the OS rather than by secure hardware. The app labels these honestly.
- **The web (PWA) build is served by the server.** A compromised server could
  serve altered app code. The native iOS and Android apps don't have this
  weakness. For real data, ship native apps only, or signed web bundles.
- **A compromised phone.** Malware with control of the operating system can
  see what you open while you open it.
- **Recovery timing is a server rule.** The cryptography keeps the seed
  secret, but the 72-hour wait and the cancel are enforced by the recovery
  service. An attacker who controls the server *and* holds your card could
  skip the wait.
- **Removing a device doesn't rotate the account key.** A thief who also
  defeated a lost phone's secure hardware would hold the account seed, though
  the server refuses that device. Rotation (re-sealing every document) is the
  follow-up.
- **Alerts appear in the app only.** There are no push or email alerts yet,
  so a recovery is noticed when you next open HumID.
- **Metadata.** The server sees account and device ids, document sizes and
  times, IP addresses at the edge, and which accounts protect which. It never
  sees names, contents or keys.
- **Demo mode has no biometric.** It exists so the app can be tried on any
  device. Set `HUMID_MIN_ASSURANCE=hardware` on a real server.
- **Server keys are files.** The gateway's HTP key and the ledger's signing
  key live on the server's volumes, not in a hardware security module.

## Before real data

1. Independent review of HTP/1, the envelope format and the recovery flows.
2. Device attestation on iOS and Android; `HUMID_MIN_ASSURANCE=hardware`.
3. Native apps only, signed, with the server key pinned at build time.
4. Server keys in an HSM or cloud KMS; encrypted, tested backups of every volume.
5. Push and email alerts for new devices and recoveries.
6. Account-key rotation after a device is removed.
7. Penetration test of the deployed stack.
8. Privacy policy, terms and data-handling review with counsel.

## Reporting a problem

The repository is private. Report anything security-related to the
maintainer directly, not in an issue.
