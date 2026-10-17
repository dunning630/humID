# Wallet passes in the vault

HumID keeps Apple Wallet passes (boarding passes, tickets, store and membership
cards, coupons) in the vault, after checking each one is genuinely from its issuer
and unchanged. `@humid/wallet` does the checking, the same in every app.

## Getting a pass in

Neither wallet lets another app read what's in it, so a pass comes in as a file:

- **iPhone:** in Wallet, open the pass, tap ••• → Share (issuers can turn sharing
  off), save it to Files, then in HumID: Add → **Add a Wallet pass**.
- **Anywhere:** a `.pkpass` file from an email, a download or another device.
- **Google Wallet** has no file to export, so its passes can't be brought in.
- **Payment cards** in Apple Pay or Google Pay aren't stored as their real numbers
  (the wallets keep a device-only substitute), so they're added in HumID directly:
  see [CARDS.md](CARDS.md).

## What's checked

A pass is refused, with the reason, unless all of these hold. They are the checks
Apple Wallet itself makes, so HumID keeps a pass only if Wallet would trust it.

1. **The archive.** Unzipped with limits: at most 64 files, 10 MB each, 20 MB in
   all, sizes checked before anything is inflated and inflating stopped at the
   claimed size (no zip bombs). No names that climb out of the folder, absolute
   paths, control characters or duplicates; every file's CRC must match.
2. **The manifest.** `manifest.json` lists every file with its SHA-1 (or SHA-256).
   Every file must be listed and match, and nothing listed may be missing.
3. **The signature.** `signature` is a detached CMS signature over the manifest.
   Its message digest must match the manifest, and its signer's key must have
   signed it (RSA or ECDSA, checked with Web Crypto).
4. **Who signed it.** The signer's certificate must be a Pass Type ID certificate
   (Apple's extension 1.2.840.113635.100.6.1.16) and not a CA. It must chain,
   through the intermediates the signature carries (Apple Worldwide Developer
   Relations), to one of **Apple's roots, pinned by fingerprint**:

   | Root | SHA-256 |
   |---|---|
   | Apple Root CA | `b0b1730e cbc7ff45 05142c49 f1295e6e da6bcaed 7e2c68c5 be91b5a1 1001f024` |
   | Apple Root CA - G3 | `63343abf b89a6a03 ebb57e9b 3f5fa7be 7c4f5c75 6f3017b3 a8c488c3 653e9179` |

   These match Apple's published list ("List of available root certificates",
   support.apple.com). The package refuses to load if its copy doesn't match.
   Every certificate must have been valid when the pass was signed (a pass signed
   while its certificate was valid stays genuine after the certificate expires),
   and each intermediate must be a CA.
5. **The pass is the one the certificate is for.** `pass.json`'s
   `passTypeIdentifier` and `teamIdentifier` must equal the certificate's UID and
   OU, so one issuer can't sign passes in another's name.

A pass that fails can still be kept as an ordinary file, labelled as such.

## What's stored and shown

- The vault keeps the **signed original**, sealed like any document, so it can go
  back into Wallet unchanged ("Save the pass").
- The encrypted index (the vault list) carries the kind, the issuer, the team, the
  date and expiry: never the barcode or the back of the pass.
- Opening a pass checks it again, then shows its fields as text and its QR code.
  Links in a pass are text, never opened, and nothing in a pass runs. Other
  barcode formats (PDF417, Aztec, Code 128) are shown as their text, with the pass
  going back into Wallet to be scanned.

## Tests

- `tests/wallet.test.js`: Apple's real WWDR G3, G4 (RSA) and G6 (ECDSA) intermediates
  chain to the pinned roots; a genuine test pass (signed under a throwaway root);
  each tampering (changed, added or missing file, changed manifest, no signature);
  each signer problem (not a pass certificate, a CA, an intermediate that isn't a
  CA, expired at signing, another team or pass type, missing certificates, another
  key); the archive limits (escaping names, duplicates, checksums, zip bombs,
  counts); bounded text.
- `tests/fuzz.test.js`: mutated passes and signatures only ever fail as `WalletError`.
- `tests/browser/cards.mjs`: a forged pass refused, a genuine one checked, sealed,
  listed and opened with its QR code. The browser check trusts its test root through
  a hook only a development build has.
