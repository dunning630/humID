# Public credentials (HumID 4.0, provisional)

> **Status:** 4.0 track, on branch `v4/credentials` (built on `v4/p2p-comms`).
> The request, verification, revocation and minimisation code is built and
> tested (`packages/mdoc`, `packages/sdjwt`, `packages/creds`,
> `apps/mobile/src/core/credentials.js`, `tests/creds.test.js`,
> `tests/sdjwt.test.js`, `tests/wallet-id.test.js`, `tests/mdoc.test.js`). The
> native platform plugins, the app screen, the server route and the production
> trust lists are not. Like the rest of HumID, it needs an independent review
> and testing against real wallets before real IDs go through it.

HumID can now ask for a government credential the way a bank or an airline
does, check it on the phone or the server, and keep only what the question
needed. One request works with every current browser and wallet; one
verifier handles every format; every answer says how far it was proved.

## What can be checked, and how far

| Credential | How HumID gets it | Issuer proven | Holder proven (not a copy) | Trust comes from |
|---|---|---|---|---|
| **US mobile driver's license or state ID** (Apple, Google, Samsung Wallet; state apps) | Online through the browser's credential picker, or in person by QR + Bluetooth | Yes: the state's Document Signer, chained to its IACA root | Yes: the phone signs this request's transcript with the key the state bound in | AAMVA Digital Trust Service (VICAL), or each DMV's published root |
| **EU digital identity (PID)**, mdoc form | Same as above | Yes | Yes | Member-state PID provider roots (EU trusted lists) |
| **EU digital identity (PID)**, SD-JWT VC form | Online (OpenID4VP) | Yes: the provider's signature through its x5c chain, or a key from its published metadata | Yes: a key-binding signature over this request's nonce and this site | Same |
| **Wallet photo IDs** (ISO/IEC 23220), such as a Digital ID made from a passport | Online or in person | Yes | Yes | The issuer's IACA. Confirm the document type and root for Apple's Digital ID from Apple's developer resources before turning it on. |
| **Passports and ID cards with a chip** (ICAO 9303) | In person, NFC (already in HumID) | Yes: passive authentication to the country's CSCA | Yes when the chip has Active Authentication; otherwise said plainly | CSCA directory, or **ICAO master lists** (new: `cscasFromMasterList`) |
| **Physical US/Canadian license** (PDF417 barcode) | Camera (already in HumID) | **No.** The barcode isn't signed | No | None: reported as `printed` |
| **US Social Security number** | Not a credential | **No credential exists.** Only SSA's eCBSV can say whether a number, name and birth date match | No | SSA, and only for permitted entities (below) |

### The honest answer on SSNs

There is nothing to verify cryptographically: the card isn't signed and isn't
in any wallet. HumID offers two things and no more:

- `checkSsnFormat`: whether a string could be an SSN at all (area 001–899 except
  666, group not 00, serial not 0000, the two published numbers refused). It
  says nothing about whether it was issued, or to whom.
- `ecbsvVerifier`: an adapter for SSA's **Electronic Consent Based SSN
  Verification**. SSA returns yes/no for a number + name + date of birth, which
  fields don't match, and a death indicator. It is open only to *permitted
  entities*: financial institutions under Gramm-Leach-Bliley section 509 and
  their service providers, subsidiaries, affiliates, agents, subcontractors or
  assignees (Economic Growth, Regulatory Relief, and Consumer Protection Act,
  section 215). Each check needs the number holder's signed consent, and SSA
  charges an annual fee by volume tier (Tier 1, up to 10,000 checks a year,
  was $5,100 in the April 2025 schedule). The adapter refuses to run unless the
  operator says it is a permitted entity and supplies its own SSA client; it
  checks consent on every call; it never returns, logs or echoes the number
  (hashing wouldn't help: a billion possibilities hash in seconds).

## How an online request works

```
 app or site (verifier)                     browser / OS                         wallet on the phone
 ──────────────────────                     ────────────                         ───────────────────
 credentialRequest({ types, ask, origin })
   keeps state: one-time keys, nonce
 navigator.credentials.get({ digital }) ──► picker: "verify.humid… wants        holder picks a
                                             your age (over 21)"  ─────────────► credential, Face ID
                                             adds the page's ORIGIN
                                                                                 signs transcript(origin, nonce, key)
                                         ◄── encrypted to the one-time key ◄──── encrypts the answer
 verifyCredentialResponse(state, answer)
   decrypt → issuer chain → holder signature → what was asked, nothing else
 checkStatus(result, fetchList)          (optional: revoked? suspended?)
 minimise(result, { share: ["age_over_21"] })  → { age_over_21: true, … }
```

One request object offers two protocols; the browser uses whichever the
holder's wallet speaks:

| Protocol string | Standard | Used by | Encryption | What the wallet signs |
|---|---|---|---|---|
| `openid4vp-v1-unsigned` | OpenID4VP 1.0 + DCQL | Chrome 141+ (Android, desktop via phone), wallets with OpenID4VP | JWE, ECDH-ES + A128GCM/A256GCM to a fresh key | mdoc: `["OpenID4VPDCAPIHandover", SHA-256([origin, nonce, key thumbprint])]`; SD-JWT: key binding with `aud = "origin:" + origin`, the nonce, and a hash of exactly what was shown |
| `org-iso-mdoc` | ISO/IEC TS 18013-7 Annex C | Safari 26 / iOS 26 and Apple Wallet, Chrome 141+ | HPKE (RFC 9180): DHKEM P-256, HKDF-SHA256, AES-128-GCM | `["dcapi", SHA-256([EncryptionInfo, origin])]` |

What that buys:

- **No relaying from a look-alike site.** The browser, not the page, puts the
  origin into what the wallet signs and into the decryption input. An answer
  given on `verify-humid.evil.test` neither decrypts nor verifies at
  `verify.humid.test`. Tested.
- **No replay.** A request's state works once and for five minutes. Tested.
- **No copies.** The answer must be signed by the device key the issuer bound
  into the credential. Data copied to another phone, or a MAC that can't be
  checked online, is refused, never silently accepted. Tested.
- **No over-asking, no over-sharing.** HumID asks for the elements a purpose
  needs (`age_over_21` asks for one element), and the wallet shows the holder
  exactly that. A wallet that answers with a document type that wasn't asked
  for is refused. Tested.
- **Optional reader authentication.** `annexCRequest(…, { readerAuth })` signs
  the request with an ISO 18013-5 reader certificate. **Apple Wallet requires
  one, issued through Apple Business Connect**, before it will answer.

## Results: one shape, an honest assurance level

```js
{
  type: "mdl" | "photoid" | "pid_mdoc" | "pid_sdjwt" | "passport_chip" | "id_card_chip" | "license_barcode",
  format, protocol,
  assurance: "issuer+holder" | "issuer" | "signature-only" | "printed",
  holderBound, issuer: { country, jurisdiction, root, signer },
  claims: { given_name, family_name, birth_date, age_over_18, age_over_21, expiry_date, … only what was shared },
  validUntil, statusRef, status
}
```

| Assurance | Meaning | Accepted by default |
|---|---|---|
| `issuer+holder` | A trusted issuer signed it and the presenting device holds its key | Yes |
| `issuer` | A trusted issuer signed it; the device didn't or couldn't prove it holds it (a passport chip without Active Authentication) | Passports only, and the result says why |
| `signature-only` | The issuer's signature verifies but its root isn't in the trust list | Only with `allowUntrustedIssuer` (the holder filing their own ID before the phone has trust lists); the device proof is still required |
| `printed` | Read from an unsigned barcode or MRZ | Never as proof; can't back a claim |

## Keeping only what the question needs

`minimise(result, { share })` turns a verified credential into the fewest facts
that answer the question:

- `age_over_18/21/25/65` from the issuer's own flag when shared, otherwise
  derived from the birth date (and marked `derived`).
- `valid_document` from the expiry date and the revocation check.
- `issuing_country`, `issuing_jurisdiction`.
- Names, birth date, document number and address only with
  `identifying: true`; a photo never goes into a claim.

With a `persona` (a 4.0 contact ID, `HC-…`), the claim gets a `commitment`:
SHA3-256 over a label and the canonical claim. It's the same shape a 4.0 live
stamp commits to, so a stamped message can say *a live human approved sharing
"over 21, valid US-IL license"* while carrying neither the credential nor
anything that identifies the person. `checkCommitment` recomputes it. (The
stamp route itself is on the 4.0 not-built list.)

## Revocation

Issuers publish one signed bit list for many credentials (IETF Token Status
List), so fetching it tells them nothing about which credential is being
checked. `checkStatus(result, { fetchList })` reads the reference in the SD-JWT
or the mdoc's signed object, and checks:

- the list's signature, under the same trust as the credential;
- that it is the list the credential named (`sub` equals the `uri`);
- that it's fresh (`exp`, `ttl`, and a 24-hour default ceiling);
- the entry, least significant bit first, 1, 2, 4 or 8 bits wide;
- a 16 MiB cap on decompression, so a hostile list can't exhaust memory.

`valid`, `revoked` or `suspended` comes back; a revoked or suspended credential
can't back a `valid_document` claim. Tested with JWT and CWT lists.

## Trust lists

| For | Load with | Where real roots come from |
|---|---|---|
| Mobile licenses and IDs (US, Canada) | `iacaFromVical(bytes, { providerRoots })` | AAMVA's Digital Trust Service publishes a signed VICAL free to relying parties, under its terms and conditions. Apple's guidance is to take each state's root from its DMV. |
| EU PID | `trust.sdjwt.roots`, `trust.iaca` | Member-state PID providers, through the EU's trusted lists |
| Passports and ID cards | `cscasFromMasterList(bytes, { publisherCscas })`, `loadCscas(dir)` | ICAO master lists (for example Germany's BSI publishes one), or the ICAO PKD |
| SD-JWT issuers without certificates | `trust.sdjwt.resolveKey` + `issuerMetadataUrl` / `keyFromIssuerMetadata` | The issuer's `/.well-known/jwt-vc-issuer` metadata, fetched by the app |

A master list or VICAL is only as good as its publisher: each loader insists
on the publisher's own root.

## Who can know what

| Party | Sees | Never sees |
|---|---|---|
| **The wallet / browser** | which site asked, and for what | anything HumID decides afterwards |
| **The verifier** (the app for the holder's own vault, or a HumID server) | exactly the elements the holder agreed to share | anything not asked for |
| **A HumID contact** (4.0, with a minimised claim) | the facts shared, e.g. "over 21, valid US-IL license", and that a live human approved them | the credential, the name, the number, the person |
| **The issuer** | that its status list was downloaded | which credential was checked, by whom, or why |
| **SSA** (eCBSV, permitted entities only) | the number, name and birth date the holder consented to check | anything else about HumID |

## Built and tested

| Piece | Where | Tests |
|---|---|---|
| Online requests: OpenID4VP DCQL + Annex C, one key across mdoc entries | `@humid/creds` `credentialRequest`; `@humid/mdoc` `annexCRequest` | request shapes; phishing relay; replay; timeout |
| HPKE (RFC 9180) | `@humid/mdoc/src/hpke.js` | interoperates both ways with `@hpke/core` |
| Session transcripts (Annex C, OpenID4VP DC API and redirect) | `@humid/mdoc/src/dcapi.js` | wallet computes them independently; wrong nonce / origin / key / handover refused |
| ReaderAuth | `signedDeviceRequest` | verified independently with `node:crypto` |
| SD-JWT VC + key binding | `@humid/sdjwt` | disclosures (nested, decoys, injected, duplicated), nonce, audience, age, sd_hash, wrong key, untrusted root, alg `none`, expiry, wrong `typ`, issuer metadata; fuzz with a fresh seed each run |
| JOSE | `@humid/sdjwt/src/jose.js` | RFC 7638 vector; JWE interoperates with `jose` (A128GCM, A256GCM); key-wrap modes refused |
| Token Status List | `@humid/sdjwt/src/status.js` | the draft's bit-order example; JWT and CWT; revoked, suspended, stale, wrong list, forged, compression bomb |
| One verifier, one result shape | `@humid/creds` `verifyCredentialResponse` | mDL, PID mdoc, PID SD-JWT, untrusted and signature-only, document type not asked for; fuzz |
| Passports and master lists | `@humid/creds/server`, `@humid/anchor` `readMasterList` | passive + active, no-AA chips, wrong country; master list tampered, wrong publisher |
| Minimised claims and commitments | `minimise`, `commit`, `checkCommitment` | derived ages, identifying facts gated, commitment binds persona and facts |
| SSN | `checkSsnFormat`, `ecbsvVerifier` | invalid ranges; not permitted; no consent; the number never in results or errors |
| The app asking a wallet | `apps/mobile/src/core/credentials.js` | feature detection; Safari-style and Chrome-style answers; filing into the ID record; cancel |

Every wallet and issuer in the tests uses independent cryptography
(`node:crypto`, `@hpke/core`, `jose`), so HumID's code is checked against code
it doesn't share.

## Limits

- **Real wallets haven't answered yet.** Everything is tested against
  standards-conformant simulated wallets. Before launch: Apple's sample
  responses (Apple Wallet developer resources), the EU reference wallet,
  Google's test wallet, and a state's test mDL.
- **EU PID claim names** follow the PID Rulebook as published; check them
  against the rulebook version the wallets in use implement (`CLAIMS` in
  `packages/creds/src/catalog.js` is the one place to change).
- **Signature algorithms:** ES256/384/512 and EdDSA for SD-JWT; ECDSA for
  mdoc and X.509 chains. An RSA-signed SD-JWT or IACA is refused, not
  accepted.
- **Certificate revocation (CRL/OCSP) for issuer certificates** isn't checked;
  credential revocation is.
- **Request state holds private keys.** It stays in memory on the side that
  verifies. Never serialise it to a client.
- **Signed OpenID4VP requests** (`openid4vp-v1-signed`) and ISO 18013-5:2025
  `readerAuthAll` aren't built; unsigned requests plus the browser's origin
  binding are what Chrome and Safari use today.
- **A verified ID proves a document, not a face.** Matching the person in front
  of a camera to the portrait is a separate step HumID doesn't do (and its
  no-biometrics stance means it won't on the server).

## What is not built yet

1. **Native plugins**: Android Credential Manager (`GetDigitalCredentialOption`)
   and iOS IdentityDocumentServices / Verify with Wallet (needs Apple's
   entitlement), so the Tauri apps can ask a wallet the way the web app can.
2. **App screen**: *Vault → + → Add from a wallet*, using
   `addFromWallet` and `toRecord`.
3. **Server route**: a verifier endpoint for servers acting as the relying party
   (recovery anchoring with a mobile ID, `mdocAuth`, already exists).
4. **Trust list jobs**: fetch and refresh AAMVA's VICAL, ICAO master lists and
   EU trusted lists on a schedule, with the publishers' roots pinned.
5. **Apple Business Connect reader certificate** for Apple Wallet requests.
6. **4.0 tie-in**: send a minimised claim as a live-stamped message.
7. **Zero-knowledge age proofs** over mdocs (e.g. longfellow-zk) once wallets
   ship them: "over 21" without even the issuer's signature being linkable.
8. **Other signed IDs**: India's Aadhaar Secure QR, AAMVA DLDV for permitted
   businesses.

## Rules to respect (not legal advice)

- **eCBSV**: permitted entities only, consent per check, SSA's user agreement.
- **Driver's license data**: several US states limit how businesses use data
  read from a license; the federal Driver's Privacy Protection Act governs DMV
  records.
- **Photos**: a portrait is biometric-adjacent; Illinois BIPA and similar laws
  may apply to anyone who processes it. HumID asks for a portrait only for the
  holder's own vault.
- **US military IDs and CACs**: don't capture them (18 U.S.C. § 701).
- **Data protection**: GDPR and US state privacy laws apply to verifiers.
  Minimise first; `minimise` exists for that.

Check these with counsel before launch.

## For patent application 4

Requesting and verifying these credentials is standards work (ISO 18013-5/-7,
OpenID4VP, SD-JWT VC); it isn't new and shouldn't be claimed as such. The prior
art review's defensible core is an anonymous credential issued once per
hardware-attested live check and bound to a specific message or action. What
this adds on top is a candidate *dependent* claim for counsel to test: a
government-verified attribute, minimised and committed to a per-contact persona,
carried inside a message whose live stamp proves a human approved sharing it,
so the recipient learns the attribute and the human approval but not the
person or the credential. The prior art review's warnings apply: personhood
credentials, World ID and zero-knowledge age proofs are close.

## Try it

```bash
node --test tests/creds.test.js tests/sdjwt.test.js tests/wallet-id.test.js tests/mdoc.test.js
SDJWT_FUZZ_CASES=5000 CREDS_FUZZ_CASES=500 node --test tests/sdjwt.test.js tests/creds.test.js
```
