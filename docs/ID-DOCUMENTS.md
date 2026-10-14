# Identity documents HumID can hold

HumID seals any identity document the holder scans (see
[ID-SCANNING.md](ID-SCANNING.md)). What differs between documents is how far
HumID can **prove the document is genuine**. That depends on whether the
issuer signed the data, and whether the holder's copy can prove it is the
original rather than a copy. Four tiers, strongest first.

## 1. Chip documents signed by the issuing country (ICAO 9303)

Read today over NFC (phones) or a USB reader (computers) with `@humid/emrtd`.
Checked with **passive authentication**: the data hashes match, signed by the
country's Document Signer, chained to its CSCA root. The chip also answers
**active authentication**: it signs a fresh challenge with a key that can't be
copied.

| Document | Notes |
|---|---|
| Passports (e-passports) | Most countries' current passports. |
| National ID cards with an ICAO chip | Every EU country's card issued since August 2021 (Regulation (EU) 2019/1157 requires the chip), and many others. Opened with the 6-digit CAN printed on the card. |
| Residence permits with an ICAO chip | EU residence permits and others in the same format. |

## 2. Mobile IDs signed by the issuing authority (ISO/IEC 18013-5)

**New:** `@humid/mdoc`. The mobile ID is held in a wallet (Apple, Google or Samsung Wallet, or
a state app) and shared to HumID over an encrypted session. **Issuer data
authentication** checks the issuing state's Document Signer signature and
chains it to that state's **IACA** root. **mdoc authentication** checks that
the wallet signed this session with the device key the state bound into the
document. These are the mobile-ID equivalents of passive and active
authentication.

| Document | Notes |
|---|---|
| US mobile driver's licenses and state IDs | TSA's participating-states list includes Arizona, Arkansas, California, Colorado, Georgia, Hawaii, Iowa, Louisiana, Maryland, New Mexico, New York, Ohio, Puerto Rico, Utah, Virginia and West Virginia. Illinois added Apple Wallet IDs in November 2025. Which wallets a state supports varies. US and Canadian IACA roots are published by AAMVA's Digital Trust Service as a signed VICAL (`readVical`). |
| EU digital identity (PID, mdoc form) | Same format, docType `eu.europa.ec.eudi.pid.1`, as member states roll out EU Digital Identity Wallets. |
| Other countries' mobile driver's licenses in ISO 18013-5 | For example, Australia, whose roots Austroads' Digital Trust Service publishes. The same code applies once their roots are trusted. |

**Status.** The verification core is done and tested: `@humid/mdoc`,
`applyMdoc` in `@humid/idscan`, and `mdocAuth` in `@humid/anchor` (the server
as reader, for recovery). Still to build: the transport and the screens.
The platform lanes need a BLE central / peripheral and NFC engagement in a
native plugin, or the platforms' own request APIs (Apple's *Verify with
Wallet*, Android Credential Manager), which deliver an encrypted response
this core can verify. The app lane needs an *Add a mobile ID* step in the
scan flow, and the server lane needs `mdocAuth` wired into the recovery
service with `HUMID_IACA_DIR`.

**What a physical US driver's license can and can't prove.** The PDF417
barcode on the back is read exactly, but it isn't signed, so it shows what's
printed, not that the card is real. A licence is authenticated the way a
passport is only through its mobile version. HumID keeps both: the card's
photos and barcode, and the mobile ID's signed data, in one record. The signed
data wins where they differ.

## 3. Signed barcodes (not built yet)

Some IDs carry a QR code signed by the issuer, which HumID could check like a
mobile ID, but without the live-device proof. The largest is **India's
Aadhaar Secure QR**: the identity data and photo are signed by UIDAI with RSA
over SHA-256. It should be built from UIDAI's official specification and real
test vectors, not from third-party descriptions. Store the masked form only
(see below).

## 4. Unsigned documents (photo, MRZ or barcode only)

Read and sealed, but marked as not provable:

- physical US and Canadian driver's licenses and state IDs (AAMVA barcode)
- US Passport Card and Permanent Resident Card: their RFID tags carry only a
  reference number, and the MRZ is read from the photo
- visas and any other card: photos of each side

## Storage rules to respect (not legal advice)

A person keeping an encrypted copy of their *own* ID is lawful in general.
Restrictions mostly target businesses collecting or copying other people's
IDs. Before launch, check these with counsel:

- **US military IDs and Common Access Cards: don't capture them.** Reproducing
  them is prohibited under 18 U.S.C. § 701, and the services tell members not
  to let them be photocopied. HumID's document types leave them out; the UI
  should refuse them explicitly.
- **Aadhaar (India).** The Aadhaar Act and UIDAI rules restrict who may store
  Aadhaar numbers. Keep only the masked number and the Secure QR.
- **National ID copies.** Some countries limit copies of the national ID card;
  Germany, for example, allows copies only by or with the holder's consent and
  requires them to be recognisable as copies. HumID's records are the
  holder's own; confirm per country whether they must also be marked as copies.
- **Licence barcodes.** Several US states limit how businesses use data read
  from a licence. That matters if HumID ever reads someone else's ID
  (verification stations), not for the holder's own vault.
- **Data protection law.** GDPR, US state privacy and biometric laws (e.g.
  Illinois BIPA) and others may apply to HumID as a service, even though the
  server only ever holds sealed copies. This is already on the *Before real data* list
  in [SECURITY.md](SECURITY.md).
