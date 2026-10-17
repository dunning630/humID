# Payment cards in the vault

`@humid/cards` keeps the holder's own credit and debit cards in the vault,
the same way on every platform. A card is one sealed record (media type
`application/vnd.humid.card+json`, schema `humid.card/1`). It is encrypted on
the device like any document and opened only with a live face or fingerprint
check.

This is **phase 1: storing cards**. Paying with them (phase 2) is described at
the end and isn't built.

## What a card record holds

| Holds | Never holds | Only if the holder turns it on |
|---|---|---|
| Card number, expiry, name on card, network, credit / debit / prepaid, valid-from date, issuing country | The PIN | The security code (CVV / CVC / CID), per card |
| The holder's nickname, the bank and its phone number, notes | Magnetic-stripe or chip data (track 1/2, chip cryptograms) | |
| A photo of the **front** | A photo of the **back**, which shows the security code | |

These rules are enforced in the record code (`applyTyped`, `setImage`,
`encodeCard`), not only in the UI. A record that somehow carries forbidden
data has it stripped when it is read (`decodeCard`). Turning the security
code off deletes it.

The vault list shows the network, credit or debit, last four digits, expiry
and nickname from the encrypted index (`summary`). The full number is never in
the index.

## Adding a card

| How | Platforms | What it reads |
|---|---|---|
| **Camera**: the front of the card | iPhone, Android, Mac, Windows, Linux | Number, expiry, name. `readCardText` takes the camera engine's OCR text, repairs digit look-alikes (O→0, l→1, S→5…) only inside digit groups, accepts a number only if it passes the Luhn check and fits its network's length, and takes the latest date (a *member since* date is earlier). Live scanning (`CardConsensus`) accepts a number once two frames agree. |
| **Tap**: contactless | Android (NFC), Mac / Windows with a USB contactless reader | Number, expiry, the issuer's name from the card's own label, credit / debit / prepaid, valid-from date, issuing country, and the name where the card carries one (`readContactless`, over the same APDU transport as passport chips). Fills the form by itself; see below. |
| **Typed** | all | Everything; validated as typed |

iPhone apps can't read payment cards over NFC, so the iPhone uses the camera.
Linux has no card-reader support in the app yet (`pcsc-linux` isn't shipped).

### Tap to fill

On a phone with NFC turned on, or a computer with a USB contactless reader,
the *Add a payment card* sheet starts waiting for a card the moment it opens
(no button to press). When a card is read:

- every field the chip answered is filled in and marked **From chip**: number,
  expiry, type (credit / debit / prepaid), name on card, bank, valid from and
  issued in;
- the sheet moves to *Check the details*, and the holder reviews and seals;
- anything the holder has typed stays as typed: a later read never overwrites
  it (`applyRead` ranks typed > chip > camera; the form tracks what was
  touched);
- the reader keeps waiting while the holder types, so choosing *Type it* and
  then tapping the card still fills the rest; *Read a different card's chip*
  starts it again.

The waiting stops when the sheet closes or the card is sealed (the plugin's
`cancel`, humid-nfc 1.1). A wrong card (a transit card, a passport) shows a
note and keeps waiting. The bank name comes from the card's *application
preferred name* (9F12) or *application label* (50) with the network's and
product's words removed ("CHASE VISA" → "Chase"; "VISA CREDIT" → nothing), so
it's sometimes empty; credit / debit comes from the same labels and, for US
common-debit applications, from the application id. Cards rarely carry the
holder's name on the contactless interface; the camera or typing fills it.

Development builds in a browser have no NFC: *Tap a demo card* reads a
simulated Visa debit card (`@humid/cards/sim`), which release builds don't
contain.

**The contactless read is a read, not a payment.** It selects the payment
application, asks for processing options with amount zero and today's date,
and reads the records. Some cards count that request as an interaction, as
any phone-based card reader does. It never sends GENERATE AC, never asks for
or derives a security code, and returns only the number, expiry, name,
network, card label, issuer name, credit / debit, valid-from date and issuing
country. Service codes and track discretionary data are dropped where they're
read.

## Showing and copying

Every platform follows `HANDLING`:

- The number and code stay masked (`•••• 1111`) until the holder reveals
  them. Revealing is opening a vault item: a fresh biometric check, recorded
  in the Activity ledger. They mask again after 30 seconds.
- Copying puts digits only on the clipboard and clears it after 30 seconds.
- Screenshots are blocked while a card is shown (Android `FLAG_SECURE`, a
  privacy cover elsewhere), and the card is hidden in the app switcher.

## Compliance (PCI DSS)

HumID's server stores the card record only as ciphertext and never has the
keys. The PCI Security Standards Council says a provider that stores data
someone else encrypted, and can't decrypt it, has no access to the keys and
never sees cleartext, *may* treat that data as out of PCI DSS scope. Before
launch, get a written scoping opinion from a PCI Qualified Security Assessor.
Phase 2 changes the answer.

## Phase 2: paying (not built)

HumID shouldn't hand raw card numbers to merchants. The routes, best first:

1. **Network tokens through a payment provider** (Visa Token Service,
   Mastercard MDES, via a provider such as Stripe or Adyen). The merchant sees
   a device-bound token, never the number, and each payment is approved with
   HumID's live biometric check.
2. **Payment passkeys / Secure Payment Confirmation**: the biometric confirms
   a checkout without a card number changing hands, as networks and banks
   enable it.
3. **Autofill** into the holder's own checkout pages, as password managers
   do. This is simplest, but the number does reach the merchant's page.

## Tests

`node --test tests/cards.test.js`:

- published test numbers for every network
- expiry rules
- OCR noise, member-since dates and brand words
- frame voting
- contactless reads from simulated Visa, Mastercard and Amex cards (no
  directory, chained replies). The tests check that the reader sends only
  SELECT, GET PROCESSING OPTIONS, READ RECORD and GET RESPONSE, with amount
  zero.
- one tap fills the whole form (issuer, debit, name, country, valid from), and
  a typed value survives a second tap; issuer names from labels
- `tests/browser/cards.mjs` (CI): tap the demo card in the development build,
  check every chip-filled field and its mark, seal; then type one, open,
  reveal, copy, hide
- the record's rules: PIN, track data, back photo, security code opt-in,
  masking, index contents, scrubbing on decode
