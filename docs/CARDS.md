# Payment cards in the vault

`@humid/cards` keeps the holder's own credit and debit cards in the vault,
the same way on every platform. A card is one sealed record (media type
`application/vnd.humid.card+json`, schema `humid.card/1`). It is encrypted on
the device like any document and opened only with a live face or fingerprint
check.

This is **phase 1: storing cards**, in the apps since 1.11.0. Paying with them
(phase 2) is described at the end and isn't built.

## What a card record holds

| Holds | Never holds | Only if the holder keeps it |
|---|---|---|
| Card number, expiry, name on card, network | The PIN | The security code (CVV / CVC / CID), per card: switched on in the form, or by scanning the back |
| The holder's nickname, the bank and its phone number, notes | Magnetic-stripe or chip data (track 1/2, chip cryptograms) | |
| A photo of the **front** | A photo of the **back**: it's read for the code and phone number, then discarded | |

These rules are enforced in the record code (`applyTyped`, `setImage`,
`encodeCard`), not only in the UI. A record that somehow carries forbidden
data has it stripped when it is read (`decodeCard`). Turning the security
code off deletes it.

The vault list shows the network, last four digits, expiry and nickname from
the encrypted index (`summary`). The full number is never in the index.

## Adding a card

| How | Platforms | What it reads |
|---|---|---|
| **Camera**: the front of the card | iPhone, Android, Mac, Windows, Linux | Number, expiry, name, and an American Express card's 4-digit code. `readCardText` takes the text Tesseract (English model, on the device) read, repairs digit look-alikes (O→0, l→1, S→5…) only inside digit groups, accepts a number only if it passes the Luhn check and fits its network's length, and takes the latest date (a *member since* date is earlier). A card held upside down is read turned round. |
| **Camera**: the back | all | The security code and the bank's phone number (`readCardBack`). The code is taken next to the last four digits, after a CVV / CVC label, or as the only lone group of the right length that isn't part of a phone number or date; with two candidates nothing is guessed. The photo isn't kept. |
| **Tap**: contactless | Android (NFC), Mac / Windows / Linux with a USB contactless reader | Number and expiry, sometimes the name (`readContactless`, over the same APDU transport as passport chips) |
| **Typed** | all | Everything; validated as typed |

iPhone apps can't read payment cards over NFC, so the iPhone uses the camera.

**The contactless read is a read, not a payment.** It selects the payment
application, asks for processing options with amount zero and today's date,
and reads the records. Some cards count that request as an interaction, as
any phone-based card reader does. It never sends GENERATE AC, never asks for
or derives a security code, and returns only the number, expiry, name,
network and issuing country. Service codes and track discretionary data are
dropped where they're read.

A code read from the front of an American Express card is offered, not kept: it's
kept only if the holder switches on "Keep the security code". "Member since" years
and the number's own first digits aren't taken for it. Because American Express
prints the code on the front, the photo of the front is kept only with the code.
Scanning the back is asking for the code, so it's kept (the switch can still turn
it off before sealing).

## Showing

Every platform follows `HANDLING`:

- Opening a card is opening a vault item: a fresh biometric check, recorded in
  the Activity ledger. The number and code stay masked (`•••• 1111`) until the
  holder taps Show, and mask again after 30 seconds or when HumID leaves the screen.
- Nothing is copied: other apps, keyboards and clipboard sync can read the
  clipboard, and nothing can reliably clear it (the security hardening, P2).
- Screenshots and screen recording are blocked app-wide on Android
  (`FLAG_SECURE`); the iPhone covers the app switcher and a recorded screen.

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
- the record's rules: PIN, track data, back photo, security code opt-in,
  masking, index contents, scrubbing on decode
