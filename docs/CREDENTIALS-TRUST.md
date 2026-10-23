# Trusting government credentials (HumID 4.0, provisional)

> **Status:** on branch `v4/integration`. The trust store, the list readers,
> the refresher and the operator tool are built and tested
> (`packages/creds/src/trust.js`, `trustsync.js`, `fetch.js`,
> `tests/trust.test.js`, `tests/fetch.test.js`). No real provider is pinned
> yet: that needs a person to confirm fingerprints with AAMVA, ICAO and any
> country whose list is used. Needs independent review before real IDs.

HumID checks a government credential by following its signatures up to a
root it already trusts. This document is about those roots: where they come
from, how HumID decides to believe them, and how they stay current.

## What proves what

| Credential | Signed by | Root HumID needs | Where the roots come from |
|---|---|---|---|
| US mobile driver's license / state ID (ISO 18013-5) | The state's Document Signer | The state's IACA root | AAMVA's VICAL (Digital Trust Service), or a root a DMV publishes, pinned by hand |
| Passport or ID card chip (ICAO 9303) | The country's Document Signer | The country's CSCA | ICAO master list, or a country's own (Germany's, from the BSI) |
| EU PID and other SD-JWT VCs | The provider | A named issuer, or an x5c root trusted for SD-JWT | Pinned by hand per issuer |
| Physical license barcode | Nothing | — | Can't be verified; shown as "printed" |

## The rule: a list is only as good as the key that signs it

A VICAL or master list is a signed list of roots. HumID applies one only when
its signer chains to a provider **pinned in advance by SHA-256 fingerprint**.
An empty pin list means the source is refused, never trusted blindly.

To pin a provider:

1. Download the list (AAMVA: https://vical.dts.aamva.org/ ; ICAO:
   https://www.icao.int/icao-pkd/icao-master-list ; BSI German master list).
   Each requires accepting the publisher's terms.
2. `node tools/trust.mjs inspect <file>` prints the signer chain and the
   fingerprint of every certificate in it. It trusts nothing.
3. Confirm the fingerprint **with the provider itself**, by a channel other
   than the download (AAMVA's contact, ICAO's PKD office, which provides the
   UN CSCA certificate on request; the BSI's published fingerprint).
4. Put the fingerprint in `deploy/trust/trust-config.json` (copy of the
   example) and run `node tools/trust.mjs refresh --config deploy/trust/trust-config.json`.

## What the store keeps, and enforces

- **Each mobile ID root keeps the country, state and document types its list
  assigned.** The verifier takes the issuer's country and state from the
  root, never from the document, and refuses a document whose
  `issuing_country`, `issuing_jurisdiction` or Document Signer names someone
  else. An Illinois root can't vouch for a Wisconsin license. A root that
  names no state can't vouch for any state claim (precert finding CRD-01).
- **Every namespace is checked.** A country or state claim anywhere in the
  signed data (mDL, AAMVA, PID, ISO 23220) must match the anchor, and the
  result reports the anchor's country and state, not the document's.
- **Entries that aren't usable roots are dropped with a reason**: not a CA,
  expired, unreadable, no document types, or the list and the certificate
  disagree on country or state. A root vouches only for the document types
  its list names; hand-pinned roots default to mobile driver's licenses.
- **Lists only move forward.** A VICAL with a lower issue ID (or an earlier
  date) than the one applied is refused, so replaying an old list can't bring
  back a root that was removed. A master list carries no issue number, so its
  signed CMS signing time orders it: one signed before the list applied for
  that source (or at the same time with other contents, or with no signing
  time once one was seen) is refused, so replaying last year's list can't drop
  the CSCAs added since and lock those countries' passports out (CREDS-06).
  Each source (`icao`, `bsi`, …) keeps its own clock. A list over 120 days old, more than 30 days
  past its own `nextUpdate`, or dated in the future is refused.
- **The store has a revision** that rises with every change.
  `loadTrustStore(snapshot, { minRev })` refuses an older copy; the refresher
  keeps the highest revision in `trust.json.rev`, and the recovery service
  refuses a file older than one it has already used.
- **SD-JWT roots are separate.** A DMV's mDL root is never accepted as an
  SD-JWT issuer just because it's in the VICAL. Keys from an issuer's own
  metadata count only for issuers named in the store.

## Relayed, not trusted

The trust store code is plain JavaScript, so phones can run it too. The
intended design: the server fetches the signed lists and relays the raw
bytes; each phone checks them against provider pins built into the app. A
server can then pass lists along but can't add a root of its own to anyone's
phone (the same lesson as the ledger-key finding PC-04). The app side of this
isn't wired yet.

## Keeping it current

- `node tools/trust.mjs refresh --config …` once, or `startTrustRefresh`
  (`@humid/creds/server`) to refresh every 6 hours. Each source is
  independent; a failing source keeps its last good data; saves are atomic
  and readable only by the server account.
- Fetching goes through `safeFetch`: https on 443 only, every DNS answer
  checked against private and reserved ranges and the connection pinned to
  the checked address, no redirects, time and size caps, optional host list.
  The same fetcher serves revocation status lists, whose address comes from
  the (untrusted) credential (precert finding CRD-02).
- The recovery service reads master-list CSCAs from the file named by
  `HUMID_TRUST_STORE` and picks up a refreshed file on its next request.
- `node tools/trust.mjs status` shows counts, US states covered, and each
  source's date, next update and whether it's overdue.

## Not built yet

1. The gateway route that checks a credential (`POST /creds/verify`) using
   the store, and the app screens.
2. The app checking relayed lists against built-in provider pins.
3. CSCA revocation lists (ICAO PKD CRLs) in passive authentication.
4. Real provider pins (needs a person, above).
5. Confirming whether US passport chips carry an Active Authentication key;
   without one, a US passport proves the data is the State Department's but
   not that the chip isn't a copy, and HumID says so.
