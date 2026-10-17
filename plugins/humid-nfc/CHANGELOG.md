# tauri-plugin-humid-nfc

## 1.1.0

- `cancel`: stop waiting for a chip (a pending `begin` fails as cancelled) and close any open session, on every platform. The app calls it when the screen that asked for a chip closes, so a payment-card sheet that waits for a tap on its own never leaves the reader on.
- Android and iOS: a second `begin` while one is still waiting now fails the first as cancelled instead of leaving it unanswered.
- The transport is used for contactless payment cards (`@humid/cards`) as well as passport and ID chips; it still only moves APDUs.

## 1.0.0

- Chip reader transport: iPhone Core NFC, Android IsoDep, Windows and macOS PC/SC.
