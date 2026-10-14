# Country signing certificates (CSCA)

Put the CSCA certificates of the countries whose passports and ID cards you
want HumID to accept here, as PEM or DER files (`.pem`, `.crt`, `.cer`,
`.der`). The recovery service loads every file in this folder at start-up and
uses them for ICAO 9303 passive authentication of ID chips. An empty folder
means ID anchors are switched off (the app says so).

Where to get them:

- **ICAO PKD** (Public Key Directory): the authoritative source; membership or
  download agreement required.
- **National master lists**: several countries publish a signed CSCA master
  list, for example Germany's BSI (an LDIF/ML file containing many countries'
  CSCAs). Extract the certificates and verify the master list signature
  before trusting it.
- **Individual countries**: many publish their own CSCA certificate (the US
  Department of State publishes the US CSCA).

Restart the server after changing this folder. On the Windows server the
folder is `C:\ProgramData\HumID\csca` (or `HUMID_CSCA_DIR`).
