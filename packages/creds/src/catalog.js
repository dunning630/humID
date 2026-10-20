// Which public credentials HumID can take, and how far each can be proved.
//
// "Proved" means two separate things, and HumID reports both:
//   issuer   the issuing authority signed this data, and its signing key
//            chains to a root HumID trusts for that authority
//   holder   the device presenting it holds the key the issuer bound to it
//            (mdoc device authentication, SD-JWT key binding, a passport
//            chip's Active Authentication), so it isn't a copy
//
// Nothing here is legal advice on what a business may collect; see
// docs/CREDENTIALS.md "Rules to respect".

export const MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
export const PHOTOID_DOCTYPE = "org.iso.23220.photoid.1";
export const PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";
export const PID_VCT = "urn:eudi:pid:1";

/** Credential types that can be requested online or in person. */
export const TYPES = {
  mdl: {
    label: "Mobile driver's license or state ID", format: "mso_mdoc", docType: MDL_DOCTYPE, ns: "org.iso.18013.5.1",
    trust: "iaca", proves: ["issuer", "holder"],
    where: "US states and territories in Apple Wallet, Google Wallet, Samsung Wallet and state apps; other countries' ISO 18013-5 licenses",
  },
  photoid: {
    label: "Photo ID (ISO/IEC 23220), such as a wallet Digital ID", format: "mso_mdoc", docType: PHOTOID_DOCTYPE, ns: "org.iso.23220.1",
    trust: "iaca", proves: ["issuer", "holder"],
    where: "Wallet photo IDs. Apple's Digital ID (made from a US passport) is ISO-based; confirm its document type and Apple's issuing root from Apple's developer resources before enabling it.",
  },
  pid_mdoc: {
    label: "EU digital identity (PID, mdoc)", format: "mso_mdoc", docType: PID_DOCTYPE, ns: PID_DOCTYPE,
    trust: "iaca", proves: ["issuer", "holder"], where: "EU Digital Identity Wallets as member states roll them out",
  },
  pid_sdjwt: {
    label: "EU digital identity (PID, SD-JWT VC)", format: "dc+sd-jwt", vct: [PID_VCT],
    trust: "sdjwt", proves: ["issuer", "holder"], where: "EU Digital Identity Wallets; claim names follow the PID Rulebook (check the version your wallets use)",
  },
};

/** Everything HumID knows about, including documents read in person and SSN, with what each proves. */
export const CATALOG = [
  ...Object.entries(TYPES).map(([id, t]) => ({ id, ...t, channels: ["online", "in person (QR + Bluetooth/NFC)"] })),
  {
    id: "passport_chip", label: "Passport (chip)", format: "icao-9303", trust: "csca", proves: ["issuer", "holder"], channels: ["in person (NFC)"],
    where: "E-passports of most countries: passive authentication against the country's CSCA, Active Authentication for the chip itself",
  },
  {
    id: "id_card_chip", label: "National ID card or residence permit (chip)", format: "icao-9303", trust: "csca", proves: ["issuer", "holder"], channels: ["in person (NFC)"],
    where: "Every EU ID card issued since August 2021, and many others; opened with the CAN printed on the card",
  },
  {
    id: "license_barcode", label: "Physical driver's license or state ID (barcode)", format: "aamva-pdf417", trust: null, proves: [], channels: ["camera"],
    where: "US and Canadian cards. The barcode isn't signed: it shows what's printed, not that the card is real. AAMVA's DLDV data check exists for permitted businesses only (not built).",
  },
  {
    id: "ssn", label: "US Social Security number", format: "registry-match", trust: "ssa", proves: ["registry"], channels: ["server, permitted entities only"],
    where: "No card or wallet credential exists to verify. SSA's eCBSV answers yes/no for a number, name and date of birth, only for financial institutions and their service providers, with the holder's signed consent, for an annual fee.",
  },
];

/**
 * The HumID claim vocabulary → each credential's own element. An array path
 * is for SD-JWT (nested claims). null: that credential doesn't carry it.
 */
export const CLAIMS = {
  given_name: { mdl: "given_name", photoid: "given_name_unicode", pid_mdoc: "given_name", pid_sdjwt: ["given_name"] },
  family_name: { mdl: "family_name", photoid: "family_name_unicode", pid_mdoc: "family_name", pid_sdjwt: ["family_name"] },
  birth_date: { mdl: "birth_date", photoid: "birth_date", pid_mdoc: "birth_date", pid_sdjwt: ["birthdate"] },
  age_over_18: { mdl: "age_over_18", photoid: "age_over_18", pid_mdoc: "age_over_18", pid_sdjwt: ["age_equal_or_over", "18"] },
  age_over_21: { mdl: "age_over_21", photoid: "age_over_21", pid_mdoc: "age_over_21", pid_sdjwt: ["age_equal_or_over", "21"] },
  portrait: { mdl: "portrait", photoid: "portrait", pid_mdoc: "portrait", pid_sdjwt: ["picture"] },
  document_number: { mdl: "document_number", photoid: "document_number", pid_mdoc: "document_number", pid_sdjwt: ["document_number"] },
  expiry_date: { mdl: "expiry_date", photoid: "expiry_date", pid_mdoc: "expiry_date", pid_sdjwt: ["date_of_expiry"] },
  issuing_country: { mdl: "issuing_country", photoid: "issuing_country", pid_mdoc: "issuing_country", pid_sdjwt: ["issuing_country"] },
  issuing_jurisdiction: { mdl: "issuing_jurisdiction", photoid: null, pid_mdoc: null, pid_sdjwt: null },
  nationality: { mdl: "nationality", photoid: "nationality", pid_mdoc: "nationality", pid_sdjwt: ["nationalities"] },
  sex: { mdl: "sex", photoid: "sex", pid_mdoc: "sex", pid_sdjwt: ["sex"] },
  address: {
    mdl: ["resident_address", "resident_city", "resident_state", "resident_postal_code", "resident_country"],
    photoid: ["resident_address_unicode", "resident_city_unicode", "resident_postal_code", "resident_country"],
    pid_mdoc: ["resident_address", "resident_city", "resident_postal_code", "resident_country"],
    pid_sdjwt: ["address"],
  },
};

/** Ready-made asks. Each asks for as little as the purpose needs. */
export const PURPOSES = {
  age_over_18: ["age_over_18"],
  age_over_21: ["age_over_21"],
  identity: ["given_name", "family_name", "birth_date", "issuing_country", "issuing_jurisdiction", "expiry_date"],
  identity_with_photo: ["given_name", "family_name", "birth_date", "issuing_country", "issuing_jurisdiction", "expiry_date", "portrait"],
  vault: ["given_name", "family_name", "birth_date", "sex", "nationality", "document_number", "issuing_country", "issuing_jurisdiction", "expiry_date", "portrait", "address"],
};
