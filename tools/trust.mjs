#!/usr/bin/env node
// HumID trust lists: who HumID believes issues mobile IDs and passports.
//
//   node tools/trust.mjs inspect <file>
//       What a downloaded VICAL or master list is, who signed it, and the
//       SHA-256 fingerprints to confirm with AAMVA / ICAO / the publishing
//       country BEFORE pinning them. Trusts nothing.
//
//   node tools/trust.mjs refresh --config <trust-config.json> [--store <trust.json>]
//       Fetch (or read) every configured list, check it against its pinned
//       provider, apply it, and save the store if anything changed.
//
//   node tools/trust.mjs pin-iaca <root.pem> --country US --state IL [--store …] [--note "…"]
//       Trust one state's mobile ID root by hand (published by the DMV, before
//       it is in the VICAL).
//
//   node tools/trust.mjs add-issuer <https://issuer> --country DE [--store …]
//       Accept SD-JWT VC credentials from a named issuer.
//
//   node tools/trust.mjs remove --fingerprint <sha256> | --issuer <url> [--store …]
//   node tools/trust.mjs status [--store …]
//
// The store defaults to ./data/trust.json. Services read it through
// HUMID_TRUST_STORE (see docs/CREDENTIALS-TRUST.md).

import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, X509Certificate } from "node:crypto";
import { readVical } from "@humid/mdoc";
import { readTrustStoreFile, saveTrustStoreFile, refreshTrust, unzipMasterList } from "@humid/creds/server";

const args = process.argv.slice(2);
const cmd = args.shift();
const opt = (name, dflt) => { const i = args.indexOf(`--${name}`); if (i < 0) return dflt; const v = args[i + 1]; args.splice(i, 2); return v; };
const storePath = opt("store", "data/trust.json");
const out = (x) => process.stdout.write(typeof x === "string" ? `${x}\n` : `${JSON.stringify(x, null, 2)}\n`);
const die = (m) => { process.stderr.write(`trust: ${m}\n`); process.exit(1); };
const sha = (b) => createHash("sha256").update(b).digest("hex");

function inspect(file) {
  const raw = readFileSync(file);
  // A VICAL is CBOR (a COSE_Sign1 array, 0x84 or tag 18 0xd2); a master list is DER CMS (0x30), maybe zipped.
  if (raw[0] === 0x84 || raw[0] === 0xd2) {
    const v = readVical(new Uint8Array(raw));
    out({
      kind: "VICAL", sha256: sha(raw), provider: v.provider, issueId: v.issueId, date: v.date, nextUpdate: v.nextUpdate,
      signatureVerifies: true, trusted: "not checked: confirm a fingerprint below with the provider, then pin it",
      chain: v.chain, roots: v.certificates.length,
      states: [...new Set(v.certificates.filter((c) => c.country === "US").map((c) => c.state))].filter(Boolean).sort(),
      countries: [...new Set(v.certificates.map((c) => c.country))].filter(Boolean).sort(),
    });
    return;
  }
  const ml = Buffer.from(unzipMasterList(raw));
  // Without a pinned publisher this only lists the certificates in the CMS wrapper, which is what you confirm out of band.
  const certs = [];
  for (let p = 0; p < ml.length - 4; p++) {
    if (ml[p] !== 0x30 || ml[p + 1] !== 0x82) continue;
    const len = ml.readUInt16BE(p + 2) + 4;
    try { const c = new X509Certificate(ml.subarray(p, p + len)); certs.push(c); p += len - 1; } catch { /* not a certificate here */ }
  }
  const signers = certs.filter((c) => !c.ca);
  out({
    kind: "CSCA master list (signature not checked until a publisher is pinned)", sha256: sha(raw),
    signerCertificates: signers.map((c) => ({ subject: c.subject.replace(/\n/g, ", "), issuer: c.issuer.replace(/\n/g, ", "), validTo: c.validTo, sha256: sha(c.raw) })),
    cscasListed: certs.length - signers.length,
    note: "Pin the PUBLISHER's CSCA (the issuer above), e.g. the UN CSCA for ICAO's list, after confirming its fingerprint with the publisher.",
  });
}

const store = () => readTrustStoreFile(storePath);

switch (cmd) {
  case "inspect": {
    const f = args[0] || die("inspect <file>");
    inspect(f);
    break;
  }
  case "refresh": {
    const cfgPath = opt("config") || die("refresh --config <trust-config.json>");
    const config = JSON.parse(readFileSync(cfgPath, "utf8"));
    const s = store();
    const report = await refreshTrust(s, config, { baseDir: dirname(cfgPath) });
    if (report.changed) saveTrustStoreFile(storePath, s);
    out(report);
    if (Object.values(report.sources).some((r) => !r.ok)) process.exitCode = 2;
    break;
  }
  case "pin-iaca": {
    const f = args[0] || die("pin-iaca <root.pem> --country US --state IL");
    const s = store();
    const fp = s.pinIaca(readFileSync(f, "utf8"), { country: opt("country"), state: opt("state"), note: opt("note"), docTypes: (opt("doc-types", "") || "").split(",").filter(Boolean) });
    saveTrustStoreFile(storePath, s);
    out({ pinned: fp });
    break;
  }
  case "add-issuer": {
    const iss = args[0] || die("add-issuer <https://issuer> --country DE");
    const s = store();
    s.addSdJwtIssuer({ iss, country: opt("country"), state: opt("state"), note: opt("note") });
    saveTrustStoreFile(storePath, s);
    out({ added: iss });
    break;
  }
  case "remove": {
    const s = store();
    const changed = s.remove({ fingerprint: opt("fingerprint"), iss: opt("issuer") });
    if (changed) saveTrustStoreFile(storePath, s);
    out({ removed: changed });
    break;
  }
  case "status":
    out(store().status());
    break;
  default:
    die("commands: inspect, refresh, pin-iaca, add-issuer, remove, status (see the top of tools/trust.mjs)");
}
