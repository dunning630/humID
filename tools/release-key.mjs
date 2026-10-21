#!/usr/bin/env node
// The HumID release key: the maintainer's offline ML-DSA-87 key that signs every
// HumID Server for Windows release (RELEASING.md, docs/ADMIN.md). The admin console
// installs only a zip signed by a key pinned in deploy/windows/admin/release-keys.mjs.
//
//   node tools/release-key.mjs keygen --out <file>          a new key pair; the secret key goes to <file>
//                                                            (mode 0600, never overwritten); prints the
//                                                            public key to paste into release-keys.mjs
//   node tools/release-key.mjs sign <zip> --key <file>      writes <zip>.sig
//   node tools/release-key.mjs verify <zip> [--pub <b64>]   checks <zip>.sig against that key, or against
//                                                            the keys pinned in release-keys.mjs
//
// Keep the secret key on a computer that's offline (or a USB drive kept in a drawer).
// It never goes into the repository, a GitHub secret, CI, or a server: whoever holds it
// can make every HumID server install what they like, as SYSTEM.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename } from "node:path";
import { ml_dsa87, b64u, unb64u } from "@humid/htp";
import { signRelease, verifyRelease, keyFingerprint, versionOfName, pinnedKeys } from "../deploy/windows/admin/release.mjs";

const argv = process.argv.slice(2);
const cmd = argv.shift();
const flag = (name) => { const i = argv.indexOf(name); if (i < 0) return undefined; const v = argv[i + 1]; argv.splice(i, 2); return v; };
function fail(msg, code = 1) { console.error(msg); process.exit(code); }
const usage = "usage: release-key.mjs keygen --out <file> | sign <zip> --key <file> | verify <zip> [--pub <base64url>]";

function readKey(file) {
  let k;
  try { k = JSON.parse(readFileSync(file, "utf8")); } catch (e) { fail(`Can't read the release key ${file}: ${e.message}`); }
  if (k?.format !== "humid-release-key" || !k.sk || !k.pk) fail(`${file} isn't a HumID release key.`);
  return { secretKey: unb64u(k.sk), publicKey: unb64u(k.pk) };
}

switch (cmd) {
  case "keygen": {
    const out = flag("--out");
    if (!out) fail(usage, 2);
    const k = ml_dsa87.keygen();
    const pk = b64u(k.publicKey);
    const body = JSON.stringify({ format: "humid-release-key", v: 1, created: new Date().toISOString(), fingerprint: keyFingerprint(k.publicKey), pk, sk: b64u(k.secretKey) });
    try { writeFileSync(out, body, { mode: 0o600, flag: "wx" }); } // never replace a key
    catch (e) { fail(e.code === "EEXIST" ? `${out} already exists. Nothing was written: choose another file name.` : `Couldn't write ${out}: ${e.message}`); }
    console.log(`Saved the secret release key to ${out}. Keep it offline; it never goes near GitHub, CI or a server.\n`);
    console.log(`Fingerprint: ${keyFingerprint(k.publicKey)}\n`);
    console.log("Public key: paste it into RELEASE_KEYS in deploy/windows/admin/release-keys.mjs and commit:\n");
    console.log(`  "${pk}", // ${keyFingerprint(k.publicKey)}, ${new Date().toISOString().slice(0, 10)}`);
    break;
  }
  case "sign": {
    const zip = argv.shift();
    const keyFile = flag("--key");
    if (!zip || !keyFile) fail(usage, 2);
    const name = basename(zip);
    if (!versionOfName(name)) fail(`${name} isn't a HumID Server release file name (HumID-Server-Windows-X.Y.Z.zip). Sign the zip exactly as CI built it.`);
    const key = readKey(keyFile);
    const bytes = readFileSync(zip);
    const sig = signRelease({ bytes, name, ...key });
    verifyRelease({ bytes, name, version: sig.version, sig, keys: [b64u(key.publicKey)] }); // a last look before it's written
    writeFileSync(`${zip}.sig`, JSON.stringify(sig, null, 1) + "\n");
    console.log(`Signed ${name} (version ${sig.version}, SHA-256 ${sig.sha256}) with release key ${sig.key}.`);
    console.log(`Wrote ${zip}.sig: upload it to the draft release beside the zip, then publish.`);
    if (!pinnedKeys().includes(b64u(key.publicKey))) console.warn(`\n!! Key ${sig.key} isn't in deploy/windows/admin/release-keys.mjs here: servers that don't pin it will refuse this release.`);
    break;
  }
  case "verify": {
    const zip = argv.shift();
    const pub = flag("--pub");
    if (!zip) fail(usage, 2);
    const sigFile = `${zip}.sig`;
    const name = basename(zip);
    try {
      const v = verifyRelease({ bytes: readFileSync(zip), name, version: versionOfName(name), sig: existsSync(sigFile) ? readFileSync(sigFile) : null, keys: pub ? [pub] : pinnedKeys() });
      console.log(`OK: ${name} is signed by HumID release key ${v.key} (SHA-256 ${v.sha256}).`);
    } catch (e) { fail(e.message); }
    break;
  }
  default: fail(usage, 2);
}
