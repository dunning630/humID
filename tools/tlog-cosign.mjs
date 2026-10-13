#!/usr/bin/env node
// An independent cosigner for a HumID server's public transparency log.
//
//   node tools/tlog-cosign.mjs keygen                  → a key pair; give the server operator
//                                                         the line for HUMID_TLOG_COSIGNERS
//   node tools/tlog-cosign.mjs run <url> <name> <key>  → fetch the latest checkpoint, check it
//                                                         extends the last one this cosigner
//                                                         signed, and sign it
//
// Run `run` on a schedule from somewhere the server operator doesn't control. It keeps
// its last signed checkpoint in <key>.state.json; if the server ever shows it a log that
// doesn't extend that one, it refuses and exits 2: that's proof of a rewritten history.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { ml_dsa87, b64u, unb64u, fromHex } from "@humid/htp";
import { cosignMessage, checkpointMessage, verifyConsistency } from "@humid/audit";

const [cmd, url, name, keyFile] = process.argv.slice(2);

if (cmd === "keygen") {
  const k = ml_dsa87.keygen();
  const file = url || "tlog-cosigner.json";
  writeFileSync(file, JSON.stringify({ pk: b64u(k.publicKey), sk: b64u(k.secretKey) }), { mode: 0o600 });
  console.log(`Saved ${file}. Server setting:\nHUMID_TLOG_COSIGNERS=<name>=${b64u(k.publicKey)}`);
  process.exit(0);
}
if (cmd !== "run" || !url || !name || !keyFile) {
  console.error("usage: tlog-cosign.mjs keygen [file] | run <https://server> <name> <keyfile>");
  process.exit(1);
}

const key = JSON.parse(readFileSync(keyFile, "utf8"));
const stateFile = `${keyFile}.state.json`;
const last = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, "utf8")) : null;
const base = url.replace(/\/+$/, "");

const page = await (await fetch(`${base}/tlog/v1/checkpoint`)).json();
const cp = page.checkpoint;
const root = fromHex(cp.root);
if (!ml_dsa87.verify(unb64u(cp.sig), checkpointMessage(cp.size, root, cp.at), unb64u(page.ledgerKey.dsa))) {
  console.error("Checkpoint signature is invalid."); process.exit(2);
}
if (last?.ledgerKey && last.ledgerKey !== page.ledgerKey.dsa) { console.error("The log's signing key changed."); process.exit(2); }
if (last && last.size > 0) {
  if (cp.size < last.size) { console.error(`The log shrank from ${last.size} to ${cp.size}.`); process.exit(2); }
  const { proof } = await (await fetch(`${base}/tlog/v1/consistency?from=${last.size}&to=${cp.size}`)).json();
  if (!verifyConsistency(last.size, fromHex(last.root), cp.size, root, proof.map(fromHex))) {
    console.error(`The log at ${cp.size} does not extend the one signed at ${last.size}. History was rewritten.`); process.exit(2);
  }
}
const sig = ml_dsa87.sign(cosignMessage(name, cp.size, root, cp.at), unb64u(key.sk));
const r = await fetch(`${base}/tlog/v1/cosign`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name, size: cp.size, sig: b64u(sig) }) });
if (!r.ok) { console.error(`Server refused the cosignature: ${r.status} ${await r.text()}`); process.exit(1); }
writeFileSync(stateFile, JSON.stringify({ size: cp.size, root: cp.root, at: cp.at, ledgerKey: page.ledgerKey.dsa }));
console.log(`Cosigned checkpoint ${cp.size} (${cp.root.slice(0, 16)}…).`);
