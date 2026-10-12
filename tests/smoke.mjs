#!/usr/bin/env node
// Smoke test against a RUNNING HumID deployment (used by CI against the
// docker compose stack, and by you against a real server):
//   node tests/smoke.mjs https://vault.humidsecure.ai
// Enrols a throwaway identity, seals + uploads a document, reads it back with a
// step-up proof, verifies the ledger, then closes the identity again.
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, toHex, sha3_256, random } from "@humid/htp";

const base = process.argv[2] || "https://localhost";
const step = (m) => process.stdout.write(`• ${m}\n`);
const S = suite();
const seed = random(64);
const keys = S.deriveKeys(seed);
const pub = S.publicOf(keys);
const commit = toHex(S.identityCommit(pub, sha3_256(random(16))));
const interrupt = { method: "smoke-test", assurance: "none" };
const stepUp = async ({ message }) => ({ sig: ml_dsa87.sign(message, keys.dsaSk), interrupt });

const api = new HumidApi({ baseUrl: base });
const srv = await api.server();
step(`server ${base} · fingerprint ${srv.fingerprint}`);
const s = await api.register({ pub, commit, device: { platform: "smoke", gateMethod: "smoke-test", assurance: "none" }, sign: async (m) => ml_dsa87.sign(m, keys.dsaSk) });
step(`registered ${s.id}`);
const text = `smoke ${new Date().toISOString()}`;
const { envelope } = await S.seal({ bytes: new TextEncoder().encode(text), name: "smoke.txt", type: "text/plain" }, keys, pub, { identityCommit: commit, interrupt });
const idx = await S.sealIndex(S.indexKey(seed), { name: "smoke.txt", type: "text/plain", category: "other" });
const item = await api.upload(envelope, idx);
step(`uploaded ${item.id} (${item.size} bytes sealed)`);
const back = await api.download(item.id, stepUp);
const opened = await S.open(back, keys);
if (new TextDecoder().decode(opened.bytes) !== text) throw new Error("round trip mismatch");
step("downloaded with step-up proof and decrypted on the client");
const l = await api.ledger();
if (!l.ok) throw new Error(`ledger did not verify: ${l.reason}`);
step(`ledger verified (${l.entries.length} events)`);
await api.closeIdentity(stepUp);
step("identity closed, vault erased");
console.log("SMOKE OK");
