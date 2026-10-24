#!/usr/bin/env node
// Writes crates/humid-pq2/src/selftest.bin: the larger known answers humid_pq2::self_test()
// checks at start (the small ones are hex constants in selftest.rs). Every value comes from
// a NIST ACVP fixture already in the repo, except the ML-KEM implicit-rejection answer, which
// is computed with the pinned @noble/post-quantum (an independent implementation) on NIST's
// keyGen key. Format: lp(field) for each field below, in order (lp = u32 big-endian length).
//
//   node tools/pq2-selftest-vectors.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";

const fx = (dir, name) => JSON.parse(gunzipSync(readFileSync(new URL(`../tests/fixtures/${dir}/${name}.json.gz`, import.meta.url))));
const h = (s) => new Uint8Array(Buffer.from(s, "hex"));
const first = (doc, pred) => { for (const g of doc.testGroups) if (pred(g)) return { g, t: g.tests[0] }; throw new Error("no case"); };

// ML-KEM-1024 encapsulation (ACVP): ek, m -> c, k
const enc = first(fx("acvp", "ML-KEM-encapDecap-FIPS203"), (g) => g.parameterSet === "ML-KEM-1024" && g.function === "encapsulation").t;
// ML-DSA-87 deterministic sigGen (ACVP, pure external with context): pk, message, context -> signature
const sg = first(fx("acvp", "ML-DSA-sigGen-FIPS204"), (g) => g.parameterSet === "ML-DSA-87" && g.deterministic).t;
// Implicit rejection on the self-test's keyGen key (ACVP ML-KEM keyGen, first ML-KEM-1024 case)
const kg = first(fx("acvp", "ML-KEM-keyGen-FIPS203"), (g) => g.parameterSet === "ML-KEM-1024").t;
const key = ml_kem1024.keygen(new Uint8Array([...h(kg.d), ...h(kg.z)]));
const m = new Uint8Array(32).fill(0xa5);
const e = ml_kem1024.encapsulate(key.publicKey, m);
const bad = e.cipherText.slice(); bad[0] ^= 1;
const rej = ml_kem1024.decapsulate(bad, key.secretKey);

// SLH-DSA-SHA2-256s: a valid sigVer case (pure external, with context): pk, message, context, signature
const sv = fx("acvp-pq2", "SLH-DSA-sigVer-FIPS205").testGroups
  .filter((g) => g.parameterSet === "SLH-DSA-SHA2-256s").flatMap((g) => g.tests).find((t) => t.testPassed);

const fields = [h(enc.ek), h(enc.m), h(enc.c), h(enc.k), h(sg.pk), h(sg.message), h(sg.context), h(sg.signature), e.sharedSecret, rej,
  h(sv.pk), h(sv.message), h(sv.context), h(sv.signature)];
const parts = [];
for (const f of fields) { const l = Buffer.alloc(4); l.writeUInt32BE(f.length); parts.push(l, Buffer.from(f)); }
const out = new URL("../crates/humid-pq2/src/selftest.bin", import.meta.url);
writeFileSync(out, Buffer.concat(parts));
console.log(`wrote ${out.pathname}: ML-KEM encaps tcId ${enc.tcId}, ML-DSA sigGen tcId ${sg.tcId}, keyGen tcId ${kg.tcId}`);
