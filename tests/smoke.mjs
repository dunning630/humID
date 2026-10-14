#!/usr/bin/env node
// Smoke test against a RUNNING HumID deployment (used by CI against the
// docker compose stack, and by you against a real server):
//   node tests/smoke.mjs https://vault.humidsecure.ai
// Creates a throwaway account, seals + uploads a document, sets a recovery
// card, adds a second device with a link code, opens the document from that
// device with a step-up proof, verifies the ledger, then closes the account.
//
// The smoke client has no phone, so it enrols as a biometric-only desktop
// (no hardware proof). Servers with HUMID_DEVICE_POLICY=biometric or demo run
// the whole flow; servers with the default "attested" policy must REFUSE that
// enrolment, and the test checks exactly that.
import { HumidApi } from "@humid/api";
import { suite } from "@humid/crypto";
import { ml_dsa87, toHex, sha3_256, random } from "@humid/htp";
import { newCard, cardTag, sealCard } from "@humid/recovery";

const base = process.argv[2] || "https://localhost";
const step = (m) => process.stdout.write(`• ${m}\n`);
const S = suite();
const GATE = "linux-fprintd-keyring"; // a biometric-only desktop gate; the server derives assurance itself
const assurance = "os";
const interrupt = { method: GATE, assurance };
const sign = (m, k) => ml_dsa87.sign(m, k.dsaSk);

// One account seed (shared by devices), one seed per device.
const seed = random(64);
const keys = S.deriveKeys(seed);
const pub = S.publicOf(keys);
const commit = toHex(S.identityCommit(pub, sha3_256(random(16))));
const device = (dkeys) => ({ dsaPk: dkeys.dsaPk, platform: "smoke", gateMethod: GATE, assurance });
const stepUpBy = (dkeys) => async ({ message }) => ({ sig: sign(message, dkeys), interrupt });

const phone = S.deriveKeys(random(64));
const api = new HumidApi({ baseUrl: base });
const srv = await api.server();
const policy = srv.policy?.devicePolicy;
step(`server ${base} · fingerprint ${srv.fingerprint} · device policy ${policy}`);
const enrol = () => api.register({
  pub, commit, device: device(phone),
  sign: async (m) => ({ registerSig: sign(m.register, keys), sigAccount: sign(m.device, keys), sigDevice: sign(m.device, phone) }),
});
if (policy === "attested") {
  try { await enrol(); } catch (e) {
    if (e.code !== "device_not_proven") throw e;
    step("a device without hardware proof was refused (device_not_proven)");
    console.log("SMOKE OK (attested policy: the full flow needs a real phone)");
    process.exit(0);
  }
  throw new Error("an attested-only server accepted a device with no hardware proof");
}
const s = await enrol();
step(`registered ${s.id} on device ${s.device}`);

const text = `smoke ${new Date().toISOString()}`;
const { envelope } = await S.seal({ bytes: new TextEncoder().encode(text), name: "smoke.txt", type: "text/plain" }, keys, pub, { identityCommit: commit, interrupt });
const idx = await S.sealIndex(S.indexKey(seed), { name: "smoke.txt", type: "text/plain", category: "other" });
const item = await api.upload(envelope, idx);
step(`uploaded ${item.id} (${item.size} bytes sealed)`);

const card = newCard();
await api.setCard({ tag: cardTag(card.secret), blob: await sealCard(card.secret, seed, s.id) }, stepUpBy(phone));
step("recovery card set");

// A second device joins with a link code.
const link = S.deriveKeys(random(64));
const tablet = new HumidApi({ baseUrl: base });
const { code } = await tablet.startLink({ kemPk: link.kemPk, xPk: link.xPk, platform: "smoke-2" });
const req = await api.getLink(code);
const sealedSeed = (await S.seal({ bytes: seed, name: "account key", type: "application/x-humid-key" }, keys, { kemPk: req.kemPk, xPk: req.xPk }, { identityCommit: commit, interrupt })).envelope;
await api.approveLink(code, sealedSeed, stepUpBy(phone));
const r = await tablet.linkResult(code);
const got = await S.open(r.envelope, link);
if (toHex(got.bytes) !== toHex(seed)) throw new Error("link handed over the wrong seed");
const tabletKeys = S.deriveKeys(random(64));
const t = await tablet.enrollDevice({ account: r.account, via: "link", device: device(tabletKeys), sign: async (m) => ({ sigAccount: sign(m, keys), sigDevice: sign(m, tabletKeys) }) });
step(`second device ${t.device} joined with code ${code.slice(0, 4)}…`);

const back = await tablet.download(item.id, stepUpBy(tabletKeys));
const opened = await S.open(back, keys);
if (new TextDecoder().decode(opened.bytes) !== text) throw new Error("round trip mismatch");
step("opened on the second device with a step-up proof and decrypted on the client");

const l = await api.ledger();
if (!l.ok) throw new Error(`ledger did not verify: ${l.reason}`);
step(`ledger verified (${l.entries.length} events)`);
await api.closeIdentity(stepUpBy(phone));
step("account closed, vault erased");
console.log("SMOKE OK");
