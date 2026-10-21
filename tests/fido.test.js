// @humid/fido: the CTAP 2.1 client HumID uses for security keys (docs/SECURITY-KEY.md).
// Its CBOR and NFC framing are checked on their own; everything else runs against a
// simulated key written separately from it (tests/support/fido-sim.js), whose own tests
// and python-fido2 cross-check live in fido-sim.test.js and fido-crosscheck.test.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as verifySig, randomBytes } from "node:crypto";
import {
  encode, decode, CborError, command, ctapMessage, selectFido, FIDO_AID,
  inspectKey, addRecoveryKey, readRecoveryKey, RP_ID, SALT, clientDataHash, FidoError,
} from "@humid/fido";
import { simulatedKey } from "./support/fido-sim.js";

const hex = (b) => Buffer.from(b).toString("hex");
const challenge = () => new Uint8Array(randomBytes(32));
const PIN = "246810";

/* ---------------- CBOR ---------------- */

test("CBOR: canonical encoding (CTAP 2.1 §8): shortest integers, keys sorted by encoded bytes", () => {
  assert.equal(hex(encode(0)), "00"); assert.equal(hex(encode(23)), "17"); assert.equal(hex(encode(24)), "1818");
  assert.equal(hex(encode(256)), "190100"); assert.equal(hex(encode(65536)), "1a00010000"); assert.equal(hex(encode(-1)), "20");
  assert.equal(hex(encode(-25)), "3818"); assert.equal(hex(encode(2 ** 32)), "1b0000000100000000");
  // COSE key order: 1, 3, -1, -2, -3 (0x01 0x03 0x20 0x21 0x22), whatever order they were given in.
  const cose = new Map([[-3, new Uint8Array(1)], [-1, 1], [3, -7], [-2, new Uint8Array(1)], [1, 2]]);
  assert.equal(hex(encode(cose)), "a5010203262001214100224100");
  // Text keys: shorter first, then bytewise ("id" < "name" < "displayName").
  assert.equal(hex(encode({ name: "a", displayName: "b", id: new Uint8Array(0) })), "a3" + "626964" + "40" + "646e616d65" + "6161" + "6b646973706c61794e616d65" + "6162");
  assert.deepEqual(decode(encode({ a: [1, -2, "x", true, false, null, new Uint8Array([9])] })).get("a"), [1, -2, "x", true, false, null, new Uint8Array([9])]);
  assert.throws(() => encode(1.5), CborError);
});

test("CBOR: decoding refuses what CTAP never sends, and is bounded", () => {
  const bad = (h, re) => assert.throws(() => decode(Uint8Array.from(Buffer.from(h, "hex"))), (e) => e instanceof CborError && (!re || re.test(e.message)), h);
  bad("c0", /tags/);                     // a tag
  bad("f93c00", /Floats/);               // a half float
  bad("5f", /Indefinite/);               // an indefinite byte string
  bad("9f", /Indefinite/);               // an indefinite array
  bad("0000", /Trailing/);               // two items
  bad("43aabb", /ends early/);           // truncated byte string
  bad("62c328", /UTF-8/);                // invalid UTF-8
  bad("a201010102", /Duplicate/);        // duplicate key
  bad("a1f501", /keys/);                 // a map key that's neither integer nor text
  bad("1bffffffffffffffff", /too large/);
  bad("81".repeat(10) + "00", /deeply/); // depth 10 > 8
  bad("9a00010000", /too many/);         // an array claiming 65 536 items
  // 600 items in nested arrays: over the 512-item budget.
  bad("99" + "0258" + "00".repeat(600), /too many/);
});

/* ---------------- NFC framing ---------------- */

/** A transport that records APDUs and answers from a script. */
function scripted(answers) {
  const sent = [];
  return { sent, transceive: async (apdu) => { sent.push(hex(apdu)); const a = answers.shift(); return Uint8Array.from(Buffer.from(typeof a === "function" ? a(apdu) : a, "hex")); } };
}

test("NFC: data over 255 bytes goes in chained blocks (CLA | 0x10), answers over 256 come back with 61xx and GET RESPONSE", async () => {
  const data = new Uint8Array(600).fill(0xab);
  const t = scripted(["9000", "9000", "aa".repeat(256) + "6110", "bb".repeat(16) + "9000"]);
  const r = await command(t, 0x80, 0x10, 0x80, 0x00, data);
  assert.equal(r.sw, 0x9000);
  assert.equal(r.data.length, 272);
  assert.ok(t.sent[0].startsWith("90108000ff"), "first block: CLA 0x90, 255 bytes, no Le");
  assert.equal(t.sent[0].length, (5 + 255) * 2);
  assert.ok(t.sent[1].startsWith("90108000ff"));
  assert.ok(t.sent[2].startsWith("801080005a") && t.sent[2].endsWith("00"), "last block: CLA 0x80, 90 bytes, Le 00");
  assert.equal(t.sent[3], "00c0000010", "GET RESPONSE for the rest");
});

test("NFC: SELECT the FIDO applet; a U2F-only key and a non-FIDO card are told apart", async () => {
  const t = scripted([Buffer.from("FIDO_2_0").toString("hex") + "9000"]);
  assert.equal(await selectFido(t), "FIDO_2_0");
  assert.equal(t.sent[0], "00a4040008" + hex(FIDO_AID) + "00");
  await assert.rejects(selectFido(scripted(["6a82"])), (e) => e.code === "not_fido");
  await assert.rejects(inspectKey(simulatedKey({ versions: ["U2F_V2"] })), (e) => e.code === "ctap1_only");
  // A key that does both answers U2F_V2 to SELECT, as YubiKey 5 NFC keys do: still a FIDO2 key.
  const both = simulatedKey({ versions: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"], pin: PIN });
  assert.equal((await inspectKey(both)).pinSet, true);
  const added = await addRecoveryKey(both, { pin: PIN, challenge: new Uint8Array(32).fill(7) });
  assert.equal(added.secret.length, 32);
});

test("NFC: a key that answers 9100 while it works is polled with NFCCTAP_GETRESPONSE", async () => {
  const k = simulatedKey({ busyPolls: 3, pin: PIN });
  const info = await inspectKey(k);
  assert.equal(info.pinSet, true);
  const t = scripted(["019100", "019100", "00a0" + "9000"]);
  const r = await ctapMessage(t, 0x04);
  assert.equal(hex(r), "00a0");
  assert.deepEqual(t.sent.slice(1), ["8011000000", "8011000000"]);
});

test("NFC: losing the key mid-command is a 'lost' error, not a crash", async () => {
  const t = { transceive: async () => { throw new Error("Tag was lost"); } };
  await assert.rejects(selectFido(t), (e) => e.code === "lost");
  await assert.rejects(selectFido({ transceive: async () => new Uint8Array(1) }), (e) => e.code === "bad_response");
});

/* ---------------- against a simulated key ---------------- */

test("adding: a key with no PIN needs one chosen (6+), then one tap makes the credential and reads its secret", async () => {
  const k = simulatedKey();
  assert.deepEqual(await inspectKey(k), { pinSet: false, retries: null, minPinLength: 6, problem: null });
  await assert.rejects(addRecoveryKey(k, { pin: PIN, challenge: challenge() }), (e) => e.code === "pin_not_set");
  await assert.rejects(addRecoveryKey(k, { pin: "12345", newPin: true, challenge: challenge() }), (e) => e.code === "pin_policy");
  const ch = challenge();
  const steps = [];
  const got = await addRecoveryKey(k, { pin: PIN, newPin: true, challenge: ch, onStep: (s) => steps.push(s) });
  assert.deepEqual(steps, ["setting-pin", "creating", "reading"]);
  assert.equal(got.secret.length, 32);
  assert.equal(got.publicKey.length, 65);
  // The key signed SHA-256("HUMID-KEY-v1 add " ‖ challenge) over its authenticator data, as the server checks.
  const pub = createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x: Buffer.from(got.publicKey.subarray(1, 33)).toString("base64url"), y: Buffer.from(got.publicKey.subarray(33)).toString("base64url") } });
  const cdh = createHash("sha256").update("HUMID-KEY-v1 add ").update(ch).digest();
  assert.ok(verifySig("sha256", Buffer.concat([got.authData, cdh]), { key: pub, dsaEncoding: "der" }, got.signature));
  assert.deepEqual(Buffer.from(got.authData.subarray(0, 32)), createHash("sha256").update(RP_ID).digest());
  assert.equal(got.authData[32] & 0x05, 0x05, "present and PIN-verified");
  assert.equal(k.state.credentials.length, 1);
  assert.equal(k.state.credentials[0].rpId, RP_ID);
  assert.equal(k.state.credentials[0].credProtect, 3, "invisible without the PIN");
  await assert.rejects(addRecoveryKey(k, { pin: PIN, newPin: true, challenge: challenge() }), (e) => e.code === "pin_already_set");
});

test("recovering: the same secret comes back with the PIN, on any later tap; the challenge is signed each time", async () => {
  const k = simulatedKey({ pin: PIN });
  const added = await addRecoveryKey(k, { pin: PIN, challenge: challenge() });
  k.powerCycle();
  for (let i = 0; i < 2; i++) {
    const ch = challenge();
    const [c, ...rest] = await readRecoveryKey(k, { pin: PIN, challenge: ch });
    assert.equal(rest.length, 0);
    assert.deepEqual(c.secret, added.secret, "hmac-secret is deterministic for the credential and salt");
    assert.deepEqual(c.credentialId, added.credentialId);
    assert.deepEqual([...clientDataHash("recover", ch)], [...createHash("sha256").update("HUMID-KEY-v1 recover ").update(ch).digest()]);
  }
  assert.equal(SALT.length, 32);
});

test("recovering: PIN protocol 1 keys (CTAP 2.0) work the same way", async () => {
  const k = simulatedKey({ pin: PIN, protocols: [1], versions: ["FIDO_2_0"], credProtect: false });
  const added = await addRecoveryKey(k, { pin: PIN, challenge: challenge() });
  const [c] = await readRecoveryKey(k, { pin: PIN, challenge: challenge() });
  assert.deepEqual(c.secret, added.secret);
});

test("wrong PINs: the key counts them, three in a row need a fresh tap, eight block it; HumID says how many are left", async () => {
  const k = simulatedKey({ pin: PIN });
  await addRecoveryKey(k, { pin: PIN, challenge: challenge() });
  await assert.rejects(readRecoveryKey(k, { pin: "000000", challenge: challenge() }), (e) => e.code === "pin_invalid" && e.retries === 7 && /7 tries left/.test(e.message));
  await assert.rejects(readRecoveryKey(k, { pin: "000001", challenge: challenge() }), (e) => e.code === "pin_invalid" && e.retries === 6);
  await assert.rejects(readRecoveryKey(k, { pin: "000002", challenge: challenge() }), (e) => e.code === "pin_auth_blocked" || (e.code === "pin_invalid" && e.retries === 5));
  await assert.rejects(readRecoveryKey(k, { pin: PIN, challenge: challenge() }), (e) => e.code === "pin_auth_blocked", "three in a row: even the right PIN waits for a fresh tap");
  k.powerCycle();
  const [c] = await readRecoveryKey(k, { pin: PIN, challenge: challenge() });
  assert.equal(c.secret.length, 32);
  // The right PIN resets the count; eight wrong in total blocks the key for good.
  for (let i = 0; i < 8; i++) {
    if (i % 3 === 0) k.powerCycle();
    await assert.rejects(readRecoveryKey(k, { pin: `99999${i}`, challenge: challenge() }), (e) => ["pin_invalid", "pin_auth_blocked", "pin_blocked"].includes(e.code));
  }
  k.powerCycle();
  await assert.rejects(readRecoveryKey(k, { pin: PIN, challenge: challenge() }), (e) => e.code === "pin_blocked");
});

test("several HumID credentials on one key (two people, or a cancelled attempt): each comes back with its own secret", async () => {
  const k = simulatedKey({ pin: PIN });
  const a = await addRecoveryKey(k, { pin: PIN, challenge: challenge() });
  const b = await addRecoveryKey(k, { pin: PIN, challenge: challenge() });
  const got = await readRecoveryKey(k, { pin: PIN, challenge: challenge() });
  assert.equal(got.length, 2);
  const secrets = got.map((c) => hex(c.secret)).sort();
  assert.deepEqual(secrets, [hex(a.secret), hex(b.secret)].sort());
  assert.notEqual(hex(a.secret), hex(b.secret));
});

test("an excluded credential: a key that already holds one of the account's credentials refuses to make another", async () => {
  const k = simulatedKey({ pin: PIN });
  const a = await addRecoveryKey(k, { pin: PIN, challenge: challenge() });
  await assert.rejects(addRecoveryKey(k, { pin: PIN, challenge: challenge(), exclude: [a.credentialId] }), (e) => e.code === "credential_excluded");
  assert.equal(k.state.credentials.length, 1);
});

test("keys HumID can't use are refused before anything is made, with a reason", async () => {
  await assert.rejects(addRecoveryKey(simulatedKey({ pin: PIN, hmacSecret: false }), { pin: PIN, challenge: challenge() }), (e) => e.code === "no_hmac_secret");
  const k = simulatedKey({ pin: PIN, hmacSecret: false });
  assert.match((await inspectKey(k)).problem, /hmac-secret/);
  assert.equal(k.state.credentials.length, 0);
  // A key with no HumID credential: nothing to read.
  await assert.rejects(readRecoveryKey(simulatedKey({ pin: PIN }), { pin: PIN, challenge: challenge() }), (e) => e.code === "no_credentials");
  // A key with no PIN can't be one added to HumID.
  await assert.rejects(readRecoveryKey(simulatedKey(), { pin: PIN, challenge: challenge() }), (e) => e.code === "no_credentials");
});

/** Rewrite a key's CTAP answers to model a broken or hostile key. */
function tampered(k, fix) {
  return {
    transceive: async (apdu) => {
      let r = await k.transceive(apdu);
      if (apdu[1] !== 0x10 && apdu[1] !== 0x11) return r; // only CTAP messages
      // Gather a chained answer (61xx) from the key, so the whole CBOR can be rewritten.
      const parts = [];
      while (r[r.length - 2] === 0x61) {
        parts.push(r.subarray(0, r.length - 2));
        r = await k.transceive(Uint8Array.of(0x00, 0xc0, 0x00, 0x00, r[r.length - 1]));
      }
      if (parts.length) r = Uint8Array.from([...parts.flatMap((x) => [...x]), ...r]);
      const body = r.subarray(0, r.length - 2), sw = r.subarray(r.length - 2);
      if (sw[0] !== 0x90 || body.length < 2 || body[0] !== 0) return r;
      const m = decode(body.subarray(1));
      const out = fix(m);
      if (!out) return r;
      const enc = encode(out);
      return Uint8Array.from([0, ...enc, 0x90, 0x00]);
    },
    powerCycle: () => k.powerCycle(),
  };
}

test("a hostile key is refused: no UV flag, another relying party, a public key off the curve", async () => {
  const k = simulatedKey({ pin: PIN });
  await addRecoveryKey(k, { pin: PIN, challenge: challenge() });
  // getAssertion answers carry authData at key 2 and a signature at key 3.
  const noUv = tampered(k, (m) => { if (!(m.get(2) instanceof Uint8Array) || !m.has(3)) return null; const ad = m.get(2).slice(); ad[32] &= ~0x04; m.set(2, ad); return m; });
  await assert.rejects(readRecoveryKey(noUv, { pin: PIN, challenge: challenge() }), (e) => e instanceof FidoError && /PIN/.test(e.message));
  const otherRp = tampered(k, (m) => { if (!(m.get(2) instanceof Uint8Array) || !m.has(3)) return null; const ad = m.get(2).slice(); ad[0] ^= 1; m.set(2, ad); return m; });
  await assert.rejects(readRecoveryKey(otherRp, { pin: PIN, challenge: challenge() }), (e) => /different service/.test(e.message));
  // A key-agreement key that isn't on the curve: refused before any ECDH (CTAP 2.1 §6.5.6).
  const offCurve = tampered(k, (m) => { const c = m.get(1); if (!(c instanceof Map) || c.get(3) !== -25) return null; const y = c.get(-3).slice(); y[31] ^= 1; c.set(-3, y); return m; });
  await assert.rejects(readRecoveryKey(offCurve, { pin: PIN, challenge: challenge() }), (e) => /curve/.test(e.message));
});
