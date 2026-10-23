// CRED-01 (review 2026-10-23): a mobile ID's holder signature captured by any other relying party
// must not pass here. The device signature is checked against THIS session's transcript, never
// against a payload the response carries. Adapted from the review's proof of concept.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { credentialRequest, verifyCredentialResponse } from "@humid/creds";
import { encode, decode, get, Encoded } from "@humid/mdoc";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { issuingAuthority, wallet } from "./support/mdl.js";
import { deviceResponse } from "./support/dcwallet.js";

test("a device signature replayed from another verifier is refused", async () => {
  const ORIGIN = "https://verify.humid.test";
  const authority = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
  const victim = wallet({ authority });
  const trust = { iaca: [authority.rootPem] };
  const otherTranscript = [null, null, ["dcapi", new Uint8Array(32).fill(7)]];
  const captured = decode(deviceResponse(victim, otherTranscript, {}));
  const doc = get(captured, "documents")[0];
  const sig = get(get(get(doc, "deviceSigned"), "deviceAuth"), "deviceSignature");
  sig[2] = Encoded.of(["DeviceAuthentication", otherTranscript, "org.iso.18013.5.1.mDL", get(get(doc, "deviceSigned"), "nameSpaces")]).encoded;
  const { request, state } = credentialRequest({ types: ["mdl"], ask: "identity", origin: ORIGIN, protocols: ["org-iso-mdoc"] });
  const entry = request.digital.requests[0];
  const rk = get(decode(Buffer.from(entry.data.encryptionInfo, "base64url"))[1], "recipientPublicKey");
  const tr = [null, null, ["dcapi", new Uint8Array(createHash("sha256").update(encode([entry.data.encryptionInfo, ORIGIN])).digest())]];
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  const b = (x) => Buffer.from(x).toString("base64url");
  const pub = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: b(get(rk, -2)), y: b(get(rk, -3)) }, { name: "ECDH", namedCurve: "P-256" }, true, []);
  const sender = await suite.createSenderContext({ recipientPublicKey: pub, info: encode(tr) });
  const ct = new Uint8Array(await sender.seal(encode(captured)));
  const data = { response: b(encode(["dcapi", new Map([["enc", new Uint8Array(sender.enc)], ["cipherText", ct]])])) };
  assert.throws(() => verifyCredentialResponse(state, { protocol: "org-iso-mdoc", data }, { trust }));
});
