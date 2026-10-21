// "Add from a wallet" in the app (apps/mobile/src/core/credentials.js): feature
// detection, asking through a stand-in navigator.credentials.get that answers
// like Safari (Annex C) or Chrome (OpenID4VP), checking on the phone, and
// filling the ID record. The wallet uses independent crypto (tests/support/dcwallet.js).
import test from "node:test";
import assert from "node:assert/strict";
import { walletSupport, addFromWallet, toRecord } from "../apps/mobile/src/core/credentials.js";
import { newRecord, provenance } from "@humid/idscan";
import { issuingAuthority, wallet } from "./support/mdl.js";
import { answerAnnexC, answerOpenId4Vp, deviceResponse, oid4vpTranscript, thumbprint } from "./support/dcwallet.js";

const ORIGIN = "https://app.humidsecure.ai";
const b64 = (u) => Buffer.from(u).toString("base64");

/** A browser stand-in. answer(request) plays the wallet; protocols: what userAgentAllowsProtocol says yes to. */
function browser({ answer, protocols, origin = ORIGIN, secure = true, dc = true } = {}) {
  const seen = [];
  const g = {
    isSecureContext: secure,
    location: { origin },
    navigator: { credentials: { get: async (opts) => { seen.push(opts); return answer ? answer(opts) : null; } } },
  };
  if (dc) g.DigitalCredential = protocols ? { userAgentAllowsProtocol: (p) => protocols.includes(p) } : {};
  return { g, seen };
}

test("feature detection says why it can't ask, in plain words", () => {
  assert.equal(walletSupport(browser({ secure: false }).g).available, false);
  assert.match(walletSupport(browser({ dc: false }).g).reason, /Chrome 141|Safari 26/);
  assert.equal(walletSupport(browser({ origin: "tauri://localhost" }).g).available, false);
  assert.deepEqual(walletSupport(browser({ protocols: ["org-iso-mdoc"] }).g).protocols, ["org-iso-mdoc"]);
  assert.deepEqual(walletSupport(browser().g).protocols, ["openid4vp", "org-iso-mdoc"]);
});

test("Safari-style: Annex C answer → verified on the phone → ID record with the issuer's bytes kept", async () => {
  const authority = issuingAuthority({ C: "US", ST: "IL", name: "Illinois SOS" });
  const w = wallet({ authority });
  const { g, seen } = browser({
    protocols: ["org-iso-mdoc"],
    answer: async (opts) => ({ protocol: "org-iso-mdoc", data: await answerAnnexC(w, opts.digital.requests[0], { origin: ORIGIN }) }),
  });
  const [r] = await addFromWallet({ g, types: ["mdl"], trust: { iaca: [authority.rootPem] } });
  assert.equal(seen[0].mediation, "required");
  assert.equal(r.assurance, "issuer+holder");
  const rec = toRecord(newRecord(), r, { b64 });
  assert.equal(rec.kind, "driver_license");
  assert.equal(rec.fields.surname, "SPECIMEN");
  assert.equal(rec.fields.region, "IL");
  assert.equal(rec.source.surname, "mdoc");
  assert.ok(rec.raw.mdoc.issuerSigned.length > 100, "issuer-signed bytes kept for a later re-check");
  assert.equal(provenance(rec).level, "mdoc");
});

test("Chrome-style: OpenID4VP answer without trusted roots on the phone → kept as 'root not trusted yet', device still proven", async () => {
  const w = wallet({ authority: issuingAuthority({ C: "US", ST: "UT" }) });
  const { g } = browser({
    protocols: ["openid4vp-v1-unsigned"],
    answer: async (opts) => {
      const entry = opts.digital.requests[0];
      const d = entry.data;
      const t = oid4vpTranscript(ORIGIN, d.nonce, await thumbprint(d.client_metadata.jwks.keys[0]));
      const want = { "org.iso.18013.5.1": Object.fromEntries(d.dcql_query.credentials[0].claims.map((c) => [c.path[1], true])) };
      return { protocol: entry.protocol, data: await answerOpenId4Vp(entry, { mdl: [Buffer.from(deviceResponse(w, t, { want })).toString("base64url")] }) };
    },
  });
  const [r] = await addFromWallet({ g, types: ["mdl"] });
  assert.equal(r.assurance, "signature-only");
  assert.equal(r.holderBound, true);
  const rec = toRecord(newRecord(), r, { b64 });
  assert.equal(provenance(rec).level, "mdoc-unchecked");
  assert.ok(rec.fields.number, "the vault ask includes the document number for the holder's own record");
});

test("a cancelled picker or an empty answer is 'cancelled', not an error screen", async () => {
  const abort = browser({ answer: () => { throw Object.assign(new Error("x"), { name: "NotAllowedError" }); } });
  await assert.rejects(addFromWallet({ g: abort.g }), (e) => e.code === "cancelled");
  await assert.rejects(addFromWallet({ g: browser().g }), (e) => e.code === "cancelled");
  await assert.rejects(addFromWallet({ g: browser({ dc: false }).g }), (e) => e.code === "unsupported");
});
