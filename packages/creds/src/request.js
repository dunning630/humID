// Asking a wallet for a credential online: one object for
// navigator.credentials.get({ digital }) that every current browser and
// wallet can answer, and the private state needed to check the answer.
//
//   openid4vp-v1-unsigned   OpenID4VP 1.0 with a DCQL query: mdocs and SD-JWT
//                           VCs, any one of the requested types. The answer is
//                           encrypted to a fresh key (response_mode dc_api.jwt).
//   org-iso-mdoc            ISO 18013-7 Annex C: mdocs only, HPKE-encrypted.
//                           Safari 26 and Apple Wallet use this one.
//
// The browser binds each answer to the page's origin, so the request can't be
// replayed from another site; the nonce and the one-time key bind it to this
// request. `state` never leaves the side that verifies (the app for the
// holder's own vault, the server when the server is the verifier).

import { annexCRequest, signedDeviceRequest, serializeOrigin, hpkeKeyPair } from "@humid/mdoc";
import { ecdhKeyPair, jwkThumbprint, b64u, SUPPORTED_ALGS } from "@humid/sdjwt";
import { TYPES, CLAIMS, PURPOSES } from "./catalog.js";

export class CredsError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
export const fail = (code, m) => { throw new CredsError(code, m); };

const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const REQUEST_TTL_MS = 5 * 60 * 1000;

/** The claims list for an ask: a PURPOSES name or a list of vocabulary names. */
export function claimsFor(ask) {
  const list = typeof ask === "string" ? PURPOSES[ask] : ask;
  if (!Array.isArray(list) || !list.length) fail("bad_request", "Say which details to ask for.");
  for (const c of list) if (!CLAIMS[c]) fail("bad_request", `"${c}" isn't a detail HumID knows how to ask for.`);
  return [...new Set(list)];
}

/** mdoc nameSpaces for one type: { ns: { element: intentToRetain } }. */
export function mdocElements(type, claims, retain) {
  const t = TYPES[type];
  const els = {};
  for (const c of claims) {
    const m = CLAIMS[c][type];
    if (m == null) continue;
    for (const e of Array.isArray(m) ? m : [m]) els[e] = !!retain;
  }
  return { [t.ns]: els };
}

/** DCQL claims for one type. */
function dcqlClaims(type, claims, retain) {
  const t = TYPES[type];
  const out = [];
  for (const c of claims) {
    const m = CLAIMS[c][type];
    if (m == null) continue;
    if (t.format === "mso_mdoc") for (const e of Array.isArray(m) ? m : [m]) out.push({ path: [t.ns, e], intent_to_retain: !!retain });
    else out.push({ path: m });
  }
  return out;
}

/**
 * Build a Digital Credentials API request.
 *   types:     which credentials are acceptable (any one): keys of TYPES
 *   ask:       a PURPOSES name or a list of claim names
 *   origin:    the page's origin (https)
 *   protocols: which request protocols to offer, best first
 *   retain:    whether the verifier keeps the data (shown to the holder by the wallet)
 *   readerAuth: optional ISO 18013-5 reader certificate + key for org-iso-mdoc
 * Returns { request (pass to navigator.credentials.get), state (keep private, use once) }.
 */
export function credentialRequest({ types = ["mdl", "pid_mdoc", "pid_sdjwt"], ask = "identity", origin, protocols = ["openid4vp", "org-iso-mdoc"], retain = false, readerAuth, now = Date.now() } = {}) {
  if (!types.length || types.some((t) => !TYPES[t])) fail("bad_request", "Unknown credential type.");
  const claims = claimsFor(ask);
  const serialized = serializeOrigin(origin);
  const requests = [];
  const state = { v: 1, origin: serialized, types, claims, createdAt: now, expiresAt: now + REQUEST_TTL_MS, used: false, protocols: {} };

  if (protocols.includes("openid4vp")) {
    const nonce = b64u(random(24));
    const enc = ecdhKeyPair();
    const credentials = types.map((type) => {
      const t = TYPES[type];
      const meta = t.format === "mso_mdoc" ? { doctype_value: t.docType } : { vct_values: t.vct };
      const cl = dcqlClaims(type, claims, retain);
      return { id: type, format: t.format, meta, ...(cl.length ? { claims: cl } : {}) };
    }).filter((c) => c.claims);
    if (!credentials.length) fail("bad_request", "None of these credentials carries the details asked for.");
    requests.push({
      protocol: "openid4vp-v1-unsigned",
      data: {
        response_type: "vp_token",
        response_mode: "dc_api.jwt",
        nonce,
        dcql_query: { credentials, ...(credentials.length > 1 ? { credential_sets: [{ options: credentials.map((c) => [c.id]) }] } : {}) },
        client_metadata: {
          jwks: { keys: [enc.jwk] },
          encrypted_response_enc_values_supported: ["A128GCM", "A256GCM"],
          vp_formats_supported: {
            mso_mdoc: {},
            "dc+sd-jwt": { "sd-jwt_alg_values": SUPPORTED_ALGS, "kb-jwt_alg_values": SUPPORTED_ALGS },
          },
        },
      },
    });
    state.protocols.openid4vp = { nonce, enc, thumbprint: jwkThumbprint(enc.jwk), ids: credentials.map((c) => c.id) };
  }

  const mdocTypes = types.filter((t) => TYPES[t].format === "mso_mdoc");
  if (protocols.includes("org-iso-mdoc") && mdocTypes.length) {
    // One key and one EncryptionInfo for every mdoc entry, so whichever one the
    // holder picks, the answer opens with the same state.
    const keyPair = hpkeKeyPair();
    const nonce = random(16);
    let shared = null;
    for (const type of mdocTypes) {
      const els = mdocElements(type, claims, retain);
      if (!Object.keys(Object.values(els)[0]).length) continue;
      const items = [{ docType: TYPES[type].docType, nameSpaces: els }];
      const r = annexCRequest(items, { origin: serialized, readerAuth, nonce, keyPair });
      shared = shared || r.state;
      if (r.state.encryptionInfoB64 !== shared.encryptionInfoB64) fail("bad_request", "Annex C entries must share one EncryptionInfo.");
      requests.push(r.request);
    }
    if (shared) state.protocols["org-iso-mdoc"] = { ...shared, docTypes: mdocTypes.map((t) => TYPES[t].docType) };
  }

  if (!requests.length) fail("bad_request", "No request protocol fits these credentials.");
  return { request: { mediation: "required", digital: { requests } }, state };
}

export { signedDeviceRequest };
