// Add an ID from a wallet: the app asks the browser's or phone's own
// credential picker (W3C Digital Credentials API) for the holder's mobile
// license, state ID, EU digital identity or wallet photo ID, checks it here on
// the phone with @humid/creds, and fills an ID record the vault seals like any
// other. Nothing leaves the phone: the request's keys are made here, the
// answer is encrypted to them, and the browser binds it to this origin.
//
// Where it works today: the web app on Chrome 141+ (Android, and desktop with a
// phone nearby) and Safari 26 / iOS 26. Inside the native apps the platform
// APIs (Android Credential Manager, iOS IdentityDocumentServices) need a
// plugin, which isn't built yet; walletSupport() says so.

import { credentialRequest, verifyCredentialResponse } from "@humid/creds";
import { applyMdoc } from "@humid/idscan";
import { encodeIssuerSigned } from "@humid/mdoc";

const PROTOCOLS = ["openid4vp", "org-iso-mdoc"];
const DC_PROTOCOL = { openid4vp: "openid4vp-v1-unsigned", "org-iso-mdoc": "org-iso-mdoc" };

/** Can this app ask a wallet? { available, protocols, reason }. */
export function walletSupport(g = globalThis) {
  const no = (reason) => ({ available: false, protocols: [], reason });
  if (!g.isSecureContext) return no("Adding from a wallet needs a secure (https) page.");
  if (typeof g.DigitalCredential === "undefined" || typeof g.navigator?.credentials?.get !== "function") {
    return no("This browser can't ask a wallet yet. Use Chrome 141 or later, or Safari 26 or later, or scan the ID instead.");
  }
  let origin;
  try { origin = new URL(g.location?.origin); } catch { return no("This page has no web origin a wallet can check."); }
  const local = origin.protocol === "http:" && /^(localhost|127\.0\.0\.1|\[::1\])$/.test(origin.hostname);
  if (origin.protocol !== "https:" && !local) return no("Adding from a wallet needs a secure (https) page.");
  const allows = typeof g.DigitalCredential.userAgentAllowsProtocol === "function"
    ? (p) => { try { return g.DigitalCredential.userAgentAllowsProtocol(DC_PROTOCOL[p]) !== false; } catch { return true; } }
    : () => true;
  const protocols = PROTOCOLS.filter(allows);
  return protocols.length ? { available: true, protocols, reason: null } : no("This browser doesn't support the wallet request formats HumID uses.");
}

/**
 * Ask a wallet for the holder's own ID and check it. Must run from a tap
 * (browsers require a user gesture). trust: { iaca } when the app has issuer
 * roots; without them the issuer's signature and the device proof are still
 * checked, and the record says the root isn't trusted yet.
 * Returns verified results (normally one).
 */
export async function addFromWallet({ types = ["mdl", "pid_mdoc", "photoid"], trust, signal, g = globalThis } = {}) {
  const support = walletSupport(g);
  if (!support.available) throw Object.assign(new Error(support.reason), { code: "unsupported" });
  const { request, state } = credentialRequest({ types, ask: "vault", origin: g.location.origin, protocols: support.protocols, retain: true });
  let credential;
  try { credential = await g.navigator.credentials.get({ ...request, signal }); }
  catch (e) {
    if (e?.name === "AbortError" || e?.name === "NotAllowedError") throw Object.assign(new Error("Nothing was shared."), { code: "cancelled" });
    throw Object.assign(new Error("The wallet couldn't be asked. Try again, or scan the ID instead."), { code: "wallet_error" });
  }
  if (!credential) throw Object.assign(new Error("Nothing was shared."), { code: "cancelled" });
  return verifyCredentialResponse(state, { protocol: credential.protocol, data: credential.data }, { trust, allowUntrustedIssuer: !trust?.iaca?.length });
}

/**
 * Fill an ID record (@humid/idscan) from a verified mobile ID result. The
 * issuer-signed bytes are kept, so the issuer check can be repeated later
 * (for example once the vault has trusted roots).
 */
export function toRecord(rec, result, { b64 }) {
  if (result.format !== "mso_mdoc" || !result.detail) throw Object.assign(new Error("Only mobile IDs can be filed into an ID record so far."), { code: "unsupported" });
  const d = result.detail;
  return applyMdoc(rec, {
    docType: result.docType, values: result.values, chain: d.chain, root: d.root, signer: d.signer,
    device: d.device, digestAlgorithm: d.digestAlgorithm, validity: d.validity,
  }, { b64, keep: encodeIssuerSigned(d.issuerSigned) });
}
