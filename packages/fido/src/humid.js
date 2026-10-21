// HumID's use of a security key (docs/SECURITY-KEY.md): one discoverable credential for
// the relying party "recovery.humid.invalid", PIN-verified, whose hmac-secret output is
// the secret that locks the key part of two-proof recovery, and whose signature over a
// fresh server challenge proves the key itself was there.
import { sha256 } from "@noble/hashes/sha2.js";
import { Authenticator, PERMISSION, FLAG, wipe, constantTimeEqual } from "./ctap.js";
import { FidoError } from "./errors.js";

const te = new TextEncoder();

/** RFC 2606 reserves .invalid: no website can ever ask a browser for this credential. */
export const RP_ID = "recovery.humid.invalid";
export const RP_ID_HASH = sha256(te.encode(RP_ID));
export const SALT = sha256(te.encode("HUMID-KEY-v1 hmac-secret salt"));
export const CHALLENGE_BYTES = 32;
/** A PIN HumID sets on a key: 6 or more characters (the key's own minimum may be higher). */
export const MIN_NEW_PIN = 6;
/** Discoverable HumID credentials looked at when recovering (newest first): room for a few left by cancelled attempts. */
export const MAX_CANDIDATES = 16;
const PURPOSES = new Set(["add", "recover"]);

/** What the key signs (as clientDataHash), and the server recomputes: SHA-256("HUMID-KEY-v1 <purpose> " ‖ challenge). */
export function clientDataHash(purpose, challenge) {
  if (!PURPOSES.has(purpose)) throw new Error("Unknown purpose");
  if (!(challenge instanceof Uint8Array) || challenge.length !== CHALLENGE_BYTES) throw new Error("A challenge has 32 bytes");
  const p = te.encode(`HUMID-KEY-v1 ${purpose} `);
  const m = new Uint8Array(p.length + challenge.length);
  m.set(p); m.set(challenge, p.length);
  return sha256(m);
}

/** Can this key be a HumID recovery proof? → null, or a FidoError saying why not. */
export function unsuitable(a) {
  if (!a.hasHmacSecret) return new FidoError("no_hmac_secret", "This key can't keep the secret HumID needs (hmac-secret). Most FIDO2 keys can; this one can't.");
  if (a.info.options.clientPin === undefined) return new FidoError("no_pin_support", "This key can't have a PIN, so anyone holding it could use it. HumID needs a key with a PIN.");
  if (a.info.options.rk !== true) return new FidoError("no_resident_keys", "This key can't remember credentials, so a new phone couldn't find it.");
  return null;
}

function checkFlags(parsed, what) {
  if (!constantTimeEqual(parsed.rpIdHash, RP_ID_HASH)) throw new FidoError("bad_response", `The key answered for a different service (${what}).`);
  if (!(parsed.flags & FLAG.UP)) throw new FidoError("bad_response", `The key didn't confirm it's present (${what}).`);
  if (!(parsed.flags & FLAG.UV)) throw new FidoError("bad_response", `The key didn't confirm its PIN (${what}).`);
}

/** Look at a key without changing it: { pinSet, retries, minPinLength, problem }. One tap. */
export async function inspectKey(transport) {
  const a = await Authenticator.open(transport);
  const problem = unsuitable(a);
  const retries = a.pinSet ? await a.pinRetries().catch(() => null) : null;
  return { pinSet: a.pinSet, retries, minPinLength: Math.max(MIN_NEW_PIN, a.info.minPinLength || 4), problem: problem?.message || null };
}

/**
 * Make HumID's credential on a key and read its secret. One tap does it all.
 *   pin       the key's PIN; or, with newPin, the PIN to give a key that has none
 *   challenge 32 bytes from the server, signed by the key in the same step
 *   exclude   this account's credential ids: a key that holds one refuses (credential_excluded)
 * Returns { credentialId, publicKey (65 bytes), aaguid, authData, signature, signCount, secret }.
 * The caller wipes `secret` when done.
 */
export async function addRecoveryKey(transport, { pin, newPin = false, challenge, exclude = [], onStep = () => {} }) {
  const cdh = clientDataHash("add", challenge);
  const a = await Authenticator.open(transport);
  let token, secret;
  try {
    const problem = unsuitable(a);
    if (problem) throw problem;
    if (!a.pinSet) {
      if (!newPin) throw new FidoError("pin_not_set", "This key has no PIN yet. Choose one, and HumID sets it.");
      if ([...String(pin ?? "").normalize("NFC")].length < MIN_NEW_PIN) throw new FidoError("pin_policy", `Choose a PIN of at least ${MIN_NEW_PIN} characters.`);
      onStep("setting-pin");
      await a.setPin(pin);
    } else if (newPin) {
      throw new FidoError("pin_already_set", "This key already has a PIN. Type that PIN instead.");
    }
    onStep("creating");
    token = await a.pinToken(pin, { permissions: PERMISSION.makeCredential | PERMISSION.getAssertion, rpId: RP_ID });
    const userId = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const extensions = { "hmac-secret": true, ...(a.hasCredProtect ? { credProtect: 3 } : {}) };
    const made = await a.makeCredential({
      clientDataHash: cdh, rp: { id: RP_ID, name: "HumID recovery" }, user: { id: userId, name: "HumID", displayName: "HumID recovery" },
      exclude: exclude.slice(0, 16), extensions, rk: true, token,
    });
    checkFlags(made.parsed, "new credential");
    if (!made.parsed.credentialId || !made.parsed.publicKey) throw new FidoError("bad_response", "The key didn't return the new credential.");
    if (made.parsed.extensions?.get("hmac-secret") !== true) throw new FidoError("no_hmac_secret", "This key made the credential without its secret (hmac-secret), so it can't be a recovery proof.");
    // A fresh token: CTAP 2.1 keys clear a token's presence after the first use.
    wipe(token.token);
    onStep("reading");
    token = await a.pinToken(pin, { permissions: PERMISSION.getAssertion, rpId: RP_ID });
    const got = await a.getAssertion({ rpId: RP_ID, clientDataHash: cdh, allowList: [made.parsed.credentialId], salt: SALT, token });
    checkFlags(got.parsed, "first use");
    secret = got.secret;
    return {
      credentialId: made.parsed.credentialId, publicKey: made.parsed.publicKey, aaguid: made.parsed.aaguid,
      authData: got.authData, signature: got.signature, signCount: got.parsed.signCount, secret,
    };
  } catch (e) {
    wipe(secret);
    throw e;
  } finally {
    if (token) wipe(token.token);
    a.end();
  }
}

/**
 * Recovering: the key's PIN, then every HumID credential on the key (normally one) with
 * its secret and its signature over the server's challenge. One tap.
 * Returns [{ credentialId, authData, signature, signCount, secret }]; the caller wipes the secrets.
 */
export async function readRecoveryKey(transport, { pin, challenge, max = MAX_CANDIDATES }) {
  const cdh = clientDataHash("recover", challenge);
  const a = await Authenticator.open(transport);
  const out = [];
  let token;
  try {
    if (!a.hasHmacSecret) throw new FidoError("no_hmac_secret", "This key can't keep a secret, so it isn't one you added to HumID.");
    if (!a.pinSet) throw new FidoError("no_credentials", "This key has no PIN, so it isn't one you added to HumID.");
    token = await a.pinToken(pin, { permissions: PERMISSION.getAssertion, rpId: RP_ID });
    const first = await a.getAssertion({ rpId: RP_ID, clientDataHash: cdh, salt: SALT, token });
    const take = (g) => { checkFlags(g.parsed, "recovery"); out.push({ credentialId: g.credentialId, authData: g.authData, signature: g.signature, signCount: g.parsed.signCount, secret: g.secret }); };
    take(first);
    for (let i = 1; i < Math.min(first.count, max); i++) take(await a.nextAssertion());
    return out;
  } catch (e) {
    for (const c of out) wipe(c.secret);
    throw e;
  } finally {
    if (token) wipe(token.token);
    a.end();
  }
}
