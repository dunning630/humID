// Security keys (4.0, docs/SECURITY-KEY.md): a FIDO2 key as the fourth recovery proof.
//
// Adding one: the person types the key's PIN (or chooses one for a key that has none),
// holds the key to the phone once, and approves with one live check. In that one tap the
// key makes HumID's credential, gives the phone its secret, and signs the server's
// challenge. The live check then seals the key part of recovery under that secret.
// The CTAP code (@humid/fido) loads only when a key is used.
import { keyTag, sealKeyPart } from "@humid/recovery";
import * as S from "./state.js";
import { R, wipe, sleep } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withStepUp, showInterrupt, needVault } from "./interrupt.js";
import { probeNfc, openKey } from "./nfc.js";
import { partOf, loadRecovery } from "./recovery.js";

const KEY_PROMPT = {
  phone: "Hold your security key flat against the back of your phone, near the top, and keep it there until it's done.",
  reader: "Place your security key on the card reader and leave it there until it's done.",
  demo: "Development build: using the simulated security key.",
};
const STEP_WORDS = {
  "setting-pin": "Setting your key's PIN…",
  creating: "Making HumID's credential on your key…",
  reading: "Reading your key's secret…",
  recovering: "Checking your key's PIN and reading its secret…",
};

/** Errors that the PIN field answers, not the overlay. */
const PIN_ERRORS = new Set(["pin_invalid", "pin_not_set", "pin_already_set", "pin_policy", "pin_empty", "pin_auth_blocked", "pin_blocked"]);

/** Is there a way to reach a security key here? Cached with the chip reader's answer (same transport). */
export async function keyReader({ fresh = false } = {}) {
  if (!S.nfc.value || fresh) S.nfc.value = await probeNfc();
  return S.nfc.value;
}

/**
 * Hold a key to the phone and run `work(transport, step)`. Progress shows in the NFC
 * overlay. A PIN problem closes the overlay and comes back as { pinError } for the form.
 */
async function withKey(work) {
  const n = await keyReader();
  if (!n.available) throw Object.assign(new Error(n.reason || "This device can't reach security keys. Use a phone with NFC, or a computer with a contactless card reader."), { code: "no_reader" });
  const show = (patch) => { S.chipRead.value = { ...(S.chipRead.value || {}), ...patch }; };
  show({ subject: "key", stage: "waiting", fraction: 0, message: KEY_PROMPT[n.kind] || KEY_PROMPT.phone, error: null, kind: n.kind, purpose: "key" });
  let t = null;
  try {
    t = await openKey({ prompt: KEY_PROMPT[n.kind] || KEY_PROMPT.phone });
    show({ stage: "reading", fraction: 0.2, message: "Keep holding still…" });
    let k = 0.2;
    const step = (name) => { k = Math.min(0.9, k + 0.25); const m = STEP_WORDS[name] || "Working…"; show({ stage: "reading", fraction: k, message: m }); t.message?.(m); };
    const out = await work(t, step);
    await t.end?.({ message: "Done. You can take the key away." });
    show({ stage: "done", fraction: 1, message: "Done. You can take the key away." });
    await sleep(600);
    S.chipRead.value = null;
    return out;
  } catch (e) {
    const message = e?.code === "cancelled" ? "Cancelled." : friendly(e);
    await t?.end?.({ error: message });
    if (e?.code === "cancelled" || PIN_ERRORS.has(e?.code)) { S.chipRead.value = null; throw e; }
    show({ stage: "error", message, error: e?.code || "error" });
    throw Object.assign(e, { shown: true });
  }
}

const pinResult = (e) => ({ pinError: { code: e.code, message: friendly(e), retries: e.retries } });

/**
 * Add a security key as a recovery proof.
 *   name    what the person calls it ("Blue key on my keyring"), sealed under the index key
 *   pin     its PIN, or (newPin) the PIN to give a key that has none
 * Returns { ok: true } | { pinError: { code, message, retries? } } | { ok: false }.
 */
export async function addSecurityKey({ name, pin, newPin = false }) {
  const accountId = S.identity.value?.server?.id;
  let got = null;
  try {
    needVault();
    const { challenge, exclude } = await R.api.keyChallenge();
    const { addRecoveryKey } = await import("@humid/fido");
    got = await withKey((t, step) => addRecoveryKey(t, { pin, newPin, challenge, exclude, onStep: step }));
    await withStepUp("addKey", [], "key", "Add your security key", async ({ seed, proof, Suite }) => {
      showInterrupt({ progress: 0.6, message: "Locking your key's part of recovery to it…" });
      const part = partOf(seed, "key");
      try {
        const blob = await sealKeyPart(got.secret, part, accountId);
        const label = await Suite.sealIndex(R.indexKey, { name: String(name || "").trim().slice(0, 40) || "Security key" });
        await R.api.addKey({ tag: keyTag(got.secret), blob, pub: got.publicKey, credentialId: got.credentialId, authData: got.authData, signature: got.signature, label, epoch: part.epoch }, proof);
      } finally { wipe(part.y); }
    });
    toast(got.hidden
      ? "Security key added. With any one other proof it brings your vault back."
      : "Security key added. This older key can't hide that it holds a HumID credential, but it still needs its PIN to be used.", got.hidden ? undefined : "warn");
    loadRecovery();
    return { ok: true };
  } catch (e) {
    if (PIN_ERRORS.has(e?.code)) return pinResult(e);
    if (!cancelled(e) && !e?.shown) toast(friendly(e), "error");
    return { ok: false };
  } finally {
    wipe(got?.secret);
  }
}

/** Remove a security key (one live check). It stops counting as a proof at once, also in a recovery under way. */
export async function removeSecurityKey(key) {
  try {
    await withStepUp("removeKey", [key.id], "key", `Remove “${key.name}”`, async ({ proof }) => R.api.removeKey(key.id, proof));
    toast("Security key removed. It no longer counts as a proof.");
    loadRecovery();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/**
 * Recovering on a new device: one tap with the PIN. Returns the key's candidate answers
 * (normally one) for join.js, which sends them, keeps the matching secret under this
 * device's lock, and wipes the rest. → { candidates: [{ tag, authData, signature, secret }] } | { pinError } | null
 */
export async function readKeyForRecovery(requestId, pin) {
  let list = null;
  try {
    const challenge = await R.api.recoveryKeyChallenge(requestId);
    const { readRecoveryKey } = await import("@humid/fido");
    list = await withKey((t, step) => { step("recovering"); return readRecoveryKey(t, { pin, challenge }); });
    return { candidates: list.map((c) => ({ tag: keyTag(c.secret), authData: c.authData, signature: c.signature, secret: c.secret })) };
  } catch (e) {
    for (const c of list || []) wipe(c.secret);
    if (PIN_ERRORS.has(e?.code)) return pinResult(e);
    if (!cancelled(e) && !e?.shown) toast(friendly(e), "error");
    return null;
  }
}
