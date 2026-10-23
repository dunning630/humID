// Words for things the kernel names by id: gate methods, how a device joined, recovery
// proofs, and how a check was proven. One place, so two screens never name one thing two
// ways, and a screen never claims a secure chip the device that made the proof doesn't have.
import * as S from "../core/state.js";

/**
 * How strongly THIS device proves its checks, as far as the app knows: "hardware" (a phone
 * whose secure chip signs each check), "os" (a computer: the system checks, nothing signs),
 * "none" (demo), or null (not known: the web app before setup, which can't check at all).
 */
export function deviceProof() {
  const id = S.identity.value;
  if (id?.assurance) return id.assurance;
  const p = S.hwGate.value?.probe;
  return p?.available ? p.assurance || null : null;
}

/** The promise about a live check, said only as strongly as this device can keep it. */
export function checkPromise(proof = deviceProof()) {
  if (proof === "hardware") return "Every open, save and delete needs a live face or fingerprint check on this phone, and its secure chip signs each one. A PIN or password is never accepted.";
  if (proof === "os") return "Every open, save and delete needs a live fingerprint check. On this computer the system checks it; no secure chip signs it, so a vault that asks for chip-proven checks won't accept it. A PIN or password is never accepted.";
  return "Every open, save and delete needs a live face or fingerprint check. In the HumID app for iPhone and Android, the phone's secure chip signs each one. A PIN or password is never accepted.";
}

/** Events whose `device` is the device that acted (elsewhere it can be the one acted on). */
const ACTOR = new Set(["session.opened", "device.added", "identity.created", "duress.cleared", "admin.approved"]);

/**
 * Who proved a past event, from what the server recorded with it (APP-09): never the viewing
 * device's own assurance. `e` is the ledger entry; `here` is this session's device id. Servers
 * since 4.1.x record `assurance` and `by` with every proof; for older entries without them this
 * says only "signed by one of your devices".
 */
export function eventProof(e = {}, here = S.session.value?.device) {
  const d = e.detail || {};
  const by = d.by || (ACTOR.has(e.type) ? d.device : undefined);
  const mine = !!by && by === here;
  switch (d.assurance) {
    case "hardware": return { short: mine ? "proved by this phone's chip" : "proved by a phone's secure chip", long: mine ? "This phone's secure chip" : "The secure chip of one of your phones", strong: true };
    case "os": return { short: "software-protected check", long: mine ? "A software-protected check on this device" : "A software-protected check on one of your devices", strong: false };
    case "none": return { short: "demo check", long: "A demo check (no sensor)", strong: false };
    default: return { short: "signed by one of your devices", long: "Signed by one of your devices", strong: false };
  }
}

/** The chip behind a device's checks, for a list of devices (so "its", never "this phone's"). */
const PROOF = {
  "android-strongbox": "Each check is proven by its StrongBox chip",
  "android-tee": "Each check is proven by its secure chip",
  "apple-secure-enclave": "Each check is proven by its Secure Enclave",
};
export const proofLabel = (proof, assurance) =>
  PROOF[proof] || (assurance === "os" ? "Checks are software-protected, not chip-proven" : assurance === "none" ? "No sensor (development only)" : "Not proven");

/* ---------- gate methods ---------- */
const GATE = {
  "ios-keychain-biometry": ["Face ID / Touch ID", "Face ID or Touch ID", "Face ID / Touch ID · Secure Enclave policy"],
  "android-keystore-biometric": ["Fingerprint / face", "your face or fingerprint", "Android Keystore · Class 3 biometric"],
  "macos-keychain-biometry": ["Touch ID", "Touch ID", "Touch ID · Keychain"],
  "windows-winbio-fingerprint": ["Fingerprint", "your fingerprint", "Fingerprint · Windows Biometric Framework"],
  "linux-fprintd-keyring": ["Fingerprint", "your fingerprint", "Fingerprint · fprintd + keyring"],
  "demo-no-hardware": ["Demo hold", "a press and hold", "Demo · press and hold"],
};
/** A gate method, short (Activity), in a sentence ("Confirm with …"), or in full (About). */
export const gateName = (m) => GATE[m]?.[0] || m || "";
export const gateLabel = (m) => GATE[m]?.[1] || "your face or fingerprint";
export const gateDetail = (m) => GATE[m]?.[2] || m || "";

/* ---------- how a device joined; recovery proofs ---------- */
/** How a device joined (`via`). Older single-proof routes keep their older names. */
export const VIA = { register: "First device", link: "Added from another device", card: "Recovered with an older recovery card", contacts: "Recovered with older witnesses", quorum: "Recovered with two proofs" };
/** A recovery's route (`method`), as a banner or Activity names it. */
export const RECOVERY_METHOD = { card: "older recovery card", contacts: "older witnesses", quorum: "two proofs" };
/** One kind of recovery proof. */
export const PROOF_KIND = { witness: "witnesses", card: "recovery card", anchor: "ID chip", key: "security key" };

/**
 * How recovery works, in one sentence, everywhere it's said ("one of two things", "two of
 * four" and "1 of 2 proofs" once disagreed). proofsSetUp(n): the You hub's count.
 */
const KINDS = "any two of your four kinds of proof: witnesses, your ID chip, a recovery card or a security key";
export const RECOVERY_RULE = `Recovery needs ${KINDS}.`;
export const RECOVERY_IF_LOST = `If you lose every device, recovery needs ${KINDS}.`;
export const proofsSetUp = (n) => `${n} of 2 proofs set up`;
export const CARD_IS_ONE = "Your card is one proof. Recovery needs two, for example this card and your witnesses. On its own it opens nothing.";
