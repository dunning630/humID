// App state as signals. Screens read these; only the kernel (core/) writes them.
//
// Two kinds. Device signals (signal) describe this phone and its HumID and live as long as
// the app does. Session signals (perSession) describe what an unlocked session showed or did,
// and resetSession() puts every one back as it started: lock, erase and reset all call it,
// so nothing a session showed can carry into the next one, a decoy session above all
// (APP-07: a search typed in the real vault once showed in the duress session).
// tests/state-reset.test.js checks that every signal is one or the other, on purpose.
import { signal, computed, batch } from "@preact/signals";
import { loadPrefs, sortItems } from "./prefs.js";
/* global __HUMID_ALLOW_DEMO__ */

const SESSION = new Map(); // each session signal → its starting value
/** A signal that resetSession() puts back to `initial`. Arrays start empty each time. */
const perSession = (initial) => { const s = signal(Array.isArray(initial) ? [] : initial); SESSION.set(s, initial); return s; };

export const view = signal("boot");          // boot | welcome | enroll | join | locked | app
export const tab = signal("vault");          // vault | activity | you
export const prefs = signal(loadPrefs());     // this device's preferences (core/prefs.js)
export const enrollStep = signal("connect"); // connect · access (when the server needs a pass) · bind · done + recovery card

// Anonymous payment (docs/ANONYMITY.md). The access pass bought with an access code, kept
// on this device until registration spends it: null | { state: "draft" | "ready", … }.
export const pass = signal(null);
export const passBusy = signal(false);

// A new device joining an existing account (another device, two recovery proofs, or an older card or witnesses).
export const joinStep = signal(0);           // 0 connect · 1 choose · 2 details · 3 waiting
export const joinMethod = signal(null);      // link | quorum | card | contacts
export const joinStatus = signal(null);      // last polled status from the server
// The recovery mode of the HumID being joined, as far as this new device knows: null (not said),
// or "holder-only" (the holder said so, or the vault refused a recovery): then only a link is offered.
export const joinMode = signal(null);

export const identity = signal(null);        // local identity record (public parts + wrapped seeds)
export const hwGate = signal(null);          // { adapter, probe } strongest hardware gate on this device
export const server = signal(null);          // { url, kid, fingerprint, policy }
export const serverError = signal(null);
export const session = perSession(null);         // { id, device, assurance, gateMethod, expiresAt, idleTimeoutMs }
export const lockIssue = signal(null);       // unknown_identity | server_identity_changed | device_removed

export const items = perSession([]);             // decrypted index entries
export const usage = perSession(null);
export const loading = perSession(false);
export const filter = perSession("all");         // all | a kind id (core/categories.js)
export const tagFilter = perSession(null);       // a tag id, or null for every tag
export const query = perSession("");
export const ledger = perSession(null);          // verified ledger page
export const ledgerLoading = perSession(false);

export const devices = perSession(null);         // this account's devices (from the identity service)
export const recovery = perSession(null);        // { card, contacts: { n, threshold, names[], scheme }, anchor, settings, ready }
// The recovery mode (core/recmode.js): { mode: "holder-only" | "hardened", version, epoch, escrow, trusted }.
export const recoveryMode = perSession(null);
// Chosen during setup, before the account exists: "hardened" (recommended) unless the holder picks holder-only.
export const setupMode = perSession("hardened");
export const protecting = perSession([]);        // alerts about people this HumID protects: recoveries, duress signals
export const adminSummary = perSession(null);    // { health, alerts, updates, version } — this HumID administers its server
export const station = perSession(null);         // { station: bool, countries } — this HumID runs a verification station
export const alerts = perSession([]);            // recoveries in progress for this account
export const cardCode = perSession(null);        // a recovery card to show once, then forget

// Duress. `decoy` is true for a session opened with the duress gesture: the app then shows
// only decoy documents and a calm account, while the server has locked sensitive changes.
export const decoy = perSession(false);
export const duressInfo = perSession(null);      // { lockdown, clearableAt, lastDuressAt, alert } (real sessions only)
// What a decoy session "saved" on its Duress screen ({ enabled, gesture, decoys: [ids] }), shown
// back to it until the lock and stored nowhere: an ordinary account echoes its own saves.
export const decoyEcho = perSession(null);
// Check-in (docs/CHECKIN.md): { state: off | armed | locked | erased, deadline, erasesAt, windowMs,
// maxWindowMs, graceMs, armedAt, erasedAt } while unlocked, null otherwise or when the server doesn't offer it.
export const checkin = perSession(null);
export const continuity = perSession(null);      // public-log check: { ok, reason, size, cosigned, at }
export const nfc = signal(null);             // { available, kind: "phone" | "reader" | "none", reason } — the ID chip reader
export const chipRead = perSession(null);        // { stage, message, fraction, error } while reading a chip

// Simulation build: what the in-app server checked, newest first, and the sheet that shows it.
export const simLog = signal([]);
export const simShow = signal(null);         // a report to show in the checks sheet

// Person to person (4.0, docs/MESSAGING.md). liveAt: when this phone's holder last passed a live
// check (0 = not this session); the human-to-human rule shows message content only while it's fresh.
export const liveAt = perSession(0);
// The Messages tab: { ready, error, contacts, invites, requests, newCount } (core/messaging.js), or null.
export const msg = perSession(null);
// The open conversation, only while its holder's check is fresh: { id, messages, notices } or null.
export const thread = perSession(null);
export const messagingOn = computed(() => !!server.value?.policy?.messaging);

export const interrupt = signal(null);       // overlay state
export const sheet = perSession(null);           // { type, ... } one bottom sheet at a time; each type rendered by one file
export const push = perSession(null);            // { type, ... } one pushed (full-screen) step over the tabs
export const sealing = perSession(null);         // "seal" | "upload" | "done" while a document is being sealed
export const viewer = perSession(null);          // decrypted preview
// Another app that can read the screen (core/readers.js): the question on screen
// ({ what, services }), and the set of services this session already said yes to.
export const readerWarning = perSession(null);
export const readersAccepted = perSession(null);
export const toasts = signal([]);
export const idleDeadline = perSession(0);       // when the app auto-locks
export const online = signal(typeof navigator === "undefined" ? true : navigator.onLine);
// The connection to the vault server (core/link.js): { state: "up" | "down", attempt, nextAt, since, reason }.
export const link = signal({ state: "up", attempt: 0, nextAt: 0, since: 0, reason: null });
// Offline: the app is showing the read-only copy kept on this device ({ savedAt }), or null.
export const offline = perSession(null);
export const offlineReady = signal(false);   // there's an offline copy on this device to open

// Demo mode only in a local development build talking to a server whose policy is "demo".
export const demoAllowed = computed(() => (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) && server.value?.policy?.devicePolicy === "demo");
/** Does this server need an access pass to create a HumID? */
export const passNeeded = computed(() => server.value?.policy?.registration === "pass");

export const visibleItems = computed(() => {
  const q = query.value.trim().toLowerCase();
  const t = tagFilter.value;
  return sortItems(items.value.filter((i) => (filter.value === "all" || i.kind === filter.value) && (!t || (i.tags || []).includes(t)) && (!q || i.name.toLowerCase().includes(q))), prefs.value.sort);
});

/** How many items of each kind: { all, id, card, pass, photo, file }. */
export const counts = computed(() => {
  const c = { all: items.value.length };
  for (const i of items.value) c[i.kind] = (c[i.kind] || 0) + 1;
  return c;
});

/** How many items carry each tag (only tags in use appear). */
export const tagCounts = computed(() => {
  const c = {};
  for (const i of items.value) for (const t of i.tags || []) c[t] = (c[t] || 0) + 1;
  return c;
});

/** Everything a session showed, back as it started (lock, erase, reset). */
export function resetSession() {
  batch(() => { for (const [s, initial] of SESSION) s.value = Array.isArray(initial) ? [] : initial; });
}

/**
 * The signals that outlive a session, each for a reason. Anything not listed here is a
 * session signal (tests/state-reset.test.js).
 */
export const DEVICE_SCOPED = Object.freeze({
  view: "which screen the app is on; lock sets it",
  tab: "the tab; opening the app always starts at the vault (session.js)",
  prefs: "this device's preferences",
  enrollStep: "setting up, before any session",
  pass: "the access pass kept on this device until registration",
  passBusy: "the access pass, before any session",
  joinStep: "joining, before any session",
  joinMethod: "joining, before any session",
  joinStatus: "joining, before any session",
  joinMode: "joining, before any session",
  identity: "this device's identity record",
  hwGate: "this device's sensor",
  server: "the server this device trusts",
  serverError: "the server this device trusts",
  lockIssue: "what the Lock screen explains (set after a lock)",
  nfc: "this device's ID chip reader",
  simLog: "simulation builds: what the in-app server checked",
  simShow: "simulation builds: the checks sheet",
  interrupt: "the check overlay ends itself (interrupt.js endInterrupt)",
  toasts: "the lock reason is a toast, shown after the lock",
  online: "the network",
  link: "the connection to the server",
  offlineReady: "whether this device has an offline copy",
});
