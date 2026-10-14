// App state as signals. Screens read these; only core/controller.js writes them.
import { signal, computed } from "@preact/signals";
import { DEMO_BUILD } from "@humid/gate";

export const view = signal("boot");          // boot | welcome | enroll | join | locked | app
export const tab = signal("vault");          // vault | activity | security
export const enrollStep = signal(0);         // 0 connect · 1 bind · 2 done + recovery card

// A new device joining an existing account (another device, a recovery card, or recovery contacts).
export const joinStep = signal(0);           // 0 connect · 1 choose · 2 details · 3 waiting
export const joinMethod = signal(null);      // link | quorum | card | contacts
export const joinStatus = signal(null);      // last polled status from the server

export const identity = signal(null);        // local identity record (public parts + wrapped seeds)
export const hwGate = signal(null);          // { adapter, probe } strongest hardware gate on this device
export const server = signal(null);          // { url, kid, fingerprint, policy }
export const serverError = signal(null);
export const session = signal(null);         // { id, device, assurance, gateMethod, expiresAt, idleTimeoutMs }
export const lockIssue = signal(null);       // unknown_identity | server_identity_changed | device_removed

export const items = signal([]);             // decrypted index entries
export const usage = signal(null);
export const loading = signal(false);
export const filter = signal("all");
export const query = signal("");
export const ledger = signal(null);          // verified ledger page
export const ledgerLoading = signal(false);

export const devices = signal(null);         // this account's devices (from the identity service)
export const recovery = signal(null);        // { card, contacts: { n, threshold, names[], scheme }, anchor, settings, ready }
export const protecting = signal([]);        // alerts about people this HumID protects: recoveries, duress signals
export const station = signal(null);         // { station: bool, countries } — this HumID runs a verification station
export const alerts = signal([]);            // recoveries in progress for this account
export const cardCode = signal(null);        // a recovery card to show once, then forget

// Duress. `decoy` is true for a session opened with the duress gesture: the app then shows
// only decoy documents and a calm account, while the server has locked sensitive changes.
export const decoy = signal(false);
export const duressInfo = signal(null);      // { lockdown, clearableAt, lastDuressAt, alert } (real sessions only)
export const continuity = signal(null);      // public-log check: { ok, reason, size, cosigned, at }
export const nfc = signal(null);             // { available, kind: "phone" | "reader" | "none", reason } — the ID chip reader
export const chipRead = signal(null);        // { stage, message, fraction, error } while reading a chip

// Simulation build: what the in-app server checked, newest first, and the sheet that shows it.
export const simLog = signal([]);
export const simShow = signal(null);         // a report to show in the checks sheet

export const interrupt = signal(null);       // overlay state
export const sheet = signal(null);           // { type, ... }
export const viewer = signal(null);          // decrypted preview
export const toasts = signal([]);
export const idleDeadline = signal(0);       // when the app auto-locks
export const online = signal(typeof navigator === "undefined" ? true : navigator.onLine);

// Demo mode only in a local development build talking to a server whose policy is "demo".
export const demoAllowed = computed(() => DEMO_BUILD && server.value?.policy?.devicePolicy === "demo");

export const visibleItems = computed(() => {
  const q = query.value.trim().toLowerCase();
  return items.value.filter((i) => (filter.value === "all" || i.category === filter.value) && (!q || i.name.toLowerCase().includes(q)));
});

export const counts = computed(() => {
  const c = { all: items.value.length };
  for (const i of items.value) c[i.category] = (c[i.category] || 0) + 1;
  return c;
});
