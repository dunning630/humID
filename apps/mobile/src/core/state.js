// App state as signals. Screens read these; only core/controller.js writes them.
import { signal, computed } from "@preact/signals";

export const view = signal("boot");          // boot | welcome | enroll | locked | app
export const tab = signal("vault");          // vault | activity | security
export const enrollStep = signal(0);         // 0 connect · 1 bind · 2 done

export const identity = signal(null);        // local identity record (public parts + wrapped seed)
export const hwGate = signal(null);          // { adapter, probe } strongest hardware gate on this device
export const server = signal(null);          // { url, kid, fingerprint }
export const serverError = signal(null);
export const session = signal(null);
export const lockIssue = signal(null);      // e.g. "unknown_identity" after a server reset         // { id, assurance, gateMethod, expiresAt, idleTimeoutMs }

export const items = signal([]);             // decrypted index entries
export const usage = signal(null);
export const loading = signal(false);
export const filter = signal("all");
export const query = signal("");
export const ledger = signal(null);          // verified ledger page
export const ledgerLoading = signal(false);

export const interrupt = signal(null);       // overlay state
export const sheet = signal(null);           // { type, ... }
export const viewer = signal(null);          // decrypted preview
export const toasts = signal([]);
export const idleDeadline = signal(0);    // when the app auto-locks
export const online = signal(typeof navigator === "undefined" ? true : navigator.onLine);

export const visibleItems = computed(() => {
  const q = query.value.trim().toLowerCase();
  return items.value.filter((i) => (filter.value === "all" || i.category === filter.value) && (!q || i.name.toLowerCase().includes(q)));
});

export const counts = computed(() => {
  const c = { all: items.value.length };
  for (const i of items.value) c[i.category] = (c[i.category] || 0) + 1;
  return c;
});
