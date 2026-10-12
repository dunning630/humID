// Activity: the holder's own access ledger, verified on this device.
import { useEffect } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { dayLabel, fmtTime } from "../ui.jsx";
import * as S from "../core/state.js";
import { loadLedger } from "../core/controller.js";

const METHOD = {
  "ios-keychain-biometry": "Face ID / Touch ID",
  "android-keystore-biometric": "Fingerprint / face",
  "macos-keychain-biometry": "Touch ID",
  "windows-hello-keycredential": "Windows Hello",
  "linux-fprintd-keyring": "Fingerprint",
  "webauthn-platform-uv-prf": "Passkey",
  "demo-no-hardware": "Demo hold",
};
const method = (m) => METHOD[m] || m || "";

function describe(e, names) {
  const d = e.detail || {};
  const nm = d.id ? names?.get(d.id) || "a document" : "";
  switch (e.type) {
    case "identity.created": return { icon: "sparkle", tone: "mint", title: "HumID created", meta: [d.platform, method(d.method)] };
    case "session.opened": return { icon: "unlock", tone: "amber", title: "Unlocked", meta: [method(d.method), d.platform] };
    case "session.closed": return { icon: "lock", tone: "", title: "Locked", meta: [] };
    case "object.sealed": return { icon: "lock", tone: "mint", title: `Sealed ${nm}`, meta: [] };
    case "object.opened": return { icon: "eye", tone: "amber", title: `Opened ${nm}`, meta: [method(d.method)], proof: d.proof };
    case "object.updated": return { icon: "pencil", tone: "", title: `Renamed ${nm}`, meta: [] };
    case "object.deleted": return { icon: "trash", tone: "amber", title: `Deleted ${nm}`, meta: [method(d.method)], proof: d.proof };
    case "access.denied": return { icon: "alert", tone: "danger", title: "Access blocked", meta: [reason(d.reason)] };
    case "vault.erased": return { icon: "trash", tone: "danger", title: "Vault erased", meta: [] };
    case "identity.closed": return { icon: "x", tone: "danger", title: "HumID closed", meta: [] };
    case "device.added": return { icon: "key", tone: "mint", title: `Device added · ${d.platform || "device"}`, meta: [VIA[d.via], method(d.method)] };
    case "device.removed": return { icon: "x", tone: "amber", title: `Device removed · ${d.platform || "device"}`, meta: [], proof: d.proof };
    case "device.link_approved": return { icon: "key", tone: "amber", title: `Approved ${d.platform || "a new device"}`, meta: [], proof: d.proof };
    case "recovery.card_set": return { icon: "idcard", tone: "mint", title: "Recovery card made", meta: [], proof: d.proof };
    case "recovery.card_removed": return { icon: "idcard", tone: "", title: "Recovery card removed", meta: [], proof: d.proof };
    case "recovery.contacts_set": return { icon: "user", tone: "mint", title: `Recovery contacts set · any ${d.threshold} of ${d.n}`, meta: [], proof: d.proof };
    case "recovery.contacts_removed": return { icon: "user", tone: "", title: "Recovery contacts removed", meta: [], proof: d.proof };
    case "recovery.requested": return { icon: "alert", tone: "danger", title: `Recovery requested · ${d.method === "card" ? "card" : "contacts"}`, meta: [d.platform] };
    case "recovery.approved": return { icon: "user", tone: "amber", title: `A contact helped · ${d.approvals} of ${d.threshold}`, meta: [] };
    case "recovery.cancelled": return { icon: "x", tone: "mint", title: "Recovery cancelled", meta: [d.platform], proof: d.proof };
    case "recovery.completed": return { icon: "check", tone: "amber", title: `Recovered on ${d.platform || "a new device"}`, meta: [d.method === "card" ? "Recovery card" : "Recovery contacts"] };
    case "recovery.helped": return { icon: "user", tone: "mint", title: "You helped someone recover", meta: [], proof: d.proof };
    default: return { icon: "info", tone: "", title: e.type, meta: [] };
  }
}
const VIA = { register: "First device", link: "From another device", card: "Recovery card", contacts: "Recovery contacts" };
const reason = (r) => ({ device_removed: "Removed device tried to sign in",  step_up_required: "No biometric check", bad_step_up: "Biometric proof rejected", bad_login_proof: "Sign-in proof rejected", bad_proof: "Proof rejected" })[r] || r;

export function Activity() {
  useEffect(() => { loadLedger(); }, []);
  const l = S.ledger.value;
  const entries = l?.entries ? [...l.entries].reverse() : [];
  const groups = [];
  for (const e of entries) {
    const k = dayLabel(e.at);
    if (!groups.length || groups[groups.length - 1].k !== k) groups.push({ k, items: [] });
    groups[groups.length - 1].items.push(e);
  }
  return (
    <main class="screen with-tabs">
      <div class="topbar">
        <div class="grow"><h1>Activity</h1><div class="sub"><Icon name="chain" />Every access to your vault</div></div>
        <button class="icon-btn" aria-label="Refresh" onClick={loadLedger}><Icon name="activity" /></button>
      </div>

      {S.ledgerLoading.value && !l && <p class="muted small">Verifying your ledger…</p>}

      {l && (l.ok ? (
        <div class="banner">
          <span class="b-ico"><Icon name="shield" /></span>
          <div><strong>Ledger verified on this phone</strong><span>{l.entries.length} events · hash chain intact · head signed with ML-DSA-87 · key <span class="mono">{l.keyFp?.slice(0, 8)}</span></span></div>
        </div>
      ) : (
        <div class="banner bad">
          <span class="b-ico"><Icon name="alert" /></span>
          <div><strong>Ledger failed verification</strong><span>{l.reason}. Treat this history as untrusted.</span></div>
        </div>
      ))}

      <div class="timeline">
        {groups.map((g) => (
          <>
            <div class="eyebrow day">{g.k}</div>
            {g.items.map((e) => {
              const x = describe(e, l.names);
              return (
                <div class="event" data-tone={x.tone}>
                  <span class="e-ico"><Icon name={x.icon} /></span>
                  <div style={{ minWidth: 0 }}>
                    <div class="e-title">{x.title}</div>
                    <div class="e-meta">
                      {x.meta.filter(Boolean).map((m) => <span>{m}</span>)}
                      {x.proof && <span class="pill mint" title="Hash of the biometric-signed proof"><Icon name="fingerprint" /><span class="mono">{x.proof.slice(0, 8)}</span></span>}
                      <span class="mono" title={e.hash}>#{e.seq}</span>
                    </div>
                  </div>
                  <span class="e-time">{fmtTime(e.at)}</span>
                </div>
              );
            })}
          </>
        ))}
      </div>
    </main>
  );
}
