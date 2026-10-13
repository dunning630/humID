// Activity: the holder's own access ledger, verified on this device.
import { useEffect } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { dayLabel, fmtTime, fmtAgo } from "../ui.jsx";
import * as S from "../core/state.js";
import { loadLedger } from "../core/controller.js";

const METHOD = {
  "ios-keychain-biometry": "Face ID / Touch ID",
  "android-keystore-biometric": "Fingerprint / face",
  "macos-keychain-biometry": "Touch ID",
  "windows-winbio-fingerprint": "Fingerprint",
  "linux-fprintd-keyring": "Fingerprint",
  "demo-no-hardware": "Demo hold",
};
const method = (m) => METHOD[m] || m || "";

function describe(e, names) {
  const d = e.detail || {};
  const nm = d.id ? names?.get(d.id) || "a document" : "";
  switch (e.type) {
    case "identity.created": return { icon: "sparkle", tone: "mint", title: "HumID created", meta: [d.platform, method(d.method)] };
    case "session.opened": return { icon: "unlock", tone: "amber", title: "Unlocked", meta: [method(d.method), d.platform, d.checks ? `${d.checks} server checks ✓` : null] };
    case "session.closed": return { icon: "lock", tone: "", title: "Locked", meta: [] };
    case "object.sealed": return { icon: "lock", tone: "mint", title: `Sealed ${nm}`, meta: [d.checks ? `${d.checks} server checks ✓` : null] };
    case "object.opened": return { icon: "eye", tone: "amber", title: `Opened ${nm}`, meta: [method(d.method)], proof: d.proof };
    case "object.updated": return { icon: "pencil", tone: "", title: `Renamed ${nm}`, meta: [] };
    case "object.deleted": return { icon: "trash", tone: "amber", title: `Deleted ${nm}`, meta: [method(d.method)], proof: d.proof };
    case "access.denied": return { icon: "alert", tone: "danger", title: "Access blocked", meta: [reason(d.reason)] };
    case "vault.erased": return { icon: "trash", tone: "danger", title: "Vault erased", meta: [] };
    case "identity.closed": return { icon: "x", tone: "danger", title: "HumID closed", meta: [] };
    case "device.added": return { icon: "key", tone: "mint", title: `Device added · ${d.platform || "device"}`, meta: [d.evidence ? `Proofs: ${d.evidence}` : VIA[d.via], method(d.method), d.waitedMs ? `waited ${hours(d.waitedMs)}` : null, d.soleBiometric ? "only owner's biometrics" : null] };
    case "device.removed": return { icon: "x", tone: "amber", title: `Device removed · ${d.platform || "device"}`, meta: [], proof: d.proof };
    case "device.link_approved": return { icon: "key", tone: "amber", title: `Approved ${d.platform || "a new device"}`, meta: [], proof: d.proof };
    case "recovery.card_set": return { icon: "idcard", tone: "mint", title: d.scheme === "full" ? "Recovery card made" : "Seal card made", meta: [], proof: d.proof };
    case "recovery.card_removed": return { icon: "idcard", tone: "", title: "Seal card removed", meta: [], proof: d.proof };
    case "recovery.contacts_set": return { icon: "users", tone: "mint", title: `${d.scheme === "quorum" ? "Witnesses" : "Recovery contacts"} set · any ${d.threshold} of ${d.n}`, meta: [], proof: d.proof };
    case "recovery.contacts_removed": return { icon: "users", tone: "", title: "Witnesses removed", meta: [], proof: d.proof };
    case "recovery.anchor_set": return { icon: "passport", tone: "mint", title: `Anchored to your ${d.document || "ID"}`, meta: [d.country], proof: d.proof };
    case "recovery.anchor_removed": return { icon: "passport", tone: "", title: "ID anchor removed", meta: [], proof: d.proof };
    case "recovery.requested": return { icon: "alert", tone: "danger", title: `Recovery requested · ${({ card: "older card", contacts: "older contacts", quorum: "two proofs" })[d.method] || d.method}`, meta: [d.platform] };
    case "recovery.evidence": return { icon: KIND_ICON[d.kind] || "shield", tone: "amber", title: `Recovery proof added · ${KIND[d.kind] || d.kind}${d.anchorMode === "remote" ? " (live)" : ""}`, meta: [d.releaseAt ? `opens ${new Date(d.releaseAt).toLocaleString()}` : "needs a second proof"] };
    case "recovery.station_verified": return { icon: "station", tone: "amber", title: "ID verified in person at a station", meta: [d.country, d.releaseAt ? `opens ${new Date(d.releaseAt).toLocaleString()}` : null] };
    case "station.verified": return { icon: "station", tone: "mint", title: "You verified someone at your station", meta: [d.country], proof: d.proof };
    case "recovery.approved": return { icon: "users", tone: "amber", title: `A witness approved · ${d.approvals} of ${d.threshold}`, meta: [] };
    case "recovery.cancelled": return { icon: "x", tone: "mint", title: "Recovery cancelled", meta: [d.platform], proof: d.proof };
    case "recovery.completed": return { icon: "check", tone: "amber", title: `Recovered on ${d.platform || "a new device"}`, meta: [d.evidence ? `Proofs: ${d.evidence}` : d.method === "card" ? "Recovery card" : "Recovery contacts", d.waitedMs ? `waited ${hours(d.waitedMs)}` : null] };
    case "duress.signaled": return { icon: "siren", tone: "danger", title: "Duress signal", meta: [d.platform] };
    case "duress.cleared": return { icon: "siren", tone: "mint", title: "Lockdown lifted", meta: [], proof: d.proof };
    case "settings.changed": return { icon: "siren", tone: "", title: d.duressAlert ? "Witnesses will see duress signals" : "Witnesses won't see duress signals", meta: [], proof: d.proof };
    case "recovery.helped": return { icon: "user", tone: "mint", title: "You helped someone recover", meta: [], proof: d.proof };
    default: return { icon: "info", tone: "", title: e.type, meta: [] };
  }
}
const VIA = { register: "First device", link: "From another device", card: "Older recovery card", contacts: "Older recovery contacts", quorum: "Two proofs" };
const KIND = { witness: "witnesses", card: "seal card", anchor: "ID chip" };
const KIND_ICON = { witness: "users", card: "idcard", anchor: "passport" };
const hours = (ms) => (ms >= 3600_000 ? `${Math.round(ms / 3600_000)} h` : ms >= 60_000 ? `${Math.round(ms / 60_000)} min` : `${Math.round(ms / 1000)} s`);
const reason = (r) => ({
  device_removed: "Removed device tried to sign in",
  device_not_proven: "Device can't prove a live check",
  no_live_biometric: "No live face or fingerprint check",
  step_up_required: "No biometric check",
  bad_step_up: "Biometric proof rejected",
  bad_login_proof: "Sign-in proof rejected",
  bad_proof: "Proof rejected",
  no_live_seal: "Sealed without a live check",
  lockdown: "Blocked by lockdown",
})[r] || r;

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

      {l?.ok && <Continuity />}

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

/** The public transparency log, as this phone checked it. */
function Continuity() {
  const c = S.continuity.value;
  if (!c) return <p class="muted small" style={{ marginTop: 10 }}>Checking the public log…</p>;
  if (!c.ok && c.pending) return null;
  return c.ok ? (
    <div class="banner" style={{ marginTop: 10 }}>
      <span class="b-ico"><Icon name="globe" /></span>
      <div><strong>Published in the public log</strong><span>Your latest entry is in checkpoint #{c.size}{c.cosigned?.length ? `, cosigned by ${c.cosigned.join(", ")}` : ""}. The log only grew since this phone last checked{c.at ? ` (${fmtAgo(c.at)})` : ""}.</span></div>
    </div>
  ) : (
    <div class="banner bad" style={{ marginTop: 10 }}>
      <span class="b-ico"><Icon name="alert" /></span>
      <div><strong>Public log check failed</strong><span>{c.reason}. Your history may have been altered on the server. Keep this screen and report it.</span></div>
    </div>
  );
}
