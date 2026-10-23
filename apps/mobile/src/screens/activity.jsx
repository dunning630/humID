// Activity: the holder's own access ledger, verified on this phone. One line says it was
// verified and when; the details (how many events, who signed, the public log) open from
// it. Rows carry no hashes: tapping one shows the event's proof in words.
import { useEffect, useMemo, useState } from "preact/hooks";
import { Icon } from "../brand/icons.jsx";
import { Sheet, Banner, Empty, Row } from "../ui/kit.jsx";
import { TabBanners } from "./vault.jsx";
import { dayLabel, fmtTime, fmtAgo, fmtDate } from "../ui/format.js";
import * as S from "../core/state.js";
import { loadLedger, lockNow } from "../core/index.js";
import { eventProof, gateName, VIA, RECOVERY_METHOD, PROOF_KIND as KIND } from "../ui/labels.js";

const method = gateName;

const KIND_ICON = { witness: "users", card: "idcard", anchor: "passport", key: "seckey" };
const hours = (ms) => (ms >= 3600_000 ? `${Math.round(ms / 3600_000)} h` : ms >= 60_000 ? `${Math.round(ms / 60_000)} min` : `${Math.round(ms / 1000)} s`);
const reason = (r) => ({
  device_removed: "Removed device tried to sign in",
  attestation_revoked: "Google revoked that phone's chip certificate",
  reattest_required: "Phone needs setting up again",
  device_not_proven: "Device can't prove its live checks",
  no_live_biometric: "No live check",
  step_up_required: "No live check",
  bad_step_up: "Live check rejected",
  bad_login_proof: "Sign-in proof rejected",
  bad_proof: "Proof rejected",
  no_live_seal: "Sealed without a live check",
  lockdown: "Blocked by lockdown",
  checkin_missed: "Locked: a heartbeat was missed",
  vault_erased: "Erased by Heartbeat",
})[r] || r;

/** tone → the CSS data-kind on .event: open (mint) · change (amber) · danger · "" */
const KINDS = { mint: "open", amber: "change", danger: "danger", "": "" };

function describe(e, names) {
  const d = e.detail || {};
  const nm = d.id ? names?.get(d.id) || "a document" : "";
  const verified = d.checks ? `${d.checks} server verifications` : null;
  switch (e.type) {
    case "identity.created": return { icon: "sparkle", tone: "mint", title: "HumID created", meta: [d.platform, method(d.method)] };
    case "session.opened": return { icon: "unlock", tone: "amber", title: "Unlocked", meta: [method(d.method), d.platform, verified] };
    case "session.closed": return { icon: "lock", tone: "", title: "Locked", meta: [] };
    case "object.sealed": return { icon: "lock", tone: "mint", title: `Sealed ${nm}`, meta: [verified] };
    case "object.opened": return { icon: "eye", tone: "amber", title: `Opened ${nm}`, meta: [method(d.method)], proof: d.proof };
    // a rename, tags, a pin, a decoy change, or the app re-sealing an older entry in the current format
    case "object.updated": return { icon: "pencil", tone: "", title: `Updated details of ${nm}`, meta: [] };
    case "object.deleted": return { icon: "trash", tone: "amber", title: `Deleted ${nm}`, meta: [method(d.method)], proof: d.proof };
    case "access.denied": return { icon: "alert", tone: "danger", title: "Access blocked", meta: [reason(d.reason)] };
    case "vault.erased": return { icon: "trash", tone: "danger", title: "Vault erased", meta: [] };
    case "identity.closed": return { icon: "x", tone: "danger", title: "HumID closed", meta: [] };
    case "device.added": return { icon: "key", tone: "mint", title: `Device added · ${d.platform || "device"}`, meta: [d.evidence ? `Proofs: ${d.evidence}` : VIA[d.via], method(d.method), d.waitedMs ? `waited ${hours(d.waitedMs)}` : null, d.soleBiometric ? "only the owner's face or fingerprints" : null] };
    case "device.removed": return { icon: "x", tone: d.reason === "attestation_revoked" ? "danger" : "amber", title: `Device removed · ${d.platform || "device"}`, meta: d.reason === "attestation_revoked" ? ["Google revoked its secure-chip certificate"] : [], proof: d.proof };
    case "device.keys_invalidated": return { icon: "alert", tone: "danger", title: `HumID key gone · ${d.platform || "device"}`, meta: ["reported by the device: its face or fingerprints changed, or HumID was reinstalled", "set it up again, or remove it if that wasn't you"] };
    case "device.link_approved": return { icon: "key", tone: "amber", title: `Approved ${d.platform || "a new device"}`, meta: [], proof: d.proof };
    case "recovery.card_set": return { icon: "idcard", tone: "mint", title: d.scheme === "full" ? "Recovery card made (older kind)" : "Recovery card made", meta: [], proof: d.proof };
    case "recovery.card_removed": return { icon: "idcard", tone: "", title: "Recovery card removed", meta: [], proof: d.proof };
    case "recovery.contacts_set": return { icon: "users", tone: "mint", title: `Witnesses set · any ${d.threshold} of ${d.n}${d.scheme === "quorum" ? "" : " (older kind)"}`, meta: [], proof: d.proof };
    case "recovery.contacts_removed": return { icon: "users", tone: "", title: "Witnesses removed", meta: [], proof: d.proof };
    case "recovery.anchor_set": return { icon: "passport", tone: "mint", title: `Linked to your ${d.document || "ID"}'s chip`, meta: [d.country], proof: d.proof };
    case "recovery.anchor_removed": return { icon: "passport", tone: "", title: "ID chip unlinked", meta: [], proof: d.proof };
    case "recovery.key_added": return { icon: "seckey", tone: "mint", title: "Security key added", meta: d.count ? [`${d.count} in all`] : [], proof: d.proof };
    case "recovery.key_removed": return { icon: "seckey", tone: "", title: "Security key removed", meta: [], proof: d.proof };
    case "recovery.mode_set": return { icon: d.mode === "holder-only" ? "key" : "shield", tone: d.from ? "amber" : "mint", title: d.mode === "holder-only" ? "Recovery: only my own devices" : "Recovery: two proofs, a wait and a veto", meta: [d.at === "setup" ? "chosen at setup" : d.from ? `changed from ${d.from === "holder-only" ? "only my own devices" : "two-proof recovery"}` : null, d.newPieces ? "older recovery pieces no longer fit" : null], proof: d.proof };
    case "recovery.key_refused": return { icon: "alert", tone: "danger", title: d.reason === "key_cloned" ? "A copy of your security key was refused" : "A wrong answer from your security key was refused", meta: ["during a recovery; it didn't count"] };
    case "recovery.requested": return { icon: "alert", tone: "danger", title: `Recovery requested · ${RECOVERY_METHOD[d.method] || d.method}`, meta: [d.platform] };
    case "recovery.evidence": return { icon: KIND_ICON[d.kind] || "shield", tone: "amber", title: `Recovery proof added · ${KIND[d.kind] || d.kind}${d.anchorMode === "remote" ? " (live)" : ""}`, meta: [d.releaseAt ? `opens ${fmtDate(d.releaseAt)}, ${fmtTime(d.releaseAt)}` : "needs a second proof"] };
    case "recovery.station_verified": return { icon: "station", tone: "amber", title: "ID verified in person at a station", meta: [d.country, d.releaseAt ? `opens ${fmtDate(d.releaseAt)}, ${fmtTime(d.releaseAt)}` : null] };
    case "station.verified": return { icon: "station", tone: "mint", title: "You verified someone at your station", meta: [d.country], proof: d.proof };
    case "recovery.approved": return { icon: "users", tone: "amber", title: `A witness approved · ${d.approvals} of ${d.threshold}`, meta: [] };
    case "recovery.cancelled": return { icon: "x", tone: "mint", title: "Recovery cancelled", meta: [d.platform], proof: d.proof };
    case "recovery.completed": return { icon: "check", tone: "amber", title: `Recovered on ${d.platform || "a new device"}`, meta: [d.evidence ? `Proofs: ${d.evidence}` : VIA[d.method] || d.method, d.waitedMs ? `waited ${hours(d.waitedMs)}` : null] };
    case "duress.signaled": return { icon: "siren", tone: "danger", title: "Duress signal", meta: [d.platform] };
    case "duress.cleared": return { icon: "siren", tone: "mint", title: "Lockdown lifted", meta: [], proof: d.proof };
    case "settings.changed": return { icon: "siren", tone: "", title: d.duressAlert ? "Witnesses will see duress signals" : "Witnesses won't see duress signals", meta: [], proof: d.proof };
    case "recovery.helped": return { icon: "user", tone: "mint", title: "You helped someone recover", meta: [], proof: d.proof };
    case "admin.approved": return { icon: "settings", tone: "amber", title: d.kind === "enrol" ? "You became a server administrator" : `Server change approved · ${d.title}`, meta: [], proof: d.proof, digest: d.digest };
    case "checkin.armed": return { icon: "clock", tone: "amber", title: `Heartbeat on · every ${hours(d.windowMs)}`, meta: [d.graceMs ? `${hours(d.graceMs)} grace` : "no grace", d.kept ? `${d.kept} decoy${d.kept === 1 ? "" : "s"} kept` : null], proof: d.proof };
    case "checkin.disarmed": return { icon: "clock", tone: "mint", title: "Heartbeat off", meta: [], proof: d.proof };
    case "checkin.erased": return { icon: "trash", tone: "danger", title: "Vault erased by Heartbeat", meta: [d.count != null ? `${d.count} document${d.count === 1 ? "" : "s"}` : null] };
    default: return { icon: "info", tone: "", title: e.type, meta: [] };
  }
}

export function Activity() {
  useEffect(() => { loadLedger(); }, []);
  const l = S.ledger.value;
  const [details, setDetails] = useState(false);
  const [picked, setPicked] = useState(null);
  // Described and grouped once per ledger page, not on every render (opening an event's sheet,
  // a details toggle): up to 300 entries.
  const groups = useMemo(() => {
    const out = [];
    for (const e of l?.entries ? [...l.entries].reverse() : []) {
      const k = dayLabel(e.at);
      if (!out.length || out[out.length - 1].k !== k) out.push({ k, items: [] });
      const x = describe(e, l.names);
      out[out.length - 1].items.push({ e, x, where: [...x.meta.filter(Boolean), x.proof ? eventProof(e).short : null].filter(Boolean).join(" · ") });
    }
    return out;
  }, [l]);
  const entries = l?.entries || [];
  const c = S.continuity.value;
  return (
    <main class="screen tabs">
      <header class="top">
        <div class="grow"><h1>Activity</h1><div class="small muted">Every access to your vault</div></div>
        <button class="icon-btn" aria-label="Refresh" disabled={S.ledgerLoading.value} onClick={loadLedger}><Icon name="rotate" /></button>
        <button class="icon-btn" aria-label="Lock now" onClick={lockNow}><Icon name="lock" /></button>
      </header>
      <TabBanners />

      {S.ledgerLoading.value && !l && <p class="muted small">Checking your record…</p>}

      {l && !l.ok && l.unverified && <Banner tone="amber" icon="alert" title="Not verified on this phone" text={`${l.reason}. These events are shown as the server sent them; nothing here says they're complete.`} />}
      {l && !l.ok && !l.unverified && <Banner tone="danger" icon="alert" role="alert" title="This record failed its check" text={`${l.reason}. Treat this history as untrusted.`} />}
      {l?.ok && c && !c.ok && !c.pending && <Banner tone="danger" icon="alert" role="alert" title="Public log check failed" text={`${c.reason}. Your history may have been altered on the server. Keep this screen and report it.`} />}
      {l?.ok && (
        <button class="row-x small" style={{ width: "100%", textAlign: "left", minHeight: "var(--tap)", color: "var(--mint)" }} aria-expanded={details} onClick={() => setDetails(!details)}>
          <Icon name="shield" />
          <span class="grow">{S.offline.value ? "Verified when last online" : "Verified on this phone"} ✓{l.checkedAt ? ` · as of ${fmtAgo(l.checkedAt)}` : ""}</span>
          <Icon name="chevron" style={{ transform: details ? "rotate(90deg)" : undefined, transition: "transform var(--d-fast)" }} />
        </button>
      )}
      {l?.ok && details && (
        <div class="rows mb-3">
          {/* A decoy session's list is filtered (core/ledger.js decoyView): "nothing missing" would be false there. */}
          <Row chevron={false} icon="chain" tone="mint" title={l.decoy ? `${l.entries.length} events` : `${l.entries.length} events, nothing altered or missing`} sub="Each entry is chained to the one before it; this phone re-checked every link." />
          <Row chevron={false} icon="server" tone="mint" title="Signed by your vault server" sub={<>Its signing key: <span class="mono">{l.keyFp?.slice(0, 8)}</span></>} />
          {!c && <Row chevron={false} icon="globe" title="Checking the public log…" />}
          {c?.ok && <Row chevron={false} icon="globe" tone="mint" title="Published in the public log" sub={`Your latest entry is in checkpoint #${c.size}${c.cosigned?.length ? `, cosigned by ${c.cosigned.join(", ")}` : ""}. The log only grew since this phone last checked${c.at ? ` (${fmtAgo(c.at)})` : ""}.`} />}
          {c && !c.ok && c.pending && <Row chevron={false} icon="globe" title="Public log" sub={c.reason} />}
        </div>
      )}

      {l?.ok && entries.length === 0 && (
        <Empty icon="chain" title="Nothing here yet" text="Every unlock, open, save and delete is recorded here, checked on this phone." />
      )}

      {groups.map((g) => (
        <section key={g.k}>
          <div class="day">{g.k}</div>
          <div class="rows">
            {g.items.map(({ e, x, where }) => {
              return (
                <button class="event" data-kind={KINDS[x.tone]} key={e.seq} onClick={() => setPicked({ e, x })} style={{ width: "100%", textAlign: "left" }}>
                  <Icon name={x.icon} />
                  <span style={{ minWidth: 0 }}>
                    <span class="what" style={{ display: "block" }}>{x.title}</span>
                    <span class="where" style={{ display: "block" }}>{where}</span>
                  </span>
                  <time dateTime={new Date(e.at).toISOString()}>{fmtTime(e.at)}</time>
                </button>
              );
            })}
          </div>
        </section>
      ))}

      {picked && <EventSheet e={picked.e} x={picked.x} onClose={() => setPicked(null)} />}
    </main>
  );
}

/** One event, in full: when, where, what proved it. */
function EventSheet({ e, x, onClose }) {
  const d = e.detail || {};
  // what the server recorded about the device that made this proof, never this device's own (APP-09)
  const proof = eventProof(e);
  const Fact = ({ k, v, stacked }) => (stacked
    ? <Row chevron={false} title={k} sub={<span class="selectable" style={{ wordBreak: "break-all" }}>{v}</span>} />
    : <Row chevron={false} title={k} trail={<span class="t2" style={{ textAlign: "right", whiteSpace: "normal" }}>{v}</span>} />);
  return (
    <Sheet onClose={onClose} eyebrow={dayLabel(e.at)} title={x.title}>
      <div class="rows">
        <Fact k="When" v={`${fmtDate(e.at)}, ${fmtTime(e.at)}`} />
        {d.platform && <Fact k="Device" v={d.platform} />}
        {d.method && <Fact k="Check" v={method(d.method)} />}
        {x.proof && <Fact k="Proved by" v={<><span class={`pill ${proof.strong ? "mint" : "amber"}`}><Icon name="fingerprint" />{proof.long}</span><br /><span class="mono small muted">{x.proof.slice(0, 16)}</span></>} />}
        {d.checks && <Fact k="Server verifications" v={`${d.checks} passed`} />}
        {x.digest && <Fact k="Console match code" v={<span class="mono">{String(x.digest).slice(0, 8).toUpperCase().replace(/(.{4})/, "$1-")}</span>} />}
        <Fact k="Entry" v={`#${e.seq}`} />
        <Fact stacked k="Chain hash" v={<span class="mono small">{e.hash}</span>} />
      </div>
      <p class="fine mt-3">This entry is chained to the one before it and signed by your vault server; this phone verified both. It can't be changed or removed without that showing here.</p>
      <div class="actions"><button class="btn ghost block" onClick={onClose}>Close</button></div>
    </Sheet>
  );
}
