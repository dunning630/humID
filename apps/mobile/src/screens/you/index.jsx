// You: a hub of summary rows, one per subject, each opening its own screen. What needs
// attention (a recovery in progress, a lockdown, someone you protect in trouble) sits at
// the top as banners; everything else is one line and a chevron. Daily use is Lock now.
//
// Pushed screens this file routes (S.push.value.type): protect · devices · recovery ·
// duress · heartbeat · help · settings · about. Sheets this file owns: the recovery card
// shown once after it's made (S.cardCode), kept as a draft across a lock until it's checked.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Row, Banner, Sheet, Confirm } from "../../ui/kit.jsx";
import { TabBanners } from "../vault.jsx";
import { CardBox, CardConfirm, PrintableCard, CAN_PRINT, PROOFS } from "../../ui/codes.jsx";
import { fmtAgo, fmtTime } from "../../ui/format.js";
import * as S from "../../core/state.js";
import { loadDevices, loadRecovery, loadAlerts, loadDuress, loadAdminSummary, loadCheckin, checkinOffered, cancelRecovery, clearLockdown, lockNow, saveCard, forgetNewCard } from "../../core/index.js";
import { Countdown, go } from "./common.jsx";
import { Protect, protectionItems } from "./protect.jsx";
import { Devices } from "./devices.jsx";
import { Recovery } from "./recovery.jsx";
import { Duress } from "./duress.jsx";
import { Heartbeat } from "./heartbeat.jsx";
import { Help } from "./help.jsx";
import { Settings } from "./settings.jsx";
import { About } from "./about.jsx";

const METHOD = { card: "recovery card", contacts: "witnesses", quorum: "two proofs" };
const PUSHED = { protect: Protect, devices: Devices, recovery: Recovery, duress: Duress, heartbeat: Heartbeat, help: Help, settings: Settings, about: About };

export function You() {
  const push = S.push.value;
  const Detail = push && PUSHED[push.type];
  return (
    <>
      <Hub />
      {Detail && <Detail />}
      {S.cardCode.value && <CardSheet code={S.cardCode.value} />}
    </>
  );
}

function Hub() {
  const decoy = S.decoy.value;
  useEffect(() => { loadDevices(); loadRecovery(); loadAlerts(); loadDuress(); loadAdminSummary(); loadCheckin(); }, []);
  const devices = S.devices.value;
  const rec = S.recovery.value;
  const dinfo = S.duressInfo.value;
  const duressOn = !!dinfo?.setting?.enabled; // "off" in a decoy session unless it turned it on itself
  const protecting = decoy ? [] : S.protecting.value;
  const ck = S.checkin.value;
  const items = protectionItems(rec, devices);
  const done = items.filter((i) => i.done).length;
  const proofs = rec ? PROOFS.filter((p) => rec.proofs[p.id]).length : 0;
  const admin = !decoy && !!S.adminSummary.value;
  return (
    <main class="screen tabs">
      <header class="top">
        <div class="grow"><h1>You</h1><div class="small muted">Your HumID, and how it's protected</div></div>
        <button class="icon-btn" aria-label="Lock now" onClick={lockNow}><Icon name="lock" /></button>
      </header>
      <TabBanners />

      {S.alerts.value.map((a) => (
        <Banner tone="danger" icon="alert" role="alert" key={a.ref}
          title={`Recovery in progress · ${METHOD[a.method] || a.method}`}
          text={<>Requested from {a.platform} {fmtAgo(a.createdAt)}. {a.evidence ? `Proofs so far: ${a.evidence}. ` : ""}{a.releaseAt ? <>Opens in <Countdown until={a.releaseAt} /> unless you cancel.</> : a.method === "quorum" ? "It needs a second proof before any wait starts." : `${a.approvals ?? 0} witness${a.approvals === 1 ? " has" : "es have"} helped so far.`} Cancel it and that device gets nothing.</>}
          action="Cancel it" onAction={() => cancelRecovery(a)} />
      ))}
      {dinfo?.lockdown && (
        <Banner tone="amber" icon="siren" title="Locked down after a duress signal"
          text={<>Since {fmtAgo(dinfo.since)}. Devices, recovery and closing your HumID can't change until you lift it{dinfo.clearableAt > Date.now() ? <>, which you can do in <Countdown until={dinfo.clearableAt} /></> : ""}. Recoveries wait twice as long for 14 days.</>}
          action={dinfo.clearableAt <= Date.now() ? "Lift lockdown" : null} onAction={clearLockdown} />
      )}
      {protecting.map((a, i) => (
        <Banner key={i} tone={a.kind === "duress" ? "danger" : "amber"} icon={a.kind === "duress" ? "siren" : "users"}
          title={a.kind === "duress" ? "Someone you protect signaled duress" : "Someone you protect is recovering their HumID"}
          text={a.kind === "duress"
            ? `${fmtAgo(a.at)}. They may be under pressure. Check on them in a safe way; don't help any recovery you're unsure of.`
            : `From ${a.platform}, ${fmtAgo(a.createdAt)}. Only help if they asked you themselves.`}
          action={a.kind === "duress" ? null : "Help recover"} onAction={() => go("help", { step: "recover" })} />
      ))}
      {admin && S.adminSummary.value.health !== "ok" && (
        <Banner tone="amber" icon="server" title="Your server needs a look" text={S.adminSummary.value.alerts?.[0] || "Open About › This server."} action="Open" onAction={() => go("about")} />
      )}

      <div class="rows">
        <Row icon="shield" tone={done === items.length ? "mint" : "amber"} title="Protection"
          sub={decoy || S.offline.value || !rec || !devices ? "How HumID protects you" : done === items.length ? "All set" : `${done} of ${items.length} done`}
          trail={!decoy && rec && devices && done < items.length ? <span class="pill amber">{items.length - done} to do</span> : null} onClick={() => go("protect")} />
        <Row icon="key" title="Devices" sub={devices ? `${devices.length} ${devices.length === 1 ? "device" : "devices"}` : "Loading…"} onClick={() => go("devices")} />
        <Row icon="users" tone={rec?.ready ? "mint" : ""} title="Recovery"
          sub={!rec ? "Loading…" : rec.ready ? "Ready · two proofs set up" : `${proofs} of 2 proofs set up`}
          trail={rec ? (rec.ready ? <span class="pill mint"><Icon name="check" />Ready</span> : <span class="pill amber">Needs {2 - proofs} more</span>) : null} onClick={() => go("recovery")} />
        <Row icon="siren" tone={duressOn ? "mint" : ""} title="Duress gesture" sub={duressOn ? "On · a forced unlock shows only decoys" : "Off"} onClick={() => go("duress")} />
        {checkinOffered() && (
          <Row icon="clock" tone={ck?.state === "locked" ? "danger" : ck?.state === "armed" ? "mint" : ""} title="Heartbeat"
            sub={ck?.state === "locked" ? "Missed · your vault is locked" : ck?.state === "armed" ? `On · next by ${fmtTime(ck.deadline)}` : "Off"}
            trail={ck?.state === "locked" ? <span class="pill danger">Missed</span> : null} onClick={() => go("heartbeat")} />
        )}
        <Row icon="user" title="Help others" sub={!decoy && S.station.value?.station ? "Be a witness · help recover · verification station" : "Be a witness, or help a witness of yours"} onClick={() => go("help")} />
        <Row icon="settings" title="Settings" sub="Look, text size, lock timing, sorting" onClick={() => go("settings")} />
        <Row icon="info" title="About" sub={admin ? "Your identity, this device, your server (you administer it)" : "Your identity, this device, the connection"} onClick={() => go("about")} />
      </div>

      <div class="actions"><button class="btn ghost block" onClick={lockNow}><Icon name="lock" />Lock now</button></div>
    </main>
  );
}

/**
 * The recovery card, shown once after it's made (S.cardCode); forgotten when closed. Until the
 * typed-back check passes, every way of closing it (the X, a tap outside, Escape, Back) asks
 * first: the server has already replaced the old card, so this is the only copy (APP-03).
 */
function CardSheet({ code }) {
  const [ok, setOk] = useState(false);
  const [asking, setAsking] = useState(false);
  const checked = useRef(false); // Sheet's Escape handler keeps its first onClose: read the latest here
  checked.current = ok;
  const close = () => { if (checked.current) forgetNewCard(); else setAsking(true); };
  return (
    <>
    <Sheet onClose={close} eyebrow="Shown once · write it down now" title="Your new recovery card">
      <p class="t2 small">Your old card, if you had one, no longer works. On its own this card opens nothing: recovery also needs your witnesses, your ID chip or a security key.</p>
      <CardBox code={code} />
      <div class="row-x" style={{ marginTop: 12 }}>
        {CAN_PRINT && <button class="btn quiet sm" onClick={() => window.print()}><Icon name="file" />Print</button>}
        <button class="btn quiet sm" onClick={() => saveCard(code)}><Icon name="download" />Save</button>
        <span class="fine grow">A saved file can sync to your cloud. Paper is safer.</span>
      </div>
      <CardConfirm code={code} onChange={setOk} />
      <PrintableCard code={code} />
      <div class="actions">
        <button class="btn primary mint block" onClick={() => {
          if (ok) return close();
          // never a dead grey button: point at what's missing instead
          const f = document.getElementById("card-check");
          f?.scrollIntoView({ block: "center", behavior: "smooth" });
          f?.focus({ preventScroll: true });
        }}>{ok ? "I've stored it safely" : "Check your copy to continue"}</button>
      </div>
    </Sheet>
    {asking && (
      <Confirm title="Close without saving your new card?" action="Close without saving"
        text="Your old card already stopped working, and this one won't be shown again. You'll need to make another."
        onClose={() => setAsking(false)} onConfirm={forgetNewCard} />
    )}
    </>
  );
}
