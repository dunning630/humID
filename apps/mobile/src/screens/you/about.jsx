// About: the diagnostics (your identity, this device, the connection), managing the
// server for those who administer one, the simulation (dev builds), and, under Advanced,
// closing the HumID: document count shown, CLOSE typed, then the live check.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Sheet, Banner, Confirm, AssurancePill, proofLabel } from "../../ui/kit.jsx";
import { gateDetail } from "../../ui/labels.js";
import { CodeBox, CodeInput } from "../../ui/codes.jsx";
import { fmtDate, groupKey } from "../../ui/format.js";
import * as S from "../../core/state.js";
import { serverHost, VERSION, PLATFORM, SIM, MODULES } from "../../core/config.js";
import { eraseEverything, resetSimulation } from "../../core/index.js";
import { loadAdminSummary, findAdminRequest, approveAdminRequest } from "../../core/setup.js";
import { back, twelve, Countdown, Fact, Disclosure } from "./common.jsx";

const HEALTH = { ok: ["mint", "Running normally"], warn: ["amber", "Needs a look"], bad: ["danger", "Needs attention"] };

export function About() {
  const id = S.identity.value;
  const srv = id?.server;
  const sess = S.session.value;
  const decoy = S.decoy.value;
  const sum = !decoy ? S.adminSummary.value : null;
  const [admin, setAdmin] = useState(false);
  const [closing, setClosing] = useState(false);
  const [simReset, setSimReset] = useState(false);
  useEffect(() => { loadAdminSummary(); }, []);
  const n = S.items.value.length;
  const off = !!S.offline.value;
  return (
    <Pushed title="About this HumID" onBack={back}>
      <div class="stack">
        <section>
          <div class="eyebrow mb-2">Your identity</div>
          <div class="rows">
            <Fact k="Created" v={id ? fmtDate(id.enrolledAt) : ""} />
            <Fact stacked k="HumID" v={<span class="mono">{srv?.id}</span>} />
            <Fact stacked k="Identity commitment" v={<span class="mono">{groupKey(id?.commit).slice(0, 8).join(" ")}</span>} />
            <Fact k="Keys" v="Post-quantum" />
          </div>
        </section>
        <section>
          <div class="eyebrow mb-2">This device</div>
          <div class="rows">
            <Fact k="Protection" v={<AssurancePill assurance={id?.assurance} />} />
            <Fact k="Live check" v={gateDetail(id?.method)} />
            <Fact k="Proof" v={proofLabel(id?.proof, id?.assurance)} />
            <Fact k="PIN or password" v={<span class="pill mint"><Icon name="check" />Never accepted</span>} />
            <Fact k="Device" v={PLATFORM} />
          </div>
        </section>
        <section>
          <div class="eyebrow mb-2">Connection</div>
          <div class="rows">
            <Fact k="Vault server" v={serverHost(srv?.url)} />
            <Fact stacked k="Pinned server key" v={<span class="mono">{(srv?.fingerprint || "").split("-").join(" ")}</span>} />
            <Fact k="Device policy" v={S.server.value?.policy?.devicePolicy === "attested" ? "Chip-proven phones only" : S.server.value?.policy?.devicePolicy || "—"} />
            <Fact k="Connection" v="Post-quantum, end to end" />
            <Fact k="Session" v={sess ? <span class="pill mint"><Icon name="signal" />Active · locks in <Countdown until={S.idleDeadline.value} /></span> : off ? <span class="pill amber"><Icon name="signal" />Offline · read only · locks in <Countdown until={S.idleDeadline.value} /></span> : "—"} />
          </div>
        </section>

        {sum && (
          <section class="card">
            <div class="row-x" style={{ justifyContent: "space-between" }}><h2 class="h3">This server</h2><span class={`pill ${(HEALTH[sum.health] || HEALTH.warn)[0]}`}>{(HEALTH[sum.health] || HEALTH.warn)[1]}</span></div>
            <p class="small muted mt-1">You're an administrator of {serverHost(srv?.url)}{sum.version ? ` (version ${sum.version})` : ""}. Changes from its admin console wait for your approval here.</p>
            {sum.alerts?.length > 0 && <ul class="small" style={{ margin: "8px 0 0", paddingLeft: 18 }}>{sum.alerts.map((a) => <li>{a}</li>)}</ul>}
            {(sum.updates?.humid || sum.updates?.security || sum.updates?.os) && <p class="small mt-2">Waiting to install: {[sum.updates.humid && `HumID Server ${sum.updates.humid}`, sum.updates.security ? `${sum.updates.security} security update${sum.updates.security === 1 ? "" : "s"}` : sum.updates.os ? `${sum.updates.os} Windows update${sum.updates.os === 1 ? "" : "s"}` : null].filter(Boolean).join(" and ")}. Start it from the console on the server.</p>}
            <div class="actions" style={{ paddingTop: 10 }}><button class="btn primary sm" disabled={off} onClick={() => setAdmin(true)}><Icon name="scan" />Approve a change</button></div>
          </section>
        )}
        {!sum && !decoy && !SIM && (
          <Disclosure title="Manage this server" sub="For whoever runs your vault server">
            <p class="small muted">Approve a change from your vault server's admin console, or become its administrator. Only do this for a server you run.</p>
            <div class="actions" style={{ paddingTop: 10 }}><button class="btn quiet block" disabled={off} onClick={() => setAdmin(true)}><Icon name="station" />Enter a console code</button></div>
          </Disclosure>
        )}

        {SIM && (
          <section class="card">
            <div class="row-x" style={{ justifyContent: "space-between" }}><h2 class="h3">Simulation</h2><span class="pill amber">No real server</span></div>
            <p class="small muted mt-1">The vault server runs inside this app. The connection is the real post-quantum one and the checks are real; adding devices, witnesses, ID chips and stations need other people or servers, so they're off here. Nothing leaves this phone.</p>
            <div class="actions row" style={{ paddingTop: 10 }}>
              <button class="btn quiet sm" onClick={() => (S.simShow.value = S.simLog.value[0] || { title: "Simulation", checks: [], empty: true })}><Icon name="shield" />Server verifications</button>
              <button class="btn danger sm" onClick={() => setSimReset(true)}>Reset simulation</button>
            </div>
          </section>
        )}

        <Disclosure title="Advanced" sub="Versions · closing your HumID">
          <div class="rows">
            <Fact k="HumID" v={VERSION} />
            {Object.entries(MODULES).filter(([k]) => k !== "@humid/mobile").map(([k, v]) => <Fact k={k.replace("@humid/", "")} v={v} />)}
          </div>
          <div class="card danger mt-3">
            <h2 class="h3">Close HumID and erase your vault</h2>
            <p class="small t2 mt-1">Every document is erased from the vault server ({n} {n === 1 ? "item" : "items"} right now), your identity and recovery options are closed, and the keys on this device are destroyed. Your activity history stays on file, closed. Nobody can undo this.</p>
            <div class="actions" style={{ paddingTop: 10 }}><button class="btn danger block" disabled={off} onClick={() => setClosing(true)}><Icon name="trash" />Close HumID…</button></div>
          </div>
        </Disclosure>
      </div>

      {closing && <Confirm title="Close your HumID?" typed="CLOSE" action="Close and erase" onClose={() => setClosing(false)} onConfirm={eraseEverything}
        text={`This erases ${n} ${n === 1 ? "item" : "items"} from your vault for good, closes your identity and recovery, and destroys this device's keys. Your face or fingerprint confirms it next.`} />}
      {simReset && <Confirm title="Start the simulation over?" action="Reset" onClose={() => setSimReset(false)} onConfirm={resetSimulation}
        text="The simulated server, your test HumID and every test document on this phone are erased. Then you can set up from the beginning." />}
      {admin && <AdminSheet onClose={() => setAdmin(false)} />}
    </Pushed>
  );
}

function AdminSheet({ onClose }) {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(null);
  const find = async (c = code) => { if (busy) return; setBusy(true); setReq(await findAdminRequest(c)); setBusy(false); };
  const approve = async () => { setBusy(true); const r = await approveAdminRequest(req); if (r) setDone(r); setBusy(false); };
  const enrol = req?.kind === "enrol";
  return (
    <Sheet onClose={onClose} eyebrow="Manage this server" title={done ? (enrol ? "Compare this with the console" : "Approved") : !req ? "Enter the code from the admin console" : enrol ? "Become an administrator of this server?" : req.title}>
      {done ? (
        enrol ? (
          <>
            <p class="t2 small">The admin console now shows an admin match code. It must be exactly this. If it is, choose <b>They match</b> there; if not, choose <b>They don't match</b>.</p>
            <CodeBox code={done.check} label="Admin match code" />
            <div class="actions"><button class="btn primary mint block" onClick={onClose}>Done</button></div>
          </>
        ) : (
          <>
            <p class="t2 small">The console checks your approval itself, then starts: {req.title}. You'll see its progress there.</p>
            <div class="actions"><button class="btn primary mint block" onClick={onClose}>Done</button></div>
          </>
        )
      ) : !req ? (
        <>
          <p class="t2 small">On the server, the console shows a QR code and a 12-character code for each change. Scan it or type it.</p>
          <CodeInput id="admin-code" label="Console code" value={code} onInput={setCode} expect="admin" onScanned={(c) => find(c)} />
          <div class="actions"><button class="btn primary block" disabled={busy || !twelve(code)} onClick={() => find()}>Look it up</button></div>
        </>
      ) : (
        <>
          {req.lines?.length > 0 && <ul class="small muted" style={{ margin: "0 0 8px", paddingLeft: 18 }}>{req.lines.map((l) => <li>{l}</li>)}</ul>}
          <Banner tone="mint" icon="shield" title={`Match code ${req.check}`} text={<>The console shows the same code. Your face or fingerprint approves exactly this, for <Countdown until={req.expiresAt} expired="no longer: it expired" /> more.</>} />
          <p class="small muted">{enrol ? "You'll then be able to approve updates, restarts and backups on this server. Only do this for a server you run." : "Only approve a change you started on the console yourself."}</p>
          <div class="actions">
            <button class="btn primary block" disabled={busy || req.expiresAt <= Date.now()} onClick={approve}><Icon name="fingerprint" />{enrol ? "Become an administrator" : "Approve this change"}</button>
            <button class="btn ghost block" data-back onClick={() => setReq(null)}>Not mine</button>
          </div>
        </>
      )}
    </Sheet>
  );
}
