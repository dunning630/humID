// Devices: every phone that holds this HumID; add one (a two-way match code), remove a
// lost one. Adding starts from the new device: it shows a code, this one scans it. A
// scanned QR is looked up at once; the match code is then compared in both directions.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Sheet, Banner, Row, proofLabel } from "../../ui/kit.jsx";
import { CodeBox, CodeInput } from "../../ui/codes.jsx";
import { fmtDate, fmtAgo } from "../../ui/format.js";
import * as S from "../../core/state.js";
import { loadDevices, myAccountCheck, findLink, approveLink, removeDevice } from "../../core/index.js";
import { back, twelve } from "./common.jsx";

const VIA = { register: "Created HumID", link: "Added from another device", card: "Recovered with older card", contacts: "Recovered with older witnesses", quorum: "Recovered with two proofs" };

export function Devices() {
  const devices = S.devices.value;
  const [adding, setAdding] = useState(S.push.value?.open === "add");
  const [removing, setRemoving] = useState(null);
  const off = !!S.offline.value;
  useEffect(() => { loadDevices(); }, []);
  return (
    <Pushed title="Devices" onBack={back} trailing={!off && <button class="btn quiet sm" onClick={() => setAdding(true)}><Icon name="plus" />Add</button>}>
      <p class="t2 small">Your other phones go here. Each one proves its checks with its own secure chip; remove a lost one and it can never reach your vault again.</p>
      <div class="rows" style={{ marginTop: 14 }}>
        {!devices && <Row chevron={false} title="Loading…" />}
        {devices?.length === 0 && <Row chevron={false} title="Nothing here yet" sub="Add a second device so a lost phone isn't an emergency." />}
        {devices?.map((d) => (
          <div key={d.id}>
            <Row icon="key" tone={d.current ? "mint" : ""} chevron={false}
              title={<>{d.platform || "Device"}{d.current && <span class="pill mint" style={{ marginLeft: 8 }}>This device</span>}</>}
              sub={<>{VIA[d.via] || d.via} · {fmtDate(d.enrolledAt)}{d.lastSeenAt && !d.current ? ` · seen ${fmtAgo(d.lastSeenAt)}` : ""}<br />{proofLabel(d.proof, d.assurance)}</>}
              trail={!d.current && !off && removing !== d.id ? <button class="link" onClick={() => setRemoving(d.id)}>Remove</button> : null} />
            {removing === d.id && (
              <div style={{ padding: "0 16px 14px" }}>
                <Banner tone="danger" icon="trash" title={`Remove ${d.platform || "this device"}?`} text="It can never reach your vault again. If you find it later, set it up again with I already have HumID." />
                <div class="actions row" style={{ paddingTop: 0 }}>
                  <button class="btn ghost" data-back onClick={() => setRemoving(null)}>Keep it</button>
                  <button class="btn danger solid" onClick={() => { setRemoving(null); removeDevice(d); }}><Icon name="fingerprint" />Remove</button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
      {off && <p class="fine" style={{ marginTop: 12 }}>Offline: as of your last sync. Adding or removing needs a connection.</p>}
      {adding && <AddDeviceSheet onClose={() => setAdding(false)} />}
    </Pushed>
  );
}

function AddDeviceSheet({ onClose }) {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const check = myAccountCheck();
  const find = async (c = code) => { if (busy) return; setBusy(true); setReq(await findLink(c)); setBusy(false); };
  const approve = async () => { setBusy(true); if (await approveLink(req)) setDone(true); setBusy(false); };
  return (
    <Sheet onClose={onClose} eyebrow="Add a device" title={done ? "Compare this on the new device" : !req ? "Enter the code from your new device" : "Add this device?"}>
      {done ? (
        <>
          <p class="t2 small">The new device shows a match code before it joins. It must be exactly this. If it isn't, tap "It doesn't match" there.</p>
          <CodeBox code={check} label="Match code" />
          <div class="actions"><button class="btn primary mint block" onClick={onClose}>Done</button></div>
        </>
      ) : !req ? (
        <>
          <p class="t2 small">On the new device: <b>I already have HumID → From another device</b>. Scan its QR code, or type its 12-character code.</p>
          <CodeInput id="link-code" label="Device code" value={code} onInput={setCode} expect="link" onScanned={(c) => find(c)} />
          <div class="actions"><button class="btn primary block" disabled={busy || !twelve(code)} onClick={() => find()}>Find device</button></div>
        </>
      ) : (
        <>
          <p class="small muted">It calls itself <b>“{req.platform}”</b>. The device chose that name; HumID doesn't check it.</p>
          <Banner tone="mint" icon="check" title="Code matches the device's keys" text="Your account key will be sealed to that device only. Your vault server can't open it." />
          <p class="small muted">Only approve a device you're holding right now. Anyone you approve can open your vault.</p>
          <div class="actions">
            <button class="btn primary block" disabled={busy} onClick={approve}><Icon name="fingerprint" />Approve this device</button>
            <button class="btn ghost block" data-back onClick={() => setReq(null)}>Not my device · back</button>
          </div>
        </>
      )}
    </Sheet>
  );
}
