// Security: recovery alerts, devices, two-proof recovery (witnesses, ID anchor,
// seal card), duress protection, helping others, verification station, managing
// the server (approving its admin console's changes), your identity, and the
// exits. This device and the connection are in Settings.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import {
  AssurancePill, proofLabel, Sheet, groupKey, fmtDate, fmtAgo, fmtTime, CodeBox, CardBox, useNow, fmtLeft, CheckinBar,
  QrCode, CodeInput, Scanner, Toggle, ProofMeter, PROOFS, tierText, ChipAccess, CardConfirm, PrintableCard, CAN_PRINT, OfflineBanner,
} from "../ui.jsx";
import * as S from "../core/state.js";
import {
  lockNow, eraseEverything, loadDevices, loadRecovery, loadAlerts, findLink, approveLink, removeDevice, myAccountCheck,
  makeNewCard, removeCard, saveCard, findContact, saveContacts, removeContacts,
  offerToBeContact, findHelpRequest, whoDoIProtect, releasePiece, cancelRecovery,
  readChipFiles, demoPassport, setAnchor, removeAnchor, saveDuress, loadDuress, setWitnessAlert, clearLockdown,
  stationLookup, stationVerify, stationReadChip, markPicking, DURESS_HOLD_MS, readChip,
  loadAdminSummary, findAdminRequest, approveAdminRequest,
  loadCheckin, armCheckin, checkIn, disarmCheckin, checkinOffered,
} from "../core/controller.js";
import { serverHost, VERSION, PLATFORM, DEMO_BUILD, SIM } from "../core/config.js";
import { resetSimulation } from "../core/controller.js";

export const GATE = {
  "ios-keychain-biometry": "Face ID / Touch ID · Secure Enclave policy",
  "android-keystore-biometric": "Android Keystore · Class 3 biometric",
  "macos-keychain-biometry": "Touch ID · Keychain",
  "windows-winbio-fingerprint": "Fingerprint · Windows Biometric Framework",
  "linux-fprintd-keyring": "Fingerprint · fprintd + keyring",
  "demo-no-hardware": "Demo · press and hold",
};
const VIA = { register: "Created HumID", link: "Added from another device", card: "Recovered with older card", contacts: "Recovered with older contacts", quorum: "Recovered with two proofs" };
const METHOD = { card: "recovery card", contacts: "recovery contacts", quorum: "two proofs" };

export function Security() {
  const id = S.identity.value;
  const srv = id?.server;
  const now = useNow();
  const [confirm, setConfirm] = useState(false);
  const sheet = S.sheet.value;
  useEffect(() => { loadDevices(); loadRecovery(); loadAlerts(); loadDuress(); loadAdminSummary(); loadCheckin(); }, []);
  const devices = S.devices.value;
  const rec = S.recovery.value;
  const decoy = S.decoy.value;
  const duress = S.duressSetting.value;
  const dinfo = S.duressInfo.value;
  const protecting = decoy ? [] : S.protecting.value;
  const open = (type, extra = {}) => (S.sheet.value = { type, ...extra });

  return (
    <main class="screen with-tabs">
      <div class="topbar"><div class="grow"><h1>Security</h1><div class="sub"><Icon name="shield" />How your HumID is protected</div></div></div>

      <OfflineBanner />
      <CheckinBar />

      {S.alerts.value.map((a) => (
        <div class="banner bad" style={{ marginBottom: 12 }}>
          <span class="b-ico"><Icon name="alert" /></span>
          <div>
            <strong>Recovery in progress · {METHOD[a.method] || a.method}</strong>
            <span>Requested from {a.platform} {fmtAgo(a.createdAt)}. {a.evidence ? `Proofs so far: ${a.evidence}. ` : ""}{a.releaseAt ? `Opens in ${fmtLeft(a.releaseAt - now)} unless you cancel.` : a.method === "quorum" ? "It needs a second proof before any wait starts." : `${a.approvals ?? 0} contact${a.approvals === 1 ? " has" : "s have"} helped so far.`}</span>
            <button class="btn danger sm" style={{ marginTop: 10 }} onClick={() => open("cancelAlert", { alert: a })}>This wasn't me · cancel</button>
          </div>
        </div>
      ))}

      {dinfo?.lockdown && (
        <div class="banner warn" style={{ marginBottom: 12 }}>
          <span class="b-ico"><Icon name="siren" /></span>
          <div>
            <strong>Locked down after a duress signal</strong>
            <span>Since {fmtAgo(dinfo.since)}. Devices, recovery and closing your HumID can't change until you lift it{dinfo.clearableAt > now ? `, which you can do in ${fmtLeft(dinfo.clearableAt - now)}` : ""}. Recoveries wait twice as long for 14 days.</span>
            <button class="btn quiet sm" style={{ marginTop: 10 }} disabled={dinfo.clearableAt > now} onClick={clearLockdown}><Icon name="fingerprint" />Lift lockdown</button>
          </div>
        </div>
      )}

      {protecting.map((a) => (
        <div class={`banner ${a.kind === "duress" ? "bad" : "warn"}`} style={{ marginBottom: 12 }}>
          <span class="b-ico"><Icon name={a.kind === "duress" ? "siren" : "users"} /></span>
          <div>
            <strong>{a.kind === "duress" ? "Someone you protect signaled duress" : "Someone you protect is recovering their HumID"}</strong>
            <span>{a.kind === "duress"
              ? `${fmtAgo(a.at)}. They may be under pressure. Check on them in a safe way; don't help any recovery you're unsure of.`
              : `From ${a.platform}, ${fmtAgo(a.createdAt)}. Only help if they asked you themselves. Use Help recover to see who it is.`}</span>
          </div>
        </div>
      ))}

      <div class="card">
        <div class="c-head"><h3>Devices</h3><button class="btn quiet sm" onClick={() => open("addDevice")}><Icon name="plus" />Add a device</button></div>
        <div class="rows" style={{ marginTop: 6 }}>
          {!devices && <div class="row"><span class="k">Loading…</span></div>}
          {devices?.map((d) => (
            <div class="row device">
              <span class="d-ico"><Icon name="key" /></span>
              <div style={{ minWidth: 0 }}>
                <div class="d-name">{d.platform || "Device"}{d.current && <span class="pill mint" style={{ marginLeft: 8 }}>This device</span>}</div>
                <div class="d-meta">{VIA[d.via] || d.via} · {fmtDate(d.enrolledAt)}{d.lastSeenAt && !d.current ? ` · seen ${fmtAgo(d.lastSeenAt)}` : ""}</div>
                <div class="d-meta">{proofLabel(d.proof, d.assurance)}</div>
              </div>
              {!d.current && <button class="link" onClick={() => open("removeDevice", { device: d })}>Remove</button>}
            </div>
          ))}
        </div>
        <p class="small muted" style={{ marginTop: 8 }}>Lost a phone? Remove it here. It can't reach your vault after that, and nothing on it opens without your biometric.</p>
      </div>

      <div class="card" id="recovery">
        <div class="c-head"><h3>Recovery</h3>{rec && (rec.ready ? <span class="pill mint"><Icon name="check" />Ready</span> : <span class="pill amber">Needs {2 - Object.values(rec.proofs).filter(Boolean).length} more</span>)}</div>
        <p class="small muted" style={{ marginTop: 4 }}>If you lose every device, any two of these three prove it's you. HumID never holds a key that opens your vault, and one proof alone never does.</p>
        {rec && <ProofMeter have={PROOFS.map((p) => p.id).filter((k) => rec.proofs[k])} />}
        <div class="rows" style={{ marginTop: 8 }}>
          <button class="proof-row linkrow" data-done={rec?.proofs.witness ? "1" : "0"} onClick={() => open("contacts")}>
            <span class="p-ico"><Icon name="users" /></span>
            <span><strong>Witnesses</strong><span>{rec?.contacts.n ? `${rec.contacts.names.join(", ")} · any ${rec.contacts.threshold}${rec.contacts.scheme !== "quorum" ? " · older setup" : ""}` : "People you trust approve with their own biometric"}</span></span>
            <Icon name="chevron" />
          </button>
          <button class="proof-row linkrow" data-done={rec?.proofs.anchor ? "1" : "0"} onClick={() => open("anchor")}>
            <span class="p-ico"><Icon name="passport" /></span>
            <span><strong>ID chip</strong><span>{rec?.anchor.exists ? `Your ${rec.anchor.document}${rec.anchor.country ? ` · ${rec.anchor.country}` : ""}` : rec?.anchor.available ? "Your passport or ID card's chip" : "Not available on this server yet"}</span></span>
            <Icon name="chevron" />
          </button>
          <button class="proof-row linkrow" data-done={rec?.proofs.card ? "1" : "0"} onClick={() => open("cardInfo")}>
            <span class="p-ico"><Icon name="idcard" /></span>
            <span><strong>Seal card</strong><span>{rec?.card.exists ? `Made ${fmtDate(rec.card.createdAt)}${rec.card.scheme !== "quorum" ? " · older single-proof card" : ""}` : "A code you keep offline"}</span></span>
            <Icon name="chevron" />
          </button>
        </div>
        {rec?.legacy && <div class="banner warn" style={{ marginTop: 10 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Upgrade to two-proof recovery</strong><span>You have an older card or contacts that work on their own. Make a new seal card and save your witnesses again to switch.</span></div></div>}
        <div class="split" style={{ marginTop: 12 }}>
          <button class="btn ghost sm" onClick={offerToBeContact}>Be a witness</button>
          <button class="btn ghost sm" onClick={() => open("help")}>Help recover</button>
        </div>
      </div>

      <div class="card">
        <div class="c-head"><h3>Duress protection</h3>{!decoy && duress?.enabled ? <span class="pill mint"><Icon name="check" />On</span> : <span class="pill">Off</span>}</div>
        <p class="small muted" style={{ marginTop: 4 }}>If someone forces you to unlock, a gesture opens HumID showing only documents you chose, while your vault quietly locks itself and recoveries slow down.</p>
        <div class="actions" style={{ marginTop: 10 }}><button class="btn quiet sm" onClick={() => open("duress")}><Icon name="siren" />{!decoy && duress?.enabled ? "Settings" : "Set up"}</button></div>
      </div>

      {checkinOffered() && <CheckinCard onOpen={() => open("checkin")} />}

      {!decoy && S.station.value?.station && (
        <div class="card">
          <div class="c-head"><h3>Verification station</h3><span class="pill mint"><Icon name="station" />Operator</span></div>
          <p class="small muted" style={{ marginTop: 4 }}>Check a person and their ID in person, so their recovery can count their ID chip.</p>
          <div class="actions" style={{ marginTop: 10 }}><button class="btn primary sm" onClick={() => open("station")}><Icon name="scan" />Verify someone</button></div>
        </div>
      )}

      {!decoy && S.adminSummary.value && <ServerCard sum={S.adminSummary.value} onApprove={() => open("admin")} />}

      {SIM && (
        <div class="card">
          <div class="c-head"><h3>Simulation</h3><span class="pill amber">No real server</span></div>
          <p class="small muted" style={{ marginTop: 4 }}>The vault server runs inside this app. The connection is the real post-quantum channel and the biometric checks are real; adding devices, witnesses, ID chips and stations need other people or servers, so they're off here. Nothing leaves this phone.</p>
          <div class="split" style={{ marginTop: 10 }}>
            <button class="btn quiet sm" onClick={() => (S.simShow.value = S.simLog.value[0] || { title: "Simulation", checks: [], empty: true })}><Icon name="shield" />Server checks</button>
            <button class="btn danger sm" onClick={() => open("simReset")}>Reset simulation</button>
          </div>
        </div>
      )}

      <div class="card">
        <h3>Your identity</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Created</span><span class="v">{id ? fmtDate(id.enrolledAt) : ""}</span></div>
          <div class="row"><span class="k">HumID</span><span class="v mono" style={{ fontSize: 12 }}>{srv?.id?.slice(0, 16)}…</span></div>
          <div class="row" style={{ display: "block" }}><div class="k" style={{ marginBottom: 8 }}>Identity commitment</div><div class="kid">{groupKey(id?.commit).slice(0, 8).map((g) => <span>{g}</span>)}</div></div>
          <div class="row"><span class="k">Keys</span><span class="v mono" style={{ fontSize: 12 }}>ML-DSA-87 · ML-KEM-1024 · X25519</span></div>
        </div>
      </div>

      {!decoy && !SIM && !S.adminSummary.value && (
        <button class="option" style={{ marginTop: 14 }} onClick={() => open("admin")}>
          <span class="o-ico"><Icon name="station" /></span>
          <span><strong>Manage this server</strong><span>Approve a change from the HumID server's admin console, or become its administrator.</span></span>
          <Icon name="chevron" />
        </button>
      )}

      <button class="option" style={{ marginTop: 14 }} onClick={() => { S.tab.value = "settings"; window.scrollTo({ top: 0 }); }}>
        <span class="o-ico"><Icon name="settings" /></span>
        <span><strong>This device and connection</strong><span>Now in Settings, with how HumID looks and locks.</span></span>
        <Icon name="chevron" />
      </button>

      <div class="actions" style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 10 }}>
        <button class="btn ghost block" onClick={lockNow}><Icon name="lock" />Lock now</button>
        <button class="btn danger block" onClick={() => setConfirm(true)}><Icon name="trash" />Close HumID &amp; erase vault</button>
      </div>
      <p class="fine" style={{ marginTop: 14 }}>HumID {VERSION}</p>

      {confirm && (
        <Sheet onClose={() => setConfirm(false)} label="Close HumID">
          <div class="eyebrow">This can't be undone</div>
          <h2 style={{ marginTop: 6 }}>Close your HumID?</h2>
          <p class="lede" style={{ marginTop: 10 }}>Every document is erased from the vault server, your identity and recovery options are closed, and the keys on this device are destroyed. Your activity history stays on file, closed.</p>
          <div class="actions">
            <button class="btn danger block" onClick={() => { setConfirm(false); eraseEverything(); }}><Icon name="fingerprint" />Confirm with biometric &amp; erase</button>
            <button class="btn ghost block" onClick={() => setConfirm(false)}>Keep my HumID</button>
          </div>
        </Sheet>
      )}

      {sheet?.type === "addDevice" && <AddDeviceSheet />}
      {sheet?.type === "removeDevice" && <ConfirmSheet label="Remove device" eyebrow="Remove a device" title={`Remove ${sheet.device.platform || "this device"}?`}
        text="It's signed out now and can never reach your vault again. If you find it later, set it up again with I already have HumID."
        action="Remove with biometric" onConfirm={() => removeDevice(sheet.device)} />}
      {sheet?.type === "cancelAlert" && <ConfirmSheet label="Cancel recovery" eyebrow="Recovery in progress" title="Cancel this recovery?"
        text={`A device (${sheet.alert.platform}) asked for your HumID with ${sheet.alert.evidence || `your ${METHOD[sheet.alert.method] || sheet.alert.method}`}. Cancel it and it gets nothing. If it wasn't you, also make a new seal card or choose new witnesses.`}
        action="Cancel with biometric" onConfirm={() => cancelRecovery(sheet.alert)} />}
      {sheet?.type === "cardInfo" && <CardInfoSheet />}
      {sheet?.type === "card" && <CardSheet code={sheet.code} />}
      {sheet?.type === "contacts" && <ContactsSheet />}
      {sheet?.type === "offer" && <OfferSheet code={sheet.code} expiresAt={sheet.expiresAt} />}
      {sheet?.type === "help" && <HelpSheet />}
      {sheet?.type === "anchor" && <AnchorSheet />}
      {sheet?.type === "simReset" && <ConfirmSheet label="Reset simulation" eyebrow="Simulation" title="Start the simulation over?"
        text="The simulated server, your test HumID and every test document on this phone are erased. Then you can set up from the beginning."
        action="Reset" onConfirm={resetSimulation} />}
      {sheet?.type === "duress" && <DuressSheet />}
      {sheet?.type === "checkin" && <CheckinSheet />}
      {sheet?.type === "station" && <StationSheet />}
      {sheet?.type === "admin" && <AdminSheet />}
    </main>
  );
}

const close = () => (S.sheet.value = null);

function ConfirmSheet({ label, eyebrow, title, text, action, onConfirm }) {
  return (
    <Sheet onClose={close} label={label}>
      <div class="eyebrow">{eyebrow}</div>
      <h2 style={{ marginTop: 6 }}>{title}</h2>
      <p class="lede" style={{ marginTop: 10 }}>{text}</p>
      <div class="actions">
        <button class="btn danger block" onClick={onConfirm}><Icon name="fingerprint" />{action}</button>
        <button class="btn ghost block" onClick={close}>Keep it</button>
      </div>
    </Sheet>
  );
}

function CodeField({ id, label, value, onInput, placeholder = "XXXX-XXXX-XXXX" }) {
  return (
    <div class="field">
      <label for={id}>{label}</label>
      <input autocorrect="off" id={id} class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder={placeholder} value={value} onInput={(e) => onInput(e.currentTarget.value)} />
    </div>
  );
}

function AddDeviceSheet() {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const check = myAccountCheck();
  const find = async () => { setBusy(true); setReq(await findLink(code)); setBusy(false); };
  const approve = async () => { setBusy(true); if (await approveLink(req)) setDone(true); setBusy(false); };
  return (
    <Sheet onClose={close} label="Add a device">
      <div class="eyebrow">Add a device</div>
      {done ? (
        <>
          <h2 style={{ marginTop: 6 }}>Compare this on the new device</h2>
          <p class="lede" style={{ marginTop: 10 }}>The new device shows an account check before it joins. It must be exactly this. If it isn't, tap "It doesn't match" there.</p>
          <CodeBox code={check} label="Account check" />
          <div class="actions"><button class="btn primary block" onClick={close}>Done</button></div>
        </>
      ) : !req ? (
        <>
          <h2 style={{ marginTop: 6 }}>Enter the code from your new device</h2>
          <p class="lede" style={{ marginTop: 10 }}>On the new device: <b>I already have HumID → From another device</b>. Scan its QR code or type its 12-character code.</p>
          <CodeInput id="link-code" label="Device code" value={code} onInput={setCode} expect="link" />
          <div class="actions"><button class="btn primary block" disabled={busy || code.replace(/[^0-9a-z]/gi, "").length !== 12} onClick={find}>Find device</button></div>
        </>
      ) : (
        <>
          <h2 style={{ marginTop: 6 }}>Add this device?</h2>
          <p class="small muted" style={{ marginTop: 6 }}>It calls itself <b>“{req.platform}”</b>. The device chose that name; HumID doesn't check it.</p>
          <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="check" /></span><div><strong>Code matches the device's keys</strong><span>Your account key will be sealed to that device only. The server can't open it.</span></div></div>
          <p class="small muted" style={{ marginTop: 12 }}>Only approve a device you're holding right now. Anyone you approve can open your vault.</p>
          <div class="actions">
            <button class="btn primary block" disabled={busy} onClick={approve}><Icon name="fingerprint" />Approve with biometric</button>
            <button class="btn ghost block" onClick={close}>Not my device</button>
          </div>
        </>
      )}
    </Sheet>
  );
}

function CardInfoSheet() {
  const rec = S.recovery.value;
  const has = rec?.card.exists;
  return (
    <Sheet onClose={close} label="Seal card">
      <div class="eyebrow">Seal card · one of three proofs</div>
      <h2 style={{ marginTop: 6 }}>{has ? `Your card was made ${fmtDate(rec.card.createdAt)}` : "Make a seal card"}</h2>
      <p class="lede" style={{ marginTop: 10 }}>A code you write down or print and keep away from your ID. With your witnesses or your ID chip it brings your vault back on a new phone. HumID stores only a piece locked by the card, which it can't open.</p>
      {rec?.card.exists && rec.card.scheme !== "quorum" && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>This is an older card</strong><span>It works on its own after 72 hours. A new seal card replaces it and always needs a second proof.</span></div></div>}
      <div class="actions">
        <button class="btn primary block" onClick={makeNewCard}><Icon name="fingerprint" />{has ? "Make a new card (old one stops working)" : "Make my card"}</button>
        {has && <button class="btn danger block" onClick={removeCard}>Remove my card</button>}
      </div>
    </Sheet>
  );
}

function CardSheet({ code }) {
  const [ok, setOk] = useState(false);
  return (
    <Sheet onClose={close} label="Your recovery card">
      <div class="eyebrow">Your new seal card</div>
      <h2 style={{ marginTop: 6 }}>Write this down</h2>
      <p class="lede" style={{ marginTop: 10 }}>This is the only time HumID shows it. Your old card, if you had one, no longer works.</p>
      <CardBox code={code} />
      <div class="split" style={{ marginTop: 12 }}>
        {CAN_PRINT && <button class="btn quiet sm" onClick={() => window.print()}><Icon name="file" />Print</button>}
        <button class="btn quiet sm" onClick={() => saveCard(code)}><Icon name="download" />Save</button>
      </div>
      <CardConfirm code={code} onChange={setOk} />
      <PrintableCard code={code} />
      <div class="actions"><button class="btn secure block" disabled={!ok} onClick={close}>I've stored it safely</button></div>
    </Sheet>
  );
}

function ContactsSheet() {
  const rec = S.recovery.value;
  const [me, setMe] = useState("");
  const [rows, setRows] = useState([{ name: "", code: "", offer: null }, { name: "", code: "", offer: null }, { name: "", code: "", offer: null }]);
  const [scanning, setScanning] = useState(null);
  const set = (i, patch) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const check = async (i) => { const o = await findContact(rows[i].code); set(i, { offer: o }); };
  const ready = rows.filter((r) => r.offer && r.name.trim());
  const t = ready.length >= 2 ? Math.floor(ready.length / 2) + 1 : 2;
  return (
    <Sheet onClose={close} label="Witnesses">
      <div class="eyebrow">Witnesses · one of three proofs</div>
      <h2 style={{ marginTop: 6 }}>Choose people who know you</h2>
      <p class="lede" style={{ marginTop: 10 }}>When a majority of them approve, each with their own live biometric, that counts as one proof it's you. They never learn your key, and even all of them together can't open your vault without a second proof.</p>
      {rec?.contacts.n > 0 && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Replaces {rec.contacts.names.join(", ")}</strong><span>Their pieces stop working when you save new witnesses.</span></div></div>}
      <div class="field">
        <label for="owner-name">Your name, as they know you</label>
        <input autocorrect="off" spellcheck={false} autocomplete="off" id="owner-name" value={me} maxLength={40} placeholder="e.g. Parker" onInput={(e) => setMe(e.currentTarget.value)} />
      </div>
      {rows.map((r, i) => (
        <div class="contact-row">
          <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label={`Witness ${i + 1} name`} placeholder={`Witness ${i + 1} name`} value={r.name} maxLength={40} onInput={(e) => set(i, { name: e.currentTarget.value })} />
          <input autocorrect="off" autocomplete="off" aria-label={`Contact ${i + 1} code`} class="mono up" placeholder="XXXX-XXXX-XXXX" value={r.code} autocapitalize="characters" spellcheck={false}
            onInput={(e) => set(i, { code: e.currentTarget.value, offer: null })} />
          {r.offer ? <span class="pill mint"><Icon name="check" />Verified</span>
            : r.code.replace(/[^0-9a-z]/gi, "").length === 12 ? <button class="btn quiet sm" onClick={() => check(i)}>Check</button>
            : <button class="btn quiet sm" aria-label={`Scan witness ${i + 1}'s code`} onClick={() => setScanning(i)}><Icon name="scan" /></button>}
        </div>
      ))}
      {scanning != null && <Scanner expect="contact" onCancel={() => setScanning(null)} onCode={(c) => { set(scanning, { code: c.code, offer: null }); setScanning(null); }} />}
      {rows.length < 5 && <button class="link" onClick={() => setRows([...rows, { name: "", code: "", offer: null }])}>+ Add another witness</button>}
      <p class="small muted" style={{ marginTop: 6 }}>Each witness gets their code from HumID → Security → Be a witness. Tap a code box's scan button to scan theirs.</p>
      <div class="actions">
        <button class="btn primary block" disabled={ready.length < 2 || !me.trim()} onClick={() => saveContacts(ready.map((r) => ({ code: r.code, name: r.name, offer: r.offer })), me.trim())}>
          <Icon name="fingerprint" />Save {ready.length || ""} witnesses · any {t} count as a proof
        </button>
        {rec?.contacts.n > 0 && <button class="btn danger block" onClick={removeContacts}>Remove all witnesses</button>}
      </div>
    </Sheet>
  );
}

function OfferSheet({ code, expiresAt }) {
  const now = useNow();
  return (
    <Sheet onClose={close} label="Be someone's witness">
      <div class="eyebrow">Be someone's witness</div>
      <h2 style={{ marginTop: 6 }}>Give them this code</h2>
      <p class="lede" style={{ marginTop: 10 }}>They scan or type it when choosing witnesses. It lets them seal a piece to you. On your own, you can never open their vault.</p>
      <CodeBox code={code} label="Witness code" />
      <QrCode kind="contact" code={code} expiresAt={expiresAt} />
      <p class="fine" style={{ textAlign: "center" }}>{expiresAt > now ? `Expires in ${fmtLeft(expiresAt - now)}` : "Expired. Close and make a new one."}</p>
      <div class="actions"><button class="btn ghost block" onClick={close}>Done</button></div>
    </Sheet>
  );
}

function HelpSheet() {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [people, setPeople] = useState(null);
  const [pick, setPick] = useState(null);
  const [done, setDone] = useState(null);
  const find = async () => setReq(await findHelpRequest(code));
  const reveal = async () => { const p = await whoDoIProtect(); if (p) { setPeople(p); if (p.length === 1) setPick(p[0]); } };
  const release = async () => { const r = await releasePiece(req, pick); if (r) setDone(r); };
  return (
    <Sheet onClose={close} label="Help someone recover">
      <div class="eyebrow">Help someone recover</div>
      {!req && (
        <>
          <h2 style={{ marginTop: 6 }}>Enter the code they sent you</h2>
          <p class="lede" style={{ marginTop: 10 }}>Someone who chose you as a witness lost their devices. Their new phone shows a code and a QR code.</p>
          <CodeInput id="help-code" label="Recovery code" value={code} onInput={setCode} expect="recover" />
          <div class="actions"><button class="btn primary block" disabled={code.replace(/[^0-9a-z]/gi, "").length !== 12} onClick={find}>Find request</button></div>
        </>
      )}
      {req && !people && (
        <>
          <h2 style={{ marginTop: 6 }}>A {req.platform} is asking for help</h2>
          <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="check" /></span><div><strong>Code matches that device's keys</strong><span>Requested {fmtAgo(req.createdAt)}.</span></div></div>
          <p class="small muted" style={{ marginTop: 12 }}>Next, confirm with your biometric to see whose pieces you hold.</p>
          <div class="actions"><button class="btn primary block" onClick={reveal}><Icon name="fingerprint" />Show who I protect</button></div>
        </>
      )}
      {people && !done && (
        <>
          <h2 style={{ marginTop: 6 }}>Who is asking?</h2>
          {people.length === 0 && <p class="lede" style={{ marginTop: 10 }}>You aren't anyone's witness yet.</p>}
          <div class="options" style={{ marginTop: 12 }}>
            {people.map((p) => (
              <button class="option" aria-pressed={pick?.owner === p.owner} onClick={() => setPick(p)}>
                <span class="o-ico"><Icon name="user" /></span>
                <span><strong>{p.label}</strong><span>Chose you {fmtDate(p.since)}</span></span>
                {pick?.owner === p.owner ? <Icon name="check" /> : <span />}
              </button>
            ))}
          </div>
          {pick && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="alert" /></span><div><strong>Call {pick.label} first</strong><span>Only help if they asked you themselves. Someone pretending to be them is how recovery gets abused.</span></div></div>}
          <div class="actions"><button class="btn primary block" disabled={!pick} onClick={release}><Icon name="fingerprint" />Release my piece to that device</button></div>
        </>
      )}
      {done && (
        <>
          <h2 style={{ marginTop: 6 }}>Thanks. Your piece was sent</h2>
          <p class="lede" style={{ marginTop: 10 }}>{done.releaseAt
            ? `Enough contacts have helped. ${pick.label}'s vault opens on their new device in about ${fmtLeft(done.releaseAt - Date.now())}, unless they cancel it from a device they still have.`
            : done.kinds ? `${done.approvals} of ${done.threshold} witnesses have approved. Their recovery also needs a second proof.` : `${done.approvals} of ${done.threshold} contacts have helped so far.`}</p>
          <div class="actions"><button class="btn secure block" onClick={close}>Done</button></div>
        </>
      )}
    </Sheet>
  );
}

/* ---------------- identity anchor ---------------- */

function AnchorSheet() {
  const rec = S.recovery.value;
  const a = rec?.anchor;
  const [chip, setChip] = useState(null);
  const [name, setName] = useState("Demo Person");
  const [nfcOpen, setNfcOpen] = useState(false);
  const [access, setAccess] = useState(null);
  const nfc = S.nfc.value;
  const read = async () => { const r = await readChip(access, { purpose: "anchor" }); if (r) { setChip(r); setNfcOpen(false); } };
  const files = useRef(null);
  const pick = () => { markPicking(); files.current.click(); };
  const onFiles = async (e) => { const c = await readChipFiles(e.currentTarget.files); e.currentTarget.value = ""; if (c) setChip(c); };
  return (
    <Sheet onClose={close} label="ID chip">
      <div class="eyebrow">ID chip · one of three proofs</div>
      <h2 style={{ marginTop: 6 }}>{a?.exists ? `Anchored to your ${a.document}` : "Anchor HumID to your passport or ID"}</h2>
      <p class="lede" style={{ marginTop: 10 }}>The chip in your passport or ID card is signed by the country that issued it. HumID checks that signature and keeps only a keyed fingerprint of the details that stay the same when you renew. Later, your chip proves it's you: in person at a HumID station, or live on your phone.</p>
      {!a?.exists && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>The one proof that isn't anonymous</strong><span>Someone holding this vault's secret and your passport details could confirm you have a HumID. Witnesses and your seal card don't reveal who you are. Skip this if anonymity matters more than convenience.</span></div></div>}
      {!a?.available && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="globe" /></span><div><strong>Not available on this server yet</strong><span>Its operator hasn't added the countries' signing certificates. Use witnesses and a seal card for now.</span></div></div>}
      {a?.exists && <div class="card" style={{ marginTop: 12 }}><div class="row"><span class="k">Document</span><span class="v">{a.document}{a.country ? ` · ${a.country}` : ""}</span></div><div class="row"><span class="k">Anchored</span><span class="v">{fmtDate(a.createdAt)}</span></div></div>}
      {a?.available && (
        <>
          <input ref={files} type="file" multiple hidden accept=".json,.bin,.dat,application/json,application/octet-stream" onChange={onFiles} />
          {!chip && nfcOpen && (
            <>
              <ChipAccess onChange={setAccess} />
              <div class="actions">
                <button class="btn primary block" disabled={!access} onClick={read}><Icon name="passport" />{nfc?.kind === "reader" ? "Read with the card reader" : "Hold to my phone and read"}</button>
                <button class="btn ghost block" onClick={() => setNfcOpen(false)}>Back</button>
              </div>
            </>
          )}
          {!chip ? (!nfcOpen && (
            <div class="actions">
              <button class="btn primary block" disabled={!nfc?.available} onClick={() => setNfcOpen(true)}><Icon name="passport" />{nfc?.kind === "reader" ? "Read the chip with the card reader" : "Read the chip with this phone"}</button>
              {!nfc?.available && nfc?.reason && <p class="small muted">{nfc.reason}</p>}
              <button class="btn ghost block" onClick={pick}><Icon name="file" />Load chip data from a file</button>
              {DEMO_BUILD && (
                <div class="field" style={{ marginTop: 0 }}>
                  <label for="demo-holder">Development build: demo passport holder</label>
                  <input autocorrect="off" spellcheck={false} autocomplete="off" id="demo-holder" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                  <button class="btn ghost block" style={{ marginTop: 8 }} onClick={async () => setChip(await demoPassport(name))}><Icon name="passport" />Use a demo passport</button>
                </div>
              )}
            </div>
          )) : (
            <>
              <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="check" /></span><div><strong>{chip.access ? `Chip read · ${chip.access}` : `Chip data loaded${chip.demo ? " (demo)" : ""}`}</strong><span>The server checks its country signature next. {chip.dg15 ? "This chip can also prove it's present, live." : "This chip can't prove it's present live, so recovering with it will need a HumID station."}</span></div></div>
              <div class="actions">
                <button class="btn primary block" onClick={() => setAnchor(chip)}><Icon name="fingerprint" />{a?.exists ? "Replace with this ID" : "Anchor with biometric"}</button>
                <button class="btn ghost block" onClick={() => setChip(null)}>Choose another</button>
              </div>
            </>
          )}
        </>
      )}
      {a?.exists && <div class="actions"><button class="btn danger block" onClick={removeAnchor}>Remove ID anchor</button></div>}
    </Sheet>
  );
}

/* ---------------- duress ---------------- */

const GESTURES = [
  { id: "hold", title: "Hold Unlock a little longer", desc: `Press and hold the Unlock button for about ${Math.round(DURESS_HOLD_MS / 1000)} seconds, then let go.` },
  { id: "taps", title: "Tap the mark three times", desc: "Tap the HumID mark three times quickly instead of pressing Unlock." },
];

function DuressSheet() {
  const id = S.identity.value;
  const decoy = S.decoy.value;
  const d = decoy ? { enabled: false, gesture: "hold" } : S.duressSetting.value || { enabled: false, gesture: "hold" };
  const [enabled, setEnabled] = useState(!!d.enabled);
  const [gesture, setGesture] = useState(d.gesture || "hold");
  const info = S.duressInfo.value;
  const decoys = decoy ? 0 : S.items.value.filter((i) => i.decoy).length;
  const save = () => saveDuress({ enabled, gesture });
  return (
    <Sheet onClose={close} label="Duress protection">
      <div class="eyebrow">Duress protection</div>
      <h2 style={{ marginTop: 6 }}>If you're ever forced to unlock</h2>
      <p class="lede" style={{ marginTop: 10 }}>Unlock with your duress gesture and HumID opens normally, but shows only the documents you marked for it. Meanwhile your vault server locks devices, recovery and closing your account, and any recovery waits twice as long. Nothing on screen changes.</p>
      <div class="card" style={{ marginTop: 14 }}>
        <Toggle label="Duress gesture" hint="Set on this device. Each device has its own." checked={enabled} onChange={setEnabled} />
        {enabled && (
          <div class="options" style={{ marginTop: 10 }}>
            {GESTURES.map((g) => (
              <button class="option" aria-pressed={gesture === g.id} onClick={() => setGesture(g.id)}>
                <span class="o-ico"><Icon name={g.id === "hold" ? "fingerprint" : "sparkle"} /></span>
                <span><strong>{g.title}</strong><span>{g.desc}</span></span>
                {gesture === g.id ? <Icon name="check" /> : <span />}
              </button>
            ))}
          </div>
        )}
        <div class="row"><span class="k">Decoy documents</span><span class="v">{decoys ? `${decoys} marked` : "None yet: mark some in each document's details"}</span></div>
        {!decoy && <Toggle label="Tell my witnesses" hint="They see a duress alert next time they open HumID. Only turn this on if they'd know what to do." checked={!!info?.alert} onChange={setWitnessAlert} />}
      </div>
      <p class="small muted" style={{ marginTop: 10 }}>Your biometric still unlocks either way, so no one can tell from watching. HumID records the signal in your ledger, where only a normal unlock shows it.</p>
      <div class="actions"><button class="btn primary block" onClick={() => { save(); close(); }}>Save</button></div>
    </Sheet>
  );
}

/* ---------------- Check-in (docs/CHECKIN.md) ---------------- */

const H = 3_600_000, MIN = 60_000;
const hours = (ms) => `${ms / H} h`;
const graceLabel = (ms) => (ms ? `${ms / MIN} min` : "None");

/** One choice out of a few, as a row of buttons (as in Settings). */
function Seg({ id, label, hint, value, options, onPick }) {
  return (
    <div class="setting">
      <div class="s-label" id={`${id}-label`}><strong>{label}</strong>{hint && <span>{hint}</span>}</div>
      <div class="seg" role="radiogroup" aria-labelledby={`${id}-label`} data-n={options.length}>
        {options.map(([v, text]) => <button type="button" role="radio" aria-checked={value === v} onClick={() => onPick(v)}>{text}</button>)}
      </div>
    </div>
  );
}

function CheckinCard({ onOpen }) {
  const st = S.checkin.value;
  useNow(30_000);
  if (!st) return null;
  const on = st.state === "armed" || st.state === "locked";
  return (
    <div class="card" id="checkin">
      <div class="c-head">
        <h3>Check-in</h3>
        {st.state === "locked" ? <span class="pill danger"><Icon name="alert" />Missed</span> : on ? <span class="pill mint"><Icon name="check" />On</span> : <span class="pill">Off</span>}
      </div>
      <p class="small muted" style={{ marginTop: 4 }}>
        {on
          ? `Check in by ${fmtTime(st.deadline)}, then every ${hours(st.windowMs)}. Miss one and your vault locks; ${st.graceMs ? `${st.graceMs / MIN} minutes later` : "at once"} it's erased for good.`
          : "Going somewhere you could be detained or lose your phone? Turn this on and check in every hour or two, or your vault is erased for good."}
      </p>
      {st.state === "erased" && (
        <div class="banner bad" style={{ marginTop: 10 }}>
          <span class="b-ico"><Icon name="trash" /></span>
          <div><strong>Your vault was erased by Check-in</strong><span>{fmtAgo(st.erasedAt)}. Its documents can't be opened again. Your HumID still works, and anything sealed since is here.</span></div>
        </div>
      )}
      <div class="actions" style={{ marginTop: 10 }}>
        {on && <button class="btn primary sm" onClick={() => checkIn()}><Icon name="fingerprint" />Check in</button>}
        <button class="btn quiet sm" onClick={onOpen}><Icon name="clock" />{on ? "Settings" : "Set up"}</button>
      </div>
    </div>
  );
}

function CheckinSheet() {
  const st = S.checkin.value || { state: "off" };
  const pol = S.server.value?.policy?.checkin || { windowsH: [1, 2, 4, 8, 24], graceMin: [0, 15, 30, 60] };
  const on = st.state === "armed" || st.state === "locked";
  const windows = pol.windowsH.map((h) => h * H);
  const graces = pol.graceMin.map((m) => m * MIN);
  const now = useNow(1000);
  const [win, setWin] = useState(on ? st.windowMs : 2 * H);
  const [max, setMax] = useState(on ? st.maxWindowMs : 8 * H);
  const [grace, setGrace] = useState(on ? st.graceMs : 15 * MIN);
  const [next, setNext] = useState(on ? st.windowMs : 2 * H);
  const [understood, setUnderstood] = useState(on);
  const [unsplit, setUnsplit] = useState(null);
  const [busy, setBusy] = useState(false);
  const decoy = S.decoy.value;
  const decoys = decoy ? 0 : S.items.value.filter((i) => i.decoy).length;
  // sealed before split keys: their second key isn't on the server, so an erase couldn't be final
  const older = unsplit || (decoy ? [] : S.items.value.filter((i) => !i.split).map((i) => ({ id: i.id, name: i.name })));
  const changed = !on || win !== st.windowMs || Math.max(max, win) !== st.maxWindowMs || grace !== st.graceMs;
  const run = async (fn) => { setBusy(true); try { return await fn(); } finally { setBusy(false); } };
  const arm = () => run(async () => {
    const r = await armCheckin({ windowMs: win, maxWindowMs: Math.max(max, win), graceMs: grace });
    if (r.unsplit) setUnsplit(r.unsplit);
    else if (r.ok) close();
  });
  return (
    <Sheet onClose={close} label="Check-in">
      <div class="eyebrow">Check-in</div>
      <h2 style={{ marginTop: 6 }}>{on ? (st.state === "locked" ? "You missed a check-in" : `Check in by ${fmtTime(st.deadline)}`) : "If you can't check in, erase your vault"}</h2>
      <p class="lede" style={{ marginTop: 10 }}>
        {on
          ? st.state === "locked"
            ? `Your vault opens nothing until you check in. If you don't, it's erased for good in ${fmtLeft(st.erasesAt - now)}.`
            : `${fmtLeft(st.deadline - now)} left. Miss it and your vault locks; ${st.graceMs ? `${st.graceMs / MIN} minutes later` : "at once"} it's erased for good.`
          : "Turn this on before you go somewhere you could be detained or lose your phone. Check in with your face or fingerprint before each deadline. Miss one and your vault locks; when the grace time runs out, your vault server destroys the keys to your documents, and they're gone for good."}
      </p>

      {on && (
        <div class="card" style={{ marginTop: 14 }}>
          <Seg id="ck-next" label="Next window" hint="Need longer, like overnight? Pick it as you check in." value={next}
            options={windows.filter((v) => v <= st.maxWindowMs).map((v) => [v, hours(v)])} onPick={setNext} />
          <div class="actions" style={{ marginTop: 10 }}>
            <button class="btn primary block" disabled={busy} onClick={() => run(async () => { if (await checkIn(next === st.windowMs ? undefined : next)) close(); })}><Icon name="fingerprint" />Check in now</button>
          </div>
        </div>
      )}

      <div class="card" style={{ marginTop: 14 }}>
        <Seg id="ck-win" label="Check in every" value={win} options={windows.map((v) => [v, hours(v)])} onPick={(v) => { setWin(v); if (max < v) setMax(v); }} />
        <Seg id="ck-max" label="Longest single window" hint="For the night: when you check in, you can choose a longer window up to this." value={Math.max(max, win)}
          options={windows.filter((v) => v >= win).map((v) => [v, hours(v)])} onPick={setMax} />
        <Seg id="ck-grace" label="Grace after a missed check-in" hint="Your vault is locked meanwhile; checking in opens it again." value={grace}
          options={graces.map((v) => [v, graceLabel(v)])} onPick={setGrace} />
      </div>

      <div class="banner warn" style={{ marginTop: 12 }}>
        <span class="b-ico"><Icon name="alert" /></span>
        <div>
          <strong>Nobody can undo an erase</strong>
          <span>Not you, not your witnesses, not HumID. HumID can't remind you while it's closed yet, so set an alarm for each check-in.</span>
        </div>
      </div>
      <p class="small muted" style={{ marginTop: 10 }}>
        {decoys ? `The ${decoys} document${decoys === 1 ? "" : "s"} you marked for the decoy view stay${decoys === 1 ? "s" : ""}, so a forced unlock still looks normal. ` : "Documents you mark for the decoy view stay, so a forced unlock still looks normal. "}
        While Check-in is on, unlocking with your duress gesture erases your vault at once, and nothing is kept on this phone, so HumID won't open offline.
      </p>

      {older.length > 0 && (
        <div class="banner bad" style={{ marginTop: 12 }}>
          <span class="b-ico"><Icon name="info" /></span>
          <div>
            <strong>{older.length === 1 ? "One document needs sealing again first" : `${older.length} documents need sealing again first`}</strong>
            <span>{older.slice(0, 4).map((o) => o.name).join(", ")}{older.length > 4 ? ` and ${older.length - 4} more` : ""}: sealed before split keys, so Check-in couldn't erase {older.length === 1 ? "it" : "them"} for good. Save a copy, add it again, then delete the old one, or just delete it.</span>
          </div>
        </div>
      )}

      {!on && <Toggle label="I understand my documents can be erased for good" checked={understood} onChange={setUnderstood} />}
      <div class="actions">
        {(!on || changed) && (
          <button class={`btn ${on ? "quiet" : "primary"} block`} disabled={!understood || busy || older.length > 0} onClick={arm}>
            <Icon name="fingerprint" />{on ? "Save settings and check in" : "Turn on Check-in"}
          </button>
        )}
        {on && <button class="btn ghost block" disabled={busy} onClick={() => run(disarmCheckin)}>Turn off Check-in</button>}
      </div>
    </Sheet>
  );
}

/* ---------------- verification station (operators) ---------------- */

function StationSheet() {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [chip, setChip] = useState(null);
  const [access, setAccess] = useState(null);
  const nfc = S.nfc.value;
  const [checks, setChecks] = useState({ document: false, face: false, present: false });
  const [done, setDone] = useState(null);
  const [name, setName] = useState("Demo Person");
  const all = checks.document && checks.face && checks.present;
  const tick = (k) => (e) => setChecks({ ...checks, [k]: e.currentTarget.checked });
  return (
    <Sheet onClose={close} label="Verify someone">
      <div class="eyebrow">Verification station</div>
      {!req && (
        <>
          <h2 style={{ marginTop: 6 }}>Scan their recovery code</h2>
          <p class="lede" style={{ marginTop: 10 }}>Their new phone shows it under Prove it's me.</p>
          <CodeInput id="station-code" label="Recovery code" value={code} onInput={setCode} expect="recover" />
          <div class="actions"><button class="btn primary block" disabled={code.replace(/[^0-9a-z]/gi, "").length !== 12} onClick={async () => setReq(await stationLookup(code))}>Find request</button></div>
        </>
      )}
      {req && !done && (
        <>
          <h2 style={{ marginTop: 6 }}>A {req.platform} is recovering</h2>
          <p class="small muted" style={{ marginTop: 6 }}>Started {fmtAgo(req.createdAt)}. You won't see whose HumID it is.</p>
          {!chip ? (
            <div class="actions">
              {nfc?.available && (
                <>
                  <ChipAccess onChange={setAccess} title="Details from their document" />
                  <button class="btn primary block" disabled={!access} onClick={async () => { const r = await stationReadChip(req.code, { access }); if (r) setChip(r); }}><Icon name="passport" />{nfc.kind === "reader" ? "Read with the card reader" : "Hold to this phone and read"}</button>
                </>
              )}
              {!nfc?.available && <p class="small muted">{nfc?.reason || "This device can't read ID chips."}</p>}
              {DEMO_BUILD && (
                <div class="field" style={{ marginTop: 0 }}>
                  <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="Demo passport holder" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                  <button class="btn ghost block" style={{ marginTop: 8 }} onClick={async () => setChip(await stationReadChip(req.code, { demo: name }))}><Icon name="passport" />Use a demo passport</button>
                </div>
              )}
            </div>
          ) : (
            <>
              <div class="checklist">
                <label class="check"><input type="checkbox" checked={checks.document} onChange={tick("document")} /><span>I've examined the physical document and it looks genuine and unaltered</span></label>
                <label class="check"><input type="checkbox" checked={checks.face} onChange={tick("face")} /><span>The person's face matches the document's photo</span></label>
                <label class="check"><input type="checkbox" checked={checks.present} onChange={tick("present")} /><span>The person is here with me, and is asking for this themselves</span></label>
              </div>
              <div class="actions"><button class="btn primary block" disabled={!all} onClick={async () => { const r = await stationVerify(req.code, chip, checks); if (r) setDone(r); }}><Icon name="fingerprint" />Vouch with my biometric</button></div>
            </>
          )}
        </>
      )}
      {done && (
        <>
          <h2 style={{ marginTop: 6 }}>Verified</h2>
          <p class="lede" style={{ marginTop: 10 }}>{done.releaseAt ? `Their vault opens on their new phone in about ${fmtLeft(done.releaseAt - Date.now())}, unless one of their devices vetoes it.` : "Their ID counts now. They still need one more proof: their witnesses or their seal card."}</p>
          <p class="small muted" style={{ marginTop: 6 }}>Recorded in your ledger and theirs.</p>
          <div class="actions"><button class="btn secure block" onClick={close}>Done</button></div>
        </>
      )}
    </Sheet>
  );
}

/* ---------------- managing the server (docs/ADMIN.md) ---------------- */

const HEALTH = { ok: ["mint", "Running normally"], warn: ["amber", "Needs a look"], bad: ["danger", "Needs attention"] };

function ServerCard({ sum, onApprove }) {
  const [tone, label] = HEALTH[sum.health] || HEALTH.warn;
  const updates = [sum.updates?.humid && `HumID Server ${sum.updates.humid}`, sum.updates?.security ? `${sum.updates.security} Windows security update${sum.updates.security === 1 ? "" : "s"}` : sum.updates?.os ? `${sum.updates.os} Windows update${sum.updates.os === 1 ? "" : "s"}` : null].filter(Boolean);
  return (
    <div class="card">
      <div class="c-head"><h3>This server</h3><span class={`pill ${tone}`}>{label}</span></div>
      <p class="small muted" style={{ marginTop: 4 }}>You're an administrator of {serverHost(S.identity.value?.server?.url)}{sum.version ? ` (version ${sum.version})` : ""}. Changes from its admin console wait for your approval here.</p>
      {sum.alerts?.length > 0 && <ul class="small" style={{ margin: "8px 0 0", paddingLeft: 18 }}>{sum.alerts.map((a) => <li>{a}</li>)}</ul>}
      {updates.length > 0 && <p class="small" style={{ marginTop: 8 }}>Waiting to install: {updates.join(" and ")}. Start it from the console on the server.</p>}
      <div class="actions" style={{ marginTop: 10 }}><button class="btn primary sm" onClick={onApprove}><Icon name="scan" />Approve a change</button></div>
    </div>
  );
}

function AdminSheet() {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(null);
  const now = useNow();
  const find = async () => { setBusy(true); setReq(await findAdminRequest(code)); setBusy(false); };
  const approve = async () => { setBusy(true); const r = await approveAdminRequest(req); if (r) setDone(r); setBusy(false); };
  const enrol = req?.kind === "enrol";
  return (
    <Sheet onClose={close} label="Manage this server">
      <div class="eyebrow">Manage this server</div>
      {done ? (
        enrol ? (
          <>
            <h2 style={{ marginTop: 6 }}>Compare this with the console</h2>
            <p class="lede" style={{ marginTop: 10 }}>The admin console now shows an admin check. It must be exactly this. If it is, choose <b>They match</b> there; if not, choose <b>They don't match</b>.</p>
            <CodeBox code={done.check} label="Admin check" />
            <div class="actions"><button class="btn primary block" onClick={close}>Done</button></div>
          </>
        ) : (
          <>
            <h2 style={{ marginTop: 6 }}>Approved</h2>
            <p class="lede" style={{ marginTop: 10 }}>The console checks your approval itself, then starts: {req.title}. You'll see its progress there.</p>
            <div class="actions"><button class="btn secure block" onClick={close}>Done</button></div>
          </>
        )
      ) : !req ? (
        <>
          <h2 style={{ marginTop: 6 }}>Enter the code from the admin console</h2>
          <p class="lede" style={{ marginTop: 10 }}>On the server, the console shows a QR code and a 12-character code for each change. Scan it or type it.</p>
          <CodeInput id="admin-code" label="Console code" value={code} onInput={setCode} expect="admin" />
          <div class="actions"><button class="btn primary block" disabled={busy || code.replace(/[^0-9a-z]/gi, "").length !== 12} onClick={find}>Look it up</button></div>
        </>
      ) : (
        <>
          <h2 style={{ marginTop: 6 }}>{enrol ? "Become an administrator of this server?" : req.title}</h2>
          {req.lines?.length > 0 && <ul class="small muted" style={{ margin: "8px 0 0", paddingLeft: 18 }}>{req.lines.map((l) => <li>{l}</li>)}</ul>}
          <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="shield" /></span><div><strong>Check {req.check}</strong><span>The console must show the same four-and-four. Your approval covers exactly this, for {fmtLeft(req.expiresAt - now)} more.</span></div></div>
          <p class="small muted" style={{ marginTop: 12 }}>{enrol ? "You'll then be able to approve updates, restarts and backups on this server. Only do this for a server you run." : "Only approve a change you started on the console yourself."}</p>
          <div class="actions">
            <button class="btn primary block" disabled={busy || req.expiresAt <= now} onClick={approve}><Icon name="fingerprint" />Approve with biometric</button>
            <button class="btn ghost block" onClick={close}>Not mine</button>
          </div>
        </>
      )}
    </Sheet>
  );
}
