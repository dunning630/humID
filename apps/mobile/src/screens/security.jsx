// Security: recovery alerts, devices, two-proof recovery (witnesses, ID anchor,
// seal card), duress protection, helping others, verification station, this
// device, connection, and the exits.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import {
  AssurancePill, proofLabel, Sheet, groupKey, fmtDate, fmtAgo, CodeBox, CardBox, useNow, fmtLeft,
  QrCode, CodeInput, Scanner, Toggle, ProofMeter, PROOFS, tierText, ChipAccess,
} from "../ui.jsx";
import * as S from "../core/state.js";
import {
  lockNow, eraseEverything, loadDevices, loadRecovery, loadAlerts, findLink, approveLink, removeDevice,
  makeNewCard, removeCard, saveCard, copyCard, findContact, saveContacts, removeContacts,
  offerToBeContact, findHelpRequest, whoDoIProtect, releasePiece, cancelRecovery,
  readChipFiles, demoPassport, setAnchor, removeAnchor, saveDuress, loadDuress, setWitnessAlert, clearLockdown,
  stationLookup, stationVerify, markPicking, DURESS_HOLD_MS, readChip,
} from "../core/controller.js";
import { serverHost, VERSION, PLATFORM, DEMO_BUILD } from "../core/config.js";

const GATE = {
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
  const sess = S.session.value;
  const srv = id?.server;
  const now = useNow();
  const [confirm, setConfirm] = useState(false);
  const sheet = S.sheet.value;
  useEffect(() => { loadDevices(); loadRecovery(); loadAlerts(); loadDuress(); }, []);
  const devices = S.devices.value;
  const rec = S.recovery.value;
  const decoy = S.decoy.value;
  const duress = id?.duress;
  const dinfo = S.duressInfo.value;
  const protecting = decoy ? [] : S.protecting.value;
  const open = (type, extra = {}) => (S.sheet.value = { type, ...extra });

  return (
    <main class="screen with-tabs">
      <div class="topbar"><div class="grow"><h1>Security</h1><div class="sub"><Icon name="shield" />How your HumID is protected</div></div></div>

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

      <div class="card">
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

      {!decoy && S.station.value?.station && (
        <div class="card">
          <div class="c-head"><h3>Verification station</h3><span class="pill mint"><Icon name="station" />Operator</span></div>
          <p class="small muted" style={{ marginTop: 4 }}>Check a person and their ID in person, so their recovery can count their ID chip.</p>
          <div class="actions" style={{ marginTop: 10 }}><button class="btn primary sm" onClick={() => open("station")}><Icon name="scan" />Verify someone</button></div>
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

      <div class="card">
        <h3>This device</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Protection</span><span class="v"><AssurancePill assurance={id?.assurance} /></span></div>
          <div class="row"><span class="k">Gate</span><span class="v">{GATE[id?.method] || id?.method}</span></div>
          <div class="row"><span class="k">Proof</span><span class="v">{proofLabel(id?.proof, id?.assurance)}</span></div>
          <div class="row"><span class="k">PIN or password</span><span class="v"><span class="pill mint"><Icon name="check" />Never accepted</span></span></div>
          <div class="row"><span class="k">Device</span><span class="v">{PLATFORM}</span></div>
        </div>
      </div>

      <div class="card">
        <h3>Connection</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Vault server</span><span class="v">{serverHost(srv?.url)}</span></div>
          <div class="row" style={{ display: "block" }}><div class="k" style={{ marginBottom: 8 }}>Pinned server key</div><div class="kid">{(srv?.fingerprint || "").split("-").map((g) => <span>{g}</span>)}</div></div>
          <div class="row"><span class="k">Channel</span><span class="v mono" style={{ fontSize: 12 }}>HTP/1 · ML-KEM-1024 + X25519 · AES-256-GCM</span></div>
          <div class="row"><span class="k">Session</span><span class="v">{sess ? <span class="pill mint"><Icon name="signal" />Active · auto-locks in {fmtLeft(S.idleDeadline.value - now)}</span> : "—"}</span></div>
        </div>
      </div>

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
      {sheet?.type === "duress" && <DuressSheet />}
      {sheet?.type === "station" && <StationSheet />}
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
      <input id={id} class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder={placeholder} value={value} onInput={(e) => onInput(e.currentTarget.value)} />
    </div>
  );
}

function AddDeviceSheet() {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [busy, setBusy] = useState(false);
  const find = async () => { setBusy(true); setReq(await findLink(code)); setBusy(false); };
  return (
    <Sheet onClose={close} label="Add a device">
      <div class="eyebrow">Add a device</div>
      {!req ? (
        <>
          <h2 style={{ marginTop: 6 }}>Enter the code from your new device</h2>
          <p class="lede" style={{ marginTop: 10 }}>On the new device: <b>I already have HumID → From another device</b>. Scan its QR code or type its 12-character code.</p>
          <CodeInput id="link-code" label="Device code" value={code} onInput={setCode} expect="link" />
          <div class="actions"><button class="btn primary block" disabled={busy || code.replace(/[^0-9a-z]/gi, "").length !== 12} onClick={find}>Find device</button></div>
        </>
      ) : (
        <>
          <h2 style={{ marginTop: 6 }}>Add {req.platform}?</h2>
          <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="check" /></span><div><strong>Code matches the device's keys</strong><span>Your account key will be sealed to that device only. The server can't open it.</span></div></div>
          <p class="small muted" style={{ marginTop: 12 }}>Only approve a device you're holding right now. Anyone you approve can open your vault.</p>
          <div class="actions">
            <button class="btn primary block" onClick={() => approveLink(req)}><Icon name="fingerprint" />Approve with biometric</button>
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
  return (
    <Sheet onClose={close} label="Your recovery card">
      <div class="eyebrow">Your new seal card</div>
      <h2 style={{ marginTop: 6 }}>Write this down</h2>
      <p class="lede" style={{ marginTop: 10 }}>This is the only time HumID shows it. Your old card, if you had one, no longer works.</p>
      <CardBox code={code} />
      <div class="split" style={{ marginTop: 12 }}>
        <button class="btn quiet sm" onClick={() => saveCard(code)}><Icon name="download" />Save</button>
        <button class="btn quiet sm" onClick={() => copyCard(code)}><Icon name="file" />Copy</button>
      </div>
      <div class="actions"><button class="btn secure block" onClick={close}>I've stored it safely</button></div>
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
        <input id="owner-name" value={me} maxLength={40} placeholder="e.g. Parker" onInput={(e) => setMe(e.currentTarget.value)} />
      </div>
      {rows.map((r, i) => (
        <div class="contact-row">
          <input aria-label={`Witness ${i + 1} name`} placeholder={`Witness ${i + 1} name`} value={r.name} maxLength={40} onInput={(e) => set(i, { name: e.currentTarget.value })} />
          <input aria-label={`Contact ${i + 1} code`} class="mono up" placeholder="XXXX-XXXX-XXXX" value={r.code} autocapitalize="characters" spellcheck={false}
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
      <QrCode kind="contact" code={code} />
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
                  <input id="demo-holder" value={name} onInput={(e) => setName(e.currentTarget.value)} />
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
  const d = decoy ? { enabled: false, gesture: "hold" } : id?.duress || { enabled: false, gesture: "hold" };
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
  const files = useRef(null);
  const onFiles = async (e) => { const c = await readChipFiles(e.currentTarget.files); e.currentTarget.value = ""; if (c) setChip(c); };
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
          <input ref={files} type="file" multiple hidden accept=".json,.bin,.dat,application/json,application/octet-stream" onChange={onFiles} />
          {!chip ? (
            <div class="actions">
              {nfc?.available && (
                <>
                  <ChipAccess onChange={setAccess} title="Details from their document" />
                  <button class="btn primary block" disabled={!access} onClick={async () => { const r = await readChip(access, { purpose: "station" }); if (r) setChip(r); }}><Icon name="passport" />{nfc.kind === "reader" ? "Read with the card reader" : "Hold to this phone and read"}</button>
                </>
              )}
              {!nfc?.available && <p class="small muted">{nfc?.reason || "This device can't read ID chips."}</p>}
              <button class="btn ghost block" onClick={() => { markPicking(); files.current.click(); }}><Icon name="file" />Load chip data from a file</button>
              {DEMO_BUILD && (
                <div class="field" style={{ marginTop: 0 }}>
                  <input aria-label="Demo passport holder" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                  <button class="btn ghost block" style={{ marginTop: 8 }} onClick={async () => setChip(await demoPassport(name))}><Icon name="passport" />Use a demo passport</button>
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
