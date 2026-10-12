// Security: recovery alerts, devices, recovery (card, contacts, helping
// others), this device, connection, and the exits.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { AssurancePill, Sheet, groupKey, fmtDate, fmtAgo, CodeBox, CardBox, useNow, fmtLeft } from "../ui.jsx";
import * as S from "../core/state.js";
import {
  lockNow, eraseEverything, loadDevices, loadRecovery, loadAlerts, findLink, approveLink, removeDevice,
  makeNewCard, removeCard, saveCard, copyCard, findContact, saveContacts, removeContacts,
  offerToBeContact, findHelpRequest, whoDoIProtect, releasePiece, cancelRecovery,
} from "../core/controller.js";
import { serverHost, VERSION, PLATFORM } from "../core/config.js";

const GATE = {
  "ios-keychain-biometry": "Face ID / Touch ID · Secure Enclave policy",
  "android-keystore-biometric": "Android Keystore · Class 3 biometric",
  "macos-keychain-biometry": "Touch ID · Keychain",
  "windows-hello-keycredential": "Windows Hello · TPM key",
  "linux-fprintd-keyring": "Fingerprint · fprintd + keyring",
  "webauthn-platform-uv-prf": "Device passkey (WebAuthn PRF)",
  "demo-no-hardware": "Demo · press and hold",
};
const VIA = { register: "Created HumID", link: "Added from another device", card: "Recovered with card", contacts: "Recovered with contacts" };
const METHOD = { card: "recovery card", contacts: "recovery contacts" };

export function Security() {
  const id = S.identity.value;
  const sess = S.session.value;
  const srv = id?.server;
  const now = useNow();
  const [confirm, setConfirm] = useState(false);
  const sheet = S.sheet.value;
  useEffect(() => { loadDevices(); loadRecovery(); loadAlerts(); }, []);
  const devices = S.devices.value;
  const rec = S.recovery.value;
  const open = (type, extra = {}) => (S.sheet.value = { type, ...extra });

  return (
    <main class="screen with-tabs">
      <div class="topbar"><div class="grow"><h1>Security</h1><div class="sub"><Icon name="shield" />How your HumID is protected</div></div></div>

      {S.alerts.value.map((a) => (
        <div class="banner bad" style={{ marginBottom: 12 }}>
          <span class="b-ico"><Icon name="alert" /></span>
          <div>
            <strong>Recovery in progress · {METHOD[a.method] || a.method}</strong>
            <span>Requested from {a.platform} {fmtAgo(a.createdAt)}. {a.releaseAt ? `Opens in ${fmtLeft(a.releaseAt - now)} unless you cancel.` : `${a.approvals ?? 0} contact${a.approvals === 1 ? " has" : "s have"} helped so far.`}</span>
            <button class="btn danger sm" style={{ marginTop: 10 }} onClick={() => open("cancelAlert", { alert: a })}>This wasn't me · cancel</button>
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
              </div>
              {!d.current && <button class="link" onClick={() => open("removeDevice", { device: d })}>Remove</button>}
            </div>
          ))}
        </div>
        <p class="small muted" style={{ marginTop: 8 }}>Lost a phone? Remove it here. It can't reach your vault after that, and nothing on it opens without your biometric.</p>
      </div>

      <div class="card">
        <h3>Recovery</h3>
        <p class="small muted" style={{ marginTop: 4 }}>How you get your vault back if you lose every device. HumID never holds a key that opens it.</p>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row">
            <span class="k">Recovery card</span>
            <span class="v">{rec ? (rec.card.exists ? <span class="pill mint"><Icon name="check" />Made {fmtDate(rec.card.createdAt)}</span> : <span class="pill amber">None</span>) : "…"}</span>
          </div>
          <div class="row">
            <span class="k">Recovery contacts</span>
            <span class="v">{rec ? (rec.contacts.n ? <span class="pill mint"><Icon name="user" />{rec.contacts.names.join(", ")} · any {rec.contacts.threshold}</span> : <span class="pill amber">None</span>) : "…"}</span>
          </div>
        </div>
        <div class="split" style={{ marginTop: 10 }}>
          <button class="btn quiet sm" onClick={() => open("cardInfo")}><Icon name="idcard" />{rec?.card.exists ? "Card" : "Make card"}</button>
          <button class="btn quiet sm" onClick={() => open("contacts")}><Icon name="user" />{rec?.contacts.n ? "Contacts" : "Add contacts"}</button>
        </div>
        <div class="split" style={{ marginTop: 10 }}>
          <button class="btn ghost sm" onClick={offerToBeContact}>Be a contact</button>
          <button class="btn ghost sm" onClick={() => open("help")}>Help recover</button>
        </div>
      </div>

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
        text={`A device (${sheet.alert.platform}) asked for your HumID with your ${METHOD[sheet.alert.method] || sheet.alert.method}. Cancel it and it gets nothing. If it wasn't you, also make a new recovery card or choose new contacts.`}
        action="Cancel with biometric" onConfirm={() => cancelRecovery(sheet.alert)} />}
      {sheet?.type === "cardInfo" && <CardInfoSheet />}
      {sheet?.type === "card" && <CardSheet code={sheet.code} />}
      {sheet?.type === "contacts" && <ContactsSheet />}
      {sheet?.type === "offer" && <OfferSheet code={sheet.code} expiresAt={sheet.expiresAt} />}
      {sheet?.type === "help" && <HelpSheet />}
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
          <p class="lede" style={{ marginTop: 10 }}>On the new device: <b>I already have HumID → From another device</b>. It shows a 12-character code.</p>
          <CodeField id="link-code" label="Device code" value={code} onInput={setCode} />
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
    <Sheet onClose={close} label="Recovery card">
      <div class="eyebrow">Recovery card</div>
      <h2 style={{ marginTop: 6 }}>{has ? `Your card was made ${fmtDate(rec.card.createdAt)}` : "Make a recovery card"}</h2>
      <p class="lede" style={{ marginTop: 10 }}>A code you write down or print. On a new phone it brings your vault back after 72 hours, during which every device you still have can cancel. HumID stores only a copy locked by the card, which it can't open.</p>
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
      <div class="eyebrow">Your new recovery card</div>
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
  const set = (i, patch) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const check = async (i) => { const o = await findContact(rows[i].code); set(i, { offer: o }); };
  const ready = rows.filter((r) => r.offer && r.name.trim());
  const t = ready.length >= 2 ? Math.floor(ready.length / 2) + 1 : 2;
  return (
    <Sheet onClose={close} label="Recovery contacts">
      <div class="eyebrow">Recovery contacts</div>
      <h2 style={{ marginTop: 6 }}>Choose people who can help</h2>
      <p class="lede" style={{ marginTop: 10 }}>Your account key is split so that a majority of them, together, can bring it back. Fewer learn nothing. Each one approves with their own biometric, then there's a 72-hour wait you can cancel.</p>
      {rec?.contacts.n > 0 && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Replaces {rec.contacts.names.join(", ")}</strong><span>Their pieces stop working when you save new contacts.</span></div></div>}
      <div class="field">
        <label for="owner-name">Your name, as they know you</label>
        <input id="owner-name" value={me} maxLength={40} placeholder="e.g. Parker" onInput={(e) => setMe(e.currentTarget.value)} />
      </div>
      {rows.map((r, i) => (
        <div class="contact-row">
          <input aria-label={`Contact ${i + 1} name`} placeholder={`Contact ${i + 1} name`} value={r.name} maxLength={40} onInput={(e) => set(i, { name: e.currentTarget.value })} />
          <input aria-label={`Contact ${i + 1} code`} class="mono up" placeholder="XXXX-XXXX-XXXX" value={r.code} autocapitalize="characters" spellcheck={false}
            onInput={(e) => set(i, { code: e.currentTarget.value, offer: null })} />
          {r.offer ? <span class="pill mint"><Icon name="check" />Verified</span>
            : <button class="btn quiet sm" disabled={r.code.replace(/[^0-9a-z]/gi, "").length !== 12} onClick={() => check(i)}>Check</button>}
        </div>
      ))}
      {rows.length < 5 && <button class="link" onClick={() => setRows([...rows, { name: "", code: "", offer: null }])}>+ Add another contact</button>}
      <p class="small muted" style={{ marginTop: 6 }}>Each contact gets their code from HumID → Security → Be a contact.</p>
      <div class="actions">
        <button class="btn primary block" disabled={ready.length < 2 || !me.trim()} onClick={() => saveContacts(ready.map((r) => ({ code: r.code, name: r.name, offer: r.offer })), me.trim())}>
          <Icon name="fingerprint" />Save {ready.length || ""} contacts · any {t} can help
        </button>
        {rec?.contacts.n > 0 && <button class="btn danger block" onClick={removeContacts}>Remove all contacts</button>}
      </div>
    </Sheet>
  );
}

function OfferSheet({ code, expiresAt }) {
  const now = useNow();
  return (
    <Sheet onClose={close} label="Be someone's contact">
      <div class="eyebrow">Be someone's recovery contact</div>
      <h2 style={{ marginTop: 6 }}>Give them this code</h2>
      <p class="lede" style={{ marginTop: 10 }}>They type it when choosing contacts. It lets them seal a piece of their key to you. On your own, you can never open their vault.</p>
      <CodeBox code={code} label="Contact code" />
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
          <p class="lede" style={{ marginTop: 10 }}>Someone who chose you as a recovery contact lost their devices. Their new phone shows a code.</p>
          <CodeField id="help-code" label="Recovery code" value={code} onInput={setCode} />
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
          {people.length === 0 && <p class="lede" style={{ marginTop: 10 }}>You aren't anyone's recovery contact yet.</p>}
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
            : `${done.approvals} of ${done.threshold} contacts have helped so far.`}</p>
          <div class="actions"><button class="btn secure block" onClick={close}>Done</button></div>
        </>
      )}
    </Sheet>
  );
}
