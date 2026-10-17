// You: everything about this HumID in one place, in the order it matters —
// what's left to protect it, devices, recovery (witnesses, ID chip, recovery card),
// duress protection, helping others, how HumID looks and locks on this device,
// a collapsed "About" with the diagnostics, and the exits (lock, close).
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import {
  AssurancePill, proofLabel, Sheet, groupKey, fmtDate, fmtAgo, CodeBox, CardBox, useNow, fmtLeft,
  QrCode, CodeInput, Scanner, Toggle, ProofMeter, PROOFS, ChipAccess, CardConfirm, PrintableCard, CAN_PRINT, OfflineBanner, HowProtected,
} from "../ui.jsx";
import * as S from "../core/state.js";
import {
  lockNow, eraseEverything, loadDevices, loadRecovery, loadAlerts, findLink, approveLink, removeDevice, myAccountCheck,
  makeNewCard, removeCard, saveCard, findContact, saveContacts, removeContacts,
  offerToBeContact, findHelpRequest, whoDoIProtect, releasePiece, cancelRecovery,
  readChipFiles, demoPassport, setAnchor, removeAnchor, saveDuress, loadDuress, setWitnessAlert, clearLockdown,
  stationLookup, stationVerify, stationReadChip, markPicking, DURESS_HOLD_MS, readChip, setPref, setDecoy,
} from "../core/controller.js";
import { CHOICES, IDLE_CHOICES, idleLabel } from "../core/prefs.js";
import { serverHost, VERSION, PLATFORM, DEMO_BUILD, SIM } from "../core/config.js";
import { resetSimulation } from "../core/controller.js";

const GATE = {
  "ios-keychain-biometry": "Face ID / Touch ID · Secure Enclave policy",
  "android-keystore-biometric": "Android Keystore · Class 3 biometric",
  "macos-keychain-biometry": "Touch ID · Keychain",
  "windows-winbio-fingerprint": "Fingerprint · Windows Biometric Framework",
  "linux-fprintd-keyring": "Fingerprint · fprintd + keyring",
  "demo-no-hardware": "Demo · press and hold",
};
const VIA = { register: "Created HumID", link: "Added from another device", card: "Recovered with older card", contacts: "Recovered with older witnesses", quorum: "Recovered with two proofs" };
const METHOD = { card: "recovery card", contacts: "witnesses", quorum: "two proofs" };

const LABELS = {
  theme: { system: "Match device", dark: "Night", light: "Day" },
  text: { standard: "Standard", large: "Larger" },
  sort: { newest: "Newest", oldest: "Oldest", name: "Name", expiry: "Expiring first" },
};
const opts = (key) => CHOICES[key].map((v) => [v, LABELS[key][v]]);

const close = () => (S.sheet.value = null);
const open = (type, extra = {}) => (S.sheet.value = { type, ...extra });

/** Opens a step here: a sheet, or the Recovery card when there's a choice to make there. */
function goTo(target) {
  if (target === "#recovery") setTimeout(() => document.getElementById("recovery")?.scrollIntoView({ block: "start", behavior: "smooth" }), 80);
  else open(target);
}

export function You() {
  const id = S.identity.value;
  const srv = id?.server;
  const sess = S.session.value;
  const now = useNow();
  const [confirm, setConfirm] = useState(false);
  const [how, setHow] = useState(false);
  const [removing, setRemoving] = useState(null); // a device whose row is open on "Remove this device?"
  const sheet = S.sheet.value;
  useEffect(() => { loadDevices(); loadRecovery(); loadAlerts(); loadDuress(); }, []);
  const devices = S.devices.value;
  const rec = S.recovery.value;
  const decoy = S.decoy.value;
  const duress = id?.duress;
  const dinfo = S.duressInfo.value;
  const protecting = decoy ? [] : S.protecting.value;
  const p = S.prefs.value;
  const pinned = S.items.value.filter((i) => i.pinned).length;

  return (
    <main class="screen with-tabs">
      <div class="topbar"><div class="grow"><h1>You</h1><div class="sub"><Icon name="shield" />Your HumID, and how it's protected</div></div></div>

      <OfflineBanner />

      {S.alerts.value.map((a) => (
        <div class="banner bad" style={{ marginBottom: 12 }}>
          <span class="b-ico"><Icon name="alert" /></span>
          <div>
            <strong>Recovery in progress · {METHOD[a.method] || a.method}</strong>
            <span>Requested from {a.platform} {fmtAgo(a.createdAt)}. {a.evidence ? `Proofs so far: ${a.evidence}. ` : ""}{a.releaseAt ? `Opens in ${fmtLeft(a.releaseAt - now)} unless you cancel.` : a.method === "quorum" ? "It needs a second proof before any wait starts." : `${a.approvals ?? 0} witness${a.approvals === 1 ? " has" : "es have"} helped so far.`} Cancel it and that device gets nothing; if it wasn't you, also make a new recovery card or choose new witnesses.</span>
            <button class="btn danger sm" style={{ marginTop: 10 }} onClick={() => cancelRecovery(a)}><Icon name="fingerprint" />Cancel the recovery</button>
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

      <ProtectionCard />

      <button class="option" style={{ marginBottom: 12 }} onClick={() => setHow(true)}>
        <span class="o-ico"><Icon name="shield" /></span>
        <span><strong>How HumID protects you</strong><span>Sealed on your phone, opened only by you, in plain words.</span></span>
        <Icon name="chevron" />
      </button>
      {how && <HowProtected onClose={() => setHow(false)} />}

      <div class="card">
        <div class="c-head"><h3>Devices</h3><button class="btn quiet sm" onClick={() => open("addDevice")}><Icon name="plus" />Add a device</button></div>
        <div class="rows" style={{ marginTop: 6 }}>
          {!devices && <div class="row"><span class="k">Loading…</span></div>}
          {devices?.length === 0 && <div class="row"><span class="k">Nothing here yet. Your other phones and computers go here. Add a device.</span></div>}
          {devices?.map((d) => (
            <div class="row device" data-removing={removing === d.id ? "1" : undefined}>
              <span class="d-ico"><Icon name="key" /></span>
              <div style={{ minWidth: 0 }}>
                <div class="d-name">{d.platform || "Device"}{d.current && <span class="pill mint" style={{ marginLeft: 8 }}>This device</span>}</div>
                <div class="d-meta">{VIA[d.via] || d.via} · {fmtDate(d.enrolledAt)}{d.lastSeenAt && !d.current ? ` · seen ${fmtAgo(d.lastSeenAt)}` : ""}</div>
                <div class="d-meta">{proofLabel(d.proof, d.assurance)}</div>
                {removing === d.id && (
                  <div class="row-confirm">
                    <strong>Remove {d.platform || "this device"}?</strong>
                    <span class="small muted">It can never reach your vault again. If you find it later, set it up again with I already have HumID.</span>
                    <div class="split" style={{ marginTop: 8 }}>
                      <button class="btn danger sm" onClick={() => { setRemoving(null); removeDevice(d); }}><Icon name="fingerprint" />Remove this device</button>
                      <button class="btn ghost sm" data-back onClick={() => setRemoving(null)}>Keep it</button>
                    </div>
                  </div>
                )}
              </div>
              {!d.current && removing !== d.id && <button class="link" onClick={() => setRemoving(d.id)}>Remove</button>}
            </div>
          ))}
        </div>
        <p class="small muted" style={{ marginTop: 8 }}>Lost a phone? Remove it here. It can't reach your vault after that, and nothing on it opens without your face or fingerprint.</p>
      </div>

      <div class="card" id="recovery">
        <div class="c-head"><h3>Recovery</h3>{rec && (rec.ready ? <span class="pill mint"><Icon name="check" />Ready</span> : <span class="pill amber">Needs {2 - Object.values(rec.proofs).filter(Boolean).length} more</span>)}</div>
        <p class="small muted" style={{ marginTop: 4 }}>If you lose every device, any two of these three prove it's you. HumID never holds a key that opens your vault, and one proof alone never does.</p>
        {rec && <ProofMeter have={PROOFS.map((p) => p.id).filter((k) => rec.proofs[k])} />}
        <div class="rows" style={{ marginTop: 8 }}>
          <button class="proof-row linkrow" data-done={rec?.proofs.witness ? "1" : "0"} onClick={() => open("contacts")}>
            <span class="p-ico"><Icon name="users" /></span>
            <span><strong>Witnesses</strong><span>{rec?.contacts.n ? `${rec.contacts.names.join(", ")} · any ${rec.contacts.threshold}${rec.contacts.scheme !== "quorum" ? " · older setup" : ""}` : "Nothing here yet. People you trust, who approve with their own face or fingerprint. Choose witnesses."}</span></span>
            <Icon name="chevron" />
          </button>
          <button class="proof-row linkrow" data-done={rec?.proofs.anchor ? "1" : "0"} onClick={() => open("anchor")}>
            <span class="p-ico"><Icon name="passport" /></span>
            <span><strong>ID chip</strong><span>{rec?.anchor.exists ? `Your ${rec.anchor.document}${rec.anchor.country ? ` · ${rec.anchor.country}` : ""}` : rec?.anchor.available ? "Your passport or ID card's chip" : "Not available on this server yet"}</span></span>
            <Icon name="chevron" />
          </button>
          <button class="proof-row linkrow" data-done={rec?.proofs.card ? "1" : "0"} onClick={() => open("cardInfo")}>
            <span class="p-ico"><Icon name="idcard" /></span>
            <span><strong>Recovery card</strong><span>{rec?.card.exists ? `Made ${fmtDate(rec.card.createdAt)}${rec.card.scheme !== "quorum" ? " · older single-proof card" : ""}` : "A code you keep offline"}</span></span>
            <Icon name="chevron" />
          </button>
        </div>
        {rec?.legacy && <div class="banner warn" style={{ marginTop: 10 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Upgrade to two-proof recovery</strong><span>You have an older card or witnesses that work on their own. Make a new recovery card and save your witnesses again to switch.</span></div></div>}
      </div>

      <div class="card">
        <div class="c-head"><h3>Duress protection</h3>{!decoy && duress?.enabled ? <span class="pill mint"><Icon name="check" />On</span> : <span class="pill">Off</span>}</div>
        <p class="small muted" style={{ marginTop: 4 }}>If someone forces you to unlock, a gesture opens HumID showing only documents you chose, while your vault quietly locks itself and recoveries slow down.</p>
        <div class="actions" style={{ marginTop: 10 }}><button class="btn quiet sm" onClick={() => open("duress")}><Icon name="siren" />{!decoy && duress?.enabled ? "Change" : "Set up"}</button></div>
      </div>

      <div class="card">
        <h3>Help others</h3>
        <p class="small muted" style={{ marginTop: 4 }}>Be one of someone's witnesses, or help a witness of yours get back in.</p>
        <div class="split" style={{ marginTop: 12 }}>
          <button class="btn ghost sm" onClick={offerToBeContact}>Be a witness</button>
          <button class="btn ghost sm" onClick={() => open("help")}>Help recover</button>
        </div>
        {!decoy && S.station.value?.station && (
          <>
            <div class="c-head" style={{ marginTop: 16 }}><strong>Verification station</strong><span class="pill mint"><Icon name="station" />Operator</span></div>
            <p class="small muted" style={{ marginTop: 4 }}>Check a person and their ID in person, so their recovery can count their ID chip.</p>
            <div class="actions" style={{ marginTop: 10 }}><button class="btn primary sm" onClick={() => open("station")}><Icon name="scan" />Verify someone</button></div>
          </>
        )}
      </div>

      <section class="card" aria-labelledby="set-prefs">
        <h3 id="set-prefs">Preferences</h3>
        <Choice id="theme" label="Theme" value={p.theme} options={opts("theme")} onPick={(v) => setPref({ theme: v })} />
        <Choice id="text" label="Text size" value={p.text} options={opts("text")} onPick={(v) => setPref({ text: v })} />
        <Switch id="motion" label="Animations" hint="The rings and transitions. Off keeps everything still." checked={p.motion} onChange={(v) => setPref({ motion: v })} />
        <Switch id="haptics" label="Haptics" hint="A short buzz when a check passes or a photo is taken." checked={p.haptics} onChange={(v) => setPref({ haptics: v })} />
        <Choice id="idle" label="Lock after no activity" hint="5 minutes is the longest HumID allows. Leaving the screen always locks."
          value={p.idleMs} options={IDLE_CHOICES.map((ms) => [ms, idleLabel(ms).replace(" minutes", " min").replace(" minute", " min")])} onPick={(v) => setPref({ idleMs: v })} />
        <Choice id="expiry" label="Warn before an ID expires" value={p.expiryWarnDays}
          options={CHOICES.expiryWarnDays.map((d) => [d, d < 90 ? `${d} days` : `${Math.round(d / 30)} months`])} onPick={(v) => setPref({ expiryWarnDays: v })} />
        <Choice id="sort" label="Sort the vault by" value={p.sort} options={opts("sort")} onPick={(v) => setPref({ sort: v })} />
        <p class="small muted" style={{ marginTop: 10 }}><Icon name="pushpin" /> {pinned ? `${pinned} pinned ${pinned === 1 ? "item stays" : "items stay"} at the top.` : "Pin items from their details to keep them at the top."} Pins are sealed with each item, so they show on all your devices and the server can't see them.</p>
      </section>

      {SIM && (
        <div class="card">
          <div class="c-head"><h3>Simulation</h3><span class="pill amber">No real server</span></div>
          <p class="small muted" style={{ marginTop: 4 }}>The vault server runs inside this app. The connection is the real post-quantum one and the checks are real; adding devices, witnesses, ID chips and stations need other people or servers, so they're off here. Nothing leaves this phone.</p>
          <div class="split" style={{ marginTop: 10 }}>
            <button class="btn quiet sm" onClick={() => (S.simShow.value = S.simLog.value[0] || { title: "Simulation", checks: [], empty: true })}><Icon name="shield" />Server checks</button>
            <button class="btn danger sm" onClick={() => open("simReset")}>Reset simulation</button>
          </div>
        </div>
      )}

      <details class="card about">
        <summary><span><strong>About this HumID</strong><span class="small muted">Your identity, this device, the connection</span></span></summary>
        <div class="eyebrow" style={{ marginTop: 14 }}>Your identity</div>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Created</span><span class="v">{id ? fmtDate(id.enrolledAt) : ""}</span></div>
          <div class="row"><span class="k">HumID</span><span class="v mono" style={{ fontSize: 12 }}>{srv?.id?.slice(0, 16)}…</span></div>
          <div class="row" style={{ display: "block" }}><div class="k" style={{ marginBottom: 8 }}>Identity commitment</div><div class="kid">{groupKey(id?.commit).slice(0, 8).map((g) => <span>{g}</span>)}</div></div>
          <div class="row"><span class="k">Keys</span><span class="v">Post-quantum</span></div>
        </div>
        <div class="eyebrow" style={{ marginTop: 16 }}>This device</div>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Protection</span><span class="v"><AssurancePill assurance={id?.assurance} /></span></div>
          <div class="row"><span class="k">Gate</span><span class="v">{GATE[id?.method] || id?.method}</span></div>
          <div class="row"><span class="k">Proof</span><span class="v">{proofLabel(id?.proof, id?.assurance)}</span></div>
          <div class="row"><span class="k">PIN or password</span><span class="v"><span class="pill mint"><Icon name="check" />Never accepted</span></span></div>
          <div class="row"><span class="k">Device</span><span class="v">{PLATFORM}</span></div>
        </div>
        <div class="eyebrow" style={{ marginTop: 16 }}>Connection</div>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Vault server</span><span class="v">{serverHost(srv?.url)}</span></div>
          <div class="row" style={{ display: "block" }}><div class="k" style={{ marginBottom: 8 }}>Pinned server key</div><div class="kid">{(srv?.fingerprint || "").split("-").map((g) => <span>{g}</span>)}</div></div>
          <div class="row"><span class="k">Connection</span><span class="v">Post-quantum, end to end</span></div>
          <div class="row"><span class="k">Session</span><span class="v">{sess ? <span class="pill mint"><Icon name="signal" />Active · auto-locks in {fmtLeft(S.idleDeadline.value - now)}</span> : S.offline.value ? <span class="pill amber"><Icon name="signal" />Offline · read only · auto-locks in {fmtLeft(S.idleDeadline.value - now)}</span> : "—"}</span></div>
        </div>
      </details>

      <div class="actions" style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 10 }}>
        <button class="btn ghost block" onClick={lockNow}><Icon name="lock" />Lock now</button>
        <button class="btn danger block" onClick={() => setConfirm(true)}><Icon name="trash" />Close HumID &amp; erase vault</button>
      </div>
      <p class="fine" style={{ marginTop: 14 }}>HumID {VERSION} · Preferences are kept on this device. Pins follow you.</p>

      {confirm && (
        <Sheet onClose={() => setConfirm(false)} label="Close HumID">
          <div class="eyebrow">This can't be undone</div>
          <h2 style={{ marginTop: 6 }}>Close your HumID?</h2>
          <p class="lede" style={{ marginTop: 10 }}>Every document is erased from the vault server, your identity and recovery options are closed, and the keys on this device are destroyed. Your activity history stays on file, closed.</p>
          <div class="actions">
            <button class="btn danger block" onClick={() => { setConfirm(false); eraseEverything(); }}><Icon name="fingerprint" />Close HumID &amp; erase</button>
            <button class="btn ghost block" onClick={() => setConfirm(false)}>Keep my HumID</button>
          </div>
        </Sheet>
      )}

      {sheet?.type === "addDevice" && <AddDeviceSheet />}
      {sheet?.type === "cardInfo" && <CardInfoSheet />}
      {sheet?.type === "recoveryCard" && <CardSheet code={sheet.code} />}
      {sheet?.type === "contacts" && <ContactsSheet />}
      {sheet?.type === "offer" && <OfferSheet code={sheet.code} expiresAt={sheet.expiresAt} />}
      {sheet?.type === "help" && <HelpSheet />}
      {sheet?.type === "anchor" && <AnchorSheet />}
      {sheet?.type === "simReset" && <ConfirmSheet label="Reset simulation" eyebrow="Simulation" title="Start the simulation over?"
        text="The simulated server, your test HumID and every test document on this phone are erased. Then you can set up from the beginning."
        action="Reset" onConfirm={resetSimulation} />}
      {sheet?.type === "duress" && <DuressSheet />}
      {sheet?.type === "station" && <StationSheet />}
    </main>
  );
}

/* ---------------- finish protecting it ---------------- */

/**
 * What's left to make this HumID survive a lost phone, with a button for each, until it's
 * done. Hidden in a duress (decoy) session, which must look like an ordinary account.
 */
export function ProtectionCard() {
  const decoy = S.decoy.value;
  useEffect(() => { if (!decoy) { loadRecovery(); loadDevices(); } }, [decoy]);
  const rec = S.recovery.value, devices = S.devices.value, id = S.identity.value;
  if (decoy || S.offline.value || !rec || !devices) return null; // offline: nothing here could be done until it reconnects
  const items = [
    { done: !!rec.proofs?.card, icon: "idcard", label: "Recovery card", todo: "Make the card that's one of your proofs", target: "cardInfo" },
    { done: !!(rec.proofs?.witness || rec.proofs?.anchor), icon: "users", label: "A second proof", todo: "Witnesses who vouch for you, or your ID chip", target: "#recovery" },
    { done: devices.length >= 2, icon: "key", label: "A second device", todo: "Another phone or computer, so a lost phone isn't an emergency", target: "addDevice" },
  ];
  const n = items.filter((i) => i.done).length;
  if (n === items.length) return null;
  return (
    <section class="card protect" aria-labelledby="protect-h">
      <div class="c-head"><h3 id="protect-h">Finish protecting your HumID</h3><span class="pill amber">{n} of {items.length}</span></div>
      <div class="meter" role="progressbar" aria-label="Protection" aria-valuemin={0} aria-valuemax={items.length} aria-valuenow={n}><i style={{ width: `${(n / items.length) * 100}%` }} /></div>
      {items.map((i) => (
        <button class="proof-row linkrow" data-done={i.done ? "1" : "0"} disabled={i.done} onClick={() => goTo(i.target)}>
          <span class="p-ico"><Icon name={i.done ? "check" : i.icon} /></span>
          <span><strong>{i.label}</strong><span>{i.done ? "Done" : i.todo}</span></span>
          {!i.done && <Icon name="chevron" />}
        </button>
      ))}
      {!id?.duress?.enabled && (
        <button class="proof-row linkrow" data-done="0" onClick={() => goTo("duress")}>
          <span class="p-ico"><Icon name="siren" /></span>
          <span><strong>Optional: duress gesture</strong><span>If you're ever forced to unlock, show only chosen documents</span></span>
          <Icon name="chevron" />
        </button>
      )}
    </section>
  );
}

/* ---------------- preferences ---------------- */

/** One choice out of a few, as a row of buttons. */
function Choice({ id, label, hint, value, options, onPick }) {
  return (
    <div class="setting">
      <div class="s-label" id={`${id}-label`}><strong>{label}</strong>{hint && <span>{hint}</span>}</div>
      <div class="seg" role="radiogroup" aria-labelledby={`${id}-label`} data-n={options.length}>
        {options.map(([v, text]) => (
          <button type="button" role="radio" aria-checked={value === v} data-pref={`${id}:${v}`} onClick={() => onPick(v)}>{text}</button>
        ))}
      </div>
    </div>
  );
}

function Switch({ id, label, hint, checked, onChange }) {
  return (
    <label class="toggle">
      <span><strong>{label}</strong>{hint && <span>{hint}</span>}</span>
      <input type="checkbox" role="switch" data-pref={id} checked={checked} onChange={(e) => onChange(e.currentTarget.checked)} />
      <i aria-hidden="true" />
    </label>
  );
}

/* ---------------- sheets ---------------- */

/** Only for things that can't be undone and have no check of their own (resetting the simulation). */
function ConfirmSheet({ label, eyebrow, title, text, action, onConfirm }) {
  return (
    <Sheet onClose={close} label={label}>
      <div class="eyebrow">{eyebrow}</div>
      <h2 style={{ marginTop: 6 }}>{title}</h2>
      <p class="lede" style={{ marginTop: 10 }}>{text}</p>
      <div class="actions">
        <button class="btn danger block" onClick={onConfirm}>{action}</button>
        <button class="btn ghost block" onClick={close}>Keep it</button>
      </div>
    </Sheet>
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
          <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="check" /></span><div><strong>Code matches the device's keys</strong><span>Your account key will be sealed to that device only. Your vault server can't open it.</span></div></div>
          <p class="small muted" style={{ marginTop: 12 }}>Only approve a device you're holding right now. Anyone you approve can open your vault.</p>
          <div class="actions">
            <button class="btn primary block" disabled={busy} onClick={approve}><Icon name="fingerprint" />Approve this device</button>
            <button class="btn ghost block" data-back onClick={() => setReq(null)}>Not my device · back</button>
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
      <div class="eyebrow">Recovery card · one of three proofs</div>
      <h2 style={{ marginTop: 6 }}>{has ? `Your card was made ${fmtDate(rec.card.createdAt)}` : "Make a recovery card"}</h2>
      <p class="lede" style={{ marginTop: 10 }}>A code you write down or print and keep away from your ID. With your witnesses or your ID chip it brings your vault back on a new phone. HumID stores only a piece locked by the card, which it can't open.</p>
      {rec?.card.exists && rec.card.scheme !== "quorum" && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>This is an older card</strong><span>It works on its own after 72 hours. A new recovery card replaces it and always needs a second proof.</span></div></div>}
      <div class="actions">
        <button class="btn primary block" onClick={makeNewCard}><Icon name="fingerprint" />{has ? "Make a new card (old one stops working)" : "Make my card"}</button>
        {has && <button class="btn danger block" onClick={removeCard}><Icon name="fingerprint" />Remove my card</button>}
      </div>
    </Sheet>
  );
}

function CardSheet({ code }) {
  const [ok, setOk] = useState(false);
  return (
    <Sheet onClose={close} label="Your recovery card">
      <div class="eyebrow">Your new recovery card</div>
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
      <p class="lede" style={{ marginTop: 10 }}>When a majority of them approve, each with their own face or fingerprint, that counts as one proof it's you. They never learn your key, and even all of them together can't open your vault without a second proof.</p>
      {rec?.contacts.n > 0 && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Replaces {rec.contacts.names.join(", ")}</strong><span>Their pieces stop working when you save new witnesses.</span></div></div>}
      <div class="field">
        <label for="owner-name">Your name, as they know you</label>
        <input autocorrect="off" spellcheck={false} autocomplete="off" id="owner-name" value={me} maxLength={40} placeholder="e.g. Parker" onInput={(e) => setMe(e.currentTarget.value)} />
      </div>
      {rows.map((r, i) => (
        <div class="contact-row">
          <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label={`Witness ${i + 1} name`} placeholder={`Witness ${i + 1} name`} value={r.name} maxLength={40} onInput={(e) => set(i, { name: e.currentTarget.value })} />
          <input autocorrect="off" autocomplete="off" aria-label={`Witness ${i + 1} code`} class="mono up" placeholder="XXXX-XXXX-XXXX" value={r.code} autocapitalize="characters" spellcheck={false}
            onInput={(e) => set(i, { code: e.currentTarget.value, offer: null })} />
          {r.offer ? <span class="pill mint"><Icon name="check" />Verified</span>
            : r.code.replace(/[^0-9a-z]/gi, "").length === 12 ? <button class="btn quiet sm" onClick={() => check(i)}>Check</button>
            : <button class="btn quiet sm" aria-label={`Scan witness ${i + 1}'s code`} onClick={() => setScanning(i)}><Icon name="scan" /></button>}
        </div>
      ))}
      {scanning != null && <Scanner expect="contact" onCancel={() => setScanning(null)} onCode={(c) => { set(scanning, { code: c.code, offer: null }); setScanning(null); }} />}
      {rows.length < 5 && <button class="link" onClick={() => setRows([...rows, { name: "", code: "", offer: null }])}>+ Add another witness</button>}
      <p class="small muted" style={{ marginTop: 6 }}>Each witness gets their witness code from HumID → You → Be a witness. Tap a code box's scan button to scan theirs.</p>
      <div class="actions">
        <button class="btn primary block" disabled={ready.length < 2 || !me.trim()} onClick={() => saveContacts(ready.map((r) => ({ code: r.code, name: r.name, offer: r.offer })), me.trim())}>
          <Icon name="fingerprint" />Save {ready.length || ""} witnesses · any {t} count as a proof
        </button>
        {rec?.contacts.n > 0 && <button class="btn danger block" onClick={removeContacts}><Icon name="fingerprint" />Remove all witnesses</button>}
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
      <p class="fine" style={{ textAlign: "center" }}>{expiresAt > now ? `Expires in ${fmtLeft(expiresAt - now)}` : "This code has expired."}</p>
      <div class="actions">
        {expiresAt <= now && <button class="btn primary block" onClick={offerToBeContact}><Icon name="qr" />Make a new code</button>}
        <button class="btn ghost block" onClick={close}>Done</button>
      </div>
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
          <p class="small muted" style={{ marginTop: 12 }}>Next, one check shows whose pieces you hold.</p>
          <div class="actions">
            <button class="btn primary block" onClick={reveal}><Icon name="fingerprint" />Show who I protect</button>
            <button class="btn ghost block" data-back onClick={() => setReq(null)}>Back</button>
          </div>
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
          <div class="actions">
            <button class="btn primary block" disabled={!pick} onClick={release}><Icon name="fingerprint" />Release my piece to that device</button>
            <button class="btn ghost block" data-back onClick={() => { setPeople(null); setPick(null); }}>Back</button>
          </div>
        </>
      )}
      {done && (
        <>
          <h2 style={{ marginTop: 6 }}>Thanks. Your piece was sent</h2>
          <p class="lede" style={{ marginTop: 10 }}>{done.releaseAt
            ? `Enough witnesses have helped. ${pick.label}'s vault opens on their new device in about ${fmtLeft(done.releaseAt - Date.now())}, unless they cancel it from a device they still have.`
            : done.kinds ? `${done.approvals} of ${done.threshold} witnesses have approved. Their recovery also needs a second proof.` : `${done.approvals} of ${done.threshold} witnesses have helped so far.`}</p>
          <div class="actions"><button class="btn secure block" onClick={close}>Done</button></div>
        </>
      )}
    </Sheet>
  );
}

/* ---------------- ID chip (the identity anchor, in the docs) ---------------- */

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
      <h2 style={{ marginTop: 6 }}>{a?.exists ? `Linked to your ${a.document}'s chip` : "Link HumID to your passport or ID chip"}</h2>
      <p class="lede" style={{ marginTop: 10 }}>The chip in your passport or ID card is signed by the country that issued it. HumID checks that signature and keeps only a keyed fingerprint of the details that stay the same when you renew. Later, your chip proves it's you: in person at a HumID station, or live on your phone.</p>
      {!a?.exists && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>The one proof that isn't anonymous</strong><span>Someone holding this vault's secret and your passport details could confirm you have a HumID. Witnesses and your recovery card don't reveal who you are. Skip this if anonymity matters more than convenience.</span></div></div>}
      {!a?.available && <div class="banner warn" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="globe" /></span><div><strong>Not available on this server yet</strong><span>Its operator hasn't added the countries' signing certificates. Use witnesses and a recovery card for now.</span></div></div>}
      {a?.exists && <div class="card" style={{ marginTop: 12 }}><div class="row"><span class="k">Document</span><span class="v">{a.document}{a.country ? ` · ${a.country}` : ""}</span></div><div class="row"><span class="k">Linked</span><span class="v">{fmtDate(a.createdAt)}</span></div></div>}
      {a?.available && (
        <>
          <input ref={files} type="file" multiple hidden accept=".json,.bin,.dat,application/json,application/octet-stream" onChange={onFiles} />
          {!chip && nfcOpen && (
            <>
              <ChipAccess onChange={setAccess} />
              <div class="actions">
                <button class="btn primary block" disabled={!access} onClick={read}><Icon name="passport" />{nfc?.kind === "reader" ? "Read with the card reader" : "Hold to my phone and read"}</button>
                <button class="btn ghost block" data-back onClick={() => setNfcOpen(false)}>Back</button>
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
              <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="check" /></span><div><strong>{chip.access ? `Chip read · ${chip.access}` : `Chip data loaded${chip.demo ? " (demo)" : ""}`}</strong><span>Your vault server checks its country signature next. {chip.dg15 ? "This chip can also prove it's present, live." : "This chip can't prove it's present live, so recovering with it will need a HumID station."}</span></div></div>
              <div class="actions">
                <button class="btn primary block" onClick={() => setAnchor(chip)}><Icon name="fingerprint" />{a?.exists ? "Replace with this ID" : "Link this ID chip"}</button>
                <button class="btn ghost block" data-back onClick={() => setChip(null)}>Choose another</button>
              </div>
            </>
          )}
        </>
      )}
      {a?.exists && <div class="actions"><button class="btn danger block" onClick={removeAnchor}><Icon name="fingerprint" />Unlink this ID chip</button></div>}
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
  const items = decoy ? [] : S.items.value;
  const decoys = items.filter((i) => i.decoy).length;
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
        {!decoy && <Toggle label="Tell my witnesses" hint="They see a duress alert next time they open HumID. Only turn this on if they'd know what to do." checked={!!info?.alert} onChange={setWitnessAlert} />}
      </div>
      <div class="card" style={{ marginTop: 12 }}>
        <div class="c-head"><h3>Decoy documents</h3><span class="pill">{decoys ? `${decoys} shown` : "None"}</span></div>
        <p class="small muted" style={{ marginTop: 4 }}>What someone sees if you unlock with the gesture. Choose things that look ordinary.</p>
        {items.length === 0 ? <p class="small muted" style={{ marginTop: 8 }}>Nothing in your vault yet. Seal a document first, then choose it here.</p> : (
          <div class="checklist decoys">
            {items.map((it) => (
              <label class="check" key={it.id}>
                <input type="checkbox" checked={!!it.decoy} onChange={(e) => setDecoy(it, e.currentTarget.checked)} />
                <span>{it.name}</span>
              </label>
            ))}
          </div>
        )}
      </div>
      <p class="small muted" style={{ marginTop: 10 }}>Your face or fingerprint still unlocks either way, so no one can tell from watching. HumID records the signal in your ledger, where only a normal unlock shows it.</p>
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
              <div class="actions"><button class="btn primary block" disabled={!all} onClick={async () => { const r = await stationVerify(req.code, chip, checks); if (r) setDone(r); }}><Icon name="fingerprint" />Vouch for them</button></div>
            </>
          )}
        </>
      )}
      {done && (
        <>
          <h2 style={{ marginTop: 6 }}>Verified</h2>
          <p class="lede" style={{ marginTop: 10 }}>{done.releaseAt ? `Their vault opens on their new phone in about ${fmtLeft(done.releaseAt - Date.now())}, unless one of their devices vetoes it.` : "Their ID counts now. They still need one more proof: their witnesses or their recovery card."}</p>
          <p class="small muted" style={{ marginTop: 6 }}>Recorded in your ledger and theirs.</p>
          <div class="actions"><button class="btn secure block" onClick={close}>Done</button></div>
        </>
      )}
    </Sheet>
  );
}
