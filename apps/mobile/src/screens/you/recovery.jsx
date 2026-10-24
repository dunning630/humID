// Recovery: first the recovery mode (holder-only or hardened, docs/RECOVERY.md) and the switch;
// then, for hardened, the four proofs (witnesses · ID chip · recovery card · security key); any
// two bring the vault back on a new phone. This screen shows which exist and opens each;
// progress lives on the Protection screen.
//
// Witnesses are gathered one at a time: each code is checked the moment it's complete,
// the list is kept as a draft across a lock, and one check saves the set.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Sheet, Banner, Row, Toggle } from "../../ui/kit.jsx";
import { CodeInput, ChipAccess, ProofMeter, PROOFS, WAITS } from "../../ui/codes.jsx";
import { fmtDate } from "../../ui/format.js";
import * as S from "../../core/state.js";
import { readChip, chipReader, setDraft, clearDraft, draft, toast } from "../../core/index.js";
import { loadRecovery, makeNewCard, removeCard, findContact, saveContacts, removeContacts, demoPassport, setAnchor, removeAnchor, keyReader, addSecurityKey, removeSecurityKey, switchToHardened, switchToHolderOnly, newRecoveryPieces, confirmModeHere, modeHistory, escrowWords, HOLDER_ONLY } from "../../core/setup.js";
import { back, twelve, Countdown } from "./common.jsx";
import { RECOVERY_IF_LOST } from "../../ui/labels.js";
/* global __HUMID_ALLOW_DEMO__ */

const MIN_WITNESSES = 2, MAX_WITNESSES = 5;
const threshold = (n) => Math.floor(n / 2) + 1;

export function Recovery() {
  const rec = S.recovery.value;
  const mode = S.recoveryMode.value;
  const [open, setOpen] = useState(S.push.value?.open || null); // witnesses | anchor | card | key | mode
  useEffect(() => { loadRecovery(); chipReader(); }, []);
  const off = !!S.offline.value;
  const holderOnly = mode?.mode === HOLDER_ONLY;
  // Hardened, but not a choice this phone can vouch for itself: no proofs are offered (V74B-01).
  const unconfirmed = !!(mode && !holderOnly && mode.trusted && mode.vouched === false);
  return (
    <Pushed title="Recovery" onBack={back}>
      <ModeCard mode={mode} off={off} onSwitch={() => setOpen("mode")} onConfirm={() => setOpen("confirm")} />
      {open === "mode" && <ModeSheet mode={mode} onClose={() => setOpen(null)} />}
      {open === "confirm" && <ConfirmSheet onClose={() => setOpen(null)} />}
      {holderOnly || unconfirmed ? null : <>
      <p class="t2 small mt-4">Set up <b>two</b> of these four. One proof alone never opens your vault, and HumID never holds a key that does.</p>
      {rec && <ProofMeter have={PROOFS.map((p) => p.id).filter((k) => rec.proofs[k])} />}
      <div class="rows mt-3">
        <Row icon="users" tone={rec?.proofs.witness ? "mint" : ""} title="Witnesses"
          sub={rec?.contacts.n ? `${rec.contacts.names.join(", ")} · any ${rec.contacts.threshold}${rec.contacts.scheme !== "quorum" ? " · older setup" : ""}` : "People you trust, who approve with their own face or fingerprint"}
          onClick={off ? undefined : () => setOpen("witnesses")} />
        <Row icon="passport" tone={rec?.proofs.anchor ? "mint" : ""} title="ID chip"
          sub={rec?.anchor.exists ? `Your ${rec.anchor.document}${rec.anchor.country ? ` · ${rec.anchor.country}` : ""}` : rec?.anchor.available ? "Your passport or ID card's chip" : "Not available on this server yet"}
          onClick={off ? undefined : () => setOpen("anchor")} />
        <Row icon="idcard" tone={rec?.proofs.card ? "mint" : ""} title="Recovery card"
          sub={rec?.card.exists ? `Made ${fmtDate(rec.card.createdAt)}${rec.card.scheme !== "quorum" ? " · older single-proof card" : ""}` : "A code you keep offline, away from your ID"}
          onClick={off ? undefined : () => setOpen("card")} />
        <Row icon="seckey" tone={rec?.proofs.key ? "mint" : ""} title="Security key"
          sub={rec?.keys?.list.length ? rec.keys.list.map((k) => k.name).join(", ") : rec && !rec.keys?.available ? "Not available on this server yet" : "A FIDO2 key with NFC, on your keyring"}
          onClick={off ? undefined : () => setOpen("key")} />
      </div>
      {rec?.legacy && <div class="mt-3"><Banner tone="amber" icon="info" title="Upgrade to two-proof recovery" text="You have an older card or witnesses that work on their own. Make a new recovery card and save your witnesses again to switch." /></div>}
      {!off && <NewPieces />}
      <section class="mt-5">
        <div class="eyebrow mb-2">How long a recovery waits</div>
        <div class="rows">{WAITS.map((w) => <Row chevron={false} title={w.pair} trail={w.wait} />)}</div>
        <p class="fine mt-2">Every device that still has your HumID is alerted and can veto during the wait.</p>
      </section>
      {open === "witnesses" && <WitnessesSheet onClose={() => setOpen(null)} />}
      {open === "anchor" && <AnchorSheet onClose={() => setOpen(null)} />}
      {open === "card" && <CardInfoSheet onClose={() => setOpen(null)} />}
      {open === "key" && <SecurityKeySheet onClose={() => setOpen(null)} />}
      </>}
      {off && <p class="fine mt-3">Offline: as of your last sync. Changing recovery needs a connection.</p>}
    </Pushed>
  );
}

/**
 * Removing a witness or replacing a card only stops it counting on this server: the old piece
 * still fits with the others. New pieces (a new epoch) can never be combined with old ones. Two
 * OLD pieces still fit each other, though, because the account key itself doesn't change
 * (V74-04; rotating it is VAULT-03): so the copy says to destroy them.
 */
function NewPieces() {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  if (!open) return <button class="link muted mt-3" onClick={() => setOpen(true)}>Lost a card, or dropped a witness you don't trust? Make new recovery pieces</button>;
  return (
    <div class="card mt-3">
      <h2 class="h3">Make new recovery pieces</h2>
      <p class="small t2 mt-2">Removing a witness or a card stops it counting on your vault server, but the piece itself still fits with your others. New pieces never fit with old ones, so a lost card or a removed witness's piece can't be combined with anything you make from now on.</p>
      <p class="small t2 mt-2"><b>Old pieces still fit each other.</b> Two of them together (your old card and a former witness's piece, say) could still rebuild your HumID's key, because the key itself stays the same. Destroy old recovery cards. (Witnesses' pieces are deleted from your vault server, but a witness, or an old server backup, could have kept a copy.)</p>
      <p class="small t2 mt-2">Your vault server deletes what it holds now, and you set up your proofs again: a new recovery card, your witnesses again, your ID chip and security keys again.</p>
      <div class="actions row" style={{ paddingTop: 8 }}>
        <button class="btn ghost" data-back onClick={() => setOpen(false)}>Not now</button>
        <button class="btn danger" disabled={busy} onClick={async () => { setBusy(true); try { if (await newRecoveryPieces()) { setOpen(false); loadRecovery(); } } finally { setBusy(false); } }}><Icon name="fingerprint" />Make new pieces</button>
      </div>
    </div>
  );
}

/* ---------------- the recovery mode ---------------- */

/** Why this phone doesn't trust what the server shows (core/recmode.js judgeMode). */
const UNTRUSTED = {
  unsigned: "It isn't signed by your HumID's own key.",
  missing: "It has disappeared from the server, though this phone remembers your choice.",
  "rolled back": "It's older than the choice this phone (or your activity record) remembers, as if someone put an old one back.",
  forked: "It doesn't follow from the choice this phone remembers.",
};

function ModeCard({ mode, off, onSwitch, onConfirm }) {
  if (!mode) return <div class="card"><span class="muted small">Checking how you can get back in…</span></div>;
  const holderOnly = mode.mode === HOLDER_ONLY;
  return (
    <div class="card">
      <div class="eyebrow">How you get back in</div>
      <h2 class="mt-2">{holderOnly ? "Only my own devices" : "A safe way back in"}</h2>
      <p class="small t2 mt-2">{holderOnly
        ? "Your vault opens only on devices you've already set up. HumID keeps no recovery for you, so if you lose every one of them, no one can bring it back, not even HumID."
        : `${RECOVERY_IF_LOST} Then there's a wait that any device you still have can cancel.`}</p>
      {!mode.trusted && <div class="mt-3"><Banner tone="danger" icon="alert" role="alert" title="Your vault server's record of this choice doesn't check out"
        text={`${UNTRUSTED[mode.reason] || UNTRUSTED.unsigned} This phone won't act on it: it treats your HumID as Only my own devices and won't make any recovery piece until the server shows your real choice again. Your documents aren't affected. Tell whoever runs your vault server.`} /></div>}
      {!holderOnly && mode.trusted && mode.vouched === false && <div class="mt-3"><Banner tone="amber" icon="shield" title="This phone can't confirm this choice yet"
        text={mode.legacy
          ? "Your vault server is too old to keep a choice signed with your HumID's key, so this phone has only the server's word for it. It won't make recovery pieces on that. Ask whoever runs your server to update it."
          : "Your choice is signed with your HumID's key, but this phone hasn't seen it before: it came back through recovery without it, or was set up before phones remembered it. Your vault server could be showing an older choice than your newest, and its public log can't prove otherwise. So this phone makes no recovery piece until you confirm the choice here, or add this phone again from another of your devices."}
        action={!off && !mode.legacy ? "Check and confirm" : undefined} onAction={onConfirm} /></div>}
      {!off && mode.trusted && <button class="btn quiet sm mt-3" onClick={onSwitch}>{holderOnly ? "Turn on recovery" : "Switch to only my own devices"}</button>}
    </div>
  );
}

/**
 * Confirm, on this phone, a hardened choice it can't vouch for (V74B-01). The history this phone
 * could verify comes first: if it shows a switch the holder doesn't remember, or the holder knows
 * they turned recovery off, they stop here.
 */
function ConfirmSheet({ onClose }) {
  const [busy, setBusy] = useState(false);
  const history = modeHistory();
  const words = (h) => h.mode === HOLDER_ONLY ? "Only my own devices" : "Recovery with two proofs";
  return (
    <Sheet onClose={onClose} eyebrow="Recovery" title="Is this still your choice?">
      <p class="t2 small">Your vault server says your HumID can be recovered with two proofs. Before this phone makes any recovery piece, check that's still what you want. Here's every change your activity record shows:</p>
      <div class="rows mt-3">
        {history.length ? history.map((h) => <Row chevron={false} icon={h.mode === HOLDER_ONLY ? "key" : "shield"} title={words(h)} sub={`${h.setup ? "Chosen at setup" : "Changed"}${h.at ? `, ${fmtDate(h.at)}` : ""}`} />)
          : <Row chevron={false} icon="info" title="No changes recorded" sub="Your activity record shows none" />}
      </div>
      <Banner tone="danger" icon="alert" title="Did you turn recovery off on another device?" text="Then stop: don't confirm. Your vault server may be showing this phone your older choice. Open HumID on that device instead, and tell whoever runs your vault server." />
      <p class="fine mt-2">Confirming takes one live check. It signs your choice again with your HumID's key and starts a fresh set of recovery pieces, so you set up your proofs again. Your other devices see it.</p>
      <div class="actions"><button class="btn primary block" disabled={busy} onClick={async () => { setBusy(true); try { if (await confirmModeHere()) onClose(); } finally { setBusy(false); } }}><Icon name="fingerprint" />Yes, confirm recovery here</button></div>
    </Sheet>
  );
}

function ModeSheet({ mode, onClose }) {
  const holderOnly = mode?.mode === HOLDER_ONLY;
  const left = escrowWords(mode?.escrow);
  const [sure, setSure] = useState(false);
  const [busy, setBusy] = useState(false);
  const run = async (fn) => { setBusy(true); try { if (await fn()) onClose(); } finally { setBusy(false); } };
  return holderOnly ? (
    <Sheet onClose={onClose} eyebrow="Recovery mode" title="Turn on a safe way back in">
      <p class="t2 small">You'll then set up two proofs: people you trust, your passport or ID card, a recovery card or a security key. Getting back in takes any two of them and a wait that any of your devices can cancel. Some of that proof is kept on HumID's servers. Your witnesses' pieces, your card's and your security key's are locked so the server can't open them; your passport's piece isn't (see ID chip).</p>
      <p class="fine mt-2">One live check signs this change with your HumID's key, and it's recorded in your activity.</p>
      <div class="actions"><button class="btn primary block" disabled={busy} onClick={() => run(switchToHardened)}><Icon name="fingerprint" />Turn on recovery</button></div>
    </Sheet>
  ) : (
    <Sheet onClose={onClose} eyebrow="Recovery mode" title="Only my own devices">
      <p class="t2 small">Your vault will open only on devices you've already set up. If you lose every one of them, <b>no one can get your documents back</b>: not your witnesses, not your ID, not HumID.</p>
      {left.length > 0 && <Banner tone="amber" icon="trash" title="This deletes your recovery proofs first" text={`Your ${left.join(", ")} will be deleted from your vault server, one at a time, each with its own live check. Only then does the switch happen.`} />}
      <Banner tone="danger" icon="alert" title="Old pieces still fit each other" text="This stops your vault server from keeping or using any recovery piece. But pieces made before (your printed recovery card, a witness's piece, copies in old server backups) can still rebuild your HumID's key offline if two of them come together, because the key itself doesn't change. Destroy your old recovery cards. Your witnesses' pieces are deleted from the server, but a witness or an old backup could have kept a copy. Full protection needs a new account key, which HumID can't make yet." />
      <button class="toggle mt-3" role="checkbox" aria-checked={sure} onClick={() => setSure(!sure)}>
        <span><span class="title">I understand: lose every device, lose my vault</span></span>
        <span class="lead" style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: sure ? "var(--mint)" : "var(--surface-3)", color: "var(--mint-ink)" }}>{sure && <Icon name="check" />}</span>
      </button>
      <div class="actions"><button class="btn danger block" disabled={busy || !sure} onClick={() => run(switchToHolderOnly)}><Icon name="fingerprint" />{left.length ? "Delete my proofs and switch" : "Switch"}</button></div>
    </Sheet>
  );
}

/* ---------------- recovery card ---------------- */

function CardInfoSheet({ onClose }) {
  const rec = S.recovery.value;
  const has = rec?.card.exists;
  return (
    <Sheet onClose={onClose} eyebrow="Recovery card · one of four proofs" title={has ? `Your card was made ${fmtDate(rec.card.createdAt)}` : "Make a recovery card"}>
      <p class="t2 small">A code you write down or print and keep away from your ID. With your witnesses, your ID chip or a security key it brings your vault back on a new phone. HumID stores only a piece locked by the card, which it can't open.</p>
      {has && rec.card.scheme !== "quorum" && <Banner tone="amber" icon="info" title="This is an older card" text="It works on its own after 72 hours. A new recovery card replaces it and always needs a second proof." />}
      <div class="actions">
        <button class="btn primary block" onClick={async () => { if (await makeNewCard()) onClose(); }}><Icon name="fingerprint" />{has ? "Make a new card (the old one stops counting on your server)" : "Make my card"}</button>
        {has && <button class="btn danger block" onClick={async () => { if (await removeCard()) onClose(); }}><Icon name="fingerprint" />Remove my card</button>}
      </div>
    </Sheet>
  );
}

/* ---------------- security keys (4.0) ---------------- */

function SecurityKeySheet({ onClose }) {
  const rec = S.recovery.value;
  const keys = rec?.keys?.list || [];
  const max = rec?.keys?.max || 4;
  const restored = draft.value?.kind === "seckey" ? draft.value.state : null;
  const [name, setName] = useState(restored?.name || "");
  const [pin, setPin] = useState("");
  const [newPin, setNewPin] = useState(false);
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState(null);
  const [reader, setReader] = useState(S.nfc.value);
  useEffect(() => { keyReader().then(setReader).catch(() => setReader({ available: false })); }, []);
  // The name survives a lock; a PIN never leaves this form.
  useEffect(() => { setDraft("seckey", name ? { name } : null); }, [name]);
  const available = rec?.keys?.available !== false;
  const enough = [...pin.normalize("NFC")].length >= (newPin ? 6 : 4);
  const usable = available && reader?.available && !busy;
  // Never a dead button: a tap with something missing says what, and puts the cursor there.
  const missing = () => {
    if (!enough) return ["key-pin", newPin ? "Choose a PIN of at least 6 characters." : "Type your key's PIN first."];
    if (newPin && pin !== again) return ["key-pin-again", "Type the same PIN again."];
    return null;
  };
  const add = async () => {
    const m = missing();
    if (m) { setProblem({ code: "missing", message: m[1] }); document.getElementById(m[0])?.focus(); return; }
    setBusy(true); setProblem(null);
    const r = await addSecurityKey({ name: name.trim() || `Security key ${keys.length + 1}`, pin, newPin });
    setBusy(false);
    if (r.ok) { setPin(""); setAgain(""); setName(""); setNewPin(false); clearDraft(); return; }
    if (r.pinError) {
      setProblem(r.pinError);
      if (r.pinError.code === "pin_not_set") { setNewPin(true); setAgain(""); }
      if (r.pinError.code === "pin_already_set") { setNewPin(false); setPin(""); setAgain(""); }
      if (r.pinError.code === "pin_invalid") setPin("");
    } else { setPin(""); setAgain(""); } // any other failure: the PIN doesn't linger in the form
  };
  return (
    <Sheet onClose={onClose} eyebrow="Security key · one of four proofs" title={keys.length ? (keys.length === 1 ? "Your security key" : `Your ${keys.length} security keys`) : "Add a security key"}>
      <p class="t2 small">A FIDO2 security key with NFC, like a YubiKey 5 NFC, on your keyring. Its secret never leaves it, it answers only with its PIN, and it locks itself after eight wrong tries. With any one other proof it brings your vault back. HumID never stores a fingerprint or a face, and can't open what your key locks.</p>
      <p class="fine mt-2">Type its PIN only into HumID, and hold it only to your own phone: an app that has your key and its PIN can read the key's answer.</p>
      {!available && <Banner tone="amber" icon="globe" title="Not available on this server yet" text="Your vault server needs HumID Server 4.0. Use witnesses, your ID chip and a recovery card for now." />}
      {keys.length > 0 && (
        <div class="rows mt-3">
          {keys.map((k) => (
            <Row key={k.id} icon="seckey" tone="mint" chevron={false} title={k.name} sub={`Added ${fmtDate(k.createdAt)}`}
              trail={<button class="link muted" disabled={busy} onClick={async () => { setBusy(true); await removeSecurityKey(k); setBusy(false); }}>Remove</button>} />
          ))}
        </div>
      )}
      {keys.length === 1 && <p class="fine mt-2">Add a second key and keep it somewhere else. Lose one, and the other still counts.</p>}
      {rec?.proofs.card && <p class="fine mt-2">Keep your key apart from your recovery card: together, without anyone else, they wait 7 days.</p>}
      {available && keys.length < max && (
        <div class="card mt-3">
          <div class="eyebrow mb-2">{keys.length ? "Add another key" : "Add your key"}</div>
          <div class="field">
            <label for="key-name">A name for it</label>
            <input autocorrect="off" spellcheck={false} autocomplete="off" id="key-name" class="input" value={name} maxLength={40} placeholder="e.g. Blue key on my keyring" onInput={(e) => setName(e.currentTarget.value)} />
          </div>
          <div class="field">
            <label for="key-pin">{newPin ? "Choose a PIN for the key (6 or more characters)" : "The key's PIN"}</label>
            <input id="key-pin" class="input code" type="password" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={63} value={pin} onInput={(e) => { setPin(e.currentTarget.value); setProblem(null); }} aria-describedby="key-pin-hint" />
            {problem && <span id="key-pin-hint" class="hint danger" role="alert">{problem.message}</span>}
            {!problem && <span id="key-pin-hint" class="hint">{newPin ? "The key keeps it and checks it. HumID never stores it." : "Only the key checks it. It goes to the key encrypted, never to HumID's server, and isn't stored."}</span>}
          </div>
          {newPin && (
            <div class="field">
              <label for="key-pin-again">Type it again</label>
              <input id="key-pin-again" class="input code" type="password" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={63} value={again} onInput={(e) => setAgain(e.currentTarget.value)} />
              {again && pin !== again && <span class="hint amber">The two PINs don't match yet.</span>}
            </div>
          )}
          <Toggle checked={newPin} label="My key doesn't have a PIN yet" hint="HumID gives it the one you choose. The key keeps it; HumID doesn't."
            onChange={(v) => { setNewPin(v); setProblem(null); setAgain(""); }} />
          <button class="btn primary block mt-3" disabled={!usable} onClick={add}><Icon name="fingerprint" />Hold the key to {reader?.kind === "reader" ? "the reader" : "the phone"}, then confirm</button>
          <p class="fine mt-2">{reader && !reader.available
            ? (reader.reason || "This device can't reach a security key. Use the HumID app on a phone with NFC, or a computer with a contactless card reader.")
            : "One tap: the key makes HumID's credential and proves it's there. Then your face or fingerprint seals your key's part of recovery."}</p>
        </div>
      )}
      {available && keys.length >= max && <p class="fine mt-3">You have {max} keys, the most HumID keeps. Remove one to add another.</p>}
    </Sheet>
  );
}

/* ---------------- witnesses ---------------- */

const STEPS_FOR_A_WITNESS = (me) => `${me || "I"} chose you as a HumID witness. In HumID, go to You → Help others → Be a witness, and send me the code it shows (or let me scan it). You'll never see my documents; if I ever lose my phone, you approve with your own face or fingerprint. Thanks!`;

function WitnessesSheet({ onClose }) {
  const rec = S.recovery.value;
  const restored = draft.value?.kind === "witnesses" ? draft.value.state : null;
  const [me, setMe] = useState(restored?.me || "");
  const [rows, setRows] = useState(restored?.rows || []);
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [shared, setShared] = useState(false);
  useEffect(() => { setDraft("witnesses", rows.length || me ? { me, rows } : null); }, [me, rows]);
  const add = async (c = code) => {
    if (busy || !twelve(c)) return;
    if (rows.some((r) => r.code.replace(/[^0-9a-z]/gi, "").toUpperCase() === c.replace(/[^0-9a-z]/gi, "").toUpperCase())) { toast("That witness is already in your list.", "warn"); return; }
    setBusy(true);
    const offer = await findContact(c);
    setBusy(false);
    if (!offer) return;
    setRows([...rows, { code: c, name: name.trim() || `Witness ${rows.length + 1}`, offer, at: Date.now() }]);
    setCode(""); setName("");
  };
  const remove = (i) => setRows(rows.filter((_, j) => j !== i));
  const n = rows.length, t = threshold(Math.max(n, MIN_WITNESSES));
  const save = async () => {
    setBusy(true);
    const ok = await saveContacts(rows.map((r) => ({ code: r.code, name: r.name, offer: r.offer })), me.trim());
    setBusy(false);
    if (ok) { clearDraft(); onClose(); }
  };
  const share = async () => {
    const text = STEPS_FOR_A_WITNESS(me.trim());
    try { if (navigator.share) { await navigator.share({ text }); return; } } catch { /* fall through */ }
    setShared(true);
  };
  return (
    <Sheet onClose={onClose} eyebrow="Witnesses · one of four proofs" title="Choose people who know you">
      <p class="t2 small">When a majority of them approve, each with their own face or fingerprint, that counts as one proof it's you. They never learn your key, and even all of them together can't open your vault without a second proof.</p>
      {rec?.contacts.n > 0 && <Banner tone="amber" icon="info" title={`Replaces ${rec.contacts.names.join(", ")}`} text="Their pieces stop working when you save new witnesses." />}
      <div class="field">
        <label for="owner-name">Your name, as they know you</label>
        <input autocorrect="off" spellcheck={false} autocomplete="off" id="owner-name" class="input" value={me} maxLength={40} placeholder="e.g. Parker" onInput={(e) => setMe(e.currentTarget.value)} />
      </div>
      <div class="row-x mt-3">
        <button class="btn quiet sm" type="button" onClick={share}><Icon name="users" />Send a witness the steps</button>
      </div>
      {shared && <p class="small t2 selectable mt-2">{STEPS_FOR_A_WITNESS(me.trim())}</p>}

      {rows.length > 0 && (
        <div class="rows mt-3">
          {rows.map((r, i) => (
            <Row key={r.code} icon="user" tone="mint" chevron={false} title={r.name}
              sub={<>Verified{r.offer?.expiresAt ? <> · their code expires in <Countdown until={r.offer.expiresAt} expired="now; ask for a new one" /></> : ""}</>}
              trail={<button class="link muted" onClick={() => remove(i)}>Remove</button>} />
          ))}
        </div>
      )}
      {rows.length < MAX_WITNESSES && (
        <div class="card mt-3">
          <div class="eyebrow mb-2">Add a witness</div>
          <div class="field"><label for={`wit-name`}>Their name</label><input autocorrect="off" spellcheck={false} autocomplete="off" id="wit-name" class="input" value={name} maxLength={40} onInput={(e) => setName(e.currentTarget.value)} /></div>
          <CodeInput id="wit-code" label="Their witness code" value={code} onInput={setCode} expect="contact" onScanned={(c) => add(c)} />
          <button class="btn quiet block mt-2" disabled={busy || !twelve(code)} onClick={() => add()}>Check and add</button>
          <p class="fine mt-2">Each witness gets their code from HumID → You → Help others → Be a witness. It's checked against their keys as soon as you add it.</p>
        </div>
      )}
      <div class="actions">
        <button class="btn primary block" disabled={busy || n < MIN_WITNESSES || !me.trim()} onClick={save}>
          <Icon name="fingerprint" />{n < MIN_WITNESSES ? `Add ${MIN_WITNESSES - n} more to save` : `Save ${n} witnesses · any ${t} count as a proof`}
        </button>
        {rec?.contacts.n > 0 && <button class="btn danger block" onClick={async () => { if (await removeContacts()) onClose(); }}><Icon name="fingerprint" />Remove all witnesses</button>}
      </div>
    </Sheet>
  );
}

/* ---------------- ID chip (the identity anchor) ---------------- */

/**
 * Linking the ID chip needs the chip itself, live: it answers a fresh challenge from the vault
 * server in the same read, so copied chip files can't link anyone's identity. Your recovery
 * piece is sealed on this phone to that one chip before it's sent (core/recovery.js setAnchor).
 */
function AnchorSheet({ onClose }) {
  const a = S.recovery.value?.anchor;
  const [name, setName] = useState("Demo Person");
  const [nfcOpen, setNfcOpen] = useState(false);
  const [access, setAccess] = useState(null);
  const [busy, setBusy] = useState(false);
  const nfc = S.nfc.value;
  const link = async (read) => { setBusy(true); try { if (await setAnchor(read)) onClose(); } finally { setBusy(false); } };
  const fromNfc = (nonce) => readChip(access, { nonce, purpose: "anchor" });
  const fromDemo = async (nonce) => { const c = await demoPassport(name); return c ? { ...c, aaSignature: await c.answer(nonce) } : null; };
  const older = a?.exists && a.version === 1;
  return (
    <Sheet onClose={onClose} eyebrow="ID chip · one of four proofs" title={a?.exists ? `Linked to your ${a.document}'s chip` : "Link HumID to your passport or ID chip"}>
      <p class="t2 small">The chip in your passport or ID card is signed by the country that issued it and can prove it's really there. Your recovery piece is tied to that one chip: another passport doesn't count, not an old one, not someone with the same name, and a copy of the chip's data can't link it. Later your chip proves it's you, live on your phone or in person at a HumID station.</p>
      <Banner tone="danger" icon="alert" title="Your vault server can open this piece" text="The key that locks your passport's piece comes from your chip's public data, which your vault server sees when you link it. So whoever runs that server holds this piece in a form they could open. With it and any ONE other of your proofs (a photo of your recovery card, say), they could get into your vault without the wait. If you don't want to trust the people running your server that far, use witnesses or a security key instead, or choose Only my own devices under Recovery." />
      <Banner tone="amber" icon="info" title="What HumID's server holds" text="Your recovery piece; a fingerprint of your chip's key, to find it; your document type and country. Your name and birth date pass through when you link or recover, and aren't kept. It's also the one proof that isn't anonymous: someone who runs the server and has your passport could match it to your HumID." />
      {older && <Banner tone="amber" icon="alert" title="Read your chip again" text="This link was made before recovery pieces were tied to one chip, so any passport with your name and birth date matched it. Read your passport or ID once more and HumID ties it to this chip only." />}
      <p class="fine mt-2">Renewed your passport? Link the new one here: the old one stops counting. Chips that can't prove they're present (some older ID cards) can't be a proof.</p>
      {!a?.available && <Banner tone="amber" icon="globe" title="Not available on this server yet" text="Its operator hasn't added the countries' signing certificates. Use witnesses and a recovery card for now." />}
      {a?.exists && <div class="rows mt-3"><Row chevron={false} title="Document" trail={`${a.document}${a.country ? ` · ${a.country}` : ""}`} /><Row chevron={false} title="Linked" trail={fmtDate(a.createdAt)} /></div>}
      {a?.available && (
        <>
          {nfcOpen ? (
            <>
              <ChipAccess onChange={setAccess} />
              <div class="actions">
                <button class="btn primary block" disabled={!access || busy} onClick={() => link(fromNfc)}><Icon name="nfc" />{nfc?.kind === "reader" ? "Read with the card reader" : "Hold to my phone and read"}</button>
                <button class="btn ghost block" data-back onClick={() => setNfcOpen(false)}>Back</button>
              </div>
            </>
          ) : (
            <div class="actions">
              <button class="btn primary block" disabled={!nfc?.available || busy} onClick={() => setNfcOpen(true)}><Icon name="nfc" />{a?.exists ? (older ? "Read my chip again" : "Link a different ID") : nfc?.kind === "reader" ? "Read the chip with the card reader" : "Read the chip with this phone"}</button>
              {!nfc?.available && <p class="small muted">{nfc?.reason || "Linking needs the chip itself, read live by a phone with NFC or a card reader."}</p>}
              {(typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) && (
                <div class="field mt-0">
                  <label for="demo-holder">Development build: demo passport holder</label>
                  <input autocorrect="off" spellcheck={false} autocomplete="off" id="demo-holder" class="input" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                  <button class="btn ghost block mt-2" disabled={busy} onClick={() => link(fromDemo)}><Icon name="passport" />Use a demo passport</button>
                </div>
              )}
            </div>
          )}
        </>
      )}
      {a?.exists && !nfcOpen && <div class="actions" style={{ paddingTop: 8 }}><button class="btn danger block" onClick={async () => { if (await removeAnchor()) onClose(); }}><Icon name="fingerprint" />Unlink this ID chip</button></div>}
    </Sheet>
  );
}
