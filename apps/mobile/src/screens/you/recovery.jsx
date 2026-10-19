// Recovery: the three proofs (witnesses · ID chip · recovery card); any two bring the
// vault back on a new phone. This screen shows which exist and opens each; progress
// lives on the Protection screen.
//
// Witnesses are gathered one at a time: each code is checked the moment it's complete,
// the list is kept as a draft across a lock, and one check saves the set.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Sheet, Banner, Row } from "../../ui/kit.jsx";
import { CodeInput, ChipAccess, ProofMeter, PROOFS, WAITS } from "../../ui/codes.jsx";
import { fmtDate } from "../../ui/format.js";
import * as S from "../../core/state.js";
import { DEMO_BUILD } from "../../core/config.js";
import {
  loadRecovery, makeNewCard, removeCard, findContact, saveContacts, removeContacts, readChipFiles, demoPassport, setAnchor, removeAnchor,
  readChip, chipReader, markPicking, setDraft, clearDraft, draft, toast,
} from "../../core/index.js";
import { back, twelve, Countdown } from "./common.jsx";

const MIN_WITNESSES = 2, MAX_WITNESSES = 5;
const threshold = (n) => Math.floor(n / 2) + 1;

export function Recovery() {
  const rec = S.recovery.value;
  const [open, setOpen] = useState(S.push.value?.open || null); // witnesses | anchor | card
  useEffect(() => { loadRecovery(); chipReader(); }, []);
  const off = !!S.offline.value;
  return (
    <Pushed title="Recovery" onBack={back}>
      <p class="t2 small">If you lose every device, any <b>two</b> of these three prove it's you. HumID never holds a key that opens your vault, and one proof alone never does.</p>
      {rec && <ProofMeter have={PROOFS.map((p) => p.id).filter((k) => rec.proofs[k])} />}
      <div class="rows" style={{ marginTop: 14 }}>
        <Row icon="users" tone={rec?.proofs.witness ? "mint" : ""} title="Witnesses"
          sub={rec?.contacts.n ? `${rec.contacts.names.join(", ")} · any ${rec.contacts.threshold}${rec.contacts.scheme !== "quorum" ? " · older setup" : ""}` : "People you trust, who approve with their own face or fingerprint"}
          onClick={off ? undefined : () => setOpen("witnesses")} />
        <Row icon="passport" tone={rec?.proofs.anchor ? "mint" : ""} title="ID chip"
          sub={rec?.anchor.exists ? `Your ${rec.anchor.document}${rec.anchor.country ? ` · ${rec.anchor.country}` : ""}` : rec?.anchor.available ? "Your passport or ID card's chip" : "Not available on this server yet"}
          onClick={off ? undefined : () => setOpen("anchor")} />
        <Row icon="idcard" tone={rec?.proofs.card ? "mint" : ""} title="Recovery card"
          sub={rec?.card.exists ? `Made ${fmtDate(rec.card.createdAt)}${rec.card.scheme !== "quorum" ? " · older single-proof card" : ""}` : "A code you keep offline, away from your ID"}
          onClick={off ? undefined : () => setOpen("card")} />
      </div>
      {rec?.legacy && <div style={{ marginTop: 14 }}><Banner tone="amber" icon="info" title="Upgrade to two-proof recovery" text="You have an older card or witnesses that work on their own. Make a new recovery card and save your witnesses again to switch." /></div>}
      <section style={{ marginTop: 20 }}>
        <div class="eyebrow" style={{ marginBottom: 8 }}>How long a recovery waits</div>
        <div class="rows">{WAITS.map((w) => <Row chevron={false} title={w.pair} trail={w.wait} />)}</div>
        <p class="fine" style={{ marginTop: 8 }}>Every device that still has your HumID is alerted and can veto during the wait.</p>
      </section>
      {off && <p class="fine" style={{ marginTop: 12 }}>Offline: as of your last sync. Changing recovery needs a connection.</p>}
      {open === "witnesses" && <WitnessesSheet onClose={() => setOpen(null)} />}
      {open === "anchor" && <AnchorSheet onClose={() => setOpen(null)} />}
      {open === "card" && <CardInfoSheet onClose={() => setOpen(null)} />}
    </Pushed>
  );
}

/* ---------------- recovery card ---------------- */

function CardInfoSheet({ onClose }) {
  const rec = S.recovery.value;
  const has = rec?.card.exists;
  return (
    <Sheet onClose={onClose} eyebrow="Recovery card · one of three proofs" title={has ? `Your card was made ${fmtDate(rec.card.createdAt)}` : "Make a recovery card"}>
      <p class="t2 small">A code you write down or print and keep away from your ID. With your witnesses or your ID chip it brings your vault back on a new phone. HumID stores only a piece locked by the card, which it can't open.</p>
      {has && rec.card.scheme !== "quorum" && <Banner tone="amber" icon="info" title="This is an older card" text="It works on its own after 72 hours. A new recovery card replaces it and always needs a second proof." />}
      <div class="actions">
        <button class="btn primary block" onClick={async () => { if (await makeNewCard()) onClose(); }}><Icon name="fingerprint" />{has ? "Make a new card (the old one stops working)" : "Make my card"}</button>
        {has && <button class="btn danger block" onClick={async () => { if (await removeCard()) onClose(); }}><Icon name="fingerprint" />Remove my card</button>}
      </div>
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
    <Sheet onClose={onClose} eyebrow="Witnesses · one of three proofs" title="Choose people who know you">
      <p class="t2 small">When a majority of them approve, each with their own face or fingerprint, that counts as one proof it's you. They never learn your key, and even all of them together can't open your vault without a second proof.</p>
      {rec?.contacts.n > 0 && <Banner tone="amber" icon="info" title={`Replaces ${rec.contacts.names.join(", ")}`} text="Their pieces stop working when you save new witnesses." />}
      <div class="field">
        <label for="owner-name">Your name, as they know you</label>
        <input autocorrect="off" spellcheck={false} autocomplete="off" id="owner-name" class="input" value={me} maxLength={40} placeholder="e.g. Parker" onInput={(e) => setMe(e.currentTarget.value)} />
      </div>
      <div class="row-x" style={{ marginTop: 10 }}>
        <button class="btn quiet sm" type="button" onClick={share}><Icon name="users" />Send a witness the steps</button>
      </div>
      {shared && <p class="small t2 selectable" style={{ marginTop: 8 }}>{STEPS_FOR_A_WITNESS(me.trim())}</p>}

      {rows.length > 0 && (
        <div class="rows" style={{ marginTop: 14 }}>
          {rows.map((r, i) => (
            <Row key={r.code} icon="user" tone="mint" chevron={false} title={r.name}
              sub={<>Verified{r.offer?.expiresAt ? <> · their code expires in <Countdown until={r.offer.expiresAt} expired="now; ask for a new one" /></> : ""}</>}
              trail={<button class="link muted" onClick={() => remove(i)}>Remove</button>} />
          ))}
        </div>
      )}
      {rows.length < MAX_WITNESSES && (
        <div class="card" style={{ marginTop: 14 }}>
          <div class="eyebrow" style={{ marginBottom: 8 }}>Add a witness</div>
          <div class="field"><label for={`wit-name`}>Their name</label><input autocorrect="off" spellcheck={false} autocomplete="off" id="wit-name" class="input" value={name} maxLength={40} onInput={(e) => setName(e.currentTarget.value)} /></div>
          <CodeInput id="wit-code" label="Their witness code" value={code} onInput={setCode} expect="contact" onScanned={(c) => add(c)} />
          <button class="btn quiet block" style={{ marginTop: 8 }} disabled={busy || !twelve(code)} onClick={() => add()}>Check and add</button>
          <p class="fine" style={{ marginTop: 8 }}>Each witness gets their code from HumID → You → Help others → Be a witness. It's checked against their keys as soon as you add it.</p>
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

function AnchorSheet({ onClose }) {
  const a = S.recovery.value?.anchor;
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
    <Sheet onClose={onClose} eyebrow="ID chip · one of three proofs" title={a?.exists ? `Linked to your ${a.document}'s chip` : "Link HumID to your passport or ID chip"}>
      <p class="t2 small">The chip in your passport or ID card is signed by the country that issued it. HumID checks that signature and keeps only a keyed fingerprint of the details that stay the same when you renew. Later, your chip proves it's you: in person at a HumID station, or live on your phone.</p>
      {!a?.exists && <Banner tone="amber" icon="info" title="The one proof that isn't anonymous" text="Someone holding this vault's secret and your passport details could confirm you have a HumID. Witnesses and your recovery card don't reveal who you are. Skip this if anonymity matters more than convenience." />}
      {!a?.available && <Banner tone="amber" icon="globe" title="Not available on this server yet" text="Its operator hasn't added the countries' signing certificates. Use witnesses and a recovery card for now." />}
      {a?.exists && <div class="rows" style={{ marginTop: 12 }}><Row chevron={false} title="Document" trail={`${a.document}${a.country ? ` · ${a.country}` : ""}`} /><Row chevron={false} title="Linked" trail={fmtDate(a.createdAt)} /></div>}
      {a?.available && (
        <>
          <input ref={files} type="file" multiple hidden accept=".json,.bin,.dat,application/json,application/octet-stream" onChange={onFiles} />
          {!chip && nfcOpen && (
            <>
              <ChipAccess onChange={setAccess} />
              <div class="actions">
                <button class="btn primary block" disabled={!access} onClick={read}><Icon name="nfc" />{nfc?.kind === "reader" ? "Read with the card reader" : "Hold to my phone and read"}</button>
                <button class="btn ghost block" data-back onClick={() => setNfcOpen(false)}>Back</button>
              </div>
            </>
          )}
          {!chip && !nfcOpen && (
            <div class="actions">
              <button class="btn primary block" disabled={!nfc?.available} onClick={() => setNfcOpen(true)}><Icon name="nfc" />{nfc?.kind === "reader" ? "Read the chip with the card reader" : "Read the chip with this phone"}</button>
              {!nfc?.available && nfc?.reason && <p class="small muted">{nfc.reason}</p>}
              <button class="btn ghost block" onClick={pick}><Icon name="file" />Load chip data from a file</button>
              {DEMO_BUILD && (
                <div class="field" style={{ marginTop: 0 }}>
                  <label for="demo-holder">Development build: demo passport holder</label>
                  <input autocorrect="off" spellcheck={false} autocomplete="off" id="demo-holder" class="input" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                  <button class="btn ghost block" style={{ marginTop: 8 }} onClick={async () => setChip(await demoPassport(name))}><Icon name="passport" />Use a demo passport</button>
                </div>
              )}
            </div>
          )}
          {chip && (
            <>
              <Banner tone="mint" icon="check" title={chip.access ? `Chip read · ${chip.access}` : `Chip data loaded${chip.demo ? " (demo)" : ""}`} text={`Your vault server checks its country signature next. ${chip.dg15 ? "This chip can also prove it's present, live." : "This chip can't prove it's present live, so recovering with it will need a HumID station."}`} />
              <div class="actions">
                <button class="btn primary block" onClick={async () => { if (await setAnchor(chip)) onClose(); }}><Icon name="fingerprint" />{a?.exists ? "Replace with this ID" : "Link this ID chip"}</button>
                <button class="btn ghost block" data-back onClick={() => setChip(null)}>Choose another</button>
              </div>
            </>
          )}
        </>
      )}
      {a?.exists && !chip && <div class="actions" style={{ paddingTop: 8 }}><button class="btn danger block" onClick={async () => { if (await removeAnchor()) onClose(); }}><Icon name="fingerprint" />Unlink this ID chip</button></div>}
    </Sheet>
  );
}
