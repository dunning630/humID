// Help others: be someone's witness (a code they add you with), help a witness of yours
// get back in, and, for operators, the verification station.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Sheet, Banner, Row } from "../../ui/kit.jsx";
import { CodeBox, CodeInput, QrCode, ChipAccess } from "../../ui/codes.jsx";
import { fmtDate, fmtAgo } from "../../ui/format.js";
import * as S from "../../core/state.js";
import { DEMO_BUILD } from "../../core/config.js";
import { offerToBeContact, findHelpRequest, whoDoIProtect, releasePiece, stationLookup, stationReadChip, stationVerify, chipReader } from "../../core/index.js";
import { back, twelve, Countdown, Check } from "./common.jsx";

export function Help() {
  const [open, setOpen] = useState(S.push.value?.step || null); // witness | recover | station
  const [offer, setOffer] = useState(null);
  const decoy = S.decoy.value;
  const off = !!S.offline.value;
  const station = !decoy && S.station.value?.station;
  const beWitness = async () => { const o = await offerToBeContact(); if (o) { setOffer(o); setOpen("witness"); } };
  return (
    <Pushed title="Help others" onBack={back}>
      <p class="t2 small">Be one of someone's witnesses, or help a witness of yours get back in. You never see anyone's documents.</p>
      <div class="rows mt-3">
        <Row icon="users" title="Be a witness" sub="Show a code to someone choosing their witnesses" onClick={off ? undefined : beWitness} />
        <Row icon="user" title="Help someone recover" sub="A witness of yours lost their phone and sent you a code" onClick={off ? undefined : () => setOpen("recover")} />
        {station && <Row icon="station" tone="mint" title="Verification station" sub="Check a person and their ID in person, so their recovery can count their ID chip" trail={<span class="pill mint">Operator</span>} onClick={off ? undefined : () => setOpen("station")} />}
      </div>
      {off && <p class="fine mt-3">Helping needs a connection.</p>}
      {open === "witness" && offer && <OfferSheet offer={offer} onRenew={beWitness} onClose={() => { setOpen(null); setOffer(null); }} />}
      {open === "recover" && <HelpSheet onClose={() => setOpen(null)} />}
      {open === "station" && station && <StationSheet onClose={() => setOpen(null)} />}
    </Pushed>
  );
}

function OfferSheet({ offer, onRenew, onClose }) {
  const expired = offer.expiresAt <= Date.now();
  return (
    <Sheet onClose={onClose} eyebrow="Be someone's witness" title="Give them this code">
      <p class="t2 small">They scan or type it when choosing witnesses. It lets them seal a piece to you. On your own, you can never open their vault.</p>
      <CodeBox code={offer.code} label="Witness code" />
      <QrCode kind="contact" code={offer.code} expiresAt={offer.expiresAt} />
      <p class="fine center"><Countdown until={offer.expiresAt} prefix="Expires in " expired="This code has expired." /></p>
      <div class="actions">
        {expired && <button class="btn primary block" onClick={onRenew}><Icon name="qr" />Make a new code</button>}
        <button class="btn ghost block" onClick={onClose}>Done</button>
      </div>
    </Sheet>
  );
}

function HelpSheet({ onClose }) {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [people, setPeople] = useState(null);
  const [pick, setPick] = useState(null);
  const [done, setDone] = useState(null);
  const [busy, setBusy] = useState(false);
  const find = async (c = code) => { if (busy) return; setBusy(true); setReq(await findHelpRequest(c)); setBusy(false); };
  const reveal = async () => { const p = await whoDoIProtect(); if (p) { setPeople(p); if (p.length === 1) setPick(p[0]); } };
  const release = async () => { const r = await releasePiece(req, pick); if (r) setDone(r); };
  return (
    <Sheet onClose={onClose} eyebrow="Help someone recover" title={done ? "Thanks. Your piece was sent" : people ? "Who is asking?" : req ? `A ${req.platform} is asking for help` : "Enter the code they sent you"}>
      {!req && (
        <>
          <p class="t2 small">Someone who chose you as a witness lost their devices. Their new phone shows a code and a QR code.</p>
          <CodeInput id="help-code" label="Recovery code" value={code} onInput={setCode} expect="recover" onScanned={(c) => find(c)} />
          <div class="actions"><button class="btn primary block" disabled={busy || !twelve(code)} onClick={() => find()}>Find request</button></div>
        </>
      )}
      {req && !people && (
        <>
          <Banner tone="mint" icon="check" title="Code matches that device's keys" text={`Requested ${fmtAgo(req.createdAt)}.`} />
          <p class="small muted">Next, one live check shows whose pieces you hold.</p>
          <div class="actions">
            <button class="btn primary block" onClick={reveal}><Icon name="fingerprint" />Show who I protect</button>
            <button class="btn ghost block" data-back onClick={() => setReq(null)}>Back</button>
          </div>
        </>
      )}
      {people && !done && (
        <>
          {people.length === 0 && <p class="t2 small">You aren't anyone's witness yet.</p>}
          <div class="options" role="radiogroup" aria-label="Who is asking">
            {people.map((p) => (
              <button class="option" role="radio" aria-checked={pick?.owner === p.owner} onClick={() => setPick(p)}>
                <span class="lead"><Icon name="user" /></span>
                <span><span class="title">{p.label}</span><span class="sub" style={{ display: "block" }}>Chose you {fmtDate(p.since)}</span></span>
                {pick?.owner === p.owner ? <Icon name="check" /> : <span />}
              </button>
            ))}
          </div>
          {pick && <div class="mt-3"><Banner tone="amber" icon="alert" title={`Call ${pick.label} first`} text="Only help if they asked you themselves. Someone pretending to be them is how recovery gets abused." /></div>}
          <div class="actions">
            <button class="btn primary block" disabled={!pick} onClick={release}><Icon name="fingerprint" />Release my piece to that device</button>
            <button class="btn ghost block" data-back onClick={() => { setPeople(null); setPick(null); }}>Back</button>
          </div>
        </>
      )}
      {done && (
        <>
          <p class="t2 small">{done.releaseAt
            ? <>Enough witnesses have helped. {pick.label}'s vault opens on their new device in about <Countdown until={done.releaseAt} />, unless they cancel it from a device they still have.</>
            : done.kinds ? `${done.approvals} of ${done.threshold} witnesses have approved. Their recovery also needs a second proof.` : `${done.approvals} of ${done.threshold} witnesses have helped so far.`}</p>
          <div class="actions"><button class="btn primary mint block" onClick={onClose}>Done</button></div>
        </>
      )}
    </Sheet>
  );
}

/* ---------------- verification station (operators) ---------------- */

function StationSheet({ onClose }) {
  const [code, setCode] = useState("");
  const [req, setReq] = useState(null);
  const [chip, setChip] = useState(null);
  const [access, setAccess] = useState(null);
  const nfc = S.nfc.value;
  const [checks, setChecks] = useState({ document: false, face: false, present: false });
  const [done, setDone] = useState(null);
  const [name, setName] = useState("Demo Person");
  const [busy, setBusy] = useState(false);
  useEffect(() => { chipReader(); }, []);
  const all = checks.document && checks.face && checks.present;
  const tick = (k) => (v) => setChecks({ ...checks, [k]: v });
  const find = async (c = code) => { if (busy) return; setBusy(true); setReq(await stationLookup(c)); setBusy(false); };
  return (
    <Sheet onClose={onClose} eyebrow="Verification station" title={done ? "Verified" : req ? `A ${req.platform} is recovering` : "Scan their recovery code"}>
      {!req && (
        <>
          <p class="t2 small">Their new phone shows it under Prove it's me.</p>
          <CodeInput id="station-code" label="Recovery code" value={code} onInput={setCode} expect="recover" onScanned={(c) => find(c)} />
          <div class="actions"><button class="btn primary block" disabled={busy || !twelve(code)} onClick={() => find()}>Find request</button></div>
        </>
      )}
      {req && !done && (
        <>
          <p class="small muted">Started {fmtAgo(req.createdAt)}. You won't see whose HumID it is.</p>
          {!chip ? (
            <div class="actions">
              {nfc?.available && (
                <>
                  <ChipAccess onChange={setAccess} title="Details from their document" />
                  <button class="btn primary block" disabled={!access} onClick={async () => { const r = await stationReadChip(req.code, { access }); if (r) setChip(r); }}><Icon name="nfc" />{nfc.kind === "reader" ? "Read with the card reader" : "Hold to this phone and read"}</button>
                </>
              )}
              {!nfc?.available && <p class="small muted">{nfc?.reason || "This device can't read ID chips."}</p>}
              {DEMO_BUILD && (
                <div class="field mt-0">
                  <label for="station-demo">Development build: demo passport holder</label>
                  <input autocorrect="off" spellcheck={false} autocomplete="off" id="station-demo" class="input" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                  <button class="btn ghost block mt-2" onClick={async () => setChip(await stationReadChip(req.code, { demo: name }))}><Icon name="passport" />Use a demo passport</button>
                </div>
              )}
              <button class="btn ghost block" data-back onClick={() => setReq(null)}>Back</button>
            </div>
          ) : (
            <>
              <div class="checklist">
                <Check checked={checks.document} onChange={tick("document")}>I've examined the physical document and it looks genuine and unaltered</Check>
                <Check checked={checks.face} onChange={tick("face")}>The person's face matches the document's photo</Check>
                <Check checked={checks.present} onChange={tick("present")}>The person is here with me, and is asking for this themselves</Check>
              </div>
              <div class="actions"><button class="btn primary block" disabled={!all} onClick={async () => { const r = await stationVerify(req.code, chip, checks); if (r) setDone(r); }}><Icon name="fingerprint" />Vouch for them</button></div>
            </>
          )}
        </>
      )}
      {done && (
        <>
          <p class="t2 small">{done.releaseAt ? <>Their vault opens on their new phone in about <Countdown until={done.releaseAt} />, unless one of their devices vetoes it.</> : "Their ID counts now. They still need one more proof: their witnesses or their recovery card."}</p>
          <p class="small muted">Recorded in your ledger and theirs.</p>
          <div class="actions"><button class="btn primary mint block" onClick={onClose}>Done</button></div>
        </>
      )}
    </Sheet>
  );
}
