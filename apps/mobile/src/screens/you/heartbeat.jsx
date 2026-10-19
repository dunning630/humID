// Heartbeat (the server calls it check-in): arm a timer before a high-stakes situation,
// then send one live check before each deadline, or your vault locks, then is erased for
// good. Times are your vault's: the countdown uses the server's clock, not the phone's.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Banner, Toggle } from "../../ui/kit.jsx";
import { fmtTime, fmtAgo } from "../../ui/format.js";
import * as S from "../../core/state.js";
import { loadCheckin, armCheckin, checkIn, disarmCheckin, clockOffset } from "../../core/index.js";
import { back, Choice, Countdown, Head } from "./common.jsx";

const H = 3_600_000, MIN = 60_000;
const hours = (ms) => (ms % H === 0 ? `${ms / H} h` : `${Math.round(ms / MIN)} min`);
const graceLabel = (ms) => (ms ? `${ms / MIN} min` : "None");

export function Heartbeat() {
  const st = S.checkin.value || { state: "off" };
  const pol = S.server.value?.policy?.checkin || { windowsH: [1, 2, 4, 8, 24], graceMin: [0, 15, 30, 60] };
  const on = st.state === "armed" || st.state === "locked";
  const windows = pol.windowsH.map((h) => h * H);
  const graces = pol.graceMin.map((m) => m * MIN);
  const [win, setWin] = useState(on ? st.windowMs : 2 * H);
  const [max, setMax] = useState(on ? st.maxWindowMs : 8 * H);
  const [grace, setGrace] = useState(on ? st.graceMs : 15 * MIN);
  const [next, setNext] = useState(on ? st.windowMs : 2 * H);
  const [understood, setUnderstood] = useState(on);
  const [unsplit, setUnsplit] = useState(null);
  const [busy, setBusy] = useState(false);
  const decoy = S.decoy.value;
  const off = !!S.offline.value;
  useEffect(() => { loadCheckin(); }, []);
  const offsetMs = st.offsetMs ?? clockOffset();
  const skew = Math.abs(offsetMs) > 60_000;
  const decoys = decoy ? 0 : S.items.value.filter((i) => i.decoy).length;
  // sealed before split keys: their second key isn't on the server, so an erase couldn't be final
  const older = unsplit || (decoy ? [] : S.items.value.filter((i) => !i.split).map((i) => ({ id: i.id, name: i.name })));
  const changed = !on || win !== st.windowMs || Math.max(max, win) !== st.maxWindowMs || grace !== st.graceMs;
  const run = async (fn) => { setBusy(true); try { return await fn(); } finally { setBusy(false); } };
  const arm = () => run(async () => {
    const r = await armCheckin({ windowMs: win, maxWindowMs: Math.max(max, win), graceMs: grace });
    if (r.unsplit) setUnsplit(r.unsplit);
    else if (r.ok) back();
  });
  return (
    <Pushed title="Heartbeat" onBack={back}>
      {off && <Banner tone="amber" icon="wifi_off" title="No signal" text="No signal means you can't send a heartbeat, and HumID won't show the timer. Get back online before a deadline." />}
      {st.state === "erased" && <Banner tone="danger" icon="trash" title="Your vault was erased by Heartbeat" text={`${fmtAgo(st.erasedAt)}. Its documents can't be opened again. Your HumID still works, and anything sealed since is here.`} />}

      <div class="eyebrow">{on ? (st.state === "locked" ? "Missed" : "On") : "Off"}</div>
      <h2 style={{ marginTop: 6 }}>{on ? (st.state === "locked" ? "You missed a heartbeat" : `Next heartbeat by ${fmtTime(st.deadline)}`) : "If you can't send a heartbeat, erase your vault"}</h2>
      <p class="t2 small" style={{ marginTop: 10 }}>
        {on
          ? st.state === "locked"
            ? <>Your vault opens nothing until you send one. If you don't, it's erased for good in <Countdown until={st.erasesAt} offsetMs={offsetMs} />.</>
            : <><Countdown until={st.deadline} offsetMs={offsetMs} /> left. Miss it and your vault locks; {st.graceMs ? `${st.graceMs / MIN} minutes later` : "at once"} it's erased for good.</>
          : "Turn this on before you go somewhere you could be detained or lose your phone. Send a heartbeat (one face or fingerprint check) before each deadline. Miss one and your vault locks; when the grace time runs out, your vault server destroys the keys to your documents, and they're gone for good."}
      </p>
      {on && skew && <p class="small amber" style={{ marginTop: 6 }}>Your phone's clock is {Math.round(Math.abs(offsetMs) / 60_000)} min off. Times here are your vault's, which is what counts.</p>}

      {on && !off && (
        <div class="card" style={{ marginTop: 14 }}>
          <Choice id="hb-next" label="Next window" hint="Need longer, like overnight? Pick it as you send this one." value={next}
            options={windows.filter((v) => v <= st.maxWindowMs).map((v) => [v, hours(v)])} onPick={setNext} />
          <div class="actions" style={{ marginTop: 4, paddingTop: 8 }}>
            <button class="btn primary block" disabled={busy} onClick={() => run(async () => { if (await checkIn(next === st.windowMs ? undefined : next)) back(); })}><Icon name="fingerprint" />Send a heartbeat now</button>
          </div>
        </div>
      )}

      <div class="card" style={{ marginTop: 14 }}>
        <Head title="Settings" />
        <Choice id="hb-win" label="A heartbeat every" value={win} options={windows.map((v) => [v, hours(v)])} onPick={(v) => { setWin(v); if (max < v) setMax(v); }} />
        <Choice id="hb-max" label="Longest single window" hint="For the night: when you send a heartbeat, you can choose a longer window up to this." value={Math.max(max, win)}
          options={windows.filter((v) => v >= win).map((v) => [v, hours(v)])} onPick={setMax} />
        <Choice id="hb-grace" label="Grace after a missed heartbeat" hint="Your vault is locked meanwhile; a heartbeat opens it again." value={grace}
          options={graces.map((v) => [v, graceLabel(v)])} onPick={setGrace} />
      </div>

      <div style={{ marginTop: 12 }}>
        <Banner tone="amber" icon="alert" title="Nobody can undo an erase" text="Not you, not your witnesses, not HumID. HumID can't remind you while it's closed, so set an alarm for each heartbeat. No signal means you can't send one, and HumID won't show the timer." />
      </div>
      <p class="small muted">
        {decoys ? `The ${decoys} document${decoys === 1 ? "" : "s"} you marked for the decoy view stay${decoys === 1 ? "s" : ""}, so a forced unlock still looks normal. ` : "Documents you mark for the decoy view stay, so a forced unlock still looks normal. "}
        While Heartbeat is on, unlocking with your duress gesture erases your vault at once, and nothing is kept on this phone, so HumID won't open offline.
      </p>

      {older.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <Banner tone="danger" icon="info" title={older.length === 1 ? "One document needs sealing again first" : `${older.length} documents need sealing again first`}
            text={`${older.slice(0, 4).map((o) => o.name).join(", ")}${older.length > 4 ? ` and ${older.length - 4} more` : ""}: sealed before split keys, so Heartbeat couldn't erase ${older.length === 1 ? "it" : "them"} for good. Save a copy, add it again, then delete the old one, or just delete it.`} />
        </div>
      )}

      {!on && <div class="card" style={{ marginTop: 12 }}><Toggle label="I understand my documents can be erased for good" checked={understood} onChange={setUnderstood} /></div>}
      <div class="actions">
        {(!on || changed) && (
          <button class={`btn ${on ? "quiet" : "primary"} block`} disabled={off || !understood || busy || older.length > 0} onClick={arm}>
            <Icon name="fingerprint" />{on ? "Save settings and send a heartbeat" : "Turn on Heartbeat"}
          </button>
        )}
        {on && <button class="btn ghost block" disabled={off || busy} onClick={() => run(async () => { if (await disarmCheckin()) back(); })}><Icon name="fingerprint" />Turn off Heartbeat</button>}
      </div>
    </Pushed>
  );
}
