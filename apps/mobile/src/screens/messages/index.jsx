// Messages (HumID 4.0, docs/MESSAGING.md): people you've approved, known only by an ID made
// for each of you. Nobody interacts here without a live check: inviting, asking, seeing who's
// asking, approving, sending and reading all need one (core/messaging.js says exactly where).
//
// v2 (after the first review): one vocabulary ("live check" is the act, "live" the state);
// presence in every conversation ("You ● Sam ●"), explained on tap; two people standing together
// go from invite to conversation without leaving the screen they're on; the safety code is on
// both phones while they connect; nothing claims more than the cryptography proves.
//
// Pushed screens this file routes (S.push.value.type): chat · invite · code · request · contact.
// Sheets this file owns: the "new" chooser, what "live" means, a message's actions.
import "../../brand/messages.css";
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Sheet, Banner, Row, Empty, Toggle, Confirm, useNow } from "../../ui/kit.jsx";
import { QrCode, Scanner } from "../../ui/codes.jsx";
import { fmtTime, fmtAgo, fmtLeft, dayLabel } from "../../ui/format.js";
import * as S from "../../core/state.js";
import * as Msg from "../../core/messaging.js";
import { buzz } from "../../core/index.js";

const go = (type, extra = {}) => { S.push.value = { type, ...extra }; };
const back = () => { if (S.push.value?.type === "chat") Msg.closeConversation(); S.push.value = null; };
const PUSHED = { chat: Chat, invite: Invite, code: EnterCode, request: Request, contact: Contact };
const ownLeft = (now) => (S.liveAt.value || 0) + Msg.LIVE_WINDOW_MS - now;

export function Messages() {
  const push = S.push.value;
  const Detail = push && PUSHED[push.type];
  return (
    <>
      <List />
      {Detail && <Detail key={`${push.type}:${push.id || ""}`} />}
    </>
  );
}

/* ---------------- the list ---------------- */

function List() {
  const m = S.msg.value;
  const [choosing, setChoosing] = useState(false);
  const [today, setToday] = useState(null);
  useEffect(() => { Msg.poll(); Msg.humanToday().then(setToday); }, []);
  const off = !!S.offline.value;
  const waiting = m?.contacts.reduce((n, c) => n + c.waiting, 0) || 0;
  return (
    <main class="screen tabs">
      <header class="top">
        <div class="grow"><h1>Messages</h1><div class="small muted">Only people you've approved. Each message confirmed by its sender's face or fingerprint.</div></div>
        {!off && m?.ready && m.canStamp && <button class="icon-btn" aria-label="New" onClick={() => setChoosing(true)}><Icon name="plus" /></button>}
      </header>
      {off && <Banner tone="amber" icon="info" title="Messages need a connection" text="Your conversations are safe on this phone. They open again when you're back online." />}
      {!m && !off && <Row chevron={false} title="Opening your messages…" />}
      {m?.error && <Banner tone="amber" icon="info" title="Messages aren't available" text={m.error} />}
      {m?.ready && !m.canStamp && <Banner tone="amber" icon="info" title="This device can't send" text="Connecting and sending each need a live face or fingerprint check that a phone's secure chip proves. This device has no such chip, so here you can only read what's already on it. Use HumID on your phone to talk." />}
      {m?.ready && (
        <>
          {m.contacts.length > 0 && <YouLive waiting={waiting} />}
          {m.requests.length > 0 && (
            <section style={{ marginTop: 14 }}>
              <div class="eyebrow">Asking to connect</div>
              <div class="rows">
                {m.requests.map((r) => (
                  <Row key={r.id} icon="users" tone="amber" title={r.label ? `${r.label} is asking to connect` : "Someone is asking to connect"}
                    sub={<>Used your invite · {fmtAgo(r.at)}</>}
                    onClick={() => go("request", { id: r.id })} />
                ))}
              </div>
            </section>
          )}
          {m.contacts.length > 0 && (
            <section style={{ marginTop: 14 }}>
              {(m.requests.length > 0 || m.invites.length > 0) && <div class="eyebrow">Conversations</div>}
              <div class="rows">
                {m.contacts.map((c) => <ContactRow key={c.id} c={c} />)}
              </div>
            </section>
          )}
          {m.invites.length > 0 && (
            <section style={{ marginTop: 14 }}>
              <div class="eyebrow">Invites out</div>
              <div class="rows">
                {m.invites.map((i) => (
                  <Row key={i.id} icon="qr" title={i.label ? `Invite for ${i.label}` : "Invite"}
                    sub={<>Not used yet · expires in {fmtLeft(i.expires - Date.now())}</>}
                    onClick={() => go("invite", { id: i.id })} />
                ))}
              </div>
            </section>
          )}
          {m.contacts.length === 0 && m.requests.length === 0 && m.invites.length === 0 && (
            <Empty icon="chat" title="Talk only with people you've approved"
              text="You each know the other only by an ID made for the two of you. Messages are encrypted so only your two phones can open them, and each one is confirmed by its sender's face or fingerprint.">
              {m.canStamp && <div class="actions" style={{ width: "100%" }}>
                <button class="btn primary block" onClick={() => go("invite")}><Icon name="qr" />Invite someone</button>
                <button class="btn quiet block" onClick={() => go("code")}><Icon name="scan" />I have their code</button>
                <p class="fine center">One of you shows a code; the other scans it.</p>
              </div>}
            </Empty>
          )}
          {today > 0 && <p class="fine center" style={{ marginTop: 18 }}>Today, {today.toLocaleString()} messages on HumID were sent with a live check.</p>}
        </>
      )}
      {choosing && (
        <Sheet onClose={() => setChoosing(false)} title="New conversation">
          <div class="rows">
            <Row icon="qr" title="Invite someone" sub="Make a code for one person to scan." onClick={() => { setChoosing(false); go("invite"); }} />
            <Row icon="scan" title="I have their code" sub="Scan or type the code they're showing you." onClick={() => { setChoosing(false); go("code"); }} />
          </div>
        </Sheet>
      )}
    </main>
  );
}

function ContactRow({ c }) {
  const ls = Msg.liveStateOf(c.id);
  const n = c.waiting + c.unread;
  const sub = c.status === "requested" ? "Waiting for them to approve you"
    : c.status === "closed" ? "Conversation ended"
    : c.last ? `${c.last.dir === "out" ? "You: " : ""}${c.last.text}`
    : c.waiting > 0 ? "Locked · open with a live check" : "No messages yet";
  return (
    <Row icon="chat" tone={ls.live ? "mint" : ""} title={<>{c.label}{ls.live && <span class="pill mint" style={{ marginLeft: 8 }}>Both here</span>}</>} sub={sub}
      trail={n > 0 ? <span class="unread" aria-label={`${n} new`}>{n}</span> : c.last ? <span class="small muted">{fmtTime(c.last.at)}</span> : null}
      onClick={() => go("chat", { id: c.id })} />
  );
}

/** You: live (with how long), or sealed with one tap to a live check. */
function YouLive({ waiting }) {
  const now = useNow(1000);
  const left = ownLeft(now);
  const [why, setWhy] = useState(false);
  if (left > 0) {
    return (
      <>
        <button class="you-live" data-soon={String(left < 30_000)} onClick={() => setWhy(true)}>
          <span class="dot" />{left < 30_000 ? `Locks in ${fmtLeft(left)}` : "Open · you're here"}<Icon name="info" />
        </button>
        {why && <WhatLive onClose={() => setWhy(false)} />}
      </>
    );
  }
  return (
    <Banner tone="amber" icon="lock" title={waiting ? `${waiting} new · locked` : "Your messages are locked"}
      text="One live check opens them for 5 minutes. Each message you send keeps them open."
      action="Open" onAction={() => Msg.verifyToRead()} />
  );
}

/** What "live" means, in one place. */
function WhatLive({ onClose, name }) {
  return (
    <Sheet onClose={onClose} title="Here, away, and live checks">
      <div class="rows">
        <Row icon="fingerprint" tone="mint" chevron={false} title="A live check" sub="Your face or fingerprint on your phone, proven by its secure chip. Opening, sending and approving each take one." />
        <Row icon="person" tone="mint" chevron={false} title="Here" sub="You've had a live check in the last 5 minutes. Then you're away, and your messages lock on this phone until your next one." />
        <Row icon="users" tone="mint" chevron={false} title="Both here" sub={`You and ${name || "they"} have both had a live check in the last few minutes, each confirmed by their own phone. It doesn't prove who wrote the words.`} />
      </div>
      <div class="actions"><button class="btn primary mint block" onClick={onClose}>Got it</button></div>
    </Sheet>
  );
}

/** "You ● Sam ●": who is live in this conversation right now. */
function Presence({ id, name }) {
  const now = useNow(1000);
  const [why, setWhy] = useState(false);
  const ls = Msg.liveStateOf(id);
  const mine = ownLeft(now);
  const theirs = ls.peer.fresh ? ls.peer.until - now : 0;
  return (
    <>
      <button class="presence" data-live={String(ls.live)} onClick={() => setWhy(true)} aria-label={`You: ${mine > 0 ? "here" : "away"}. ${name}: ${theirs > 0 ? "here" : "away"}. What this means`}>
        <span class="pip" data-on={String(mine > 0)}><span class="dot" />You · {mine > 0 ? "here" : "away"}</span>
        <span class="pip" data-on={String(theirs > 0)}><span class="dot" />{name} · {theirs > 0 ? "here" : "away"}</span>
        <span class="what">{ls.live ? "Both here" : ""}<Icon name="info" /></span>
      </button>
      {why && <WhatLive name={name} onClose={() => setWhy(false)} />}
    </>
  );
}

/* ---------------- a conversation ---------------- */

function Chat() {
  const id = S.push.value.id;
  const c = S.msg.value?.contacts.find((x) => x.id === id);
  const t = S.thread.value;
  const now = useNow(1000);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [acting, setActing] = useState(null);
  const end = useRef(null);
  useEffect(() => { Msg.showConversation(id); Msg.waitingOnOther(c?.status === "requested"); return () => Msg.waitingOnOther(false); }, [id, c?.status]);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [t?.messages?.length, t?.locked]);
  if (!c) return <Pushed title="Conversation" onBack={back}><Row chevron={false} title="This conversation is gone." /></Pushed>;
  const send = async () => {
    if (!text.trim() || busy) return;
    setBusy(true);
    if (await Msg.send(id, text)) setText("");
    setBusy(false);
  };
  const canSend = c.status === "connected" && !S.offline.value && S.msg.value?.canStamp !== false;
  const sealed = t?.locked !== false;
  const left = ownLeft(now);
  const firstSend = !sealed && !t.messages.some((x) => x.dir === "out");
  return (
    <Pushed title={c.label} onBack={back} class="chat" trailing={<button class="icon-btn" aria-label="Details" onClick={() => go("contact", { id })}><Icon name="more" /></button>}>
      {c.status === "connected" && <Presence id={id} name={c.label} />}
      {c.status === "requested" && (
        <Banner icon="clock" title={`Waiting for ${c.label} to approve you`} text="They see your note and approve with a live check. This opens by itself when they do."
          action="Withdraw" onAction={async () => { if (await Msg.withdrawRequest(id)) back(); }} />
      )}
      {c.status === "closed" && <Banner icon="info" title="This conversation has ended" text="You can still read and delete what's here." />}
      {c.duressAt > 0 && <Banner tone="danger" icon="siren" role="alert" title={`${c.label} may be under duress`} text={`Their message ${fmtAgo(c.duressAt)} came from a duress unlock. Check on them in a safe way.`} />}
      {sealed ? (
        <div class="thread sealed-thread">
          {Array.from({ length: t?.count || 0 }, (_, i) => <span class={`ghost ${i % 3 === 1 ? "out" : "in"}`}><Icon name="lock" />Message · locked</span>)}
          <div class="sealed">
            <Icon name="lock" />
            <h3>{c.waiting ? `${c.waiting} new · locked` : "Locked"}</h3>
            <p class="small muted">You've been away for a few minutes, so this conversation locked itself on your phone. Nothing in it opens until your next live check.</p>
            <button class="btn primary" onClick={() => Msg.verifyToRead()}><Icon name="fingerprint" />Open with a live check</button>
          </div>
        </div>
      ) : (
        <div class="thread" aria-live="polite">
          {t.messages.length === 0 && t.notices.length === 0 && <p class="small muted center">No messages yet. Say hello.</p>}
          {t.missing > 0 && <div class="notice" role="status">{t.missing === 1 ? "1 message" : `${t.missing} messages`} from {c.label} didn't arrive. A later one did, so it was sent, but it never reached this phone. Ask them to send it again if it mattered.</div>}
          {merge(t.messages, t.notices).map((x, i, all) => (
            <>
              {(i === 0 || dayLabel(x.at) !== dayLabel(all[i - 1].at)) && <div class="day-sep">{dayLabel(x.at)}</div>}
              {x.notice ? <div class="notice">{x.text}</div> : (
                <button class={`bubble ${x.dir}${x.duress ? " duress" : ""}`} style={{ textAlign: "left" }} onClick={() => setActing(x)}>
                  {x.text ?? "Voice note or photo"}
                  <span class="meta">{fmtTime(x.at)}{x.expiresAt && <Icon name="clock" />}</span>
                </button>
              )}
            </>
          ))}
          <div ref={end} />
        </div>
      )}
      {canSend && !sealed && (
        <div class="composer">
          {left > 0 && left < 30_000 ? <span class="hint soon"><Icon name="clock" />Locks in {fmtLeft(left)}. Sending keeps it open.</span>
            : firstSend && <span class="hint"><Icon name="fingerprint" />Sending takes a live check, so {c.label} knows the message was confirmed on your phone.</span>}
          <textarea aria-label="Message" rows={1} placeholder={`Message ${c.label}`} value={text} maxLength={4000}
            onInput={(e) => { setText(e.currentTarget.value); e.currentTarget.style.height = "auto"; e.currentTarget.style.height = `${e.currentTarget.scrollHeight}px`; }}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } }} />
          <button class="send" aria-label="Send with a live check" disabled={!text.trim() || busy} onClick={send}><Icon name="fingerprint" /><span>Send</span></button>
        </div>
      )}
      {acting && <MessageActions id={id} m={acting} connected={c.status === "connected"} onClose={() => setActing(null)} />}
    </Pushed>
  );
}

const merge = (msgs, notices) => [...msgs, ...notices.map((n) => ({ ...n, notice: true }))].sort((a, b) => a.at - b.at);

function MessageActions({ id, m, connected, onClose }) {
  return (
    <Sheet onClose={onClose} title={m.dir === "out" ? "Your message" : "Their message"}>
      <p class="small muted">{fmtTime(m.at)} · confirmed by {m.dir === "out" ? "your" : "their"} live check{m.expiresAt ? ` · disappears in ${fmtLeft(m.expiresAt - Date.now())}` : ""}</p>
      <div class="rows" style={{ marginTop: 12 }}>
        <Row icon="trash" title="Delete for me" sub="Gone from this phone. Their copy stays." onClick={() => { onClose(); Msg.deleteMessage(id, m.id); }} />
        {m.dir === "out" && connected && <Row icon="trash" danger title="Delete for both of you" sub="Erased from their phone too; if it hasn't arrived, it never will. Takes a live check." onClick={() => { onClose(); Msg.deleteMessage(id, m.id, { forBoth: true }); }} />}
      </div>
    </Sheet>
  );
}

/* ---------------- invite someone: the screen stays with you until they're in ---------------- */

function Invite() {
  const pid = S.push.value.id;
  const m = S.msg.value; // re-render when a request arrives for this invite
  const existing = pid ? m?.invites.find((i) => i.id === pid) : null;
  const [label, setLabel] = useState("");
  const [made, setMade] = useState(existing ? { id: existing.id, code: existing.code, expires: existing.expires, label: existing.label } : null);
  const [busy, setBusy] = useState(false);
  const [cancel, setCancel] = useState(false);
  useNow(30_000);
  useEffect(() => { if (made) { Msg.waitingOnOther(true); return () => Msg.waitingOnOther(false); } }, [made?.id]);
  const make = async () => { setBusy(true); const r = await Msg.makeInvite({ label }); setBusy(false); if (r) setMade({ ...r, label: label.trim() }); };
  const asking = made && m ? Msg.requestsForInvite(made.id) : [];
  useEffect(() => { if (asking.length) buzz([30, 60, 30]); }, [asking.length > 0]);
  if (made && asking.length) return <Pushed title="Asking to connect" onBack={back}><Review reqId={asking[0]} defaultLabel={made.label} /></Pushed>;
  const share = async () => {
    try { await navigator.share({ text: `My HumID invite code (works once, for 24 hours): ${made.code}` }); } catch { /* cancelled */ }
  };
  return (
    <Pushed title="Invite someone" onBack={back}>
      {!made ? (
        <>
          <p class="t2">You'll get a code for one person. They scan it and ask to connect with a live check; you see their note and approve with yours.</p>
          <div class="field" style={{ marginTop: 16 }}>
            <label for="inv-label">Who is it for? <span class="muted">(only you see this)</span></label>
            <input id="inv-label" class="input" maxLength={40} autocomplete="off" placeholder="e.g. Sam" value={label} onInput={(e) => setLabel(e.currentTarget.value)} />
          </div>
          <ul class="small muted" style={{ marginTop: 12, paddingLeft: 18 }}>
            <li>They'll know you only by an ID made for the two of you.</li>
            <li>It works for one person and expires in 24 hours.</li>
          </ul>
          <div class="actions"><button class="btn primary block" disabled={busy} onClick={make}><Icon name="fingerprint" />Make invite with a live check</button></div>
        </>
      ) : (
        <>
          <p class="t2 center">{made.label ? `Let ${made.label} scan this` : "Let them scan this"}, in person if you can.</p>
          <div class="center" style={{ marginTop: 12 }}><QrCode payload={Msg.inviteQr(made.code, made.expires)} size={220} /></div>
          <p class="waiting-line" role="status"><span class="dot" />Waiting for {made.label || "them"} to scan it…</p>
          <details style={{ marginTop: 6 }}>
            <summary class="small">Not together? Use the code</summary>
            <div class="invite-code" style={{ marginTop: 10 }} aria-label="Invite code">{made.code.slice(3).split("-").map((g) => <span>{g}</span>)}</div>
            <p class="small muted" style={{ marginTop: 8 }}>Anyone who sees this code can use it, once, for {fmtLeft(made.expires - Date.now())}. Send it only somewhere private, and read it on a call only if you're sure of the voice: voices can be faked. Compare safety codes when you next meet.</p>
            {typeof navigator !== "undefined" && navigator.share && <button class="btn quiet block" style={{ marginTop: 8 }} onClick={share}>Share code…</button>}
          </details>
          <div class="actions">
            <button class="btn ghost block" onClick={back}>Close · the invite stays open</button>
            <button class="btn ghost block" onClick={() => setCancel(true)}>Cancel this invite</button>
          </div>
        </>
      )}
      {cancel && <Confirm title="Cancel this invite?" text="The code stops working at once. Anyone who already used it won't be shown." action="Cancel invite"
        onClose={() => setCancel(false)} onConfirm={async () => { await Msg.cancelInvite(made.id); back(); }} />}
    </Pushed>
  );
}

/* ---------------- someone invited me ---------------- */

function EnterCode() {
  const [code, setCode] = useState("");
  const [scan, setScan] = useState(false);
  const [found, setFound] = useState(null);
  const [label, setLabel] = useState("");
  const [intro, setIntro] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(null);
  const find = async (c = code) => { setBusy(true); setFound(await Msg.openCode(c)); setBusy(false); };
  const ask = async () => { setBusy(true); const r = await Msg.askToConnect(found, { label, intro }); if (r) setSent(r); setBusy(false); };
  // Waiting on the other phone: check often, and open the conversation the moment they approve.
  const conv = sent && S.msg.value?.contacts.find((x) => x.id === sent.id);
  useEffect(() => { if (sent) { Msg.waitingOnOther(true); return () => Msg.waitingOnOther(false); } }, [sent?.id]);
  useEffect(() => { if (conv?.status === "connected") go("chat", { id: sent.id }); }, [conv?.status]);
  const enough = code.replace(/[^0-9a-z]/gi, "").length >= 44;
  if (scan) {
    return (
      <Pushed title="Scan their code" onBack={() => setScan(false)}>
        <Scanner parse={Msg.parseInviteQr} onCancel={() => setScan(false)} onCode={(c) => { setScan(false); setCode(c.code); find(c.code); }} />
      </Pushed>
    );
  }
  return (
    <Pushed title={sent ? `Waiting for ${label || "them"}` : "Someone invited me"} onBack={back}>
      {sent ? (
        <>
          <p class="waiting-line" role="status" style={{ marginTop: 4 }}><span class="dot" />Asked {label || "them"} to connect. This opens by itself when they approve.</p>
          <SafetyCompare code={sent.safetyCode} when={`${label || "They"} will see this code once they open your request.`} onMatch={(how) => Msg.updateContact(sent.id, { safetyVerified: how })} />
          <div class="actions"><button class="btn ghost block" onClick={back}>Back to Messages</button></div>
        </>
      ) : !found ? (
        <>
          <p class="t2">Scan the code they're showing you, or type it.</p>
          <div class="actions" style={{ paddingTop: 8 }}><button class="btn primary block" onClick={() => setScan(true)}><Icon name="scan" />Scan their code</button></div>
          <div class="field" style={{ marginTop: 12 }}>
            <label for="inv-code">Or type it</label>
            <textarea id="inv-code" class="input code" rows={2} autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HI-XXXX-XXXX-…" value={code} onInput={(e) => setCode(e.currentTarget.value)} />
          </div>
          <div class="actions"><button class="btn quiet block" disabled={busy || !enough} onClick={() => find()}>Find invite</button></div>
        </>
      ) : (
        <>
          <Banner tone="mint" icon="check" title="Invite found" text="This code matches a real invite. Make sure it came from the person you expect." />
          <div class="field" style={{ marginTop: 14 }}>
            <label for="ct-label">What do you call them? <span class="muted">(only you see this)</span></label>
            <input id="ct-label" class="input" maxLength={40} autocomplete="off" placeholder="e.g. Sam" value={label} onInput={(e) => setLabel(e.currentTarget.value)} />
          </div>
          <div class="field" style={{ marginTop: 12 }}>
            <label for="ct-intro">A note so they know it's you <span class="muted">(optional)</span></label>
            <textarea id="ct-intro" class="input" rows={2} maxLength={280} placeholder="e.g. From the workshop on Tuesday" value={intro} onInput={(e) => setIntro(e.currentTarget.value)} />
          </div>
          <div class="actions">
            <button class="btn primary block" disabled={busy || !label.trim()} onClick={ask}><Icon name="fingerprint" />Ask with a live check</button>
            <button class="btn ghost block" onClick={() => setFound(null)}>Wrong code · back</button>
          </div>
        </>
      )}
    </Pushed>
  );
}

/**
 * The safety code, compared out loud: same on both phones means nobody is in between. One
 * person's tap can only say "I compared it", so that's what's recorded, with how.
 */
function SafetyCompare({ code, onMatch, onDifferent, matched: initial = false, when = null }) {
  const [matched, setMatched] = useState(initial);
  const [how, setHow] = useState("in person");
  const groups = String(code || "").split("-");
  return (
    <div class="card" style={{ marginTop: 14 }}>
      <div class="eyebrow">Safety code</div>
      <div class="safety" aria-label="Safety code" style={{ marginTop: 8 }}>{groups.map((g) => <span>{g}</span>)}</div>
      {when && <p class="small muted" style={{ marginTop: 8 }}>{when}</p>}
      {matched ? <p class="small mint row-x" style={{ gap: 6, marginTop: 8 }}><Icon name="check" />You marked this the same{typeof matched === "string" ? ` (${matched})` : ""}</p> : (
        <>
          <p class="small" style={{ marginTop: 8 }}>Read it to each other. Is it the same on both phones?</p>
          <div class="seg" role="radiogroup" aria-label="How you compared" style={{ marginTop: 8 }}>
            {["in person", "on a video call"].map((h) => <button type="button" role="radio" aria-checked={how === h} onClick={() => setHow(h)} style={how === h ? { background: "var(--surface-3)", color: "var(--text)" } : undefined}>{h === "in person" ? "In person" : "Video call"}</button>)}
          </div>
          <div class="actions row" style={{ paddingTop: 8 }}>
            <button class="btn quiet" onClick={() => onDifferent?.()}>Different</button>
            <button class="btn quiet" onClick={() => { setMatched(how); onMatch?.(how); }}><Icon name="check" />Same</button>
          </div>
          <p class="fine">Not together now? Skip this and compare later in Details.</p>
        </>
      )}
    </div>
  );
}

/* ---------------- someone is asking to connect ---------------- */

function Request() {
  return <Pushed title="Asking to connect" onBack={back}><Review reqId={S.push.value.id} /></Pushed>;
}

function Review({ reqId, defaultLabel = "" }) {
  const [shown, setShown] = useState(null);
  const [label, setLabel] = useState(defaultLabel);
  const [busy, setBusy] = useState(false);
  const [matched, setMatched] = useState(false);
  const [different, setDifferent] = useState(false);
  const see = async () => {
    setBusy(true);
    const r = await Msg.reviewRequest(reqId);
    setBusy(false);
    if (r) { setShown(r); setLabel(defaultLabel || r.label || ""); }
    else if (!S.msg.value?.requests.some((x) => x.id === reqId)) back();
  };
  const approve = async () => { setBusy(true); const conv = await Msg.approveRequest(reqId, { label, safetyVerified: matched }); setBusy(false); if (conv) go("chat", { id: conv }); };
  const decline = async () => { await Msg.declineRequest(reqId); back(); };
  if (!shown) {
    return (
      <>
        <Empty icon="users" title={defaultLabel ? `${defaultLabel} is asking to connect` : "Someone used your invite"}
          text="Their request is sealed to your phone. Your live check opens it, so you can see their note before you decide." />
        <div class="actions"><button class="btn primary block" disabled={busy} onClick={see}><Icon name="fingerprint" />See who's asking</button></div>
      </>
    );
  }
  return (
    <>
      <Banner tone="mint" icon="fingerprint" title="Asked with a live check"
        text="It was confirmed by a face or fingerprint on a proven phone. Anyone who saw your code could have made it, so check their note, and compare safety codes if you can." />
      {shown.intro ? <div class="card" style={{ marginTop: 10 }}><div class="eyebrow">Their note</div><p>{shown.intro}</p></div>
        : <p class="small muted" style={{ marginTop: 10 }}>They didn't add a note.</p>}
      <div class="field" style={{ marginTop: 14 }}>
        <label for="rq-label">What do you call them? <span class="muted">(only you see this)</span></label>
        <input id="rq-label" class="input" maxLength={40} autocomplete="off" value={label} onInput={(e) => setLabel(e.currentTarget.value)} />
      </div>
      <SafetyCompare code={shown.safetyCode} onMatch={(how) => setMatched(how)} onDifferent={() => setDifferent(true)} />
      {different && <Banner tone="danger" icon="alert" role="alert" title="Stop: the codes are different" text="Someone may be in between you. Decline, and make a new invite when you're together." />}
      <div class="actions">
        <button class="btn primary block" disabled={busy || !label.trim() || different} onClick={approve}><Icon name="fingerprint" />Approve with a live check</button>
        <button class="btn ghost block" onClick={decline}>Decline</button>
      </div>
    </>
  );
}

/* ---------------- details ---------------- */

function Contact() {
  const id = S.push.value.id;
  const c = S.msg.value?.contacts.find((x) => x.id === id);
  const [rename, setRename] = useState(null);
  const [del, setDel] = useState(false);
  const [safety, setSafety] = useState(false);
  if (!c) return <Pushed title="Details" onBack={back}><Row chevron={false} title="This conversation is gone." /></Pushed>;
  const s = Msg.safetyOf(id);
  return (
    <Pushed title={c.label} onBack={() => go("chat", { id })}>
      <div class="rows">
        <Row icon="pencil" title="Name" sub={`${c.label} · only you see this`} onClick={() => setRename(c.label)} />
        <Row icon="shield" tone={c.safetyVerified ? "mint" : ""} title="Safety code" sub={c.safetyVerified ? `You marked this compared${typeof c.safetyVerified === "string" ? ` (${c.safetyVerified})` : ""}` : "Not compared yet"} onClick={() => setSafety(true)} />
      </div>
      {c.status === "connected" && (
        <div class="rows" style={{ marginTop: 14 }}>
          <div style={{ padding: "4px 16px" }}>
            <div class="small" style={{ fontWeight: 600, padding: "8px 0 4px" }}>Disappearing messages</div>
            <div class="seg" role="radiogroup" aria-label="Disappearing messages">
              {Msg.TIMERS.map(([ms, t]) => (
                <button type="button" role="radio" aria-checked={c.timer === ms} onClick={() => c.timer !== ms && Msg.setTimer(id, ms)}
                  style={c.timer === ms ? { background: "var(--surface-3)", color: "var(--text)" } : undefined}>{t}</button>
              ))}
            </div>
            <p class="hint small muted" style={{ padding: "6px 0 10px" }}>For both of you. Changing it takes a live check.</p>
          </div>
          <div style={{ padding: "0 16px" }}><Toggle checked={c.showHere} onChange={(v) => Msg.updateContact(id, { showHere: v })} label={`Show ${c.label} when you're here`} hint="When you open this conversation with a live check, they see you're here, even if you don't write. Nothing else is sent." /></div>
          <div style={{ padding: "0 16px 6px" }}><Toggle checked={c.duressAlert} onChange={(v) => Msg.updateContact(id, { duressAlert: v })} label="Tell me if they may be under duress" hint="Their app marks messages sent after a duress unlock. Only you see it." /></div>
        </div>
      )}
      <div class="rows" style={{ marginTop: 14 }}>
        <Row icon="trash" danger title="Delete conversation" onClick={() => setDel(true)} />
      </div>
      {s && <p class="fine" style={{ marginTop: 12 }}>To {c.label} you're <span class="persona">{s.mine}</span>. To you they're <span class="persona">{s.theirs}</span>. These IDs are used only between you two; HumID's relay never sees them.</p>}
      {rename !== null && (
        <Sheet onClose={() => setRename(null)} title="Name">
          <input class="input" maxLength={40} value={rename} onInput={(e) => setRename(e.currentTarget.value)} aria-label="Name" />
          <div class="actions"><button class="btn primary block" onClick={() => { Msg.updateContact(id, { label: rename }); setRename(null); }}>Save</button></div>
        </Sheet>
      )}
      {safety && s && (
        <Sheet onClose={() => setSafety(false)} title="Safety code">
          <SafetyCompare code={s.safetyCode} matched={c.safetyVerified} onMatch={(how) => Msg.updateContact(id, { safetyVerified: how })} />
          <div class="actions"><button class="btn ghost block" onClick={() => setSafety(false)}>Close</button></div>
        </Sheet>
      )}
      {del && (
        <Sheet onClose={() => setDel(false)} title="Delete this conversation?">
          <p class="small muted">Every message and every key for it is erased from this phone, for good.</p>
          <div class="rows" style={{ marginTop: 12 }}>
            <Row icon="trash" title="Delete for me" sub="They aren't told and keep their copy, and their messages to you will no longer arrive." onClick={async () => { setDel(false); if (await Msg.deleteConversation(id)) back(); }} />
            {c.status === "connected" && <Row icon="trash" danger title="Delete for both of you"
              sub={Msg.deleteSteps(id) > 1
                ? `Your messages are erased from their phone too, and the conversation ends. There are so many that it takes ${Msg.deleteSteps(id)} live checks, one after the other; nothing here is erased until the last one.`
                : "Your messages are erased from their phone too, and the conversation ends. Takes a live check."}
              onClick={async () => { setDel(false); if (await Msg.deleteConversation(id, { forBoth: true })) back(); }} />}
          </div>
        </Sheet>
      )}
    </Pushed>
  );
}
