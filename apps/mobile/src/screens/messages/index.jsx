// Messages (HumID 4.0, docs/MESSAGING.md): people you've approved, known only by an ID made
// for each of you. Nobody interacts here without a live check: inviting, asking, approving,
// sending, and reading all need one (core/messaging.js says exactly where).
//
// Pushed screens this file routes (S.push.value.type): chat · invite · code · request · contact.
// Sheets this file owns: the "new" chooser, a message's actions.
import "../../brand/messages.css";
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Sheet, Banner, Row, Empty, Toggle, Confirm, useNow } from "../../ui/kit.jsx";
import { QrCode, Scanner } from "../../ui/codes.jsx";
import { fmtTime, fmtAgo, fmtLeft, dayLabel } from "../../ui/format.js";
import * as S from "../../core/state.js";
import * as Msg from "../../core/messaging.js";

const go = (type, extra = {}) => { S.push.value = { type, ...extra }; };
const back = () => { if (S.push.value?.type === "chat") Msg.closeConversation(); S.push.value = null; };
const PUSHED = { chat: Chat, invite: Invite, code: EnterCode, request: Request, contact: Contact };

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
  return (
    <main class="screen tabs">
      <header class="top">
        <div class="grow"><h1>Messages</h1><div class="small muted">Only people you've approved. Only live humans.</div></div>
        {!off && m?.ready && <button class="icon-btn" aria-label="New" onClick={() => setChoosing(true)}><Icon name="plus" /></button>}
      </header>
      {off && <Banner tone="amber" icon="info" title="Messages need a connection" text="Your conversations are safe on this phone. They open again when you're back online." />}
      {!m && !off && <Row chevron={false} title="Opening your messages…" />}
      {m?.error && <Banner tone="amber" icon="info" title="Messages aren't available" text={m.error} />}
      {m?.ready && (
        <>
          {m.contacts.length > 0 && <ReadBar waiting={m.contacts.reduce((n, c) => n + c.waiting, 0)} />}
          {m.requests.length > 0 && (
            <section style={{ marginTop: 14 }}>
              <div class="eyebrow">Asking to connect</div>
              <div class="rows">
                {m.requests.map((r) => (
                  <Row key={r.id} icon="users" tone="amber" title="Someone asked to connect"
                    sub={<>Through your invite{r.label ? <> for <b>{r.label}</b></> : ""} · {fmtAgo(r.at)}</>}
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
              <div class="eyebrow">Invites waiting</div>
              <div class="rows">
                {m.invites.map((i) => (
                  <Row key={i.id} icon="qr" title={i.label ? `Invite for ${i.label}` : "Invite"}
                    sub={<>Expires in {fmtLeft(i.expires - Date.now())}</>}
                    onClick={() => go("invite", { id: i.id })} />
                ))}
              </div>
            </section>
          )}
          {m.contacts.length === 0 && m.requests.length === 0 && m.invites.length === 0 && (
            <Empty icon="chat" title="Talk only with people you've approved"
              text="Each of you knows the other only by an ID made for you. Every message carries proof a live human sent it, and nobody, HumID included, can read it.">
              <div class="actions" style={{ width: "100%" }}>
                <button class="btn primary block" onClick={() => go("invite")}><Icon name="qr" />Invite someone</button>
                <button class="btn quiet block" onClick={() => go("code")}>I have an invite code</button>
              </div>
            </Empty>
          )}
          {today > 0 && <p class="fine center" style={{ marginTop: 18 }}>Today, {today.toLocaleString()} messages on HumID were approved by a live human.</p>}
        </>
      )}
      {choosing && (
        <Sheet onClose={() => setChoosing(false)} title="New conversation">
          <div class="rows">
            <Row icon="qr" title="Invite someone" sub="Make a code to show them in person." onClick={() => { setChoosing(false); go("invite"); }} />
            <Row icon="scan" title="I have an invite code" sub="Scan or type the code someone showed you." onClick={() => { setChoosing(false); go("code"); }} />
          </div>
        </Sheet>
      )}
    </main>
  );
}

function ContactRow({ c }) {
  const ls = Msg.liveStateOf(c.id);
  const sub = c.status === "requested" ? "Waiting for them to approve you"
    : c.status === "closed" ? "Conversation ended"
    : c.last ? `${c.last.dir === "out" ? "You: " : ""}${c.last.text}`
    : c.waiting > 0 ? `${c.waiting} new · check to read` : "No messages yet";
  return (
    <Row icon="chat" tone={ls.live ? "mint" : ""} title={c.label} sub={sub}
      trail={(c.waiting + c.unread) > 0 ? <span class="unread">{c.waiting + c.unread}</span> : c.last ? <span class="small muted">{fmtTime(c.last.at)}</span> : null}
      onClick={() => go("chat", { id: c.id })} />
  );
}

/** Reading needs a fresh check. While it's fresh, say how long; when it isn't, offer one. */
function ReadBar({ waiting }) {
  const now = useNow(1000);
  const left = (S.liveAt.value || 0) + Msg.LIVE_WINDOW_MS - now;
  if (left > 0) return <p class="small muted row-x" style={{ gap: 6 }}><Icon name="fingerprint" />Verified live · reading open for {fmtLeft(left)}</p>;
  return (
    <Banner tone="amber" icon="fingerprint" title={waiting ? `${waiting} new · verify it's you to read` : "Verify it's you to read"}
      text="Messages open only while you're proven live. Nothing is decrypted until then."
      action="Verify" onAction={() => Msg.verifyToRead()} />
  );
}

/** "Live · both verified" — the human-to-human state of one conversation, ticking down. */
function LiveState({ id }) {
  useNow(1000);
  const ls = Msg.liveStateOf(id);
  const text = ls.live ? `Live · both verified · ${fmtLeft(ls.until - Date.now())}`
    : ls.needs === "peer" ? "You're verified · waiting for them"
    : ls.needs === "own" ? "They're verified · verify it's you"
    : "Neither of you is verified right now";
  return <span class="live-state" data-live={String(ls.live)} data-needs={ls.needs || ""} data-own={ls.own.at || ""} data-peer={ls.peer.at || ""}><span class="dot" />{text}</span>;
}

/* ---------------- a conversation ---------------- */

function Chat() {
  const id = S.push.value.id;
  const c = S.msg.value?.contacts.find((x) => x.id === id);
  const t = S.thread.value;
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [acting, setActing] = useState(null);
  const end = useRef(null);
  useEffect(() => { Msg.showConversation(id); return () => {}; }, [id]);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [t?.messages?.length]);
  if (!c) return <Pushed title="Conversation" onBack={back}><Row chevron={false} title="This conversation is gone." /></Pushed>;
  const send = async () => {
    if (!text.trim() || busy) return;
    setBusy(true);
    if (await Msg.send(id, text)) setText("");
    setBusy(false);
  };
  const canSend = c.status === "connected" && !S.offline.value;
  return (
    <Pushed title={c.label} onBack={back} trailing={<button class="icon-btn" aria-label="Details" onClick={() => go("contact", { id })}><Icon name="more" /></button>}>
      <LiveState id={id} />
      {c.status === "requested" && (
        <Banner icon="clock" title="Waiting for them to approve you" text="They see your note and approve with a live check. Until then nothing can be sent either way."
          action="Withdraw" onAction={async () => { if (await Msg.withdrawRequest(id)) back(); }} />
      )}
      {c.status === "closed" && <Banner icon="info" title="This conversation has ended" text="You can still read and delete what's here." />}
      {c.duressAt > 0 && <Banner tone="danger" icon="siren" role="alert" title="They may be under duress" text={`Their last message, ${fmtAgo(c.duressAt)}, came from a duress unlock. Check on them in a safe way.`} />}
      {t?.locked !== false ? (
        <div class="sealed">
          <Icon name="lock" />
          <h3>{c.waiting ? `${c.waiting} new` : "Sealed until you verify"}</h3>
          <p class="small muted">Messages open only while you're proven live. Nothing here is decrypted until you are.</p>
          <button class="btn primary" onClick={() => Msg.verifyToRead()}><Icon name="fingerprint" />Verify it's you</button>
        </div>
      ) : (
        <div class="thread" aria-live="polite">
          {t.messages.length === 0 && t.notices.length === 0 && <p class="small muted center">No messages yet. Say hello.</p>}
          {merge(t.messages, t.notices).map((x, i, all) => (
            <>
              {(i === 0 || dayLabel(x.at) !== dayLabel(all[i - 1].at)) && <div class="day-sep">{dayLabel(x.at)}</div>}
              {x.notice ? <div class="notice">{x.text}</div> : (
                <button class={`bubble ${x.dir}${x.duress ? " duress" : ""}`} style={{ textAlign: "left" }} onClick={() => setActing(x)}>
                  {x.text ?? "Voice note or photo"}
                  <span class="meta">
                    {fmtTime(x.at)}
                    {x.live && <span class="lv"><Icon name="fingerprint" />live</span>}
                    {x.expiresAt && <span><Icon name="clock" /></span>}
                  </span>
                </button>
              )}
            </>
          ))}
          <div ref={end} />
        </div>
      )}
      {canSend && (
        <div class="composer">
          <textarea aria-label="Message" rows={1} placeholder="Message" value={text} maxLength={4000}
            onInput={(e) => { setText(e.currentTarget.value); e.currentTarget.style.height = "auto"; e.currentTarget.style.height = `${e.currentTarget.scrollHeight}px`; }}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } }} />
          <button class="send" aria-label="Send with a live check" disabled={!text.trim() || busy} onClick={send}><Icon name="send" /></button>
          <span class="hint"><Icon name="fingerprint" />Each message is sent with a live check, so they know it's really you.</span>
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
      <p class="small muted">{fmtTime(m.at)} · {m.live ? "Sent with a live check" : "Not verified"}{m.expiresAt ? ` · disappears in ${fmtLeft(m.expiresAt - Date.now())}` : ""}</p>
      <div class="rows" style={{ marginTop: 12 }}>
        <Row icon="trash" title="Delete for me" sub="Gone from this phone. Their copy stays." onClick={() => { onClose(); Msg.deleteMessage(id, m.id); }} />
        {m.dir === "out" && connected && <Row icon="trash" danger title="Delete for both of you" sub="Erased from their phone too. If it hasn't arrived, it never will. Needs a live check." onClick={() => { onClose(); Msg.deleteMessage(id, m.id, { forBoth: true }); }} />}
      </div>
    </Sheet>
  );
}

/* ---------------- invite someone ---------------- */

function Invite() {
  const existing = S.push.value.id ? S.msg.value?.invites.find((i) => i.id === S.push.value.id) : null;
  const [label, setLabel] = useState("");
  const [made, setMade] = useState(existing ? { id: existing.id, code: existing.code, expires: existing.expires } : null);
  const [busy, setBusy] = useState(false);
  const [cancel, setCancel] = useState(false);
  useNow(30_000);
  const make = async () => { setBusy(true); const r = await Msg.makeInvite({ label }); setBusy(false); if (r) setMade(r); };
  return (
    <Pushed title="Invite someone" onBack={back}>
      {!made ? (
        <>
          <p class="t2">You'll get a code to show one person. They scan it, ask to connect with a live check, and you approve them with yours.</p>
          <div class="field" style={{ marginTop: 16 }}>
            <label for="inv-label">Who is it for? <span class="muted">(only you see this)</span></label>
            <input id="inv-label" class="input" maxLength={40} autocomplete="off" placeholder="e.g. Sam" value={label} onInput={(e) => setLabel(e.currentTarget.value)} />
          </div>
          <ul class="small muted" style={{ marginTop: 12, paddingLeft: 18 }}>
            <li>They'll know you only by an ID made just for them.</li>
            <li>It works for one person and expires in 24 hours.</li>
          </ul>
          <div class="actions"><button class="btn primary block" disabled={busy} onClick={make}><Icon name="fingerprint" />Make an invite</button></div>
        </>
      ) : (
        <>
          <p class="t2 center">Let them scan this, in person if you can.</p>
          <div class="center" style={{ marginTop: 12 }}><QrCode payload={Msg.inviteQr(made.code, made.expires)} size={220} /></div>
          <div class="invite-code" style={{ marginTop: 14 }} aria-label="Invite code">{made.code.slice(3).split("-").map((g) => <span>{g}</span>)}</div>
          <p class="small muted center" style={{ marginTop: 8 }}>Expires in {fmtLeft(made.expires - Date.now())}. Reading it out on a call? Only on one you trust: voices can be faked.</p>
          <Banner icon="info" title="What happens next" text="When they ask to connect, it shows up in Messages. You'll see their note and approve with a live check." />
          <div class="actions">
            <button class="btn primary mint block" onClick={back}>Done</button>
            <button class="btn ghost block" onClick={() => setCancel(true)}>Cancel this invite</button>
          </div>
        </>
      )}
      {cancel && <Confirm title="Cancel this invite?" text="The code stops working at once. Anyone who already asked with it won't be shown." action="Cancel invite"
        onClose={() => setCancel(false)} onConfirm={async () => { await Msg.cancelInvite(made.id); back(); }} />}
    </Pushed>
  );
}

/* ---------------- I have a code ---------------- */

function EnterCode() {
  const [code, setCode] = useState("");
  const [scan, setScan] = useState(false);
  const [found, setFound] = useState(null);
  const [label, setLabel] = useState("");
  const [intro, setIntro] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const find = async (c = code) => { setBusy(true); setFound(await Msg.openCode(c)); setBusy(false); };
  const ask = async () => { setBusy(true); if (await Msg.askToConnect(found, { label, intro })) setSent(true); setBusy(false); };
  const enough = code.replace(/[^0-9a-z]/gi, "").length >= 44;
  if (scan) {
    return (
      <Pushed title="Scan their code" onBack={() => setScan(false)}>
        <Scanner parse={Msg.parseInviteQr} onCancel={() => setScan(false)} onCode={(c) => { setScan(false); setCode(c.code); find(c.code); }} />
      </Pushed>
    );
  }
  return (
    <Pushed title={sent ? "Request sent" : "Connect with someone"} onBack={back}>
      {sent ? (
        <>
          <Empty icon="check" title={`Asked ${label || "them"} to connect`} text="They'll see your note and approve you with a live check. The conversation opens when they do." />
          <div class="actions"><button class="btn primary mint block" onClick={back}>Done</button></div>
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
          <Banner tone="mint" icon="check" title="Invite found" text="The code checks out: it was made by the person who showed it to you." />
          <p class="small muted" style={{ marginTop: 10 }}>They'll appear to you as <span class="persona">{found.id}</span>, an ID made just for you two.</p>
          <div class="field" style={{ marginTop: 14 }}>
            <label for="ct-label">What do you call them? <span class="muted">(only you see this)</span></label>
            <input id="ct-label" class="input" maxLength={40} autocomplete="off" placeholder="e.g. Sam" value={label} onInput={(e) => setLabel(e.currentTarget.value)} />
          </div>
          <div class="field" style={{ marginTop: 12 }}>
            <label for="ct-intro">A note so they know it's you <span class="muted">(optional)</span></label>
            <textarea id="ct-intro" class="input" rows={2} maxLength={280} placeholder="e.g. From the workshop on Tuesday" value={intro} onInput={(e) => setIntro(e.currentTarget.value)} />
          </div>
          <div class="actions">
            <button class="btn primary block" disabled={busy || !label.trim()} onClick={ask}><Icon name="fingerprint" />Ask to connect</button>
            <button class="btn ghost block" onClick={() => setFound(null)}>Not them · back</button>
          </div>
        </>
      )}
    </Pushed>
  );
}

/* ---------------- someone asked to connect ---------------- */

function Request() {
  const id = S.push.value.id;
  const [shown, setShown] = useState(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const see = async () => { setBusy(true); const r = await Msg.reviewRequest(id); setBusy(false); if (r) { setShown(r); setLabel(r.label || ""); } else if (!S.msg.value?.requests.some((x) => x.id === id)) back(); };
  const approve = async () => { setBusy(true); const conv = await Msg.approveRequest(id, { label }); setBusy(false); if (conv) go("chat", { id: conv }); };
  const decline = async () => { await Msg.declineRequest(id); back(); };
  return (
    <Pushed title="Asking to connect" onBack={back}>
      {!shown ? (
        <>
          <p class="t2">Someone used your invite. See who's asking: your live check opens their request on this phone.</p>
          <div class="actions"><button class="btn primary block" disabled={busy} onClick={see}><Icon name="fingerprint" />See who's asking</button></div>
        </>
      ) : (
        <>
          <Banner tone={shown.live ? "mint" : "amber"} icon={shown.live ? "fingerprint" : "alert"} title={shown.live ? "Made with a live check" : "Not verified"}
            text={shown.live ? "A live human on a verified phone asked. Only the person you gave the code to could have." : "This request wasn't made live."} />
          <p class="small muted" style={{ marginTop: 10 }}>They'll be <span class="persona">{shown.from}</span> to you.</p>
          {shown.intro && <div class="card" style={{ marginTop: 10 }}><div class="eyebrow">Their note</div><p>{shown.intro}</p></div>}
          <div class="field" style={{ marginTop: 14 }}>
            <label for="rq-label">What do you call them? <span class="muted">(only you see this)</span></label>
            <input id="rq-label" class="input" maxLength={40} autocomplete="off" value={label} onInput={(e) => setLabel(e.currentTarget.value)} />
          </div>
          <details style={{ marginTop: 12 }}>
            <summary class="small">Safety code (compare later, in person)</summary>
            <Safety code={shown.safetyCode} />
          </details>
          <div class="actions">
            <button class="btn primary block" disabled={busy || !label.trim()} onClick={approve}><Icon name="fingerprint" />Approve</button>
            <button class="btn ghost block" onClick={decline}>Decline</button>
          </div>
        </>
      )}
    </Pushed>
  );
}

const Safety = ({ code }) => <div class="safety" aria-label="Safety code">{String(code || "").split("-").map((g) => <span>{g}</span>)}</div>;

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
        <Row icon="shield" tone={c.safetyVerified ? "mint" : ""} title="Safety code" sub={c.safetyVerified ? "Compared in person" : "Not compared yet"} onClick={() => setSafety(true)} />
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
            <p class="hint small muted" style={{ padding: "6px 0 10px" }}>For both of you. Changing it needs a live check.</p>
          </div>
          <Toggle checked={c.duressAlert} onChange={(v) => Msg.updateContact(id, { duressAlert: v })} label="Tell me if they may be under duress" hint="Their app marks messages sent from a duress unlock. Only you see it." />
        </div>
      )}
      <div class="rows" style={{ marginTop: 14 }}>
        <Row icon="trash" danger title="Delete conversation" onClick={() => setDel(true)} />
      </div>
      {s && <p class="fine" style={{ marginTop: 12 }}>You're <span class="persona">{s.mine}</span> to them. They're <span class="persona">{s.theirs}</span> to you.</p>}
      {rename !== null && (
        <Sheet onClose={() => setRename(null)} title="Name">
          <input class="input" maxLength={40} value={rename} onInput={(e) => setRename(e.currentTarget.value)} aria-label="Name" />
          <div class="actions"><button class="btn primary block" onClick={() => { Msg.updateContact(id, { label: rename }); setRename(null); }}>Save</button></div>
        </Sheet>
      )}
      {safety && s && (
        <Sheet onClose={() => setSafety(false)} title="Safety code">
          <p class="small muted">Sit with them and compare. If it's the same on both phones, nobody swapped keys between you, anywhere.</p>
          <Safety code={s.safetyCode} />
          <div class="actions">
            <button class="btn primary mint block" onClick={() => { Msg.updateContact(id, { safetyVerified: true }); setSafety(false); }}><Icon name="check" />It matches</button>
            <button class="btn ghost block" onClick={() => setSafety(false)}>Not now</button>
          </div>
        </Sheet>
      )}
      {del && (
        <Sheet onClose={() => setDel(false)} title="Delete this conversation?">
          <p class="small muted">Every message and every key for it is erased from this phone, for good.</p>
          <div class="rows" style={{ marginTop: 12 }}>
            <Row icon="trash" title="Delete for me" sub="They keep their copy and aren't told." onClick={async () => { setDel(false); if (await Msg.deleteConversation(id)) back(); }} />
            {c.status === "connected" && <Row icon="trash" danger title="Delete for both of you" sub="Your messages are erased from their phone too, and the conversation ends. Needs a live check." onClick={async () => { setDel(false); if (await Msg.deleteConversation(id, { forBoth: true })) back(); }} />}
          </div>
        </Sheet>
      )}
    </Pushed>
  );
}
