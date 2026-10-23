// Protection: how HumID protects you (the first point: no password, ever), and what's
// left to make this HumID survive a lost phone. This screen owns progress; the Recovery
// screen only shows which proofs exist.
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Row, PROTECTION } from "../../ui/kit.jsx";
import * as S from "../../core/state.js";
import { go, back } from "./common.jsx";

/** The checklist, so the hub can count it too. Empty until recovery and devices are known. */
export function protectionItems(rec, devices) {
  if (!rec || !devices) return [];
  return [
    { done: !!rec.proofs?.card, icon: "idcard", label: "Recovery card", todo: "Make the card that's one of your proofs", target: "recovery", extra: { open: "card" } },
    { done: !!(rec.proofs?.witness || rec.proofs?.anchor || rec.proofs?.key), icon: "users", label: "A second proof", todo: "Witnesses who vouch for you, your ID chip, or a security key", target: "recovery" },
    { done: devices.length >= 2, icon: "key", label: "A second device", todo: "Another phone, so a lost phone isn't an emergency", target: "devices", extra: { open: "add" } },
  ];
}

export function Protect() {
  // A decoy session shows the same checklist, from its calm recovery state (core/recovery.js)
  // and the account's real devices: an ordinary account with nothing set up (verify-71 #3).
  const rec = S.recovery.value, devices = S.devices.value;
  const items = S.offline.value ? [] : protectionItems(rec, devices);
  const n = items.filter((i) => i.done).length;
  const duressOn = !!S.duressInfo.value?.setting?.enabled;
  return (
    <Pushed title="Protection" onBack={back}>
      <div class="eyebrow">Safe. Secure. Simple.</div>
      <h2 style={{ marginTop: 6 }}>How HumID protects you</h2>
      <div class="rows" style={{ marginTop: 12 }}>
        {PROTECTION.map((p) => <Row icon={p.icon} tone="mint" title={p.title} sub={p.text} chevron={false} />)}
      </div>

      {items.length > 0 && (
        <section class="section" style={{ marginTop: 24 }} aria-labelledby="protect-h">
          <div class="row-x" style={{ justifyContent: "space-between", marginBottom: 8 }}>
            <h2 id="protect-h">{n === items.length ? "Your HumID is protected" : "Finish protecting your HumID"}</h2>
            <span class={`pill ${n === items.length ? "mint" : "amber"}`}>{n} of {items.length}</span>
          </div>
          <div class="stepper" role="progressbar" aria-label="Protection" aria-valuemin={0} aria-valuemax={items.length} aria-valuenow={n} style={{ marginBottom: 12 }}>
            {items.map((_, i) => <i class={i < n ? "done" : ""} />)}
          </div>
          <div class="rows">
            {items.map((i) => (
              <Row icon={i.done ? "check" : i.icon} tone={i.done ? "mint" : "amber"} title={i.label} sub={i.done ? "Done" : i.todo}
                onClick={i.done ? undefined : () => go(i.target, i.extra)} chevron={!i.done} />
            ))}
            {!duressOn && <Row icon="siren" title="Optional: duress gesture" sub="If you're ever forced to unlock, show only chosen documents" onClick={() => go("duress")} />}
          </div>
          <p class="fine" style={{ marginTop: 12 }}>If you lose every device, any two of four proofs bring your vault back. HumID never holds a key that opens it, and one proof alone never does.</p>
        </section>
      )}
      {S.offline.value && <p class="fine" style={{ marginTop: 16 }}>Offline: nothing here can be set up until you reconnect.</p>}
    </Pushed>
  );
}
