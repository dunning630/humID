// Protection: how HumID protects you (the first point: no password, ever), and what's
// left to make this HumID survive a lost phone. This screen owns progress; the Recovery
// screen only shows which proofs exist.
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Row, Banner, protection } from "../../ui/kit.jsx";
import * as S from "../../core/state.js";
import { protectionItems } from "../../core/index.js";
import { go, back } from "./common.jsx";

// The checklist lives in the kernel (core/recmode.js) so the hub can count it too.
export { protectionItems };

export function Protect() {
  // A decoy session shows the same checklist, from its calm recovery state (core/recovery.js)
  // and the account's real devices: an ordinary account with nothing set up (verify-71 #3).
  const rec = S.recovery.value, devices = S.devices.value;
  const items = S.offline.value ? [] : protectionItems(rec, devices);
  const n = items.filter((i) => i.done).length;
  const duressOn = !!S.duressInfo.value?.setting?.enabled;
  const holderOnly = S.recoveryMode.value?.mode === "holder-only";
  const alone = holderOnly && devices && devices.length <= 1;
  return (
    <Pushed title="Protection" onBack={back}>
      <div class="eyebrow">Safe. Secure. Simple.</div>
      <h2 style={{ marginTop: 6 }}>How HumID protects you</h2>
      <div class="rows" style={{ marginTop: 12 }}>
        {protection().map((p) => <Row icon={p.icon} tone="mint" title={p.title} sub={p.text} chevron={false} />)}
      </div>
      {alone && <div style={{ marginTop: 16 }}><Banner tone="danger" icon="alert" role="alert" title="This is your only device" text="You chose Only my own devices, so if this phone is lost, your vault is gone for good. Add another device now." action="Add a device" onAction={() => go("devices", { open: "add" })} /></div>}

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
          <p class="fine" style={{ marginTop: 12 }}>{holderOnly
            ? "You chose Only my own devices: HumID keeps no way back in for you. Your devices are your recovery."
            : "If you lose every device, any two of four proofs bring your vault back. HumID never holds a key that opens it, and one proof alone never does."}</p>
        </section>
      )}
      {S.offline.value && <p class="fine" style={{ marginTop: 16 }}>Offline: nothing here can be set up until you reconnect.</p>}
    </Pushed>
  );
}
