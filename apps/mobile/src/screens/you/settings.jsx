// Settings: how HumID looks and behaves on this device. Nothing here is secret and
// nothing here can weaken protection (core/prefs.js). Values are CHOICES from prefs.
import { Icon } from "../../brand/icons.jsx";
import { Pushed, Toggle } from "../../ui/kit.jsx";
import * as S from "../../core/state.js";
import { setPref } from "../../core/index.js";
import { CHOICES, IDLE_CHOICES } from "../../core/prefs.js";
import { back, Choice } from "./common.jsx";

const LABELS = {
  theme: { system: "Match device", dark: "Dark", light: "Light" },
  text: { standard: "A", large: "A+", larger: "A++", largest: "A+++" },
  sort: { newest: "Newest", oldest: "Oldest", name: "Name", expiry: "Expiring first" },
};
const TEXT_HINT = { standard: "Standard", large: "Larger (120%)", larger: "Much larger (145%)", largest: "Largest (175%)" };
const opts = (key) => CHOICES[key].map((v) => [v, LABELS[key][v]]);
const idleLabel = (ms) => { const m = Math.round(ms / 60_000); return `${m} min`; };

export function Settings() {
  const p = S.prefs.value;
  const pinned = S.items.value.filter((i) => i.pinned).length;
  return (
    <Pushed title="Settings" onBack={back}>
      <div class="card">
        <div class="eyebrow">Look</div>
        <Choice id="theme" label="Theme" value={p.theme} options={opts("theme")} onPick={(v) => setPref({ theme: v })} />
        <Choice id="text" label="Text size" hint={`${TEXT_HINT[p.text]} · on top of your phone's own text size setting`} value={p.text} options={opts("text")} onPick={(v) => setPref({ text: v })} />
        <Toggle label="Animations" hint="The rings and transitions. Off keeps everything still." checked={p.motion} onChange={(v) => setPref({ motion: v })} />
        <Toggle label="Haptics" hint="A short buzz when a check passes or a photo is taken." checked={p.haptics} onChange={(v) => setPref({ haptics: v })} />
      </div>

      <div class="card" style={{ marginTop: 12 }}>
        <div class="eyebrow">Locking</div>
        <Choice id="idle" label="Lock after no activity" hint="5 minutes is the longest HumID allows. Leaving the screen always locks."
          value={p.idleMs} options={IDLE_CHOICES.map((ms) => [ms, idleLabel(ms)])} onPick={(v) => setPref({ idleMs: v })} />
      </div>

      <div class="card" style={{ marginTop: 12 }}>
        <div class="eyebrow">Vault</div>
        <Choice id="sort" label="Sort the vault by" value={p.sort} options={opts("sort")} onPick={(v) => setPref({ sort: v })} />
        <Choice id="expiry" label="Warn before an ID expires" value={p.expiryWarnDays}
          options={CHOICES.expiryWarnDays.map((d) => [d, d < 90 ? `${d} days` : `${Math.round(d / 30)} months`])} onPick={(v) => setPref({ expiryWarnDays: v })} />
        <Toggle label="Location stamp when sealing" hint="Off unless you turn it on. Sealed inside the encrypted index: your vault never sees it. You can still change it on each seal." checked={!!p.placeStamp} onChange={(v) => setPref({ placeStamp: v })} />
        <p class="small muted" style={{ marginTop: 10 }}><Icon name="pushpin" /> {pinned ? `${pinned} pinned ${pinned === 1 ? "item stays" : "items stay"} at the top.` : "Pin items from their details to keep them at the top."} Pins are sealed with each item, so they show on all your devices and the server can't see them.</p>
      </div>
      <p class="fine" style={{ marginTop: 14 }}>Settings are kept on this device. Pins follow you.</p>
    </Pushed>
  );
}
