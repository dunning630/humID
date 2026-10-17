// Settings: how HumID looks and behaves on this device, how the vault is arranged,
// reminders, and what this device and its connection are. Nothing here can weaken
// protection: auto-lock only gets shorter, and leaving the screen always locks.
import { Icon } from "../icons.jsx";
import { AssurancePill, proofLabel, useNow, fmtLeft } from "../ui.jsx";
import * as S from "../core/state.js";
import { setPref, lockNow } from "../core/controller.js";
import { CHOICES, IDLE_CHOICES, idleLabel } from "../core/prefs.js";
import { serverHost, VERSION, PLATFORM } from "../core/config.js";
import { GATE } from "./security.jsx";

const LABELS = {
  theme: { system: "Match device", dark: "Night", light: "Day" },
  text: { standard: "Standard", large: "Larger" },
  startTab: { vault: "Vault", activity: "Activity", security: "Security", settings: "Settings" },
  sort: { newest: "Newest", oldest: "Oldest", name: "Name", expiry: "Expiring first" },
};

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

const opts = (key) => CHOICES[key].map((v) => [v, LABELS[key][v]]);

export function Settings() {
  const p = S.prefs.value;
  const id = S.identity.value;
  const srv = id?.server;
  const sess = S.session.value;
  const now = useNow();
  const pinned = S.items.value.filter((i) => i.pinned).length;
  return (
    <main class="screen with-tabs">
      <div class="topbar">
        <div class="grow">
          <h1>Settings</h1>
          <div class="sub"><Icon name="settings" />How HumID looks and behaves on this device</div>
        </div>
      </div>

      <section class="card" aria-labelledby="set-look">
        <h3 id="set-look">Appearance</h3>
        <Choice id="theme" label="Theme" value={p.theme} options={opts("theme")} onPick={(v) => setPref({ theme: v })} />
        <Choice id="text" label="Text size" value={p.text} options={opts("text")} onPick={(v) => setPref({ text: v })} />
        <Switch id="motion" label="Animations" hint="The rings and transitions. Off keeps everything still." checked={p.motion} onChange={(v) => setPref({ motion: v })} />
        <Switch id="haptics" label="Haptics" hint="A short buzz when a check passes or a photo is taken." checked={p.haptics} onChange={(v) => setPref({ haptics: v })} />
      </section>

      <section class="card" aria-labelledby="set-lock">
        <h3 id="set-lock">Locking</h3>
        <Choice id="idle" label="Lock after no activity" hint="5 minutes is the longest HumID allows."
          value={p.idleMs} options={IDLE_CHOICES.map((ms) => [ms, idleLabel(ms).replace(" minutes", " min").replace(" minute", " min")])} onPick={(v) => setPref({ idleMs: v })} />
        <div class="setting fixed">
          <div class="s-label"><strong>Lock when HumID leaves the screen</strong><span>Always. Switching apps or turning off the screen locks your vault.</span></div>
          <span class="pill mint"><Icon name="lock" />Always</span>
        </div>
        <div class="setting fixed">
          <div class="s-label"><strong>Unlock</strong><span>Face or fingerprint only. A PIN or password is never accepted.</span></div>
          <span class="pill mint"><Icon name="fingerprint" />Biometric</span>
        </div>
      </section>

      <section class="card" aria-labelledby="set-vault">
        <h3 id="set-vault">Vault</h3>
        <Choice id="startTab" label="Open on" value={p.startTab} options={opts("startTab")} onPick={(v) => setPref({ startTab: v })} />
        <Choice id="sort" label="Sort items by" value={p.sort} options={opts("sort")} onPick={(v) => setPref({ sort: v })} />
        <p class="small muted" style={{ marginTop: 10 }}><Icon name="pin" /> {pinned ? `${pinned} pinned ${pinned === 1 ? "item stays" : "items stay"} at the top.` : "Pin items from their details to keep them at the top."} Pins are sealed with each item, so they show on all your devices and the server can't see them.</p>
      </section>

      <section class="card" aria-labelledby="set-remind">
        <h3 id="set-remind">Reminders</h3>
        <Choice id="expiry" label="Warn before an ID expires" value={p.expiryWarnDays}
          options={CHOICES.expiryWarnDays.map((d) => [d, d < 90 ? `${d} days` : `${Math.round(d / 30)} months`])} onPick={(v) => setPref({ expiryWarnDays: v })} />
      </section>

      <section class="card" aria-labelledby="set-device">
        <h3 id="set-device">This device</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Protection</span><span class="v"><AssurancePill assurance={id?.assurance} /></span></div>
          <div class="row"><span class="k">Gate</span><span class="v">{GATE[id?.method] || id?.method}</span></div>
          <div class="row"><span class="k">Proof</span><span class="v">{proofLabel(id?.proof, id?.assurance)}</span></div>
          <div class="row"><span class="k">PIN or password</span><span class="v"><span class="pill mint"><Icon name="check" />Never accepted</span></span></div>
          <div class="row"><span class="k">Device</span><span class="v">{PLATFORM}</span></div>
        </div>
      </section>

      <section class="card" aria-labelledby="set-conn">
        <h3 id="set-conn">Connection</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Vault server</span><span class="v">{serverHost(srv?.url)}</span></div>
          <div class="row" style={{ display: "block" }}><div class="k" style={{ marginBottom: 8 }}>Pinned server key</div><div class="kid">{(srv?.fingerprint || "").split("-").map((g) => <span>{g}</span>)}</div></div>
          <div class="row"><span class="k">Channel</span><span class="v mono" style={{ fontSize: 12 }}>HTP/1 · ML-KEM-1024 + X25519 · AES-256-GCM</span></div>
          <div class="row"><span class="k">Session</span><span class="v">{sess ? <span class="pill mint"><Icon name="signal" />Active · auto-locks in {fmtLeft(S.idleDeadline.value - now)}</span> : S.offline.value ? <span class="pill amber"><Icon name="signal" />Offline · read only · auto-locks in {fmtLeft(S.idleDeadline.value - now)}</span> : "—"}</span></div>
        </div>
      </section>

      <div class="actions" style={{ marginTop: 18 }}>
        <button class="btn ghost block" onClick={lockNow}><Icon name="lock" />Lock now</button>
      </div>
      <p class="fine" style={{ marginTop: 14 }}>HumID {VERSION} · Settings are kept on this device. Pins follow you.</p>
    </main>
  );
}
