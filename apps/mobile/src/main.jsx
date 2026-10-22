// HumID 3.0 — app entry. One column, one view at a time, one pushed screen and one sheet
// at most. The first paint carries Welcome, Lock and the Vault; every other screen is a
// chunk that loads when it's first needed (the Add flow and its readers, Activity, You,
// and the two onboarding flows), so what a phone downloads and parses at start is small.
import "./brand/base.css";
import "./brand/flows.css";
import "./brand/shell.css";
import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import * as S from "./core/state.js";
import { boot } from "./core/index.js";
import { wireBack } from "./core/back.js";
import { applyPrefs } from "./core/prefs.js";
import { SIM } from "./core/config.js";
import { Mark } from "./brand/mark.jsx";
import { Interrupt, ChipReadOverlay, Toasts, TabBar } from "./ui/kit.jsx";
import { ConnectionBar, DraftOffer, SimStrip, ChecksSheet } from "./ui/shell.jsx";
import { Welcome } from "./screens/welcome.jsx";
import { Lock } from "./screens/lock.jsx";
import { Vault, Item, Viewer } from "./screens/vault.jsx";

/** Shown while a chunk loads: the same calm screen as boot, never a spinner. */
const Loading = () => <main class="screen boot"><Mark state="idle" size={96} label="Loading" /></main>;

/**
 * A screen whose code loads the first time it's needed. Unlike preact/compat's lazy, a load
 * that fails (no connection yet, in the web app) isn't remembered: the screen says so and
 * Try again loads it afresh. `warm()` fetches it ahead of time without showing it.
 */
function chunk(load, name, fallback = <Loading />) {
  let mod = null, pending = null;
  const get = () => {
    pending ||= load().then((m) => { mod = m; return m; }, (e) => { pending = null; throw e; });
    return pending;
  };
  function Chunk(props) {
    const [, ready] = useState(0);
    const [failed, setFailed] = useState(false);
    useEffect(() => {
      if (mod || failed) return;
      let live = true;
      get().then(() => live && ready((n) => n + 1), () => live && setFailed(true));
      return () => { live = false; };
    }, [failed]);
    if (mod) { const C = mod[name]; return <C {...props} />; }
    if (failed) return <Unavailable onRetry={() => setFailed(false)} />;
    return fallback;
  }
  Chunk.warm = () => get().catch(() => {});
  return Chunk;
}

/** A screen whose code couldn't be fetched: calm words and a way to try again. */
function Unavailable({ onRetry }) {
  return (
    <main class="screen tabs">
      <div class="empty" role="status">
        <h3>This screen needs a connection the first time</h3>
        <p class="small">Your vault is safe. Connect to the internet once and it opens, offline too, from then on.</p>
        <button class="btn primary" onClick={onRetry}>Try again</button>
      </div>
    </main>
  );
}

const Create = chunk(() => import("./screens/create.jsx"), "Create");
const Join = chunk(() => import("./screens/join.jsx"), "Join");
const Add = chunk(() => import("./screens/add/index.jsx"), "Add", null);
const Activity = chunk(() => import("./screens/activity.jsx"), "Activity");
const You = chunk(() => import("./screens/you/index.jsx"), "You");
// 4.0 person to person: the screens and the protocol load together, the first time Messages opens.
const Messages = chunk(() => import("./screens/messages/index.jsx"), "Messages");

/**
 * Once the vault is open, fetch the other tabs' code in idle time, so they open at once
 * and still open if the connection drops (offline, read only). After first paint, so the
 * start-up budget is untouched; the Add flow and its readers stay on demand.
 */
let warmed = false;
function warmTabs() {
  if (warmed) return;
  warmed = true;
  const go = () => { Activity.warm(); You.warm(); };
  if ("requestIdleCallback" in globalThis) requestIdleCallback(go, { timeout: 4000 }); else setTimeout(go, 1500);
}

function App() {
  const v = S.view.value;
  const push = S.push.value;
  if (v === "app") warmTabs();
  return (
    <>
      {SIM && v !== "boot" && <SimStrip />}
      <ConnectionBar />
      {v === "boot" && <Loading />}
      {v === "welcome" && <Welcome />}
      {v === "enroll" && <Create />}
      {v === "join" && <Join />}
      {v === "locked" && <Lock />}
      {v === "app" && (
        <>
          {S.tab.value === "vault" && <Vault />}
          {S.tab.value === "messages" && S.messagingOn.value && <Messages />}
          {S.tab.value === "activity" && <Activity />}
          {S.tab.value === "you" && <You />}
          <TabBar />
          {push?.type === "add" && <Add />}
          {push?.type === "item" && <Item key={push.id} />}
          {/* You's own pushed screens (protect, devices, …) are rendered by You itself */}
          <Viewer />
          <DraftOffer />
        </>
      )}
      {SIM && <ChecksSheet />}
      <ChipReadOverlay />
      <Interrupt />
      <Toasts />
    </>
  );
}

// The look comes first, before anything is drawn; "Match device" follows the system's changes.
applyPrefs(S.prefs.value);
try { matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => applyPrefs(S.prefs.value)); } catch {}

render(<App />, document.getElementById("app"));
boot();
wireBack();

// Installable web app: cache the app shell so HumID opens offline (vault data always comes
// over HTP/1 and is never cached).
if ("serviceWorker" in navigator && !globalThis.__TAURI_INTERNALS__ && location.protocol === "https:") {
  navigator.serviceWorker.register("/sw.js").catch(() => {});
}
