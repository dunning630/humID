// HumID 3.0 — app entry. One column, one view at a time, one pushed screen and one sheet
// at most. The first paint carries Welcome, Lock and the Vault; every other screen is a
// chunk that loads when it's first needed (the Add flow and its readers, Activity, You,
// and the two onboarding flows), so what a phone downloads and parses at start is small.
import "./brand/base.css";
import "./brand/flows.css";
import "./brand/shell.css";
import { render } from "preact";
import { lazy, Suspense } from "preact/compat";
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

const chunk = (load, name) => lazy(() => load().then((m) => ({ default: m[name] })));
const Create = chunk(() => import("./screens/create.jsx"), "Create");
const Join = chunk(() => import("./screens/join.jsx"), "Join");
const Add = chunk(() => import("./screens/add/index.jsx"), "Add");
const Activity = chunk(() => import("./screens/activity.jsx"), "Activity");
const You = chunk(() => import("./screens/you/index.jsx"), "You");

/** Shown while a chunk loads: the same calm screen as boot, never a spinner. */
const Loading = () => <main class="screen boot"><Mark state="idle" size={96} label="Loading" /></main>;

function App() {
  const v = S.view.value;
  const push = S.push.value;
  return (
    <>
      {SIM && v !== "boot" && <SimStrip />}
      <ConnectionBar />
      {v === "boot" && <Loading />}
      {v === "welcome" && <Welcome />}
      {v === "enroll" && <Suspense fallback={<Loading />}><Create /></Suspense>}
      {v === "join" && <Suspense fallback={<Loading />}><Join /></Suspense>}
      {v === "locked" && <Lock />}
      {v === "app" && (
        <>
          {S.tab.value === "vault" && <Vault />}
          {S.tab.value === "activity" && <Suspense fallback={<Loading />}><Activity /></Suspense>}
          {S.tab.value === "you" && <Suspense fallback={<Loading />}><You /></Suspense>}
          <TabBar />
          {push?.type === "add" && <Suspense fallback={null}><Add /></Suspense>}
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
