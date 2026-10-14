// HumID app entry.
import "./styles/fonts.css";
import "./styles/app.css";
import { render } from "preact";
import * as S from "./core/state.js";
import { boot } from "./core/controller.js";
import { InterruptOverlay, ChipReadOverlay, Toasts, TabBar, SimStrip, ChecksSheet } from "./ui.jsx";
import { SIM } from "./core/config.js";
import { Welcome, Enroll, Join, Lock } from "./screens/onboarding.jsx";
import { Vault, AddSheet, ItemSheet, Viewer } from "./screens/vault.jsx";
import { Activity } from "./screens/activity.jsx";
import { Security } from "./screens/security.jsx";
import { Mark } from "./brand.jsx";

function App() {
  const v = S.view.value;
  const sheet = S.sheet.value;
  return (
    <>
      {SIM && v !== "boot" && <SimStrip />}
      {v === "boot" && <main class="screen"><div class="hero"><Mark state="scanning" /></div></main>}
      {v === "welcome" && <Welcome />}
      {v === "enroll" && <Enroll />}
      {v === "join" && <Join />}
      {v === "locked" && <Lock />}
      {v === "app" && (
        <>
          {S.tab.value === "vault" && <Vault />}
          {S.tab.value === "activity" && <Activity />}
          {S.tab.value === "security" && <Security />}
          <TabBar />
          {sheet?.type === "add" && <AddSheet />}
          {sheet?.type === "item" && <ItemSheet key={sheet.id} />}
          <Viewer />
        </>
      )}
      {SIM && <ChecksSheet />}
      <ChipReadOverlay />
      <InterruptOverlay />
      <Toasts />
    </>
  );
}

render(<App />, document.getElementById("app"));
boot();

// Installable web app: cache the app shell so it opens offline (vault data always comes over HTP/1).
if ("serviceWorker" in navigator && !globalThis.__TAURI_INTERNALS__ && location.protocol === "https:") {
  navigator.serviceWorker.register("/sw.js").catch(() => {});
}
