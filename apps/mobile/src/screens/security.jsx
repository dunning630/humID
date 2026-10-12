// Security: identity, device gate, connection, session, and the exits.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { AssurancePill, Sheet, groupKey, fmtDate } from "../ui.jsx";
import * as S from "../core/state.js";
import { lockNow, eraseEverything } from "../core/controller.js";
import { serverHost, VERSION, PLATFORM } from "../core/config.js";

const GATE = {
  "ios-keychain-biometry": "Face ID / Touch ID · Secure Enclave policy",
  "android-keystore-biometric": "Android Keystore · Class 3 biometric",
  "macos-keychain-biometry": "Touch ID · Keychain",
  "windows-hello-keycredential": "Windows Hello · TPM key",
  "linux-fprintd-keyring": "Fingerprint · fprintd + keyring",
  "webauthn-platform-uv-prf": "Device passkey (WebAuthn PRF)",
  "demo-no-hardware": "Demo · press and hold",
};

function useCountdown(until) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  const s = Math.max(0, Math.floor((until - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function Security() {
  const id = S.identity.value;
  const sess = S.session.value;
  const srv = id?.server;
  const idle = useCountdown(S.idleDeadline.value);
  const [confirm, setConfirm] = useState(false);
  return (
    <main class="screen with-tabs">
      <div class="topbar"><div class="grow"><h1>Security</h1><div class="sub"><Icon name="shield" />How your HumID is protected</div></div></div>

      <div class="card">
        <h3>Your identity</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Created</span><span class="v">{id ? fmtDate(id.enrolledAt) : ""}</span></div>
          <div class="row"><span class="k">HumID</span><span class="v mono" style={{ fontSize: 12 }}>{srv?.id?.slice(0, 16)}…</span></div>
          <div class="row" style={{ display: "block" }}><div class="k" style={{ marginBottom: 8 }}>Identity commitment</div><div class="kid">{groupKey(id?.commit).slice(0, 8).map((g) => <span>{g}</span>)}</div></div>
          <div class="row"><span class="k">Keys</span><span class="v mono" style={{ fontSize: 12 }}>ML-DSA-87 · ML-KEM-1024 · X25519</span></div>
        </div>
      </div>

      <div class="card">
        <h3>This device</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Protection</span><span class="v"><AssurancePill assurance={id?.assurance} /></span></div>
          <div class="row"><span class="k">Gate</span><span class="v">{GATE[id?.method] || id?.method}</span></div>
          <div class="row"><span class="k">Device</span><span class="v">{PLATFORM}</span></div>
        </div>
      </div>

      <div class="card">
        <h3>Connection</h3>
        <div class="rows" style={{ marginTop: 6 }}>
          <div class="row"><span class="k">Vault server</span><span class="v">{serverHost(srv?.url)}</span></div>
          <div class="row" style={{ display: "block" }}><div class="k" style={{ marginBottom: 8 }}>Pinned server key</div><div class="kid">{(srv?.fingerprint || "").split("-").map((g) => <span>{g}</span>)}</div></div>
          <div class="row"><span class="k">Channel</span><span class="v mono" style={{ fontSize: 12 }}>HTP/1 · ML-KEM-1024 + X25519 · AES-256-GCM</span></div>
          <div class="row"><span class="k">Session</span><span class="v">{sess ? <span class="pill mint"><Icon name="signal" />Active · auto-locks in {idle}</span> : "—"}</span></div>
        </div>
      </div>

      <div class="actions" style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 10 }}>
        <button class="btn ghost block" onClick={lockNow}><Icon name="lock" />Lock now</button>
        <button class="btn danger block" onClick={() => setConfirm(true)}><Icon name="trash" />Close HumID &amp; erase vault</button>
      </div>
      <p class="fine" style={{ marginTop: 14 }}>HumID {VERSION}</p>

      {confirm && (
        <Sheet onClose={() => setConfirm(false)} label="Close HumID">
          <div class="eyebrow">This can't be undone</div>
          <h2 style={{ marginTop: 6 }}>Close your HumID?</h2>
          <p class="lede" style={{ marginTop: 10 }}>Every document is erased from the vault server, your identity is closed, and the keys on this device are destroyed. Your activity history stays on file, closed.</p>
          <div class="actions">
            <button class="btn danger block" onClick={() => { setConfirm(false); eraseEverything(); }}><Icon name="fingerprint" />Confirm with biometric &amp; erase</button>
            <button class="btn ghost block" onClick={() => setConfirm(false)}>Keep my HumID</button>
          </div>
        </Sheet>
      )}
    </main>
  );
}
