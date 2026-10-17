// Apple Wallet passes: the check shown while adding one, and the pass, opened.
// Everything shown comes from pass.json as text (@humid/wallet summarizePass): no
// links are followed and nothing in a pass runs. The barcode is drawn only for QR
// passes; for other formats its text is shown, and the pass can go back into Wallet.
import { useEffect, useMemo } from "preact/hooks";
import qrcode from "qrcode-generator";
import { Icon } from "../icons.jsx";
import { fmtDate } from "../ui.jsx";
import { saveCopy } from "../core/controller.js";

/** Adding a pass: checking, verified (with who signed it), or refused (with why). */
export function PassCheck({ check, onPlain, onAnother }) {
  if (check.state === "checking") return (
    <div class="banner" role="status" style={{ marginTop: 6 }}><span class="b-ico"><Icon name="ticket" /></span>
      <div><strong>Checking the pass…</strong><span>Its files, its issuer's signature, and Apple's certificate chain.</span></div></div>
  );
  if (!check.ok) return (
    <>
      <div class="banner bad" role="alert" style={{ marginTop: 6 }}><span class="b-ico"><Icon name="alert" /></span>
        <div><strong>HumID won't add this as a Wallet pass</strong><span>{check.reason}</span></div></div>
      <div class="actions">
        <button class="btn ghost block" onClick={onAnother}>Choose another file</button>
        <button class="btn quiet block" onClick={onPlain}>Keep it as an ordinary file instead</button>
      </div>
    </>
  );
  const { pass, issuer } = check.result;
  return (
    <>
      <PassFace pass={pass} images={check.result.images} compact />
      <div class="banner" role="status" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="check" /></span>
        <div><strong>Signed by {issuer.organization || pass.organization}, verified through Apple</strong>
          <span>Unchanged since its issuer signed it{check.result.signedAt ? ` on ${fmtDate(check.result.signedAt)}` : ""}. Team {issuer.team}.</span></div></div>
    </>
  );
}

const useImage = (bytes) => {
  const url = useMemo(() => (bytes ? URL.createObjectURL(new Blob([bytes], { type: "image/png" })) : null), [bytes]);
  useEffect(() => () => { if (url) URL.revokeObjectURL(url); }, [url]);
  return url;
};

function Fields({ list, big }) {
  if (!list?.length) return null;
  return (
    <div class={`pf-row${big ? " big" : ""}`}>
      {list.map((f) => <div class="pf"><span class="pf-l">{f.label}</span><span class="pf-v">{f.value}</span></div>)}
    </div>
  );
}

/** The front of a pass, in its own colours where it gives readable ones. */
function PassFace({ pass, images, compact }) {
  const logo = useImage(images?.logo || images?.icon);
  const style = pass.colors.background && pass.colors.foreground ? { "--pass-bg": pass.colors.background, "--pass-fg": pass.colors.foreground, "--pass-label": pass.colors.label || pass.colors.foreground } : {};
  return (
    <div class={`pass-face${pass.colors.background ? " own" : ""}`} style={style} data-style={pass.style}>
      <div class="pf-head">
        {logo && <img src={logo} alt="" />}
        <span class="pf-org">{pass.logoText || pass.organization}</span>
        <span class="pf-kind">{pass.styleLabel}{pass.voided ? " · voided" : ""}</span>
      </div>
      <Fields list={pass.fields.header} />
      <Fields list={pass.fields.primary} big />
      {!compact && <Fields list={pass.fields.secondary} />}
      {!compact && <Fields list={pass.fields.auxiliary} />}
      {compact && <p class="pf-desc">{pass.description}</p>}
    </div>
  );
}

function Barcode({ code }) {
  const svg = useMemo(() => {
    if (!code || code.format !== "PKBarcodeFormatQR") return null;
    try {
      const q = qrcode(0, "M"); q.addData(code.message); q.make();
      const n = q.getModuleCount();
      let d = "";
      for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
      return { n, d };
    } catch { return null; }
  }, [code]);
  if (!code) return null;
  return (
    <div class="pass-code">
      {svg ? (
        <svg viewBox={`0 0 ${svg.n + 8} ${svg.n + 8}`} width="200" height="200" role="img" aria-label="The pass's QR code" shape-rendering="crispEdges">
          <rect width={svg.n + 8} height={svg.n + 8} fill="#fff" rx="2" /><path d={svg.d} fill="#000" />
        </svg>
      ) : <p class="small muted">This pass uses a {code.format.replace("PKBarcodeFormat", "").toLowerCase() || "barcode"} code. Put it back into Apple Wallet to show it for scanning.</p>}
      {code.altText && <span class="mono small">{code.altText}</span>}
    </div>
  );
}

/** A pass, opened from the vault (checked again as it opened). */
export function PassView({ v }) {
  if (v.passError) return (
    <div class="banner bad" role="alert"><span class="b-ico"><Icon name="alert" /></span>
      <div><strong>This pass no longer checks out</strong><span>{v.passError} It was verified when it was added; save a copy if you need the file.</span></div></div>
  );
  const { pass, issuer } = v.pass;
  return (
    <div class="pass-view">
      <PassFace pass={pass} images={v.pass.images} />
      <Barcode code={pass.barcode} />
      <div class="card" style={{ marginTop: 14 }}>
        <div class="row"><span class="k">Issued by</span><span class="v">{issuer.organization || pass.organization}</span></div>
        <div class="row"><span class="k">Signature</span><span class="v"><span class="pill mint"><Icon name="check" />Verified through Apple</span></span></div>
        {pass.relevantDate && <div class="row"><span class="k">Date</span><span class="v">{fmtDate(pass.relevantDate)}</span></div>}
        {pass.expirationDate && <div class="row"><span class="k">Expires</span><span class="v">{fmtDate(pass.expirationDate)}</span></div>}
        {pass.serialNumber && <div class="row"><span class="k">Serial</span><span class="v mono small">{pass.serialNumber}</span></div>}
      </div>
      {pass.fields.back.length > 0 && (
        <details class="card pass-back" style={{ marginTop: 14 }}>
          <summary>Details on the back of the pass</summary>
          {pass.fields.back.map((f) => <div class="row" style={{ display: "block" }}><div class="k">{f.label}</div><div class="v" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{f.value}</div></div>)}
        </details>
      )}
      <div class="actions">
        <button class="btn secure block" onClick={() => saveCopy(v.item)}><Icon name="download" />Save the pass (opens in Apple Wallet)</button>
      </div>
      <p class="fine" style={{ marginTop: 10 }}>Links in a pass are shown as text, never opened. HumID keeps the signed original, so it can go back into Wallet unchanged.</p>
    </div>
  );
}
