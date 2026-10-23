// Apple Wallet passes: the check shown while adding one, and the pass, opened.
// Everything shown comes from pass.json as text (@humid/wallet summarizePass): no links
// are followed and nothing in a pass runs. The barcode is drawn only for QR passes; for
// other formats its text is shown, and the pass can go back into Wallet.
import { useEffect, useMemo } from "preact/hooks";
import qrcode from "qrcode-generator";
import { Icon } from "../../brand/icons.jsx";
import { Banner, Row } from "../../ui/kit.jsx";
import { fmtDate } from "../../ui/format.js";
import { saveCopy } from "../../core/index.js";

/** Who signed it: the organisation in the certificate Apple issued, never the pass's own text. */
const signedBy = (issuer) => (issuer.organization ? `Signed by “${issuer.organization}”` : `Signed by team ${issuer.team}`);

/** Adding a pass: checking, verified (with who signed it), or refused (with why). */
export function PassCheck({ check, onPlain, onAnother }) {
  if (check.state === "checking") return <Banner icon="ticket" title="Checking the pass…" text="Its files, its issuer's signature, and Apple's certificate chain." />;
  if (!check.ok) return (
    <>
      <Banner tone="danger" icon="alert" role="alert" title="HumID won't add this as a Wallet pass" text={check.reason} />
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
      <Banner tone={issuer.certExpired ? "amber" : "mint"} icon={issuer.certExpired ? "clock" : "check"} title={`${signedBy(issuer)}, verified through Apple`}
        text={`${issuer.certExpired
          ? `Unchanged since it was signed${check.result.signedAt ? ` (it says ${fmtDate(check.result.signedAt)})` : ""}, but the issuer's certificate has since expired, so HumID can't tell when it was really signed.`
          : `Unchanged since its issuer signed it${check.result.signedAt ? ` on ${fmtDate(check.result.signedAt)}` : ""}.`} Team ${issuer.team}.`} />
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
  if (v.passError) return <Banner tone="danger" icon="alert" role="alert" title="This pass no longer checks out" text={`${v.passError} It was verified when it was added; save a copy if you need the file.`} />;
  const { pass, issuer } = v.pass;
  const expired = Date.parse(issuer.certExpires) < Date.now();
  return (
    <div class="pass-view stack" style={{ width: "100%", maxWidth: 520, margin: "0 auto" }}>
      <PassFace pass={pass} images={v.pass.images} />
      <Barcode code={pass.barcode} />
      <div class="rows">
        <Row chevron={false} title="Signed by" trail={<span class="t2">{issuer.organization || `Team ${issuer.team}`}</span>} />
        <Row chevron={false} title="Signature" trail={expired
          ? <span class="pill amber"><Icon name="clock" />Genuine · certificate since expired</span>
          : <span class="pill mint"><Icon name="check" />Verified through Apple</span>} />
        {pass.relevantDate && <Row chevron={false} title="Date" trail={<span class="t2">{fmtDate(pass.relevantDate)}</span>} />}
        {pass.expirationDate && <Row chevron={false} title="Expires" trail={<span class="t2">{fmtDate(pass.expirationDate)}</span>} />}
        {pass.serialNumber && <Row chevron={false} title="Serial" trail={<span class="t2 mono small">{pass.serialNumber}</span>} />}
      </div>
      {pass.fields.back.length > 0 && (
        <details class="card pass-back">
          <summary>Details on the back of the pass</summary>
          {pass.fields.back.map((f) => <div class="mt-3"><div class="small muted">{f.label}</div><div class="t2" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{f.value}</div></div>)}
        </details>
      )}
      <div class="actions">
        <button class="btn primary mint block" onClick={() => saveCopy(v.item)}><Icon name="download" />Save a copy (opens in Apple Wallet)</button>
      </div>
      <p class="fine">Links in a pass are shown as text, never opened. HumID keeps the signed original, so it can go back into Wallet unchanged.</p>
    </div>
  );
}
