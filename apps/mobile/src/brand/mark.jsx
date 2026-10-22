// The HumID mark and wordmark. One SVG, no raster, crisp at every size; state is carried by
// data attributes and a few CSS rules in brand/base.css, so the only JavaScript here is markup.
//
// 3.0.1: inside the app the mark is the fingerprint again (2.x's ridges, in the brand's amber to
// mint, inside 3.0's ring); the peace-sign hand is the logo and the app's icon (logo-data.js,
// tools/app-icon.mjs).
//
//   <Mark />                          the full mark: ring, fingerprint, no words
//   <Mark state="scanning" />         a live check is running (ring turns, ridges breathe)
//   <Mark state="verified" />         the check passed (mint badge)
//   <Mark state="failed" />           it didn't
//   <Mark progress={0.4} />           how far the check is (0..1), while scanning
//   <Print />                         the fingerprint alone, for small places (the empty vault)
//   <Hand />                          the logo's hand alone
//   <Wordmark />                      "HumID." — Hum amber, ID. mint
import { useMemo } from "preact/hooks";
import { HAND, PRINTS, HUM, ID } from "./logo-data.js";

const R = 28.5;                       // the ring's centre line (outer radius 30)
const C = 2 * Math.PI * R;            // its circumference
const GAP_DEG = 83.6;                 // where the mint arc sits, the amber ring stops
const GAP = (C * GAP_DEG) / 360;
const P_R = 24.6;                     // the progress ring, just inside
const P_C = 2 * Math.PI * P_R;
const rad = (d) => (d * Math.PI) / 180;
const pt = (r, d) => `${(r * Math.cos(rad(d))).toFixed(2)} ${(r * Math.sin(rad(d))).toFixed(2)}`;
// the mint arc: −94.2° → −19.8°, round caps
const MINT_ARC = `M ${pt(R, -94.2)} A ${R} ${R} 0 0 1 ${pt(R, -19.8)}`;

/**
 * The fingerprint's ridges (2.x's whorl): ten ellipses around one centre, each broken where its gap is,
 * the outer six broken once more for texture. Drawn at `k` units per 2.x unit, centred on (0, dy).
 */
function ridges(k = 0.34, dy = 1) {
  const gaps = [[2.2, 0.9], [1.5, 0.7], [4.1, 0.6], [0.9, 0.55], [3.3, 0.5], [5.2, 0.45], [2.6, 0.42], [4.6, 0.4], [1.2, 0.38], [3.9, 0.36]];
  const out = [];
  for (let i = 0; i < 10; i++) {
    const rx = (5 + i * 3.6) * k, ry = (7 + i * 4.6) * k;
    const [g, w] = gaps[i];
    const a0 = g + w / 2, a1 = g - w / 2 + Math.PI * 2;
    const cuts = i > 3 ? [a0, a0 + (a1 - a0) * 0.46, a0 + (a1 - a0) * 0.52, a1] : [a0, a1];
    for (let j = 0; j < cuts.length; j += 2) {
      const s0 = cuts[j], e = cuts[j + 1];
      const p = (t) => `${(rx * Math.cos(t)).toFixed(2)} ${(dy + ry * Math.sin(t)).toFixed(2)}`;
      out.push(`M ${p(s0)} A ${rx.toFixed(2)} ${ry.toFixed(2)} 0 ${e - s0 > Math.PI ? 1 : 0} 1 ${p(e)}`);
    }
  }
  return out.join(" ");
}
const RIDGES = ridges();
let ids = 0;

/** The ridges with their amber-to-mint stroke (a gradient per drawing: two marks on one screen keep their own). */
function Ridges({ id, width = 0.6 }) {
  return (
    <>
      <defs>
        <linearGradient id={id} x1="0.15" y1="0.9" x2="0.85" y2="0.1">
          <stop offset="0" class="mk-fp-a" />
          <stop offset="1" class="mk-fp-b" />
        </linearGradient>
      </defs>
      <path class="mk-fp" d={RIDGES} fill="none" stroke={`url(#${id})`} stroke-width={width} stroke-linecap="round" />
    </>
  );
}

export function Mark({ state = "idle", progress = 0, size, label, class: cls = "" }) {
  const id = useMemo(() => `mkfp${++ids}`, []);
  const p = state === "verified" ? 1 : Math.max(0, Math.min(1, progress));
  return (
    <div class={`mark ${cls}`} data-state={state} style={size ? { "--size": `${size}px` } : undefined}
      role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : "true"}>
      <svg viewBox="-31 -31 62 62">
        <circle class="mk-ground" r="30" />
        <g class="mk-ring">
          <circle class="mk-amber" r={R} fill="none" stroke-width="2.2" stroke-linecap="round"
            stroke-dasharray={`${(C - GAP).toFixed(2)} ${GAP.toFixed(2)}`} transform="rotate(-15.2)" />
          <path class="mk-mint" d={MINT_ARC} fill="none" stroke-width="2.2" stroke-linecap="round" />
        </g>
        <circle class="mk-progress" r={P_R} fill="none" stroke-width="1.6" stroke-linecap="round"
          stroke-dasharray={P_C.toFixed(2)} stroke-dashoffset={(P_C * (1 - p)).toFixed(2)} transform="rotate(-90)" />
        <g class="mk-print"><Ridges id={id} /></g>
        <g class="mk-badge" transform="translate(19 19)">
          <circle r="7.5" />
          <path class="mk-ok" d="M -3.4 0.2 l 2.3 2.3 l 4.4 -4.8" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
          <path class="mk-no" d="M -2.8 -2.8 l 5.6 5.6 M 2.8 -2.8 l -5.6 5.6" fill="none" stroke-width="1.8" stroke-linecap="round" />
        </g>
      </svg>
    </div>
  );
}

/** The fingerprint alone, for small places (the empty vault). */
export function Print({ size = 24, class: cls = "" }) {
  const id = useMemo(() => `mkfp${++ids}`, []);
  return (
    <svg class={`print ${cls}`} width={size} height={size} viewBox="-18 -17 36 36" aria-hidden="true">
      <Ridges id={id} width={1} />
    </svg>
  );
}

/** The logo's hand alone (amber, mint tips). Inherits `currentColor` for monochrome places when `mono`. */
export function Hand({ size = 24, mono = false, class: cls = "" }) {
  return (
    <svg class={`hand ${cls}`} width={size} height={size} viewBox="-18.5 -27 37 37" aria-hidden="true">
      <path d={HAND} fill-rule="evenodd" fill={mono ? "currentColor" : "var(--amber)"} />
      <path d={PRINTS} fill-rule="evenodd" fill={mono ? "var(--ground)" : "var(--mint)"} />
    </svg>
  );
}

/** "HumID." in the official letterforms. `height` in px; width follows. */
export function Wordmark({ height = 28, class: cls = "" }) {
  // the letters span x −16.1..16.1, y 13.9..21.5 in the mark's box
  return (
    <svg class={`wordmark ${cls}`} height={height} viewBox="-16.6 13.6 33.2 8.4" role="img" aria-label="HumID">
      <path d={HUM} fill-rule="evenodd" fill="var(--amber)" />
      <path d={ID} fill-rule="evenodd" fill="var(--mint)" />
    </svg>
  );
}
