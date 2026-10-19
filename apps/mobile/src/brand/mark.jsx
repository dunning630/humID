// The HumID mark and wordmark, drawn from the official vector data (logo-data.js).
// One SVG, no raster, crisp at every size; state is carried by data attributes and
// a few CSS rules in brand/base.css, so the only JavaScript here is markup.
//
//   <Mark />                          the full mark: ring, hand, no words
//   <Mark state="scanning" />         a live check is running (ring turns, tips pulse)
//   <Mark state="verified" />         the check passed (mint badge)
//   <Mark state="failed" />           it didn't
//   <Mark progress={0.4} />           how far the check is (0..1), while scanning
//   <Hand />                          the hand alone, for small places (tab bar, rows)
//   <Wordmark />                      "HumID." — Hum amber, ID. mint
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

export function Mark({ state = "idle", progress = 0, size, label, class: cls = "" }) {
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
        <g class="mk-hand" transform="translate(0 -1.5) scale(1.04)">
          <path class="mk-palm" d={HAND} fill-rule="evenodd" />
          <path class="mk-prints" d={PRINTS} fill-rule="evenodd" />
        </g>
        <g class="mk-badge" transform="translate(19 19)">
          <circle r="7.5" />
          <path class="mk-ok" d="M -3.4 0.2 l 2.3 2.3 l 4.4 -4.8" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
          <path class="mk-no" d="M -2.8 -2.8 l 5.6 5.6 M 2.8 -2.8 l -5.6 5.6" fill="none" stroke-width="1.8" stroke-linecap="round" />
        </g>
      </svg>
    </div>
  );
}

/** The hand alone (amber, mint tips). Inherits `currentColor` for monochrome places when `mono`. */
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
