// Brand elements recreated from the humidsecure.ai hero, drawn in code so
// they are crisp at any size and can carry state (idle → scanning → verified).
import { useEffect, useRef } from "preact/hooks";

/* ---------- fingerprint ridges, generated once ---------- */
function ridges() {
  const cx = 100, cy = 103, out = [];
  // Gaps per ridge (in radians) give the whorl look of the hero fingerprint.
  const gaps = [[2.2, 0.9], [1.5, 0.7], [4.1, 0.6], [0.9, 0.55], [3.3, 0.5], [5.2, 0.45], [2.6, 0.42], [4.6, 0.4], [1.2, 0.38], [3.9, 0.36]];
  for (let i = 0; i < 10; i++) {
    const rx = 5 + i * 3.6, ry = 7 + i * 4.6;
    const [g, w] = gaps[i];
    const a0 = g + w / 2, a1 = g - w / 2 + Math.PI * 2;
    // split long ridges once more for texture
    const cuts = i > 3 ? [a0, a0 + (a1 - a0) * 0.46, a0 + (a1 - a0) * 0.52, a1] : [a0, a1];
    for (let k = 0; k < cuts.length; k += 2) {
      const s = cuts[k], e = cuts[k + 1];
      const p = (t) => `${(cx + rx * Math.cos(t)).toFixed(2)} ${(cy + ry * Math.sin(t)).toFixed(2)}`;
      const large = e - s > Math.PI ? 1 : 0;
      out.push(`M ${p(s)} A ${rx} ${ry} 0 ${large} 1 ${p(e)}`);
    }
  }
  return out;
}
const RIDGES = ridges();
const C_PROGRESS = 2 * Math.PI * 74;

/**
 * The HumID mark. state: "idle" | "scanning" | "verified" | "failed".
 * progress 0..1 fills the inner ring (amber while scanning, mint when verified).
 */
export function Mark({ state = "idle", progress = 0, size, label }) {
  const p = state === "verified" ? 1 : progress;
  return (
    <div class="mark" data-state={state} style={size ? { "--size": `${size}px` } : undefined} role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : "true"}>
      <svg viewBox="0 0 200 200">
        <defs>
          <linearGradient id="fpGrad" x1="0.15" y1="0.9" x2="0.85" y2="0.1">
            <stop offset="0" stop-color="#da934a" />
            <stop offset="0.5" stop-color="#c7a35b" />
            <stop offset="1" stop-color="#8ac988" />
          </linearGradient>
          <radialGradient id="markGlow">
            <stop offset="0" stop-color="#8ac988" stop-opacity="0.16" />
            <stop offset="0.6" stop-color="#8ac988" stop-opacity="0.04" />
            <stop offset="1" stop-color="#8ac988" stop-opacity="0" />
          </radialGradient>
        </defs>
        <circle class="glow" cx="100" cy="100" r="99" />
        <circle class="r-outer" cx="100" cy="100" r="93" fill="none" stroke-width="1" />
        <circle class="r-ticks" cx="100" cy="100" r="89" fill="none" stroke-width="3.5" stroke-dasharray="0.8 6.2" />
        <g class="r-mint" fill="none" stroke-width="3.2" stroke-linecap="round">
          <circle cx="100" cy="100" r="84" stroke-dasharray="70 34 22 92 46 264" />
        </g>
        <g class="r-amber" fill="none">
          <circle cx="100" cy="100" r="78" stroke-width="1.3" />
          {[0, 120, 240].map((a) => (
            <path d="M 100 19 l 4 3.2 l -4 3.2 z" fill="#da934a" stroke="none" transform={`rotate(${a} 100 100)`} />
          ))}
        </g>
        <circle class="r-progress" cx="100" cy="100" r="74" fill="none" stroke-width="2.4" stroke-linecap="round"
          stroke-dasharray={C_PROGRESS} stroke-dashoffset={C_PROGRESS * (1 - Math.max(0, Math.min(1, p)))} />
        <g class="fp">{RIDGES.map((d) => <path d={d} />)}</g>
        <g class="check">
          <circle cx="146" cy="146" r="15" />
          <path d="M 139 146.5 l 5 5 l 9 -10" />
        </g>
      </svg>
    </div>
  );
}

export function Wordmark({ small }) {
  return (
    <span class={`wordmark${small ? " sm" : ""}`} aria-label="HumID">
      <span class="hum">Hum</span><span class="id">ID.</span>
    </span>
  );
}

/** Slow starfield like the hero video. Pauses when hidden; static under reduced motion. */
export function Stars({ count = 90 }) {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    let raf = 0, last = 0, w = 0, h = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let seed = 7;
    const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    const stars = Array.from({ length: count }, () => ({
      x: rnd(), y: rnd(), r: 0.35 + rnd() * 1.1, a: 0.25 + rnd() * 0.6, tw: rnd() * Math.PI * 2,
      c: rnd() < 0.12 ? "218,147,74" : rnd() < 0.3 ? "138,201,136" : "205,222,212",
      dy: 0.002 + rnd() * 0.006,
    }));
    const resize = () => {
      w = canvas.clientWidth; h = canvas.clientHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const draw = (t) => {
      ctx.clearRect(0, 0, w, h);
      for (const s of stars) {
        const a = s.a * (0.65 + 0.35 * Math.sin(s.tw + t / 1400));
        ctx.fillStyle = `rgba(${s.c},${a.toFixed(3)})`;
        ctx.beginPath();
        ctx.arc(s.x * w, ((s.y + (t / 1000) * s.dy) % 1) * h, s.r, 0, Math.PI * 2);
        ctx.fill();
      }
    };
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const loop = (t) => {
      if (t - last > 48) { draw(t); last = t; }
      raf = requestAnimationFrame(loop);
    };
    resize();
    draw(0);
    if (!still) raf = requestAnimationFrame(loop);
    const onVis = () => { cancelAnimationFrame(raf); if (!document.hidden && !still) raf = requestAnimationFrame(loop); };
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVis);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); document.removeEventListener("visibilitychange", onVis); };
  }, []);
  return <div class="stars" aria-hidden="true"><canvas ref={ref} /></div>;
}
