// The app's launcher icon (3.0.1): the HumID logo's peace-sign hand inside its ring, on the brand's
// ink, without the wordmark (the launcher prints the app's name under it). Drawn from the same
// vector data as the app (apps/mobile/src/brand/logo-data.js), rendered with Playwright's Chromium,
// then handed to `tauri icon` for every platform's sizes.
//
//   node tools/app-icon.mjs            writes apps/mobile/src-tauri/icons/** (and app-icon/*.png, the sources)
//
// Android gets an adaptive icon: the ring and hand on a transparent foreground (inside the 66 dp
// safe zone, so no launcher mask cuts them) over a solid ink background.
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { chromium } from "playwright";
import { HAND, PRINTS } from "../apps/mobile/src/brand/logo-data.js";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = join(repo, "apps", "mobile");
const out = join(app, "src-tauri", "app-icon");
mkdirSync(out, { recursive: true });

const tokens = readFileSync(join(app, "src", "brand", "tokens.css"), "utf8");
const brand = (n) => tokens.match(new RegExp(`--brand-${n}:\\s*(#[0-9A-Fa-f]{6})`))[1];
const AMBER = brand("amber"), MINT = brand("mint"), INK = brand("ink");

// the ring, as the app's mark draws it (brand/mark.jsx)
const R = 28.5, C = 2 * Math.PI * R, GAP = (C * 83.6) / 360;
const pt = (r, d) => `${(r * Math.cos((d * Math.PI) / 180)).toFixed(2)} ${(r * Math.sin((d * Math.PI) / 180)).toFixed(2)}`;
const ring = `<circle r="${R}" fill="none" stroke="${AMBER}" stroke-width="2.4" stroke-linecap="round" stroke-dasharray="${(C - GAP).toFixed(2)} ${GAP.toFixed(2)}" transform="rotate(-15.2)"/>
  <path d="M ${pt(R, -94.2)} A ${R} ${R} 0 0 1 ${pt(R, -19.8)}" fill="none" stroke="${MINT}" stroke-width="2.4" stroke-linecap="round"/>`;
// the hand sits above the wordmark in the logo (its middle at y ≈ −7.8): brought to the middle, a little larger
const hand = `<g transform="scale(1.16) translate(0 7.8)"><path d="${HAND}" fill="${AMBER}" fill-rule="evenodd"/><path d="${PRINTS}" fill="${MINT}" fill-rule="evenodd"/></g>`;

/** An SVG of the logo with the ring's outer edge at `share` of the picture's width; `bg` fills it (or none). */
const svg = (share, bg) => {
  const half = 30 / share;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="${-half} ${-half} ${2 * half} ${2 * half}">
  ${bg ? `<rect x="${-half}" y="${-half}" width="${2 * half}" height="${2 * half}" fill="${bg}"/>` : ""}
  <circle r="30" fill="${INK}"/>
  ${ring}
  ${hand}
</svg>`;
};

const pictures = {
  "icon.png": svg(0.84, INK),           // iOS, desktop, Android before 8: the whole square
  "android-fg.png": svg(0.6, null),     // Android 8+: the foreground layer, inside the safe zone
  "android-bg.png": `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024"><rect width="1024" height="1024" fill="${INK}"/></svg>`,
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1024, height: 1024 } });
for (const [name, s] of Object.entries(pictures)) {
  writeFileSync(join(out, name.replace(/\.png$/, ".svg")), s);
  await page.setContent(`<html><body style="margin:0;background:transparent">${s}</body></html>`);
  await page.locator("svg").screenshot({ path: join(out, name), omitBackground: true });
}
await browser.close();

writeFileSync(join(out, "manifest.json"), JSON.stringify({ default: "icon.png", bg_color: INK, android_bg: "android-bg.png", android_fg: "android-fg.png", android_fg_scale: 100 }, null, 2) + "\n");
execFileSync(join(repo, "node_modules", ".bin", "tauri"), ["icon", join(out, "manifest.json")], { cwd: app, stdio: "inherit" });
console.log("icons written to apps/mobile/src-tauri/icons");
