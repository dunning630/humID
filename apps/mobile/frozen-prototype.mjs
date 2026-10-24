// The native shells freeze Object.prototype before any app script runs (tauri.conf.json
// app.security.freezePrototype; V5 "narrow web view"). After that, a plain assignment to a
// name a frozen prototype owns (valueOf, toString, toJSON, ...) on an object that inherits
// it throws in strict code: the "override mistake". Three of the app's libraries do that, so
// the app would stop before its first paint (or on the first suspended screen):
//   @preact/signals-core  Signal.prototype.valueOf / toString / toJSON = function () {...}
//   qrcode-generator      _this.toString = function () {...}   (its byte and base64 streams)
//   preact, preact/compat assign(target, source) copying a vnode's own `constructor` key
//
// This esbuild plugin rewrites each such `X.key = function` into
// `own(X, "key").key = function`: `own` first gives X an own, writable, enumerable property
// (what the plain assignment would have created), so the original assignment just writes it.
// Each file must contain exactly the assignments listed, so a dependency update that changes
// them fails the build instead of breaking the app on a phone. Workers are untouched: Tauri's
// init script freezes the page's realm only.
//
// tests/modules.test.js runs these libraries, built with this plugin, under a frozen prototype;
// the browser checks run the whole app that way (tools/dev.mjs mirrors freezePrototype).
import { readFile } from "node:fs/promises";

const OWN = "((o,k)=>Object.defineProperty(o,k,{value:void 0,writable:!0,enumerable:!0,configurable:!0}))";

// Preact's internal assign(target, source) (in core and in compat, which Suspense and lazy
// come from) copies with `target[key] = source[key]`, and its vnodes carry an own
// `constructor: undefined` (Preact's guard against JSON-injected vnodes), so copying one (a
// re-render, a suspended subtree, cloneElement) writes `constructor` onto a plain object. Its
// loop gets the same treatment: an own property first where the frozen prototype has one.
const assignLoop = (name, t, s, k) =>
  `function ${name}(${t},${s}){for(var ${k} in ${s})Object.prototype.hasOwnProperty.call(Object.prototype,${k})&&!Object.prototype.hasOwnProperty.call(${t},${k})&&Object.defineProperty(${t},${k},{value:void 0,writable:!0,enumerable:!0,configurable:!0}),${t}[${k}]=${s}[${k}];return ${t}}`;

export const OVERRIDES = [
  { file: /[\\/]@preact[\\/]signals-core[\\/]dist[\\/]signals-core\.(mjs|module\.js)$/, re: /\b([A-Za-z_$][\w$]*\.prototype)\.(valueOf|toString|toJSON)=(?=function)/g, want: 3 },
  { file: /[\\/]qrcode-generator[\\/]dist[\\/]qrcode\.mjs$/, re: /\b(_this)\.(toString) = (?=function)/g, want: 2 },
  {
    file: /[\\/]preact[\\/](compat[\\/])?dist[\\/](preact|compat)\.(mjs|module\.js)$/,
    re: /function ([A-Za-z_$][\w$]*)\(([a-z]),([a-z])\)\{for\(var ([a-z]) in \3\)\2\[\4\]=\3\[\4\];return \2\}/g,
    want: 1,
    to: (_, name, t, s, k) => assignLoop(name, t, s, k),
  },
];

export const frozenPrototypeSafe = {
  name: "frozen-prototype-safe",
  setup(b) {
    for (const o of OVERRIDES) {
      b.onLoad({ filter: o.file }, async (args) => {
        let n = 0;
        const contents = (await readFile(args.path, "utf8")).replace(o.re, (...m) => { n++; return o.to ? o.to(...m) : `${OWN}(${m[1]},"${m[2]}").${m[2]}=`; });
        if (n !== o.want) throw new Error(`frozen-prototype-safe: expected ${o.want} assignments in ${args.path}, found ${n}. The dependency changed: check it still runs with a frozen Object.prototype, then update OVERRIDES in apps/mobile/frozen-prototype.mjs.`);
        return { contents, loader: "js" };
      });
    }
  },
};
