// Bundle one service into a single self-contained file:
//   node services/build-service.mjs vault   ->  services/vault/dist/server.mjs
// The runtime image then needs only Node and this one file: no node_modules,
// no package manager, no shell.
import * as esbuild from "esbuild";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

const name = process.argv[2];
const dir = fileURLToPath(new URL(`./${name}/`, import.meta.url));
const pkg = JSON.parse(readFileSync(`${dir}package.json`, "utf8"));

await esbuild.build({
  entryPoints: [`${dir}src/server.js`],
  outfile: `${dir}dist/server.mjs`,
  bundle: true,
  platform: "node",
  target: "node24",
  format: "esm",
  minify: false, // keep stack traces readable in logs
  sourcemap: false,
  legalComments: "eof",
  define: { "process.env.HUMID_SERVICE_VERSION": JSON.stringify(pkg.version) },
  logLevel: "info",
});
