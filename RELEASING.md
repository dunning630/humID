# Releasing HumID without forklift upgrades

The goal: every change ships as the smallest possible release, and nothing a
user already has (identities, sealed envelopes) ever needs a bulk conversion.

## 1. Seams that make small releases possible

| Seam | Rule | What it allows |
|---|---|---|
| **Modules** (`modules/*`) | Own semver, own CHANGELOG; talk only through exported interfaces. | Fix the vault table without touching crypto. |
| **Contracts** (`"humid": {provides, requires}`) | The shell build fails on a mismatch. | Modules release independently, safely. |
| **Envelope format v1** (`@humid/codec`) | Frozen. A new layout gets a new magic version byte and a new parse branch. | Envelopes sealed today open in every future build. |
| **Sealing suites** (`@humid/crypto`) | A suite is frozen once released. Changing any primitive means a new suite id (e.g. `HUMID-PQ2`) added beside PQ1. | Crypto agility: new seals use the new suite, old envelopes still open. |
| **Gate contract v1** (`@humid/gate`) | Adapters implement probe / enroll / release / forget. | Add a gate (FIDO2, a new OS API) as one file. |
| **Native plugin** (`plugins/humid-gate`) | Command names + response shapes are its API (`humid-gate@1`). Platform code is split per OS file. | A Windows Hello fix rebuilds and ships Windows only. |
| **Identity schema** (`@humid/store`) | Records carry `schema`; one migration step per bump, run on read. Never edit a released step. | Data upgrades happen lazily per record, never as a bulk conversion. |
| **Shell** (`shell/`) | Thin on purpose: hosts modules, one `save_bytes` command. | Rarely needs a release of its own. |

## 2. Day-to-day flow

1. Make the change in the module(s) that own it.
2. `npx changeset`: tick only the modules you changed and choose patch / minor / major.
3. Open a PR. CI runs the tests and compiles **only the affected platforms**
   (`node tools/affected.mjs` shows what it decided).
4. Merge. `npm run version-modules` bumps exactly the changed modules and
   their dependents, and writes their CHANGELOG entries.

## 3. Shipping apps

- **One or a few platforms:** Actions → *Release apps* → platforms: `windows`
  (or `ios,android`). Only those build and upload.
- **Everything:** tag `app-vX.Y.Z` (bump `shell/package.json` first); a draft
  GitHub release collects all five platforms' installers.
- Each app embeds `modules.json` listing the module versions it contains, so a
  bug report pins the exact combination.

### What a change costs

| You changed | Modules bumped | Apps rebuilt |
|---|---|---|
| `plugins/humid-gate/src/desktop/windows.rs` | humid-gate crate | Windows |
| `plugins/humid-gate/android/**` | humid-gate crate | Android |
| `modules/ui/**` | @humid/ui | all five (the UI ships inside each app) |
| `modules/crypto/**` | @humid/crypto, @humid/ui | all five |
| docs, tests, CI | none | none |

## 4. Versioning the native plugin

The Rust crate's version lives in `plugins/humid-gate/Cargo.toml`. Bump it
by hand with the same patch / minor / major meaning, and tag
`humid-gate-vX.Y.Z`. A **major** bump (a renamed command or changed response
shape) also needs `@humid/gate` to update its `requires.native-plugin`
contract, which the shell build enforces.

## 5. Breaking changes, safely

- **New envelope layout:** add a codec branch, keep v1 parsing forever.
- **New crypto:** add a suite file and a registry line, then switch
  `DEFAULT_SUITE`. Never modify a released suite.
- **New identity fields:** add a migration step and bump `IDENTITY_SCHEMA`.
  Older apps refuse to open newer records with a clear "update HumID" message
  instead of corrupting them.
