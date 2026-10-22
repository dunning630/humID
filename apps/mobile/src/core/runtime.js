// The kernel's shared state and small helpers. One object, R, holds what the core
// modules share at run time (the store, the API client, the session keys). Nothing
// here is exported to screens: they read signals (state.js) and call functions.
//
// Keys on a device (docs/RECOVERY.md):
//   account seed A   shared by all of the holder's devices. Its keys seal and open
//                    documents, encrypt the index, and authorise new devices.
//   device seed D    this device only. Its ML-DSA-87 key signs in and signs every
//                    step-up proof, so one device can be removed without the others.
// The biometric gate releases one secret that unwraps A ‖ D. Seeds exist only inside
// one check (core/interrupt.js withKeys) and are wiped right after. What stays in
// memory while unlocked: three keys derived from A (index, offline copy, settings),
// wiped on lock.
import { fromB64 } from "@humid/codec";
import { random } from "@humid/crypto";

export const R = {
  store: null,         // @humid/store, opened at boot
  api: null,           // @humid/api client
  sim: null,           // simulation build: the server inside the app
  indexKey: null,      // decrypts item names while unlocked; wiped on lock
  offlineKey: null,    // seals this device's offline copy while unlocked; wiped on lock
  settingsKey: null,   // opens this device's sealed settings (duress gesture); wiped on lock
  duressSetting: null, // { enabled, gesture } once a live check opened it; cleared on lock
  duressUnreadable: false,
  offline: null,       // the offline copy, as last saved (in memory while unlocked)
  busy: false,         // a check is running: leaving the screen doesn't lock
  knownNames: new Map(), // object id → name, so Activity can name deleted items
  hooks: {},           // late-bound callbacks between modules (keyGone, loadCheckin)
  epoch: 0,            // counts locks: a result that began in an earlier epoch is dropped, not shown
};
/** The epoch now, to compare after an await: `if (stale(e)) return`. */
export const epoch = () => R.epoch;
export const stale = (e) => e !== R.epoch;

export const SEED = 64;
export const CARD = 15;            // a recovery card's secret
export const KEY_TYPE = "application/x-humid-key";
export const MAX_FILE = 50 * 1024 * 1024;

export const wipe = (...b) => { for (const x of b) if (x && x.fill) x.fill(0); };
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
export const utf8 = (s) => new TextEncoder().encode(s);
/** For checks no server verifies (seeing whose pieces you hold): still a live check, fresh challenge. */
export const localChallenge = (purpose) => concat(utf8(`HUMID-LOCAL-v1 ${purpose} `), random(32));
export const fromB64u = (s) => fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

/* global __HUMID_SIM__, __HUMID_ALLOW_DEMO__ */
// Build flags (build.mjs `define`, always a literal true/false). They're tested INLINE
// where they matter (the spelled-out `typeof … && … === true`), never through a helper:
// esbuild folds a define only where it appears, and that's what makes every simulation
// and demo branch disappear from release builds (tests/bundle.test.js).
