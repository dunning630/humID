// Boots the seven HumID services on random local ports with throwaway data
// directories — the same code that runs in the containers.
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newInternalKeys, newStatementKeys } from "@humid/svc";
import { createIdentity } from "../../services/identity/src/server.js";
import { createVault } from "../../services/vault/src/server.js";
import { createLedger } from "../../services/ledger/src/server.js";
import { createRecovery } from "../../services/recovery/src/server.js";
import { createGateway } from "../../services/gateway/src/server.js";
import { createAccess } from "../../services/access/src/server.js";
import { createKeyshare } from "../../services/keyshare/src/server.js";
import { createRelay } from "../../services/relay/src/server.js";
import { ROOTS, IOS_APP_ID } from "./holder.js";

/**
 * devicePolicy: "attested" (default, like production) | "biometric" | "demo".
 * registration: "open" (default here, so flows that aren't about payment stay short) | "pass" (production default).
 * Attestations are checked against test roots shaped like Google's and Apple's.
 */
export async function startStack({ messaging = true, relayOpts = {}, port = 0, recoveryDelayMs = 1500, devicePolicy = "attested", cscas = [], stations = [], allowAnyStation = false, cosigners = new Map(), duressCoolOffMs = 24 * 3600_000, registration = "open", passKeyBits = 2048, passBuyUrl = "", shareReleasesPerHour = 120, dataDir = "", admin = null, checkin = "off", checkinSweepMs = 10_000, keyshareClock = {}, demoStamps = false, recoveryStartsPerHour = 10_000 } = {}) {
  // recoveryStartsPerHour: every test shares one address, so the per-network recovery cap is lifted unless a test sets it.
  // checkin: HUMID_CHECKIN. keyshareClock: { now, mono, tickMs } for Check-in tests that move time.
  // dataDir: keep the stack's data (and so the server's key) between runs; otherwise a fresh temp dir, removed on stop.
  const root = dataDir ? (mkdirSync(dataDir, { recursive: true }), dataDir) : mkdtempSync(join(tmpdir(), "humid-e2e-"));
  const ik = newInternalKeys();
  // SRV-30: what the gateway never holds. core: identity's device vouches and the ledger's
  // receipts; keys: keyshare's erase tokens.
  const coreKeys = newStatementKeys(), keysKeys = newStatementKeys();
  const revoked = new Set(); // Google's status list, as tests set it
  const url = (svc) => `http://127.0.0.1:${svc.server.address().port}`;
  const identity = createIdentity({
    port: 0, dataDir: join(root, "identity"), internalPk: ik.pk, statementSk: coreKeys.sk, duressCoolOffMs,
    attest: {
      roots: { android: [ROOTS.android.pem], apple: [ROOTS.apple.pem] },
      androidPackages: ["app.humid.vault"], iosAppId: IOS_APP_ID, appAttestEnvironment: "production", requireLockedBoot: true,
      // the test chains' app signing certificate digest (tests/support/pki.js)
      androidDigests: ["01".repeat(32)], revokedSerials: () => revoked,
    },
  });
  const vault = createVault({ port: 0, dataDir: join(root, "vault"), internalPk: ik.pk, corePk: coreKeys.pk, keysPk: keysKeys.pk, quotaBytes: 5 * 1024 * 1024, maxObjectBytes: 2 * 1024 * 1024 });
  // checkpointEveryMs 0: a new checkpoint whenever the log has grown, so tests see their entries at once.
  const ledger = createLedger({ port: 0, dataDir: join(root, "ledger"), internalPk: ik.pk, statementSk: coreKeys.sk, cosigners, checkpointEveryMs: 0 });
  const recovery = createRecovery({ port: 0, dataDir: join(root, "recovery"), internalPk: ik.pk, delayMs: recoveryDelayMs, cscas, stations, allowAnyStation });
  const access = createAccess({ port: 0, dataDir: join(root, "access"), internalPk: ik.pk, keyBits: passKeyBits, stampKeyBits: passKeyBits });
  // 4.0 messaging: the relay (no accounts) beside the other services; messaging=false runs a server without one.
  const relay = messaging ? createRelay({ port: 0, dataDir: join(root, "relay"), internalPk: ik.pk, ...relayOpts }) : null;
  let keyshare = createKeyshare({ port: 0, dataDir: join(root, "keyshare"), internalPk: ik.pk, corePk: coreKeys.pk, statementSk: keysKeys.sk, releasesPerHour: shareReleasesPerHour, ...keyshareClock });
  await Promise.all([identity.start(), vault.start(), ledger.start(), recovery.start(), access.start(), keyshare.start(), relay?.start()]);
  const upstreams = { identity: url(identity), vault: url(vault), ledger: url(ledger), recovery: url(recovery), access: url(access), keyshare: url(keyshare), ...(relay ? { relay: url(relay) } : {}) };
  const gateway = createGateway({
    port, dataDir: join(root, "gateway"), internalSk: ik.sk,
    upstreams,
    allowedOrigins: ["http://localhost:5173"], trustProxy: false, devicePolicy, registration, passBuyUrl, admin, checkin, checkinSweepMs, demoStamps, recoveryStartsPerHour,
  });
  await gateway.start();
  const stack = {
    revoked,
    baseUrl: url(gateway), gateway, identity, vault, ledger, recovery, access, keyshare, relay, root, upstreams, internalSk: ik.sk, internalPk: ik.pk, coreKeys, keysKeys,
    /** Stop keyshare and start it again on the same port and data, as a crash or an update would. */
    async restartKeyshare() {
      const port = keyshare.server.address().port;
      await keyshare.stop(); keyshare.close();
      keyshare = createKeyshare({ port, dataDir: join(root, "keyshare"), internalPk: ik.pk, corePk: coreKeys.pk, statementSk: keysKeys.sk, releasesPerHour: shareReleasesPerHour, ...keyshareClock });
      await keyshare.start();
      stack.keyshare = keyshare;
    },
    async stop() {
      // whatever is running now (a test may have restarted one)
      await Promise.all([stack.gateway, stack.identity, stack.vault, stack.ledger, stack.recovery, stack.access, stack.keyshare, stack.relay].filter(Boolean).map((s) => s.stop()));
      stack.access.close(); stack.keyshare.close(); stack.relay?.close();
      if (!dataDir) rmSync(root, { recursive: true, force: true });
    },
  };
  return stack;
}
