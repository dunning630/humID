// Boots the six HumID services on random local ports with throwaway data
// directories — the same code that runs in the containers.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newInternalKeys } from "@humid/svc";
import { createIdentity } from "../../services/identity/src/server.js";
import { createVault } from "../../services/vault/src/server.js";
import { createLedger } from "../../services/ledger/src/server.js";
import { createRecovery } from "../../services/recovery/src/server.js";
import { createGateway } from "../../services/gateway/src/server.js";
import { createAccess } from "../../services/access/src/server.js";
import { ROOTS, IOS_APP_ID } from "./holder.js";

/**
 * devicePolicy: "attested" (default, like production) | "biometric" | "demo".
 * registration: "open" (default here, so flows that aren't about payment stay short) | "pass" (production default).
 * Attestations are checked against test roots shaped like Google's and Apple's.
 */
export async function startStack({ port = 0, recoveryDelayMs = 1500, devicePolicy = "attested", cscas = [], stations = [], cosigners = new Map(), duressCoolOffMs = 24 * 3600_000, registration = "open", passKeyBits = 2048, passBuyUrl = "" } = {}) {
  const root = mkdtempSync(join(tmpdir(), "humid-e2e-"));
  const ik = newInternalKeys();
  const url = (svc) => `http://127.0.0.1:${svc.server.address().port}`;
  const identity = createIdentity({
    port: 0, dataDir: join(root, "identity"), internalPk: ik.pk, duressCoolOffMs,
    attest: {
      roots: { android: [ROOTS.android.pem], apple: [ROOTS.apple.pem] },
      androidPackages: ["app.humid.vault"], iosAppId: IOS_APP_ID, appAttestEnvironment: "production", requireLockedBoot: true,
    },
  });
  const vault = createVault({ port: 0, dataDir: join(root, "vault"), internalPk: ik.pk, quotaBytes: 5 * 1024 * 1024, maxObjectBytes: 2 * 1024 * 1024 });
  const ledger = createLedger({ port: 0, dataDir: join(root, "ledger"), internalPk: ik.pk, cosigners });
  const recovery = createRecovery({ port: 0, dataDir: join(root, "recovery"), internalPk: ik.pk, delayMs: recoveryDelayMs, cscas, stations });
  const access = createAccess({ port: 0, dataDir: join(root, "access"), internalPk: ik.pk, keyBits: passKeyBits });
  await Promise.all([identity.start(), vault.start(), ledger.start(), recovery.start(), access.start()]);
  const upstreams = { identity: url(identity), vault: url(vault), ledger: url(ledger), recovery: url(recovery), access: url(access) };
  const gateway = createGateway({
    port, dataDir: join(root, "gateway"), internalSk: ik.sk,
    upstreams,
    allowedOrigins: ["http://localhost:5173"], trustProxy: false, devicePolicy, registration, passBuyUrl,
  });
  await gateway.start();
  return {
    baseUrl: url(gateway), gateway, identity, vault, ledger, recovery, access, root, upstreams, internalSk: ik.sk,
    async stop() {
      await Promise.all([gateway, identity, vault, ledger, recovery, access].map((s) => s.stop()));
      access.close();
      rmSync(root, { recursive: true, force: true });
    },
  };
}
