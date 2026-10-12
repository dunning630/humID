// Boots the five HumID services on random local ports with throwaway data
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

export async function startStack({ port = 0, recoveryDelayMs = 1500, minAssurance = "none" } = {}) {
  const root = mkdtempSync(join(tmpdir(), "humid-e2e-"));
  const ik = newInternalKeys();
  const url = (svc) => `http://127.0.0.1:${svc.server.address().port}`;
  const identity = createIdentity({ port: 0, dataDir: join(root, "identity"), internalPk: ik.pk });
  const vault = createVault({ port: 0, dataDir: join(root, "vault"), internalPk: ik.pk, quotaBytes: 5 * 1024 * 1024, maxObjectBytes: 2 * 1024 * 1024 });
  const ledger = createLedger({ port: 0, dataDir: join(root, "ledger"), internalPk: ik.pk });
  const recovery = createRecovery({ port: 0, dataDir: join(root, "recovery"), internalPk: ik.pk, delayMs: recoveryDelayMs });
  await Promise.all([identity.start(), vault.start(), ledger.start(), recovery.start()]);
  const gateway = createGateway({
    port, dataDir: join(root, "gateway"), internalSk: ik.sk,
    upstreams: { identity: url(identity), vault: url(vault), ledger: url(ledger), recovery: url(recovery) },
    allowedOrigins: ["http://localhost:5173"], trustProxy: false, minAssurance,
  });
  await gateway.start();
  return {
    baseUrl: url(gateway), gateway, identity, vault, ledger, recovery, root,
    async stop() {
      await Promise.all([gateway, identity, vault, ledger, recovery].map((s) => s.stop()));
      rmSync(root, { recursive: true, force: true });
    },
  };
}
