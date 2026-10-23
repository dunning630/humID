// PC-21: every container in the Docker deployment runs read-only, as non-root, with no
// capabilities and no privilege escalation, the edge included; and every base image is
// pinned by digest or carries the TODO that says it isn't yet.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parse } from "yaml";

const repo = new URL("../", import.meta.url);
const compose = parse(readFileSync(new URL("deploy/docker-compose.yml", repo), "utf8"), { merge: true });

test("every service, the edge included, is read-only, non-root, capability-free", () => {
  for (const [name, svc] of Object.entries(compose.services)) {
    assert.equal(svc.read_only, true, `${name}: read_only`);
    assert.deepEqual(svc.cap_drop, ["ALL"], `${name}: cap_drop ALL`);
    assert.ok((svc.security_opt || []).includes("no-new-privileges:true"), `${name}: no-new-privileges`);
    assert.equal(svc.cap_add, undefined, `${name}: no capability added back`);
    assert.notEqual(svc.privileged, true, `${name}: not privileged`);
  }
  const edge = compose.services.edge;
  assert.equal(edge.user, "65532:65532", "the edge runs as an unprivileged user");
  assert.equal(edge.sysctls?.["net.ipv4.ip_unprivileged_port_start"], 0, "…which may bind 80 and 443 in its own network namespace");
  assert.match(readFileSync(new URL("services/edge/Dockerfile", repo), "utf8"), /^USER 65532:65532$/m);
});

test("only the edge and the attestation-status sidecar touch the public network", () => {
  for (const [name, svc] of Object.entries(compose.services)) {
    const nets = svc.networks || [];
    if (name === "edge") assert.deepEqual([...nets].sort(), ["internal", "public"]);
    else if (name === "attestation-status") assert.deepEqual(nets, ["public"], "the fetcher can't reach any service");
    else assert.deepEqual(nets, ["internal"], `${name} has no route out`);
  }
  assert.equal(compose.networks.internal.internal, true);
});

test("base images: pinned by digest, or marked TODO(PC-21)", () => {
  for (const f of ["services/Dockerfile", "services/edge/Dockerfile"]) {
    const text = readFileSync(new URL(f, repo), "utf8");
    const froms = [...text.matchAll(/^FROM\s+(\S+)/gm)].map((m) => m[1]);
    assert.ok(froms.length >= 2, f);
    const unpinned = froms.filter((i) => !/@sha256:[0-9a-f]{64}$/.test(i));
    if (unpinned.length) assert.match(text, /TODO\(PC-21\): pin both base images by digest/, `${f}: ${unpinned.join(", ")} not pinned and not marked`);
  }
});
