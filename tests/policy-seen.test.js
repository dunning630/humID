// CRYPTO-07 round 2, on the phone: the newest signed policy this device accepted is kept
// in the identity record, so after a restart a replayed older one still isn't used.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HtpServer, createStatics } from "@humid/htp/server";
import { HumidApi } from "@humid/api";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { connectServer } from "../apps/mobile/src/core/session.js";

test("the phone remembers the newest signed policy and refuses an older one after a restart", async () => {
  const server = new HtpServer(createStatics());
  const now = Date.now();
  const old = server.signedPolicy({ devicePolicy: "attested", registration: "pass", splitKeys: true, passBuyUrl: "https://old.example/buy" }, now - 5 * 86_400_000);
  server.policyCache = null;
  const cur = server.signedPolicy({ devicePolicy: "attested", registration: "pass", splitKeys: true, passBuyUrl: "https://humidsecure.com/access" }, now - 60_000);
  let serving = cur;
  const fetch = async () => Response.json({ ...server.publicKeys(), ...serving });
  const saved = [];
  R.store = { getIdentity: async () => saved.at(-1) ?? S.identity.value, putIdentity: async (r) => { saved.push(r); } };
  S.identity.value = { server: { id: "hid_x" }, schema: 4 };
  R.api = new HumidApi({ fetch, pinnedKid: server.kid });
  await connectServer();
  assert.equal(S.server.value.policy.passBuyUrl, "https://humidsecure.com/access");
  assert.equal(saved.at(-1).policySeen.at, cur.policySig.at);

  // restart: a new client, as boot() makes it from the stored record, on a network replaying the old policy
  serving = old;
  R.api = new HumidApi({ fetch, pinnedKid: server.kid });
  R.api.htp.policySeen = S.identity.value.policySeen;
  await connectServer();
  assert.equal(S.server.value.policy.passBuyUrl, "https://humidsecure.com/access", "the old shop link never comes back");
  assert.equal(S.identity.value.policySeen.at, cur.policySig.at);
});
