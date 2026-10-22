// Penetration regression: sign-in brute force. 10 wrong proofs per identity per
// 5 minutes, then rate_limited for further WRONG proofs. A valid proof is never refused
// because of other people's failures (SRV-02): the account id is not a secret, and a holder
// locked out of sign-in could miss a Check-in and lose the vault. Own stack: the
// handshake bucket (one hello per sign-in attempt) is shared per process.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { ml_dsa87 } from "@humid/htp";
import { HumidApi } from "@humid/api";
import { startStack } from "../e2e/stack.js";
import { makeHolder } from "../e2e/holder.js";
import { registered } from "./_lib.js";

let stack, holder;
before(async () => { stack = await startStack(); });
after(async () => { await stack?.stop(); });

test("15 wrong sign-ins: 10 bad_proof, then rate_limited, and the right key still signs in", async () => {
  const r = await registered(stack, "brute-victim");
  holder = r.holder;
  await r.api.logout();
  const mallory = makeHolder("brute-mallory");
  // a wrong device key under the victim's own liveness signature, the strongest thing a thief of one key could try
  const badSign = async (m) => ({ sig: ml_dsa87.sign(m, mallory.dkeys.dsaSk), interrupt: holder.interrupt, live: holder.liveKey.sign(m) });
  const codes = [];
  for (let i = 0; i < 15; i++) {
    const api = new HumidApi({ baseUrl: stack.baseUrl });
    codes.push(await api.login({ id: holder.id, device: holder.deviceId, sign: badSign }).then(() => "signed-in", (e) => e.code));
  }
  assert.deepEqual(codes.slice(0, 10), Array(10).fill("bad_proof"));
  assert.deepEqual(codes.slice(10), Array(5).fill("rate_limited"));
  // the throttle counts failures only: the holder's own, correct key is never refused because of them
  const ok = await new HumidApi({ baseUrl: stack.baseUrl }).login({ id: holder.id, device: holder.deviceId, sign: holder.sign });
  assert.equal(ok.id, holder.id);
});

test("the limit is per identity, not per server: another account signs in normally", async () => {
  const { api, holder: other } = await registered(stack, "brute-bystander");
  await api.logout();
  const s = await new HumidApi({ baseUrl: stack.baseUrl }).login({ id: other.id, device: other.deviceId, sign: other.sign });
  assert.equal(s.id, other.id);
});

test("every failed sign-in up to the budget is in the victim's ledger as access.denied, then one throttle note", async () => {
  // the ledger is read through a signed-in session; the victim is locked out, so read the service directly
  const { verifyLedger } = await import("@humid/audit");
  const { signRequest } = await import("@humid/svc");
  const a = signRequest(stack.internalSk, { aud: "ledger", method: "GET", path: "/events?limit=200", claims: { sub: holder.id } });
  const res = await fetch(`${stack.upstreams.ledger}/events?limit=200`, { headers: { "x-humid-assertion": a } });
  assert.equal(res.status, 200);
  const page = await res.json();
  assert.equal(verifyLedger(page).ok, true);
  const denied = page.entries.map((e) => JSON.parse(e.body)).filter((e) => e.type === "access.denied" && e.detail?.reason === "bad_login_proof");
  assert.equal(denied.length, 10);
  const notes = page.entries.map((e) => JSON.parse(e.body)).filter((e) => e.type === "access.denied" && e.detail?.reason === "sign_in_throttled");
  assert.equal(notes.length, 1, "the 5 throttled failures leave one note, not five entries");
});
