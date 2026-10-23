// CRYPTO-01 (review 2026-10-23): a reply for a session dropped while its request was in flight
// must never be sealed. drop() wipes the keys in place, so sealing afterwards encrypted the reply
// under 32 zero bytes, readable by anyone on the path (recovery parts and shares included).
import { test } from "node:test";
import assert from "node:assert/strict";
import { HtpServer, createStatics } from "@humid/htp/server";
import { clientHello, clientFinish } from "../packages/htp/src/handshake.js";
import { sealFrame, parseHeader, openFrame, DIR } from "../packages/htp/src/frame.js";

async function opened() {
  const statics = createStatics();
  const srv = new HtpServer(statics);
  const { wire, state } = clientHello({ kemPk: statics.kemPk, xPk: statics.xPk, dsaPk: statics.dsaPk });
  const cs = clientFinish(state, srv.hello(wire));
  const req = await sealFrame(cs.c2s, DIR.request, cs.sid, 1, { m: "GET", p: "/x" });
  const { session, seq } = await srv.open(req);
  return { srv, cs, session, seq };
}

test("a session dropped mid-request can't have a reply sealed for it", async () => {
  const { srv, session, seq } = await opened();
  srv.drop(session);
  await assert.rejects(async () => srv.seal(session, seq, 200, {}, new TextEncoder().encode('{"secret":1}')),
    (e) => e.code === "session_unknown" && e.status === 401);
});

test("no reply ever opens under an all-zero key", async () => {
  const { srv, session, seq } = await opened();
  const reply = await srv.seal(session, seq, 200, {}, new TextEncoder().encode("ok"));
  await assert.rejects(openFrame(new Uint8Array(32), parseHeader(reply)));
});

test("a live session still gets its reply", async () => {
  const { srv, cs, session, seq } = await opened();
  const reply = await srv.seal(session, seq, 200, {}, new TextEncoder().encode("ok"));
  const pt = await openFrame(cs.s2c, parseHeader(reply));
  assert.equal(new TextDecoder().decode(pt.body), "ok");
});
