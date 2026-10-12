// HTP/1 handshake: one round trip, hybrid post-quantum + classical, with
// forward secrecy and implicit + explicit server authentication.
//
//   Client                                              Server (static: KEM_S, X_S)
//   ekC, dkC  <- ML-KEM-1024.KeyGen()   (ephemeral)
//   xC        <- X25519 ephemeral
//   ctS, ssS  <- ML-KEM-1024.Encaps(KEM_S.pk)
//   ClientHello{kid, nC, ts, ekC, xC, ctS}  ------------>
//                                                      ssS  <- Decaps(KEM_S.sk, ctS)
//                                                      ctC, ssE <- Encaps(ekC)
//                                                      xS   <- X25519 ephemeral
//                                                      ssXS <- X25519(X_S.sk, xC)
//                                                      ssXE <- X25519(xS.sk, xC)
//                     <------------  ServerHello{sid, nS, exp, ctC, xS, confirm}
//   ssE <- Decaps(dkC, ctC); ssXS, ssXE likewise
//
//   th  = SHA3-256(length-prefixed transcript of every field above)
//   prk = HKDF-SHA3-256(ikm = ssS || ssE || ssXS || ssXE, salt = th)
//   kC2S, kS2C, kConfirm = HKDF expand with distinct labels
//   confirm = HMAC-SHA3-256(kConfirm, "HTP/1 server confirm" || th)
//
// Breaking the session needs BOTH ML-KEM-1024 and X25519 broken (hybrid).
// Compromise of the server's static keys later does not expose past sessions
// (ssE and ssXE come from ephemerals that are discarded).

import {
  ml_kem1024, x25519, sha3_256, concat, lp, u64, utf8, random, kdf, mac, equal, wipe,
  b64u, unb64u, toHex, fromHex,
} from "./primitives.js";

export const VERSION = 1;
export const SUITE = "HTP1-MLKEM1024+X25519-HKDF-SHA3-256-AES256GCM";
const LABEL = utf8("HTP/1 handshake");
export const HELLO_SKEW_MS = 5 * 60 * 1000;

const SIZES = { ek: 1568, ct: 1568, x: 32, n: 32, sid: 16, kid: 32 };

/** Server key id: binds every static public key the server presents. */
export const keyId = (kemPk, xPk, dsaPk) =>
  sha3_256(concat(utf8("HTP/1 server key"), lp(kemPk, xPk, dsaPk)));

/** Human-readable fingerprint, e.g. "7A3F-91C2-…" (first 16 bytes). */
export const fingerprint = (kid) => toHex(kid.subarray(0, 16)).toUpperCase().match(/.{4}/g).join("-");

function transcript(h) {
  return sha3_256(concat(LABEL, lp(
    h.kid, h.nC, u64(h.ts), h.ekC, h.xC, h.ctS,
    h.sid, h.nS, u64(h.exp), h.ctC, h.xS,
  )));
}

function deriveKeys(shared, th) {
  const ikm = concat(...shared);
  const out = {
    c2s: kdf(ikm, th, "HTP/1 c2s key"),
    s2c: kdf(ikm, th, "HTP/1 s2c key"),
    confirm: kdf(ikm, th, "HTP/1 confirm key"),
  };
  wipe(ikm, ...shared);
  return out;
}

function check(bytes, size, name) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== size) throw new Error(`HTP: bad ${name}`);
  return bytes;
}

/* ---------------- client side ---------------- */

/** Build a ClientHello for a server whose public keys the client trusts. */
export function clientHello(server) {
  const kid = keyId(server.kemPk, server.xPk, server.dsaPk);
  const eph = ml_kem1024.keygen();
  const xSk = x25519.utils.randomSecretKey();
  const { cipherText: ctS, sharedSecret: ssS } = ml_kem1024.encapsulate(server.kemPk);
  const hello = { kid, nC: random(32), ts: Date.now(), ekC: eph.publicKey, xC: x25519.getPublicKey(xSk), ctS };
  const wire = {
    v: VERSION, suite: SUITE, kid: toHex(kid), nC: b64u(hello.nC), ts: hello.ts,
    ekC: b64u(hello.ekC), xC: b64u(hello.xC), ctS: b64u(hello.ctS),
  };
  return { wire, state: { hello, dkC: eph.secretKey, xSk, ssS, server } };
}

/** Process the ServerHello. Returns session keys, or throws if the server is not who we pinned. */
export function clientFinish(state, wire) {
  const { hello, dkC, xSk, ssS, server } = state;
  if (wire.v !== VERSION) throw new Error("HTP: unsupported version");
  const s = {
    sid: check(unb64u(wire.sid), SIZES.sid, "sid"),
    nS: check(unb64u(wire.nS), SIZES.n, "nS"),
    exp: Number(wire.exp),
    ctC: check(unb64u(wire.ctC), SIZES.ct, "ctC"),
    xS: check(unb64u(wire.xS), SIZES.x, "xS"),
    confirm: unb64u(wire.confirm),
  };
  const ssE = ml_kem1024.decapsulate(s.ctC, dkC);
  const ssXS = x25519.getSharedSecret(xSk, server.xPk);
  const ssXE = x25519.getSharedSecret(xSk, s.xS);
  const th = transcript({ ...hello, ...s });
  const keys = deriveKeys([ssS, ssE, ssXS, ssXE], th);
  const ok = equal(mac(keys.confirm, concat(utf8("HTP/1 server confirm"), th)), s.confirm);
  wipe(dkC, xSk, keys.confirm);
  if (!ok) { wipe(keys.c2s, keys.s2c); throw new Error("HTP: server failed key confirmation (wrong server or tampering)"); }
  return { sid: s.sid, sidText: b64u(s.sid), th, c2s: keys.c2s, s2c: keys.s2c, expiresAt: s.exp };
}

/* ---------------- server side ---------------- */

/**
 * Answer a ClientHello. `statics` = { kemPk, kemSk, xPk, xSk, dsaPk, kid }.
 * Returns the wire ServerHello and the session secrets to store.
 */
export function serverRespond(statics, wire, { ttlMs, now = Date.now() } = {}) {
  if (wire?.v !== VERSION || wire.suite !== SUITE) throw new Error("HTP: unsupported version or suite");
  const kid = fromHex(String(wire.kid));
  if (!equal(kid, statics.kid)) throw new Error("HTP: unknown server key id");
  const ts = Number(wire.ts);
  if (!Number.isSafeInteger(ts) || Math.abs(now - ts) > HELLO_SKEW_MS) throw new Error("HTP: hello outside time window");
  const hello = {
    kid, ts,
    nC: check(unb64u(wire.nC), SIZES.n, "nC"),
    ekC: check(unb64u(wire.ekC), SIZES.ek, "ekC"),
    xC: check(unb64u(wire.xC), SIZES.x, "xC"),
    ctS: check(unb64u(wire.ctS), SIZES.ct, "ctS"),
  };
  const ssS = ml_kem1024.decapsulate(hello.ctS, statics.kemSk);
  const { cipherText: ctC, sharedSecret: ssE } = ml_kem1024.encapsulate(hello.ekC);
  const xEsk = x25519.utils.randomSecretKey();
  const xS = x25519.getPublicKey(xEsk);
  const ssXS = x25519.getSharedSecret(statics.xSk, hello.xC);
  const ssXE = x25519.getSharedSecret(xEsk, hello.xC);
  wipe(xEsk);
  const s = { sid: random(SIZES.sid), nS: random(SIZES.n), exp: now + ttlMs, ctC, xS };
  const th = transcript({ ...hello, ...s });
  const keys = deriveKeys([ssS, ssE, ssXS, ssXE], th);
  const confirm = mac(keys.confirm, concat(utf8("HTP/1 server confirm"), th));
  wipe(keys.confirm);
  return {
    wire: { v: VERSION, sid: b64u(s.sid), nS: b64u(s.nS), exp: s.exp, ctC: b64u(ctC), xS: b64u(xS), confirm: b64u(confirm) },
    session: { sid: s.sid, sidText: b64u(s.sid), th, c2s: keys.c2s, s2c: keys.s2c, expiresAt: s.exp },
  };
}

/** Generate a server's long-term key set. */
export function generateServerKeys() {
  const kem = ml_kem1024.keygen();
  const xSk = x25519.utils.randomSecretKey();
  return { kemPk: kem.publicKey, kemSk: kem.secretKey, xPk: x25519.getPublicKey(xSk), xSk };
}
