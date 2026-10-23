// The server's own small PKI, for mutual TLS between its roles when they run on separate
// machines (server 3.0, docs/DEPLOY-VMS.md). One private CA, and one certificate per role:
//
//   humid-front   the edge and gateway: the only role that calls the others
//   humid-core    identity, vault, ledger, recovery, access
//   humid-keys    keyshare (the second half of every split document key)
//
// Each certificate is both a TLS server and a TLS client certificate. A service accepts a
// connection only from a client certificate this CA issued to humid-front; the gateway
// accepts a server only if this CA issued it to the role it meant to reach. Names, not
// addresses, are checked, so a VM can change its IP without new certificates, and nothing
// outside this CA can stand in for a role.
//
// Ed25519 certificates, TLS 1.3, and the hybrid X25519MLKEM768 key exchange only
// (INTERNAL_TLS_GROUPS). The X.509 is written here, a few hundred bytes of DER, so
// the server needs no OpenSSL tools and no extra packages on Windows or in a container.

import { generateKeyPairSync, createPrivateKey, createPublicKey, createHash, sign, randomBytes, X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";

export const ROLES = ["front", "core", "keys"];
export const roleName = (role) => `humid-${role}`;

/**
 * Holder cells (docs/CELLS.md): one small VM per HumID holder, running only the vault. Each
 * gets its own certificate, issued to humid-cell-<id>. roleOf() never returns a role for one,
 * so a cell's certificate can't stand in for front, core or keys; the gateway accepts a cell
 * only under the exact name the pool lists for it (clientTls expectName).
 */
export const CELL_ID = /^[a-z0-9]{8,32}$/;
export const cellName = (id) => {
  if (!CELL_ID.test(String(id))) throw new Error(`A cell id is 8 to 32 lowercase letters and digits (got "${id}")`);
  return `humid-cell-${id}`;
};

/* ---------------- DER, just enough for a certificate ---------------- */

const len = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, ...parts) => { const body = Buffer.concat(parts.map((p) => Buffer.from(p))); return Buffer.concat([Buffer.from([tag]), len(body.length), body]); };
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const ctx = (n, ...p) => tlv(0xa0 | n, ...p);
const int = (buf) => { let b = Buffer.from(buf); while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return tlv(0x02, b); };
const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
const octets = (b) => tlv(0x04, b);
const bits = (b, unused = 0) => tlv(0x03, Buffer.from([unused]), b);
const utf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const oid = (dotted) => {
  const [a, b, ...rest] = dotted.split(".").map(Number);
  const out = [40 * a + b];
  for (const n of rest) {
    const chunk = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift(0x80 | (v & 0x7f));
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
};
const time = (d) => {
  const z = d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z"; // YYYYMMDDHHMMSSZ
  return d.getUTCFullYear() < 2050 ? tlv(0x17, Buffer.from(z.slice(2))) : tlv(0x18, Buffer.from(z));
};

const OID = {
  ed25519: "1.3.101.112", cn: "2.5.4.3", o: "2.5.4.10",
  basicConstraints: "2.5.29.19", keyUsage: "2.5.29.15", extKeyUsage: "2.5.29.37",
  serverAuth: "1.3.6.1.5.5.7.3.1", clientAuth: "1.3.6.1.5.5.7.3.2",
  ski: "2.5.29.14", aki: "2.5.29.35",
};
const ALG = seq(oid(OID.ed25519));
const name = (cn) => seq(set(seq(oid(OID.o), utf8("HumID"))), set(seq(oid(OID.cn), utf8(cn))));
const ext = (id, critical, value) => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value));
const rawPub = (keyObj) => (keyObj.type === "public" ? keyObj : createPublicKey(keyObj)).export({ format: "der", type: "spki" }).subarray(-32);
const keyId = (pub) => createHash("sha1").update(pub).digest(); // RFC 5280 4.2.1.2, method (1): SHA-1 of the public key

function certificate({ subject, issuer, pub, signer, ca, days, issuerPub }) {
  const now = Date.now();
  const serial = randomBytes(16); serial[0] &= 0x7f;
  // a CA signs certificates (keyCertSign); a role certificate signs TLS handshakes (digitalSignature)
  const ku = ca ? bits(Buffer.from([0x06]), 1) : bits(Buffer.from([0x80]), 7);
  const exts = [
    ext(OID.basicConstraints, true, ca ? seq(bool(true), int(Buffer.from([0]))) : seq()),
    ext(OID.keyUsage, true, ku),
    ...(ca ? [] : [ext(OID.extKeyUsage, false, seq(oid(OID.serverAuth), oid(OID.clientAuth)))]),
    ext(OID.ski, false, octets(keyId(pub))),
    ext(OID.aki, false, seq(tlv(0x80, keyId(issuerPub)))),
  ];
  const tbs = seq(
    ctx(0, int(Buffer.from([2]))),                       // v3
    int(serial),
    ALG,
    name(issuer),
    seq(time(new Date(now - 5 * 60_000)), time(new Date(now + days * 86_400_000))),
    name(subject),
    seq(ALG, bits(pub)),
    ctx(3, seq(...exts)),
  );
  const sig = sign(null, tbs, signer);
  const der = seq(tbs, ALG, bits(sig));
  return `-----BEGIN CERTIFICATE-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
}

const pemKey = (k) => k.export({ format: "pem", type: "pkcs8" }).toString();

/** A new private CA: { certPem, keyPem }. Ten years by default: it only signs this server's roles. */
export function makeCa({ cn = "HumID internal CA", days = 3650 } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = rawPub(publicKey);
  return { certPem: certificate({ subject: cn, issuer: cn, pub, signer: privateKey, ca: true, days, issuerPub: pub }), keyPem: pemKey(privateKey) };
}

/** A certificate for one role, signed by the CA: { certPem, keyPem }. About two years by default. */
export function issueRoleCert(ca, role, { days = 825 } = {}) {
  if (!ROLES.includes(role)) throw new Error(`Unknown role "${role}" (one of ${ROLES.join(", ")})`);
  const caCert = new X509Certificate(ca.certPem);
  const caKey = createPrivateKey(ca.keyPem);
  const issuerCn = /CN=([^\n,]+)/.exec(caCert.subject)?.[1] || "HumID internal CA";
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    certPem: certificate({ subject: roleName(role), issuer: issuerCn, pub: rawPub(publicKey), signer: caKey, ca: false, days, issuerPub: rawPub(caKey) }),
    keyPem: pemKey(privateKey),
  };
}

/** A certificate for one holder cell, signed by the CA: { certPem, keyPem }. */
export function issueCellCert(ca, id, { days = 825 } = {}) {
  const cn = cellName(id);
  const caCert = new X509Certificate(ca.certPem);
  const caKey = createPrivateKey(ca.keyPem);
  const issuerCn = /CN=([^\n,]+)/.exec(caCert.subject)?.[1] || "HumID internal CA";
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    certPem: certificate({ subject: cn, issuer: issuerCn, pub: rawPub(publicKey), signer: caKey, ca: false, days, issuerPub: rawPub(caKey) }),
    keyPem: pemKey(privateKey),
  };
}

/** The cell id a certificate was issued to (humid-cell-<id>), or null. */
export function cellOf(cert) {
  const cn = typeof cert === "string" ? /CN=([^\n,]+)/.exec(new X509Certificate(cert).subject)?.[1] : cert?.subject?.CN;
  const m = /^humid-cell-([a-z0-9]{8,32})$/.exec(Array.isArray(cn) ? cn[0] : cn || "");
  return m ? m[1] : null;
}

/** The role a certificate was issued to (by its CN), or null. */
export function roleOf(cert) {
  const cn = typeof cert === "string" ? /CN=([^\n,]+)/.exec(new X509Certificate(cert).subject)?.[1] : cert?.subject?.CN;
  const m = /^humid-(front|core|keys)$/.exec(Array.isArray(cn) ? cn[0] : cn || "");
  return m ? m[1] : null;
}

/** Days until a certificate expires (negative once it has). */
export const daysLeft = (certPem) => (Date.parse(new X509Certificate(certPem).validTo) - Date.now()) / 86_400_000;

/**
 * Key exchange between roles: the hybrid X25519 + ML-KEM-768 group only (CRYPTO-03). What
 * crosses these links (split-key shares, anchor parts, ID-chip fields) must stay secret against
 * someone who records it now and has a quantum computer later, so a peer that can't do the
 * hybrid exchange is refused rather than falling back to X25519 alone. Both ends set it.
 */
export const INTERNAL_TLS_GROUPS = "X25519MLKEM768";

let groupsChecked = false;
/** Fail at start-up, not at the first call, if this Node's OpenSSL can't do the hybrid group. */
function needHybridGroup() {
  if (groupsChecked) return;
  try { createSecureContext({ ecdhCurve: INTERNAL_TLS_GROUPS }); }
  catch { throw new Error(`Internal TLS needs the hybrid post-quantum key exchange ${INTERNAL_TLS_GROUPS}, which this Node (OpenSSL ${process.versions.openssl}) doesn't offer. Use a Node built with OpenSSL 3.5 or later.`); }
  groupsChecked = true;
}

/**
 * TLS settings for a service that takes calls from other machines: { ca, cert, key } (PEM)
 * plus which client roles may call (default: only humid-front, the gateway).
 */
export function serverTls({ ca, cert, key, allow = ["front"] }) {
  needHybridGroup();
  return { ca, cert, key, allow, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3", ecdhCurve: INTERNAL_TLS_GROUPS };
}

/**
 * TLS settings for the gateway's calls to a role on another machine (expect: "core" | "keys"),
 * or to one holder cell (expectCell: its id; the certificate must be humid-cell-<that id>).
 */
export function clientTls({ ca, cert, key, expect, expectCell }) {
  needHybridGroup();
  const want = expectCell != null ? cellName(expectCell) : roleName(expect);
  const ok = (peer) => (expectCell != null ? cellOf(peer) === expectCell : roleOf(peer) === expect);
  return {
    ca, cert, key, minVersion: "TLSv1.3", rejectUnauthorized: true, ecdhCurve: INTERNAL_TLS_GROUPS,
    // the CA is this server's own; the name it gave the role is what is checked, not the address
    checkServerIdentity: (_host, peer) => (ok(peer) ? undefined : new Error(`expected ${want}, got ${peer?.subject?.CN || "no name"}`)),
  };
}
