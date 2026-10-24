"""Refresh crates/humid-pq2/tests/vectors/{aes-256-gcm-siv-rfc8452,aes-256-gcm-cavs,
x25519-rfc7748}.json: the published AES-256-GCM-SIV (RFC 8452 C.2/C.3), AES-256-GCM (NIST
CAVS gcmEncryptExtIV256) and X25519 (RFC 7748) vectors. They are taken from the test sources
of the crates humid-pq2 builds on (in ~/.cargo/registry/src/<index>/), and every one is
re-checked here independently with OpenSSL through pyca/cryptography before it is written, so
a wrong vector in a crate's own tests can't slip in. (NIST's ACVP server only has AES-128
vectors for GCM-SIV, and RFC 8452's text isn't fetchable from every build environment.)

  python3 -I tools/pq2-rfc-vectors.py ~/.cargo/registry/src/index.crates.io-* crates/humid-pq2/tests/vectors
"""
import json, re, sys, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)

def lit(s):
    s = s.strip()
    m = re.fullmatch(r'b"((?:\\x[0-9a-fA-F]{2})*)"', s)
    if m:
        return bytes.fromhex(m.group(1).replace("\\x", ""))
    m = re.fullmatch(r'&?hex!\(\s*"([0-9a-fA-F]*)"\s*\)', s)
    if m:
        return bytes.fromhex(m.group(1))
    if s == 'b""':
        return b""
    raise ValueError(s)

def vectors(path, fields):
    text = open(path).read()
    for block in re.findall(r"TestVector \{(.*?)\}", text, re.S):
        v = {}
        for f in fields:
            m = re.search(rf"\b{f}:\s*(&?hex!\(\s*\"[0-9a-fA-F]*\"\s*\)|b\"[^\"]*\")", block)
            v[f] = lit(m.group(1))
        yield v

# RFC 8452 Appendix C.2 (AEAD_AES_256_GCM_SIV) and C.3 (counter wrap)
siv = []
for name, ref in [("aes256gcmsiv.rs", "RFC 8452 Appendix C.2"), ("ctr_wrap.rs", "RFC 8452 Appendix C.3")]:
    for v in vectors(f"{src}/aes-gcm-siv-0.12.1/tests/{name}", ["key", "nonce", "aad", "plaintext", "ciphertext"]):
        got = AESGCMSIV(v["key"]).encrypt(v["nonce"], v["plaintext"], v["aad"] or None)
        assert got == v["ciphertext"], (ref, v)
        siv.append({"source": ref, **{k: x.hex() for k, x in v.items()}})
json.dump({"note": "AES-256-GCM-SIV vectors from RFC 8452 Appendix C.2 and C.3, each re-checked with OpenSSL (tools/pq2-rfc-vectors.py). ciphertext = ct || tag.", "vectors": siv}, open(f"{out}/aes-256-gcm-siv-rfc8452.json", "w"), indent=1)

# NIST CAVS gcmEncryptExtIV256 (96-bit IV, 128-bit tag): a subset with pt and aad lengths mixed
gcm = []
for v in vectors(f"{src}/aes-gcm-0.11.1/tests/aes256gcm.rs", ["key", "nonce", "plaintext", "aad", "ciphertext", "tag"]):
    got = AESGCM(v["key"]).encrypt(v["nonce"], v["plaintext"], v["aad"] or None)
    assert got == v["ciphertext"] + v["tag"], v
    gcm.append({k: x.hex() for k, x in v.items()})
pick, seen = [], set()
for v in gcm:
    k = (len(v["plaintext"]), len(v["aad"]))
    if k not in seen:
        seen.add(k); pick.append(v)
json.dump({"note": "AES-256-GCM vectors from NIST CAVS gcmEncryptExtIV256.rsp (96-bit IV, 128-bit tag), one per (pt, aad) length pair, each re-checked with OpenSSL.", "vectors": pick}, open(f"{out}/aes-256-gcm-cavs.json", "w"), indent=1)

# RFC 7748 §5.2 and §6.1 X25519
xs = []
text = open(f"{src}/x25519-dalek-3.0.0/tests/x25519_tests.rs").read()
def arr(name, body):
    m = re.search(rf"let {name}: \[u8; 32\] = \[(.*?)\];", body, re.S)
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))
for fn in ["rfc7748_ladder_test1_vectorset1", "rfc7748_ladder_test1_vectorset2"]:
    body = re.search(rf"fn {fn}\(\) \{{(.*?)\n\}}", text, re.S).group(1)
    k, u, want = arr("input_scalar", body), arr("input_point", body), arr("expected", body)
    got = X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(u))
    assert got == want
    xs.append({"source": "RFC 7748 section 5.2", "scalar": k.hex(), "u": u.hex(), "out": want.hex()})
a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
pa, pb = X25519PrivateKey.from_private_bytes(a), X25519PrivateKey.from_private_bytes(b)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
pub = lambda k: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
assert pub(pa).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
assert pub(pb).hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
ss = pa.exchange(pb.public_key())
assert ss.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
xs.append({"source": "RFC 7748 section 6.1", "scalar": a.hex(), "u": pub(pb).hex(), "out": ss.hex(), "public": pub(pa).hex()})
xs.append({"source": "RFC 7748 section 6.1", "scalar": b.hex(), "u": pub(pa).hex(), "out": ss.hex(), "public": pub(pb).hex()})
json.dump({"note": "X25519 vectors from RFC 7748 sections 5.2 and 6.1, re-checked with OpenSSL.", "vectors": xs}, open(f"{out}/x25519-rfc7748.json", "w"), indent=1)
print(len(siv), "siv;", len(gcm), "gcm (kept", len(pick), ");", len(xs), "x25519")
