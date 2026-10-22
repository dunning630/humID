"""Cross-check of tests/support/fido-sim.js against Yubico's python-fido2.

python-fido2 (the reference CTAP2 client) talks to the simulated key through a
CtapDevice whose call() hands each CTAPHID.CBOR payload (command byte || CBOR)
to the node test (tests/fido-crosscheck.test.js) over stdout, one JSON line per
request. The node side wraps it in NFCCTAP_MSG APDUs (command chaining, 9100
polling, 61xx response chaining), feeds them to simulatedKey and answers on
stdin with the CTAP response body.

Every request/answer is a JSON line:
  -> {"op": "cbor", "data": hex}                 <- {"data": hex}
  -> {"op": "powerCycle"}                        <- {}
  -> {"op": "hmacSecret", "cred": hex, "salt": hex, "uv": bool}
                                                 <- {"data": hex}  (test-only hook)
  -> {"op": "state"}                             <- {"counter": n, "pinRetries": n, ...}
  -> {"op": "check", "name": str}                (a passed check, for the report)

Ctap2 is used with strict_cbor=True, so every response must also be canonical
CTAP2 CBOR as python-fido2 encodes it.

Usage: python3 fido_crosscheck.py   (spawned by the node test; exits 0 on success)
"""

import hashlib
import json
import os
import sys

from fido2.client import Fido2Client, UserInteraction
from fido2.cose import ES256, CoseKey
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.extensions import CredProtectExtension, HmacSecretExtension, HMACGetSecretOutput
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.hid import CAPABILITY, CTAPHID
from fido2.webauthn import (
    AuthenticatorData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)

PIN = "123456"
RP_ID = "recovery.humid.invalid"
SALT = hashlib.sha256(b"HUMID-KEY-v1 hmac-secret salt").digest()
ERR = CtapError.ERR
PERM = ClientPin.PERMISSION

_out = sys.stdout
_in = sys.stdin


def bridge(msg):
    _out.write(json.dumps(msg) + "\n")
    _out.flush()
    if msg["op"] == "check":
        return None
    line = _in.readline()
    if not line:
        raise RuntimeError("bridge closed")
    return json.loads(line)


def check(name):
    bridge({"op": "check", "name": name})


class NfcBridgeDevice(CtapDevice):
    """A CtapDevice whose transport is the node side's simulated NFC key."""

    @property
    def capabilities(self):
        return CAPABILITY.CBOR | CAPABILITY.NMSG

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        if cmd != CTAPHID.CBOR:
            raise CtapError(ERR.INVALID_COMMAND)
        resp = bridge({"op": "cbor", "data": bytes(data).hex()})
        return bytes.fromhex(resp["data"])

    def close(self):
        pass

    @classmethod
    def list_devices(cls):
        return iter(())


def power_cycle():
    bridge({"op": "powerCycle"})


def key_hmac_secret(cred_id, salt, uv=True):
    return bytes.fromhex(bridge({"op": "hmacSecret", "cred": cred_id.hex(), "salt": salt.hex(), "uv": uv})["data"])


def expect_error(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except CtapError as e:
        assert e.code == code, f"expected {code!r}, got {e.code!r}"
        return
    raise AssertionError(f"expected CtapError {code!r}")


def cdh(label):
    return hashlib.sha256(label.encode()).digest()


def hmac_secret_assertion(ctap, protocol, token, token_protocol, allow=None, salts=(SALT,)):
    """getAssertion with hmac-secret through python-fido2's own HmacSecretExtension
    (it does the key agreement, encrypts and authenticates the salt, decrypts the output)."""
    ext = HmacSecretExtension(ctap, allow_hmac_secret=True)
    hmac_in = {"salt1": salts[0]}
    if len(salts) > 1:
        hmac_in["salt2"] = salts[1]
    options = PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32),
        rp_id=RP_ID,
        allow_credentials=[{"type": "public-key", "id": c} for c in allow] if allow else None,
        extensions={"hmacGetSecret": hmac_in},
    )
    processor = ext.get_assertion(ctap, options, protocol)
    assert processor is not None, "hmac-secret not offered"
    inputs = processor.prepare_inputs(None, token)
    client_data_hash = cdh("hmac-secret " + os.urandom(4).hex())
    pin_auth = token_protocol.authenticate(token, client_data_hash) if token else None
    resp = ctap.get_assertion(
        RP_ID,
        client_data_hash,
        [{"type": "public-key", "id": c} for c in allow] if allow else None,
        inputs,
        None,
        pin_auth,
        token_protocol.VERSION if token else None,
    )
    out = processor.prepare_outputs(resp, token)["hmacGetSecret"]
    return resp, client_data_hash, out


def main():
    ctap = Ctap2(NfcBridgeDevice(), strict_cbor=True)

    # -- getInfo -------------------------------------------------------------
    info = ctap.info
    assert info.versions == ["FIDO_2_0", "FIDO_2_1"], info.versions
    assert set(info.extensions) == {"credProtect", "hmac-secret"}, info.extensions
    assert len(bytes(info.aaguid)) == 16
    assert info.options.get("rk") is True and info.options.get("up") is True
    assert info.options.get("clientPin") is False, "no PIN yet"
    assert ClientPin.is_token_supported(info)
    assert info.pin_uv_protocols == [2, 1], info.pin_uv_protocols
    assert info.max_msg_size == 1200
    assert info.min_pin_length == 4
    assert HmacSecretExtension(ctap).is_supported()
    assert CredProtectExtension(ctap).is_supported()
    check("getInfo parses (strict canonical CBOR): versions, extensions, aaguid, options, protocols, maxMsgSize, minPINLength")

    # -- setPIN (protocol 2), tokens with both protocols ------------------------
    ClientPin(ctap, PinProtocolV2()).set_pin(PIN)
    ctap = Ctap2(NfcBridgeDevice(), strict_cbor=True)  # fresh info: clientPin is now true
    assert ctap.info.options["clientPin"] is True
    assert ClientPin(ctap).protocol.VERSION == 2, "python-fido2 negotiates protocol 2"
    assert ClientPin(ctap, PinProtocolV1()).get_pin_retries() == (8, False)
    check("setPIN with PinProtocolV2; clientPin option true; getPINRetries (8, powerCycleState false)")

    tokens = {}
    for proto in (PinProtocolV1(), PinProtocolV2()):
        cp = ClientPin(ctap, proto)
        legacy = cp.get_pin_token(PIN)  # 0x05 getPinToken
        perm = cp.get_pin_token(PIN, PERM.MAKE_CREDENTIAL | PERM.GET_ASSERTION, RP_ID)  # 0x09
        assert len(legacy) == 32 and len(perm) == 32 and legacy != perm
        tokens[proto.VERSION] = perm
    check("getPinToken and getPinUvAuthTokenUsingPinWithPermissions with PinProtocolV1 and PinProtocolV2")

    # -- wrong PIN ---------------------------------------------------------------
    cp1 = ClientPin(ctap, PinProtocolV1())
    cp2 = ClientPin(ctap, PinProtocolV2())
    expect_error(ERR.PIN_INVALID, cp2.get_pin_token, "000000", PERM.GET_ASSERTION, RP_ID)
    assert cp2.get_pin_retries()[0] == 7
    expect_error(ERR.PIN_INVALID, cp1.get_pin_token, "000000")
    expect_error(ERR.PIN_AUTH_BLOCKED, cp2.get_pin_token, "000000", PERM.GET_ASSERTION, RP_ID)
    expect_error(ERR.PIN_AUTH_BLOCKED, cp2.get_pin_token, PIN, PERM.GET_ASSERTION, RP_ID)
    assert cp2.get_pin_retries() == (5, True)
    power_cycle()
    cp2.get_pin_token(PIN, PERM.GET_ASSERTION, RP_ID)
    assert cp2.get_pin_retries() == (8, False)
    check("wrong PIN -> PIN_INVALID (retries 7), third in a row -> PIN_AUTH_BLOCKED until power cycle, right PIN resets to 8")

    # -- setPIN refused when set; PIN policy --------------------------------------
    expect_error(ERR.PIN_AUTH_INVALID, cp2.set_pin, "654321")
    check("setPIN on a key with a PIN -> PIN_AUTH_INVALID")

    # -- makeCredential rk + hmac-secret + credProtect 3, low level, both protocols
    creds = {}
    for proto in (PinProtocolV1(), PinProtocolV2()):
        token = ClientPin(ctap, proto).get_pin_token(PIN, PERM.MAKE_CREDENTIAL, RP_ID)
        client_data_hash = cdh(f"mc {proto.VERSION}")
        att = ctap.make_credential(
            client_data_hash,
            {"id": RP_ID, "name": "HumID"},
            {"id": bytes([proto.VERSION]) * 16, "name": "parker", "displayName": "Parker"},
            [{"type": "public-key", "alg": -7}],
            extensions={"hmac-secret": True, "credProtect": 3},
            options={"rk": True},
            pin_uv_param=proto.authenticate(token, client_data_hash),
            pin_uv_protocol=proto.VERSION,
        )
        ad = att.auth_data
        assert att.fmt == "none" and att.att_stmt == {}
        assert ad.rp_id_hash == hashlib.sha256(RP_ID.encode()).digest()
        assert ad.flags == (AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT | AuthenticatorData.FLAG.ED)
        assert ad.extensions == {"hmac-secret": True, "credProtect": 3}, ad.extensions
        assert bytes(ad.credential_data.aaguid) == bytes(info.aaguid)
        pk = ad.credential_data.public_key
        assert isinstance(pk, ES256), type(pk)
        creds[proto.VERSION] = (ad.credential_data.credential_id, pk)
        # the token was spent by the operation (CTAP 2.1: permissions cleared after UP)
        expect_error(
            ERR.PIN_AUTH_INVALID,
            ctap.make_credential,
            client_data_hash,
            {"id": RP_ID},
            {"id": b"again"},
            [{"type": "public-key", "alg": -7}],
            pin_uv_param=proto.authenticate(token, client_data_hash),
            pin_uv_protocol=proto.VERSION,
        )
    expect_error(ERR.PUAT_REQUIRED, ctap.make_credential, cdh("x"), {"id": RP_ID}, {"id": b"u"}, [{"type": "public-key", "alg": -7}])
    expect_error(ERR.UNSUPPORTED_ALGORITHM, ctap.make_credential, cdh("x"), {"id": RP_ID}, {"id": b"u"}, [{"type": "public-key", "alg": -8}],
                 pin_uv_param=b"\0" * 32, pin_uv_protocol=2)
    check("makeCredential rk + hmac-secret + credProtect 3 (protocols 1 and 2): authData, flags, ES256 COSE key, extension outputs; PUAT_REQUIRED; UNSUPPORTED_ALGORITHM")

    cred_id, public_key = creds[2]

    # -- getAssertion with hmac-secret: python-fido2 encrypts the salt and decrypts S
    outputs = []
    for hmac_proto in (PinProtocolV2(), PinProtocolV1()):
        for token_proto in (PinProtocolV2(), PinProtocolV1()):
            power_cycle()  # a new session: new key agreement, no token
            token = ClientPin(ctap, token_proto).get_pin_token(PIN, PERM.GET_ASSERTION, RP_ID)
            resp, client_data_hash, out = hmac_secret_assertion(ctap, hmac_proto, token, token_proto, allow=[cred_id])
            assert resp.auth_data.flags & AuthenticatorData.FLAG.UV
            resp.verify(client_data_hash, public_key)  # python-fido2 checks the ES256 signature
            outputs.append(out.output1)
    assert len(set(outputs)) == 1, "same salt -> same output whatever the session or protocol"
    assert outputs[0] == key_hmac_secret(cred_id, SALT, True), "python's decrypted output == HMAC(CredRandomWithUV, salt) inside the key"
    check("hmac-secret via HmacSecretExtension: same output across sessions and protocols 1/2 (salt and token), equal to the key's own HMAC(CredRandomWithUV, salt)")

    salt2 = os.urandom(32)
    token = ClientPin(ctap, PinProtocolV2()).get_pin_token(PIN, PERM.GET_ASSERTION, RP_ID)
    _, _, out = hmac_secret_assertion(ctap, PinProtocolV2(), token, PinProtocolV2(), allow=[cred_id], salts=(SALT, salt2))
    assert out.output1 == outputs[0] and out.output2 == key_hmac_secret(cred_id, salt2, True)
    check("hmac-secret with two salts: output1 and output2")

    # -- credProtect 3: invisible without UV --------------------------------------
    expect_error(ERR.NO_CREDENTIALS, ctap.get_assertion, RP_ID, cdh("no uv"), [{"type": "public-key", "id": cred_id}])
    expect_error(ERR.NO_CREDENTIALS, ctap.get_assertion, RP_ID, cdh("no uv"))
    check("credProtect 3 credential invisible without UV (allowList and discoverable) -> NO_CREDENTIALS")

    # -- discoverable: two credentials, getNextAssertion, signatures, counter ----------
    state0 = bridge({"op": "state"})
    token = ClientPin(ctap, PinProtocolV1()).get_pin_token(PIN, PERM.GET_ASSERTION, RP_ID)
    client_data_hash = cdh("discover")
    assertions = ctap.get_assertions(RP_ID, client_data_hash, pin_uv_param=PinProtocolV1().authenticate(token, client_data_hash), pin_uv_protocol=1)
    assert len(assertions) == 2 and assertions[0].number_of_credentials == 2
    by_id = {c[0]: c[1] for c in creds.values()}
    counters = []
    for a in assertions:
        a.verify(client_data_hash, by_id[a.credential["id"]])
        assert a.user["id"] in (b"\x01" * 16, b"\x02" * 16)
        counters.append(a.auth_data.counter)
    assert counters == [state0["counter"] + 1, state0["counter"] + 2], counters
    expect_error(ERR.NOT_ALLOWED, ctap.get_next_assertion)
    check("discoverable getAssertion: numberOfCredentials 2 + getNextAssertion, both signatures verified by python-fido2, global counter increments")

    # -- the high-level WebAuthn client: Fido2Client with PIN, credProtect, hmac-secret --
    class Pin(UserInteraction):
        def request_pin(self, permissions, rp_id):
            return PIN

    client = Fido2Client(
        NfcBridgeDevice(),
        "https://humid.invalid",
        verify=lambda rp_id, origin: rp_id == RP_ID,
        user_interaction=Pin(),
        extensions=[HmacSecretExtension(allow_hmac_secret=True), CredProtectExtension()],
    )
    reg = client.make_credential(
        PublicKeyCredentialCreationOptions.from_dict(
            {
                "rp": {"id": RP_ID, "name": "HumID"},
                "user": {"id": b"webauthn-user", "name": "p", "displayName": "P"},
                "challenge": os.urandom(32),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
                "extensions": {
                    "hmacCreateSecret": True,
                    "credentialProtectionPolicy": "userVerificationRequired",
                    "enforceCredentialProtectionPolicy": True,
                },
            }
        )
    )
    assert reg.extension_results.get("hmacCreateSecret") is True, reg.extension_results
    # python-fido2 reports no client output for credProtect; the authenticator's is in authData
    assert reg.attestation_object.auth_data.extensions.get("credProtect") == 3
    cd = reg.attestation_object.auth_data.credential_data
    sel = client.get_assertion(
        PublicKeyCredentialRequestOptions.from_dict(
            {
                "challenge": os.urandom(32),
                "rpId": RP_ID,
                "allowCredentials": [{"type": "public-key", "id": cd.credential_id}],
                "userVerification": "required",
                "extensions": {"hmacGetSecret": {"salt1": SALT}},
            }
        )
    )
    res = sel.get_response(0)
    assert res.authenticator_data.flags & AuthenticatorData.FLAG.UV
    assert res.credential_id == cd.credential_id
    sel.get_assertions()[0].verify(res.client_data.hash, cd.public_key)
    out1 = HMACGetSecretOutput.from_dict(res.extension_results["hmacGetSecret"]).output1  # JSON form: base64url
    assert out1 == key_hmac_secret(cd.credential_id, SALT, True)
    check("Fido2Client (WebAuthn level): PIN-verified registration with credProtect 3 + hmac-secret, assertion with hmacGetSecret, signature verified")

    # -- PIN blocked for good ----------------------------------------------------------
    power_cycle()
    for left in (7, 6):
        expect_error(ERR.PIN_INVALID, cp2.get_pin_token, "999999", PERM.GET_ASSERTION, RP_ID)
        assert cp2.get_pin_retries()[0] == left
    for _ in range(2):
        power_cycle()
        expect_error(ERR.PIN_INVALID, cp1.get_pin_token, "999999")
        expect_error(ERR.PIN_INVALID, cp1.get_pin_token, "999999")
    assert cp2.get_pin_retries()[0] == 2
    power_cycle()
    expect_error(ERR.PIN_INVALID, cp2.get_pin_token, "999999", PERM.GET_ASSERTION, RP_ID)
    expect_error(ERR.PIN_BLOCKED, cp2.get_pin_token, "999999", PERM.GET_ASSERTION, RP_ID)
    power_cycle()
    expect_error(ERR.PIN_BLOCKED, cp2.get_pin_token, PIN, PERM.GET_ASSERTION, RP_ID)
    assert bridge({"op": "state"})["pinRetries"] == 0
    check("eight wrong PINs across power cycles -> PIN_BLOCKED, then even the right PIN is refused")

    bridge({"op": "done"})


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
