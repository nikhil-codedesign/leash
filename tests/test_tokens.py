import base64
import json

import pytest

from leash import tokens
from leash.tokens import TokenError

SECRET = "unit-test-secret-0123456789"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_roundtrip():
    t = tokens.issue("grant123", 1_800_000_600, SECRET)
    assert tokens.verify(t, SECRET) == {"gid": "grant123", "exp": 1_800_000_600}


def test_bytes_secret_works():
    key = b"b" * 32
    assert tokens.verify(tokens.issue("g", 5, key), key)["gid"] == "g"


def test_wrong_secret_rejected():
    t = tokens.issue("g", 5, SECRET)
    with pytest.raises(TokenError):
        tokens.verify(t, "another-secret-0123456789")


def test_forged_signature_rejected():
    payload, _ = tokens.issue("g", 5, SECRET).split(".")
    for sig in ["", "AAAA", b64(b"x" * 32)]:
        with pytest.raises(TokenError):
            tokens.verify(f"{payload}.{sig}", SECRET)


def test_extended_expiry_rejected():
    payload, sig = tokens.issue("g", 100, SECRET).split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["exp"] = 10**10
    forged_payload = b64(json.dumps(claims, separators=(",", ":")).encode())
    with pytest.raises(TokenError):
        tokens.verify(f"{forged_payload}.{sig}", SECRET)


def test_swapped_grant_id_rejected():
    payload, sig = tokens.issue("grantA", 100, SECRET).split(".")
    other_payload, _ = tokens.issue("grantB", 100, SECRET).split(".")
    with pytest.raises(TokenError):
        tokens.verify(f"{other_payload}.{sig}", SECRET)


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        123,
        b"abc.def",
        "nodot",
        "a.b.c",
        ".",
        "a.",
        ".b",
        "has space.sig",
        "pay load.sig",
        "x" * 2000,
        "é.é",
    ],
)
def test_malformed_tokens_rejected(bad):
    with pytest.raises(TokenError):
        tokens.verify(bad, SECRET)


def test_validly_signed_but_malformed_payload_rejected():
    # An attacker without the secret can't produce these, but the code must
    # still reject them if the secret ever leaks or a bug issues one.
    for body in [b"not json", b"[]", b'{"gid": 5, "exp": 1}', b'{"gid": "g"}', b'{"gid":"g","exp":"9"}', b'{"gid":"g","exp":1.5}']:
        payload = b64(body)
        token = f"{payload}.{tokens._sign(payload, SECRET)}"
        with pytest.raises(TokenError):
            tokens.verify(token, SECRET)


def test_short_secret_refused():
    with pytest.raises(ValueError):
        tokens.issue("g", 5, "short")
    with pytest.raises(ValueError):
        tokens.verify("a.b", "short")


def test_is_expired():
    claims = {"gid": "g", "exp": 100}
    assert not tokens.is_expired(claims, 99.9)
    assert tokens.is_expired(claims, 100)
