"""Signed grant tokens (HMAC-SHA256).

A token is `<payload>.<signature>` where payload is base64url(JSON) holding
the grant id (`gid`) and an expiry (`exp`, epoch seconds), and signature is
base64url(HMAC-SHA256(secret, payload)). Changing any byte of the payload
(for example to extend the expiry) invalidates the signature.

This module only authenticates a token. Whether the grant is expired,
revoked or within limits is decided by the policy engine.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Union

MIN_SECRET_BYTES = 16
MAX_TOKEN_LEN = 1024
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class TokenError(Exception):
    """The token is malformed or its signature is invalid."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key(secret: Union[str, bytes]) -> bytes:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    if len(key) < MIN_SECRET_BYTES:
        raise ValueError(f"secret must be at least {MIN_SECRET_BYTES} bytes")
    return key


def _sign(payload_b64: str, secret: Union[str, bytes]) -> str:
    mac = hmac.new(_key(secret), payload_b64.encode("ascii"), hashlib.sha256)
    return _b64e(mac.digest())


def issue(grant_id: str, exp: int, secret: Union[str, bytes]) -> str:
    payload = _b64e(
        json.dumps({"gid": grant_id, "exp": int(exp)}, separators=(",", ":")).encode()
    )
    return f"{payload}.{_sign(payload, secret)}"


def verify(token: Any, secret: Union[str, bytes]) -> Dict[str, Any]:
    """Return {"gid": str, "exp": int} or raise TokenError."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN:
        raise TokenError("malformed token")
    parts = token.split(".")
    if len(parts) != 2:
        raise TokenError("malformed token")
    payload_b64, sig = parts
    if not _B64URL.match(payload_b64) or not _B64URL.match(sig):
        raise TokenError("malformed token")

    # Check the signature over the payload string exactly as received,
    # before parsing anything inside it.
    expected = _sign(payload_b64, secret)
    if not hmac.compare_digest(expected.encode("ascii"), sig.encode("ascii")):
        raise TokenError("bad signature")

    try:
        claims = json.loads(_b64d(payload_b64))
    except Exception as exc:
        raise TokenError("malformed payload") from exc
    if (
        not isinstance(claims, dict)
        or not isinstance(claims.get("gid"), str)
        or type(claims.get("exp")) is not int
    ):
        raise TokenError("malformed payload")
    return {"gid": claims["gid"], "exp": claims["exp"]}


def is_expired(claims: Dict[str, Any], now: float) -> bool:
    return now >= claims["exp"]
