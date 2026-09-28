# src/agentcore_platform_poc/grant.py
"""Session grants: short JWTs (ES256) signed by the unified API, checked by the Resource Hub."""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

GRANT_ISSUER = "poc3-unified-api"
GRANT_AUDIENCE = "poc3-resource-hub"
DEFAULT_TTL_SECONDS = 3600
_REQUIRED = ("iss", "aud", "sub", "agent", "sid", "jti", "iat", "exp")


class GrantRejected(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Grant:
    sub: str
    agent: str
    sid: str
    jti: str
    iat: int
    exp: int


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes: ...


def der_to_raw(der: bytes) -> bytes:
    """KMS and cryptography return DER ECDSA; JWS ES256 needs 32-byte R || 32-byte S."""
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class LocalSigner:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._key = private_key

    def sign(self, message: bytes) -> bytes:
        return der_to_raw(self._key.sign(message, ec.ECDSA(hashes.SHA256())))


class KmsSigner:
    def __init__(self, kms_client: Any, key_id: str) -> None:
        self._kms = kms_client
        self._key_id = key_id

    def sign(self, message: bytes) -> bytes:
        response = self._kms.sign(
            KeyId=self._key_id, Message=message, MessageType="RAW", SigningAlgorithm="ECDSA_SHA_256"
        )
        return der_to_raw(response["Signature"])


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def issue_grant(
    signer: Signer,
    *,
    sub: str,
    agent: str,
    sid: str,
    ttl_seconds: int,
    now: int,
    jti: str | None = None,
) -> str:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    header = _b64(json.dumps({"alg": "ES256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {
        "iss": GRANT_ISSUER,
        "aud": GRANT_AUDIENCE,
        "sub": sub,
        "agent": agent,
        "sid": sid,
        "jti": jti or uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{_b64(signer.sign(signing_input))}"


def verify_grant(token: str, public_key_pem: bytes, *, now: int) -> Grant:
    try:
        claims = jwt.decode(
            token,
            public_key_pem,
            algorithms=["ES256"],
            audience=GRANT_AUDIENCE,
            issuer=GRANT_ISSUER,
            options={"verify_exp": False, "verify_iat": False, "require": list(_REQUIRED)},
        )
    except (jwt.PyJWTError, ValueError, TypeError) as error:
        raise GrantRejected("grant_invalid") from error
    exp, iat = claims["exp"], claims["iat"]
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (exp, iat)):
        raise GrantRejected("grant_invalid")
    if not all(isinstance(claims[k], str) and claims[k] for k in ("sub", "agent", "sid", "jti")):
        raise GrantRejected("grant_invalid")
    if now >= exp:
        raise GrantRejected("grant_expired")
    return Grant(
        sub=claims["sub"],
        agent=claims["agent"],
        sid=claims["sid"],
        jti=claims["jti"],
        iat=iat,
        exp=exp,
    )
