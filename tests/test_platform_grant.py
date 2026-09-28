# tests/test_platform_grant.py
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from agentcore_platform_poc.grant import (
    GRANT_AUDIENCE,
    GRANT_ISSUER,
    GrantRejected,
    KmsSigner,
    LocalSigner,
    der_to_raw,
    issue_grant,
    verify_grant,
)

A = "00000000-0000-0000-0000-00000000000a"
KEY = ec.generate_private_key(ec.SECP256R1())
PEM = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
OTHER = ec.generate_private_key(ec.SECP256R1())


def _grant(**overrides: object) -> str:
    args: dict[str, object] = {
        "sub": A,
        "agent": "research-agent-id",
        "sid": "s1",
        "ttl_seconds": 3600,
        "now": 1000,
    }
    args.update(overrides)
    return issue_grant(LocalSigner(KEY), **args)  # type: ignore[arg-type]


def test_round_trip() -> None:
    grant = verify_grant(_grant(), PEM, now=1001)
    assert (grant.sub, grant.agent, grant.sid, grant.iat, grant.exp) == (
        A,
        "research-agent-id",
        "s1",
        1000,
        4600,
    )
    assert grant.jti


def test_header_and_claims_shape() -> None:
    header_b64, payload_b64, _ = _grant().split(".")
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    assert header == {"alg": "ES256", "typ": "JWT"}
    assert payload["iss"] == GRANT_ISSUER and payload["aud"] == GRANT_AUDIENCE


def test_expired_at_exact_exp() -> None:
    with pytest.raises(GrantRejected) as caught:
        verify_grant(_grant(), PEM, now=4600)
    assert caught.value.code == "grant_expired"


def test_wrong_key_is_invalid() -> None:
    token = issue_grant(LocalSigner(OTHER), sub=A, agent="x", sid="s", ttl_seconds=60, now=1000)
    with pytest.raises(GrantRejected) as caught:
        verify_grant(token, PEM, now=1001)
    assert caught.value.code == "grant_invalid"


def test_changed_sub_is_invalid() -> None:
    header, payload, sig = _grant().split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["sub"] = "00000000-0000-0000-0000-00000000000b"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    with pytest.raises(GrantRejected) as caught:
        verify_grant(f"{header}.{forged}.{sig}", PEM, now=1001)
    assert caught.value.code == "grant_invalid"


def test_alg_none_and_garbage_are_invalid() -> None:
    none = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    for token in (f"{none}.e30.", "not-a-jwt", ""):
        with pytest.raises(GrantRejected):
            verify_grant(token, PEM, now=1001)


def test_ttl_must_be_positive() -> None:
    with pytest.raises(ValueError):
        _grant(ttl_seconds=0)


def test_der_to_raw_known_vector() -> None:
    der = encode_dss_signature(1, 2)
    assert der_to_raw(der) == (1).to_bytes(32, "big") + (2).to_bytes(32, "big")


class FakeKms:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def sign(self, **kwargs: object) -> dict[str, bytes]:
        self.calls.append(kwargs)
        message = kwargs["Message"]
        assert isinstance(message, bytes)
        return {"Signature": KEY.sign(message, ec.ECDSA(hashes.SHA256()))}  # DER, like KMS


def test_kms_signer_output_verifies() -> None:
    kms = FakeKms()
    token = issue_grant(
        KmsSigner(kms, "key-1"), sub=A, agent="a", sid="s", ttl_seconds=60, now=1000
    )
    assert verify_grant(token, PEM, now=1001).sub == A
    assert (
        kms.calls[0]["SigningAlgorithm"] == "ECDSA_SHA_256" and kms.calls[0]["MessageType"] == "RAW"
    )
