from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agentcore_identity_poc.jwt_validation import JwtPolicy, TokenRejected, make_http_jwks_loader

ISSUER = "https://login.microsoftonline.com/example-tenant/v2.0"
AUDIENCE = "api://agentcore-resource"


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwk(signing_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    return {**public_jwk, "kid": "current-key", "use": "sig", "alg": "RS256"}


@pytest.fixture
def token_factory(signing_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def make_token(**overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-123",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        }
        claims.update(overrides)
        return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "current-key"})

    return make_token


@pytest.fixture
def policy(jwk: dict[str, Any]) -> JwtPolicy:
    return JwtPolicy(issuer=ISSUER, audience=AUDIENCE, jwks_loader=lambda: {"keys": [jwk]})


def test_validates_token_with_expected_claims(
    policy: JwtPolicy, token_factory: Callable[..., str]
) -> None:
    claims = policy.validate(token_factory())

    assert claims["sub"] == "subject-123"


def test_rejects_foreign_issuer(policy: JwtPolicy, token_factory: Callable[..., str]) -> None:
    with pytest.raises(TokenRejected):
        policy.validate(token_factory(iss="https://foreign.example/"))


def test_rejects_wrong_audience(policy: JwtPolicy, token_factory: Callable[..., str]) -> None:
    with pytest.raises(TokenRejected):
        policy.validate(token_factory(aud="api://other-resource"))


def test_accepts_any_of_multiple_configured_audiences(
    jwk: dict[str, Any], token_factory: Callable[..., str]
) -> None:
    # Entra v2.0 tokens carry the bare client-ID GUID as `aud`, not the
    # `api://<client-id>` URI form; a policy configured for both must accept either.
    policy = JwtPolicy(
        issuer=ISSUER,
        audience=("agentcore-resource", AUDIENCE),
        jwks_loader=lambda: {"keys": [jwk]},
    )

    claims = policy.validate(token_factory(aud="agentcore-resource"))

    assert claims["sub"] == "subject-123"
    assert policy.validate(token_factory(aud=AUDIENCE))["sub"] == "subject-123"

    with pytest.raises(TokenRejected):
        policy.validate(token_factory(aud="api://unrelated"))


def test_rejects_expired_token(policy: JwtPolicy, token_factory: Callable[..., str]) -> None:
    with pytest.raises(TokenRejected):
        policy.validate(token_factory(exp=datetime.now(UTC) - timedelta(minutes=1)))


def test_rejects_token_without_subject(
    policy: JwtPolicy, signing_key: rsa.RSAPrivateKey
) -> None:
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        signing_key,
        algorithm="RS256",
        headers={"kid": "current-key"},
    )

    with pytest.raises(TokenRejected):
        policy.validate(token)


def test_rejects_unknown_key_id(policy: JwtPolicy, token_factory: Callable[..., str]) -> None:
    token = token_factory()
    parts = token.split(".")
    header = jwt.get_unverified_header(token)
    header["kid"] = "unknown-key"
    altered_header = jwt.utils.base64url_encode(json.dumps(header).encode()).decode()
    altered_token = ".".join([altered_header, *parts[1:]])

    with pytest.raises(TokenRejected):
        policy.validate(altered_token)


def test_rejects_invalid_signature(policy: JwtPolicy, token_factory: Callable[..., str]) -> None:
    token = token_factory()
    header, payload, signature = token.split(".")
    tampered_payload = f"{payload[:-1]}{'A' if payload[-1] != 'A' else 'B'}"

    with pytest.raises(TokenRejected):
        policy.validate(".".join([header, tampered_payload, signature]))


def test_refreshes_jwks_once_when_key_id_is_missing(
    token_factory: Callable[..., str], jwk: dict[str, Any]
) -> None:
    calls = 0

    def loader() -> dict[str, list[dict[str, Any]]]:
        nonlocal calls
        calls += 1
        return {"keys": []} if calls == 1 else {"keys": [jwk]}

    policy = JwtPolicy(issuer=ISSUER, audience=AUDIENCE, jwks_loader=loader)

    assert policy.validate(token_factory())["sub"] == "subject-123"
    assert calls == 2


def test_uses_cached_jwks_for_five_minutes(
    token_factory: Callable[..., str], jwk: dict[str, Any]
) -> None:
    now = [1000.0]
    calls = 0

    def loader() -> dict[str, list[dict[str, Any]]]:
        nonlocal calls
        calls += 1
        return {"keys": [jwk]}

    policy = JwtPolicy(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_loader=loader,
        clock=lambda: now[0],
    )

    policy.validate(token_factory())
    policy.validate(token_factory())

    assert calls == 1

    now[0] += 300.0
    policy.validate(token_factory())

    assert calls == 2


@pytest.mark.parametrize("jwks_url", ["http://keys.example/jwks", "https://", "not a URL"])
def test_http_jwks_loader_rejects_non_absolute_https_urls(jwks_url: str) -> None:
    with pytest.raises(ValueError, match="absolute HTTPS"):
        make_http_jwks_loader(jwks_url)


def test_http_jwks_loader_filters_non_public_rsa_keys(jwk: dict[str, Any]) -> None:
    received_timeout: object | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal received_timeout
        received_timeout = request.extensions["timeout"]
        return httpx.Response(
            200,
            json={
                "keys": [
                    jwk,
                    {**jwk, "kid": "private", "d": "not-public"},
                    {"kty": "EC", "kid": "elliptic"},
                ]
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        keys = make_http_jwks_loader("https://keys.example/jwks", client)()["keys"]

    assert keys == [jwk]
    assert received_timeout == {"connect": 5.0, "read": 5.0, "write": 5.0, "pool": 5.0}


@pytest.mark.parametrize("body", [[], {}, {"keys": "not-a-list"}])
def test_http_jwks_loader_rejects_malformed_responses(body: object) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        loader = make_http_jwks_loader("https://keys.example/jwks", client)

        with pytest.raises(ValueError):
            loader()


def test_http_jwks_loader_propagates_http_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        loader = make_http_jwks_loader("https://keys.example/jwks", client)

        with pytest.raises(httpx.HTTPStatusError):
            loader()
