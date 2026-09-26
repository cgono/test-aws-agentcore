from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agentcore_identity_poc.jwt_validation import JwtPolicy
from agentcore_runtime_poc.gateway_sim.auth import (
    AppRoleAuthorizer,
    CallerRejected,
    build_authorizer,
)
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings

ISSUER = "https://login.microsoftonline.com/example-tenant/v2.0"
AUDIENCE = "gateway-app-id"


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def authorizer(signing_key: rsa.RSAPrivateKey) -> AppRoleAuthorizer:
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    jwk = {**public_jwk, "kid": "k1", "use": "sig", "alg": "RS256"}
    policy = JwtPolicy(issuer=ISSUER, audience=AUDIENCE, jwks_loader=lambda: {"keys": [jwk]})
    return AppRoleAuthorizer(
        policy=policy, required_role="Gateway.Invoke", allowed_caller_ids=frozenset({"caller-a"})
    )


@pytest.fixture
def token(signing_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def make(drop: tuple[str, ...] = (), **overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "service-principal-object-id",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "azp": "caller-a",
            "roles": ["Gateway.Invoke"],
            "idtyp": "app",
            "ver": "2.0",
        }
        claims.update(overrides)
        for name in drop:
            claims.pop(name)
        return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "k1"})

    return make


def _header(value: str) -> str:
    return "Bearer " + value


def test_app_token_with_role_from_allowed_caller_is_accepted(
    authorizer: AppRoleAuthorizer, token: Callable[..., str]
) -> None:
    assert authorizer.authorize(_header(token())) == "caller-a"


def test_token_without_idtyp_is_accepted_when_otherwise_valid(
    authorizer: AppRoleAuthorizer, token: Callable[..., str]
) -> None:
    assert authorizer.authorize(_header(token(drop=("idtyp",)))) == "caller-a"


@pytest.mark.parametrize(
    ("description", "kwargs"),
    [
        ("missing roles", {"drop": ("roles",)}),
        ("wrong role", {"roles": ["Other.Role"]}),
        ("delegated token", {"scp": "access_as_user"}),
        ("user token type", {"idtyp": "user"}),
        ("caller not allowed", {"azp": "caller-z"}),
        ("missing azp", {"drop": ("azp",)}),
        ("v1 issuer", {"iss": "https://sts.windows.net/example-tenant/"}),
        ("wrong audience", {"aud": "other-app"}),
        ("expired", {"exp": datetime.now(UTC) - timedelta(minutes=5)}),
        ("v1 token version", {"ver": "1.0"}),
        ("missing version", {"drop": ("ver",)}),
        ("api uri audience", {"aud": "api://gateway-app-id"}),
        ("multi-value audience", {"aud": [AUDIENCE, "other-app"]}),
    ],
)
def test_rejections(
    authorizer: AppRoleAuthorizer,
    token: Callable[..., str],
    description: str,
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(CallerRejected):
        authorizer.authorize(_header(token(**kwargs)))


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer "])
def test_missing_or_malformed_header_is_rejected(
    authorizer: AppRoleAuthorizer, header: str | None
) -> None:
    with pytest.raises(CallerRejected):
        authorizer.authorize(header)


def test_rejection_message_never_contains_the_token(
    authorizer: AppRoleAuthorizer, token: Callable[..., str]
) -> None:
    value = token(roles=[])
    with pytest.raises(CallerRejected) as caught:
        authorizer.authorize(_header(value))

    assert value not in str(caught.value)


def test_build_authorizer_uses_exact_bare_audience_and_v2_issuer() -> None:
    settings = GatewaySettings(
        tenant_id="example-tenant",
        gateway_app_client_id=AUDIENCE,
        allowed_caller_ids=frozenset({"caller-a"}),
        openai_models=frozenset({"model-o"}),
        anthropic_models=frozenset({"model-a"}),
        openai_api_key="test-openai-key",
        anthropic_api_key="test-anthropic-key",
    )

    authorizer = build_authorizer(settings)

    assert authorizer.policy.audience == AUDIENCE
    assert authorizer.policy.issuer == ISSUER
    assert authorizer.required_role == "Gateway.Invoke"
    assert authorizer.allowed_caller_ids == frozenset({"caller-a"})
