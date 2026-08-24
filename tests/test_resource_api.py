from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.jwt_validation import JwtPolicy
from agentcore_identity_poc.resource_api import create_app, create_resource_app

ISSUER = "https://login.microsoftonline.com/example-tenant/v2.0"
AUDIENCE = "api://agentcore-resource"
SCOPE = "api://agentcore-resource/access_as_user"


@pytest.fixture
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwk(signing_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    return {**public_jwk, "kid": "resource-key", "use": "sig", "alg": "RS256"}


@pytest.fixture
def token_factory(signing_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def make_token(**overrides: Any) -> str:
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "entra-subject-value",
            "scp": SCOPE,
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        }
        claims.update(overrides)
        return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "resource-key"})

    return make_token


@pytest.fixture
def client(jwk: dict[str, Any]) -> TestClient:
    policy = JwtPolicy(ISSUER, AUDIENCE, lambda: {"keys": [jwk]})
    return TestClient(create_resource_app(policy, SCOPE, subject_alias="run-alias"))


def test_health_check(client: TestClient) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metadata_returns_only_per_run_alias_and_empty_items(
    client: TestClient, token_factory: Callable[..., str]
) -> None:
    response = client.get("/metadata", headers={"Authorization": f"Bearer {token_factory()}"})

    assert response.status_code == 200
    assert response.json() == {"subject_alias": "run-alias", "items": []}
    assert "entra-subject-value" not in response.text


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://foreign.example.test"},
        {"aud": "api://wrong-audience"},
        {"exp": datetime.now(UTC) - timedelta(minutes=1)},
        {"scp": "some-other-scope"},
    ],
)
def test_metadata_rejects_invalid_or_underscoped_tokens(
    client: TestClient, token_factory: Callable[..., str], overrides: dict[str, object]
) -> None:
    response = client.get(
        "/metadata", headers={"Authorization": f"Bearer {token_factory(**overrides)}"}
    )

    expected = 403 if overrides.get("scp") else 401
    assert response.status_code == expected
    assert "entra-subject-value" not in response.text


@pytest.mark.parametrize("authorization", [None, "Basic credential", "Bearer "])
def test_metadata_requires_bearer_authentication(
    client: TestClient, authorization: str | None
) -> None:
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.get("/metadata", headers=headers)

    assert response.status_code == 401
    assert "authorization" not in response.text.lower()


def test_production_factory_derives_audience_variants_and_short_scope_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        aws_region="us-west-2",
        aws_budget_name="poc-budget",
        entra_tenant_id="tenant-id",
        entra_public_client_id="public-client",
        entra_api_client_id="middle-tier-client",
        entra_downstream_scope="api://resource-app-id/access_as_user",
        agentcore_workload_name="approved-workload",
        agentcore_second_workload_name="unapproved-workload",
        agentcore_microsoft_provider="microsoft-provider",
        agentcore_google_provider="google-provider",
        resource_api_audience="api://resource-app-id",
        resource_api_url="https://resource.example.test/metadata",
        public_base_url="https://callback.example.test",
    )
    captured: dict[str, object] = {}

    class FakePolicy:
        def __init__(self, *, issuer: str, audience: object, jwks_loader: object) -> None:
            captured["issuer"] = issuer
            captured["audience"] = audience
            captured["jwks_loader"] = jwks_loader

    def fake_create_resource_app(policy: object, delegated_scope: str) -> str:
        captured["policy"] = policy
        captured["delegated_scope"] = delegated_scope
        return "the-app"

    monkeypatch.setattr(
        "agentcore_identity_poc.resource_api.Settings.from_mapping", lambda _: settings
    )
    monkeypatch.setattr("agentcore_identity_poc.resource_api.JwtPolicy", FakePolicy)
    monkeypatch.setattr(
        "agentcore_identity_poc.resource_api.make_http_jwks_loader",
        lambda url: captured.setdefault("jwks_url", url),
    )
    monkeypatch.setattr(
        "agentcore_identity_poc.resource_api.create_resource_app", fake_create_resource_app
    )

    app = create_app()

    assert app == "the-app"
    assert captured["issuer"] == settings.entra_issuer
    # Entra puts the bare client-ID GUID in `aud`, not the `api://` URI form
    # configured for RESOURCE_API_AUDIENCE; both must be accepted.
    assert captured["audience"] == ("resource-app-id", "api://resource-app-id")
    assert captured["jwks_url"] == (
        "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys"
    )
    # Entra puts only the short scope name in `scp`, never the full
    # api://<client-id>/access_as_user URI used to request the scope.
    assert captured["delegated_scope"] == "access_as_user"
