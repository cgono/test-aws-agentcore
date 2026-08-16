from __future__ import annotations

import json
from collections.abc import Mapping

import pytest
from fastapi.testclient import TestClient

from agentcore_identity_poc.agentcore import AuthorizationRequired
from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.web import WebRuntime, create_app

USER_TOKEN = "user-token-value"
OTHER_USER_TOKEN = "other-user-token-value"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        aws_region="us-west-2",
        aws_budget_name="poc-budget",
        entra_tenant_id="tenant-id",
        entra_public_client_id="public-client",
        entra_api_client_id="middle-tier-client",
        entra_downstream_scope="api://downstream/access_as_user",
        agentcore_workload_name="approved-workload",
        agentcore_second_workload_name="unapproved-workload",
        agentcore_microsoft_provider="microsoft-provider",
        agentcore_google_provider="google-provider",
        resource_api_audience="api://resource",
        resource_api_url="https://resource.example.test/metadata",
        public_base_url="https://callback.example.test",
    )


class FakeMsal:
    def __init__(self, access_token: str = USER_TOKEN) -> None:
        self.completed_flows: list[tuple[Mapping[str, object], Mapping[str, str]]] = []
        self._access_token = access_token

    def initiate_auth_code_flow(
        self, *, scopes: list[str], redirect_uri: str
    ) -> Mapping[str, object]:
        assert scopes == ["api://middle-tier-client/access_as_user"]
        assert redirect_uri == "https://callback.example.test/auth/entra/callback"
        return {
            "auth_uri": "https://login.example.test/authorize?code=not-a-token",
            "state": "entra-state",
            "code_verifier": "pkce-verifier",
        }

    def acquire_token_by_auth_code_flow(
        self, flow: Mapping[str, object], auth_response: Mapping[str, str]
    ) -> Mapping[str, object]:
        self.completed_flows.append((flow, auth_response))
        return {"access_token": self._access_token}


class FakeIdentity:
    def __init__(self) -> None:
        self.complete_calls: list[tuple[str, str]] = []
        self.google_calls: list[tuple[str, str, list[str], str, str]] = []

    def workload_token(self, workload_name: str, user_token: str) -> str:
        assert workload_name == "approved-workload"
        assert user_token in {USER_TOKEN, OTHER_USER_TOKEN}
        return "workload-token"

    def google_token(
        self,
        workload_token: str,
        provider: str,
        scopes: list[str],
        return_url: str,
        state: str,
    ) -> AuthorizationRequired:
        self.google_calls.append((workload_token, provider, scopes, return_url, state))
        return AuthorizationRequired(
            authorization_url="https://accounts.example.test/authorize?opaque=value",
            session_uri="urn:test",
        )

    def complete_google(self, session_uri: str, user_token: str) -> None:
        self.complete_calls.append((session_uri, user_token))


@pytest.fixture
def clock() -> list[float]:
    return [1_000.0]


@pytest.fixture
def fake_identity() -> FakeIdentity:
    return FakeIdentity()


@pytest.fixture
def client(
    settings: Settings, clock: list[float], fake_identity: FakeIdentity
) -> TestClient:
    runtime = WebRuntime(
        settings=settings,
        msal=lambda _: FakeMsal(),
        validate_token=lambda token: {
            "iss": settings.entra_issuer,
            "aud": f"api://{settings.entra_api_client_id}",
            "sub": "user-a" if token == USER_TOKEN else "user-b",
        }
        if token in {USER_TOKEN, OTHER_USER_TOKEN}
        else (_ for _ in ()).throw(ValueError("token rejected: secret=value")),
        identity=lambda _: fake_identity,
        clock=lambda: clock[0],
        random_urlsafe=lambda: "opaque-state",
    )
    return TestClient(create_app(runtime), base_url="https://callback.example.test")


def _start_google(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/oauth/google/start", headers={"Authorization": f"Bearer {USER_TOKEN}"}
    )
    assert response.status_code == 200
    return response.json()


def test_google_return_does_not_complete_without_live_browser_token(
    client: TestClient, fake_identity: FakeIdentity
) -> None:
    response = client.get("/oauth/google/return?session_id=urn:test&state=valid")

    assert response.status_code == 200
    assert "sessionStorage" in response.text
    assert fake_identity.complete_calls == []


def test_complete_rejects_state_mismatch(client: TestClient, fake_identity: FakeIdentity) -> None:
    _start_google(client)
    original_cookie = client.cookies.get("agentcore_google_state")

    response = client.post(
        "/oauth/google/complete",
        json={"session_uri": "urn:test", "state": "wrong"},
        headers={"Authorization": f"Bearer {USER_TOKEN}"},
    )

    assert response.status_code == 400
    assert fake_identity.complete_calls == []

    replay = client.post(
        "/oauth/google/complete",
        json={"session_uri": "urn:test", "state": "opaque-state"},
        headers={
            "Authorization": f"Bearer {USER_TOKEN}",
            "Cookie": f"agentcore_google_state={original_cookie}",
        },
    )
    assert replay.status_code == 400
    assert fake_identity.complete_calls == []


@pytest.mark.parametrize("payload", [{}, {"session_uri": "urn:test", "state": "opaque-state"}])
def test_complete_requires_a_live_browser_token(
    client: TestClient, fake_identity: FakeIdentity, payload: dict[str, str]
) -> None:
    _start_google(client)

    response = client.post("/oauth/google/complete", json=payload)

    assert response.status_code == 401
    assert fake_identity.complete_calls == []


def test_complete_rejects_missing_state_cookie(
    client: TestClient, fake_identity: FakeIdentity
) -> None:
    response = client.post(
        "/oauth/google/complete",
        json={"session_uri": "urn:test", "state": "opaque-state"},
        headers={"Authorization": f"Bearer {USER_TOKEN}"},
    )

    assert response.status_code == 400
    assert fake_identity.complete_calls == []


def test_complete_rejects_expired_state_cookie(
    client: TestClient, clock: list[float], fake_identity: FakeIdentity
) -> None:
    _start_google(client)
    clock[0] += 601

    response = client.post(
        "/oauth/google/complete",
        json={"session_uri": "urn:test", "state": "opaque-state"},
        headers={"Authorization": f"Bearer {USER_TOKEN}"},
    )

    assert response.status_code == 400
    assert fake_identity.complete_calls == []


def test_state_cookie_has_ten_minute_secure_flags(client: TestClient) -> None:
    response = client.post(
        "/oauth/google/start", headers={"Authorization": f"Bearer {USER_TOKEN}"}
    )

    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "Max-Age=600" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" in cookie


def test_complete_rejects_a_different_valid_user(
    client: TestClient, fake_identity: FakeIdentity
) -> None:
    _start_google(client)

    response = client.post(
        "/oauth/google/complete",
        json={"session_uri": "urn:test", "state": "opaque-state"},
        headers={"Authorization": f"Bearer {OTHER_USER_TOKEN}"},
    )

    assert response.status_code == 400
    assert fake_identity.complete_calls == []


def test_complete_consumes_state_and_rejects_replay(
    client: TestClient, fake_identity: FakeIdentity
) -> None:
    _start_google(client)
    payload = {"session_uri": "urn:test", "state": "opaque-state"}

    success = client.post(
        "/oauth/google/complete",
        json=payload,
        headers={"Authorization": f"Bearer {USER_TOKEN}"},
    )
    replay = client.post(
        "/oauth/google/complete",
        json=payload,
        headers={"Authorization": f"Bearer {USER_TOKEN}"},
    )

    assert success.status_code == 204
    assert replay.status_code == 400
    assert fake_identity.complete_calls == [("urn:test", USER_TOKEN)]


def test_connect_and_entra_callback_use_one_time_secure_flow_cookie(client: TestClient) -> None:
    connect = client.get("/connect", follow_redirects=False)

    assert connect.status_code == 307
    assert "HttpOnly" in connect.headers["set-cookie"]
    assert "Max-Age=600" in connect.headers["set-cookie"]
    callback = client.get("/auth/entra/callback?code=authorization-code&state=entra-state")

    assert callback.status_code == 200
    assert "sessionStorage.setItem" in callback.text
    assert "history.replaceState" in callback.text
    assert "script-src 'nonce-" in callback.headers["content-security-policy"]
    assert "connect-src 'self'" in callback.headers["content-security-policy"]
    assert "Max-Age=0" in callback.headers["set-cookie"]


def test_auth_errors_are_redacted_and_security_headers_are_consistent(client: TestClient) -> None:
    response = client.post(
        "/oauth/google/start", headers={"Authorization": "Bearer bad-secret-token"}
    )

    assert response.status_code == 401
    assert "bad-secret-token" not in response.text
    assert "secret=value" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_entra_callback_escapes_token_for_inline_json(
    settings: Settings, fake_identity: FakeIdentity
) -> None:
    dangerous_token = "header.<>&" + chr(0x2028) + chr(0x2029)
    runtime = WebRuntime(
        settings=settings,
        msal=lambda _: FakeMsal(dangerous_token),
        validate_token=lambda _: {},
        identity=lambda _: fake_identity,
        clock=lambda: 1_000.0,
        random_urlsafe=lambda: "opaque-state",
    )
    client = TestClient(create_app(runtime), base_url="https://callback.example.test")
    client.get("/connect", follow_redirects=False)
    response = client.get("/auth/entra/callback?code=authorization-code&state=entra-state")

    encoded = (
        json.dumps(dangerous_token)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    assert encoded in response.text
    assert "<>&" not in response.text
    assert chr(0x2028) not in response.text
    assert chr(0x2029) not in response.text


def test_healthz_is_available(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
