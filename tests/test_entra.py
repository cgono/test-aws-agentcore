from __future__ import annotations

import pytest

from agentcore_identity_poc.entra import EntraAuthError, EntraDeviceAuth


class FakePublicClientApplication:
    def __init__(self, response: dict[str, str]) -> None:
        self._response = response
        self.requested_scopes: list[str] | None = None
        self.flow: dict[str, str] | None = None

    def initiate_device_flow(self, *, scopes: list[str]) -> dict[str, str]:
        self.requested_scopes = scopes
        return {"message": "Open https://microsoft.example/device", "device_code": "secret"}

    def acquire_token_by_device_flow(self, flow: dict[str, str]) -> dict[str, str]:
        self.flow = flow
        return self._response


def test_device_code_requests_only_worker_api_scope() -> None:
    client = FakePublicClientApplication({"access_token": "entra-user-token"})
    messages: list[str] = []

    token = EntraDeviceAuth(client, ["api://worker/access_as_user"]).acquire(messages.append)

    assert token == "entra-user-token"
    assert client.requested_scopes == ["api://worker/access_as_user"]
    assert client.flow == {
        "message": "Open https://microsoft.example/device",
        "device_code": "secret",
    }
    assert messages == ["Open https://microsoft.example/device"]


def test_device_code_displays_no_flow_fields_other_than_message() -> None:
    client = FakePublicClientApplication({"access_token": "entra-user-token"})
    displayed: list[str] = []

    EntraDeviceAuth(client, ["scope"]).acquire(displayed.append)

    assert displayed == ["Open https://microsoft.example/device"]
    assert "secret" not in displayed[0]


@pytest.mark.parametrize(
    "response",
    [
        {"error": "authorization_pending", "error_description": "token-value"},
        {"error": "interaction_required", "error_description": "https://example.test/?token=value"},
        {"error_description": "missing error code"},
    ],
)
def test_device_code_error_is_sanitized(response: dict[str, str]) -> None:
    client = FakePublicClientApplication(response)

    with pytest.raises(EntraAuthError) as raised:
        EntraDeviceAuth(client, ["scope"]).acquire(lambda _: None)

    assert raised.value.error_code == response.get("error", "unknown_error")
    assert "token-value" not in str(raised.value)
    assert "https://example.test" not in str(raised.value)


def test_device_auth_constructs_msal_public_client_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed: list[tuple[str, str]] = []
    client = FakePublicClientApplication({"access_token": "entra-user-token"})

    def build_client(client_id: str, *, authority: str) -> FakePublicClientApplication:
        constructed.append((client_id, authority))
        return client

    monkeypatch.setattr("agentcore_identity_poc.entra.msal.PublicClientApplication", build_client)

    auth = EntraDeviceAuth.for_tenant("public-client", "tenant-id", ["scope"])

    assert auth.acquire(lambda _: None) == "entra-user-token"
    assert constructed == [("public-client", "https://login.microsoftonline.com/tenant-id")]
