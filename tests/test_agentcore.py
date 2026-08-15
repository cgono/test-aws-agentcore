from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from agentcore_identity_poc.agentcore import (
    AgentCoreAccessDenied,
    AgentCoreIdentity,
    AgentCoreInternalError,
    AgentCoreThrottled,
    AgentCoreValidationError,
    AuthorizationRequired,
    OAuthToken,
)


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.resource_response: dict[str, object] = {"accessToken": "downstream-value"}

    def get_workload_access_token_for_jwt(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("workload", kwargs))
        return {"workloadAccessToken": "wat-value"}

    def get_resource_oauth2_token(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("resource", kwargs))
        return self.resource_response

    def complete_resource_token_auth(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("complete", kwargs))
        return {}

    def get_workload_access_token_for_user_id(self, **kwargs: object) -> dict[str, object]:
        raise AssertionError("The user ID workload-token operation must never be called")


def test_obo_uses_jwt_workload_binding_and_declared_scope() -> None:
    client = RecordingClient()
    identity = AgentCoreIdentity(client)

    wat = identity.workload_token("approved-workload", "user-jwt")
    token = identity.obo_token(wat, "microsoft-provider", ["api://resource/access"])

    assert token == "downstream-value"
    assert client.calls == [
        ("workload", {"workloadName": "approved-workload", "userToken": "user-jwt"}),
        (
            "resource",
            {
                "workloadIdentityToken": "wat-value",
                "resourceCredentialProviderName": "microsoft-provider",
                "scopes": ["api://resource/access"],
                "oauth2Flow": "ON_BEHALF_OF_TOKEN_EXCHANGE",
            },
        ),
    ]


def test_google_token_uses_user_federation_return_url_state_and_offline_access() -> None:
    client = RecordingClient()
    client.resource_response = {"accessToken": "google-access-token"}

    result = AgentCoreIdentity(client).google_token(
        "wat-value",
        "google-provider",
        ["https://www.googleapis.com/auth/drive.metadata.readonly"],
        "https://callback.example.test/oauth/google/return",
        "opaque-state",
        force_authentication=True,
    )

    assert result == OAuthToken("google-access-token")
    assert client.calls == [
        (
            "resource",
            {
                "workloadIdentityToken": "wat-value",
                "resourceCredentialProviderName": "google-provider",
                "scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly"],
                "oauth2Flow": "USER_FEDERATION",
                "resourceOauth2ReturnUrl": "https://callback.example.test/oauth/google/return",
                "forceAuthentication": True,
                "customParameters": {"access_type": "offline"},
                "customState": "opaque-state",
            },
        )
    ]


def test_google_token_returns_authorization_required_when_agentcore_requires_consent() -> None:
    client = RecordingClient()
    client.resource_response = {
        "authorizationUrl": "https://accounts.example.test/authorize?secret=value",
        "sessionUri": "session-uri-value",
    }

    result = AgentCoreIdentity(client).google_token(
        "wat-value",
        "google-provider",
        ["scope-a"],
        "https://callback.example.test/oauth/google/return",
        "opaque-state",
    )

    assert result == AuthorizationRequired(
        authorization_url="https://accounts.example.test/authorize?secret=value",
        session_uri="session-uri-value",
    )
    assert client.calls[0][1]["forceAuthentication"] is False


def test_complete_google_binds_the_signed_user_jwt_to_the_session() -> None:
    client = RecordingClient()

    AgentCoreIdentity(client).complete_google("session-uri-value", "signed-user-jwt")

    assert client.calls == [
        (
            "complete",
            {
                "userIdentifier": {"userToken": "signed-user-jwt"},
                "sessionUri": "session-uri-value",
            },
        )
    ]


@pytest.mark.parametrize(
    ("code", "exception_type"),
    [
        ("AccessDeniedException", AgentCoreAccessDenied),
        ("ThrottlingException", AgentCoreThrottled),
        ("ValidationException", AgentCoreValidationError),
        ("InternalServerException", AgentCoreInternalError),
    ],
)
def test_aws_error_codes_map_to_stable_sanitized_exceptions(
    code: str,
    exception_type: type[Exception],
) -> None:
    sensitive_url = "https://accounts.example.test/authorize?secret=value"

    class FailingClient(RecordingClient):
        def get_workload_access_token_for_jwt(self, **kwargs: object) -> dict[str, object]:
            raise ClientError(
                {"Error": {"Code": code, "Message": sensitive_url}},
                "GetWorkloadAccessTokenForJWT",
            )

    with pytest.raises(exception_type) as raised:
        AgentCoreIdentity(FailingClient()).workload_token("approved-workload", "user-jwt")

    assert isinstance(raised.value.__cause__, ClientError)
    assert sensitive_url not in str(raised.value)
    assert "user-jwt" not in str(raised.value)


def test_unrecognized_aws_errors_do_not_expose_the_aws_response() -> None:
    sensitive_url = "https://accounts.example.test/authorize?secret=value"

    class FailingClient(RecordingClient):
        def get_workload_access_token_for_jwt(self, **kwargs: object) -> dict[str, object]:
            raise ClientError(
                {"Error": {"Code": "UnexpectedException", "Message": sensitive_url}},
                "GetWorkloadAccessTokenForJWT",
            )

    with pytest.raises(AgentCoreInternalError) as raised:
        AgentCoreIdentity(FailingClient()).workload_token("approved-workload", "user-jwt")

    assert isinstance(raised.value.__cause__, ClientError)
    assert sensitive_url not in str(raised.value)


def test_does_not_offer_or_call_the_user_id_workload_token_operation() -> None:
    client = RecordingClient()

    result = AgentCoreIdentity(client).workload_token("approved-workload", "user-jwt")

    assert result == "wat-value"
    assert [name for name, _ in client.calls] == ["workload"]
    assert not hasattr(AgentCoreIdentity, "workload_token_for_user_id")


def test_preserves_non_aws_failures_as_sanitized_internal_errors() -> None:
    class FailingClient(RecordingClient):
        def get_resource_oauth2_token(self, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("https://accounts.example.test/authorize?secret=value")

    with pytest.raises(AgentCoreInternalError) as raised:
        AgentCoreIdentity(FailingClient()).obo_token("wat-value", "provider", ["scope"])

    assert isinstance(raised.value.__cause__, RuntimeError)
    assert "https://accounts.example.test/authorize?secret=value" not in str(raised.value)
