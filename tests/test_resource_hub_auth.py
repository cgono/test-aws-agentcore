# tests/test_resource_hub_auth.py
from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentcore_platform_poc.entra import AuthError
from agentcore_platform_poc.grant import LocalSigner, issue_grant
from agentcore_platform_poc.resource_hub.auth import authenticate
from agentcore_platform_poc.resource_hub.settings import HubSettings

A = "00000000-0000-0000-0000-00000000000a"
KEY = ec.generate_private_key(ec.SECP256R1())
PEM = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
TOKENS: dict[str, dict[str, Any]] = {
    "user": {"ver": "2.0", "aud": "hub", "oid": A, "scp": "Workspace.ReadWrite", "azp": "cli"},
    "research": {
        "ver": "2.0",
        "aud": "hub",
        "roles": ["Workspace.Agent"],
        "azp": "research",
        "idtyp": "app",
    },
    "bench": {
        "ver": "2.0",
        "aud": "hub",
        "roles": ["Workspace.Agent"],
        "azp": "bench",
        "idtyp": "app",
    },
}


class FakeVerifier:
    def claims(self, token: str) -> dict[str, Any]:
        if token == "expired":
            raise AuthError(401, "token_expired")
        if token not in TOKENS:
            raise AuthError(401, "token_invalid")
        return dict(TOKENS[token])


def _settings(raw: bool = False) -> HubSettings:
    return HubSettings(
        "example-tenant", "hub", frozenset({"research", "bench"}), PEM, "bucket", raw
    )


def _grant(agent: str = "research", ttl: int = 60) -> str:
    return issue_grant(LocalSigner(KEY), sub=A, agent=agent, sid="s1", ttl_seconds=ttl, now=1000)


def _auth(headers: dict[str, str], raw: bool = False, now: int = 1001) -> Any:
    return authenticate(headers, verifier=FakeVerifier(), settings=_settings(raw), now=now)  # type: ignore[arg-type]


def test_user_mode() -> None:
    caller = _auth({"authorization": "Bearer user"})
    assert (caller.mode, caller.oid) == ("user", A)


def test_agent_grant_mode() -> None:
    caller = _auth(
        {"authorization": "Bearer research", "x-resource-grant": _grant(), "x-session-id": "s1"}
    )
    assert (caller.mode, caller.oid, caller.azp, caller.sid) == ("agent_grant", A, "research", "s1")


@pytest.mark.parametrize(
    ("headers", "status", "code"),
    [
        ({}, 401, "missing_token"),
        ({"authorization": "Basic x"}, 401, "missing_token"),
        ({"authorization": "Bearer nope"}, 401, "token_invalid"),
        ({"authorization": "Bearer expired"}, 401, "token_expired"),
        ({"authorization": "Bearer research"}, 403, "not_user_token"),
        ({"authorization": "Bearer user", "x-resource-grant": "g"}, 403, "not_app_token"),
        ({"authorization": "Bearer bench", "x-resource-grant": "GRANT"}, 403, "agent_mismatch"),
        ({"authorization": "Bearer research", "x-resource-grant": "garbage"}, 401, "grant_invalid"),
        ({"authorization": "Bearer research", "x-user-token": "user"}, 403, "raw_mode_disabled"),
    ],
)
def test_rejections(headers: dict[str, str], status: int, code: str) -> None:
    headers = {k: (_grant() if v == "GRANT" else v) for k, v in headers.items()}
    with pytest.raises(AuthError) as caught:
        _auth(headers)
    assert (caught.value.status, caught.value.code) == (status, code)


def test_expired_grant() -> None:
    with pytest.raises(AuthError) as caught:
        _auth({"authorization": "Bearer research", "x-resource-grant": _grant(ttl=60)}, now=2000)
    assert caught.value.code == "grant_expired"


def test_raw_mode_when_enabled() -> None:
    caller = _auth({"authorization": "Bearer research", "x-user-token": "user"}, raw=True)
    assert (caller.mode, caller.oid, caller.azp) == ("agent_raw", A, "research")


def test_raw_mode_expired_user_token() -> None:
    with pytest.raises(AuthError) as caught:
        _auth({"authorization": "Bearer research", "x-user-token": "expired"}, raw=True)
    assert caught.value.code == "token_expired"


def test_both_grant_and_user_token_rejected() -> None:
    with pytest.raises(AuthError, match="ambiguous_mode"):
        _auth(
            {
                "authorization": "Bearer research",
                "x-resource-grant": _grant(),
                "x-user-token": "user",
            },
            raw=True,
        )


def test_settings_from_env() -> None:
    settings = HubSettings.from_env(
        {
            "TENANT_ID": "t",
            "HUB_APP_ID": "h",
            "ALLOWED_AGENT_IDS": "a, b",
            "GRANT_PUBLIC_KEY_PEM": "pem",
            "WORKSPACE_BUCKET": "w",
            "ALLOW_RAW_USER_TOKEN": "false",
        }
    )
    assert (
        settings.allowed_agent_ids == frozenset({"a", "b"})
        and settings.allow_raw_user_token is False
    )
    with pytest.raises(ValueError):
        HubSettings.from_env({})
