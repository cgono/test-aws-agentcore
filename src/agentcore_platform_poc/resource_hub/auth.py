# src/agentcore_platform_poc/resource_hub/auth.py
"""The three Resource Hub caller modes. The user always comes from a verified token or grant."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from agentcore_platform_poc.entra import AuthError, EntraVerifier, require_app, require_user
from agentcore_platform_poc.grant import GrantRejected, verify_grant
from agentcore_platform_poc.resource_hub.settings import HubSettings

USER_SCOPE = "Workspace.ReadWrite"
AGENT_ROLE = "Workspace.Agent"


@dataclass(frozen=True)
class Caller:
    mode: Literal["user", "agent_grant", "agent_raw"]
    oid: str
    azp: str | None
    sid: str | None


def _bearer(headers: Mapping[str, str]) -> str:
    value = headers.get("authorization", "")
    token = value.removeprefix("Bearer ").strip() if value.startswith("Bearer ") else ""
    if not token:
        raise AuthError(401, "missing_token")
    return token


def authenticate(
    headers: Mapping[str, str], *, verifier: EntraVerifier, settings: HubSettings, now: int
) -> Caller:
    token = _bearer(headers)
    grant, user_token = headers.get("x-resource-grant"), headers.get("x-user-token")
    sid = headers.get("x-session-id")
    if grant is None and user_token is None:
        return Caller("user", require_user(verifier.claims(token), scope=USER_SCOPE), None, None)
    if grant is not None and user_token is not None:
        raise AuthError(400, "ambiguous_mode")
    azp = require_app(
        verifier.claims(token), role=AGENT_ROLE, allowed_azp=settings.allowed_agent_ids
    )
    if grant is not None:
        try:
            checked = verify_grant(grant, settings.grant_public_key_pem, now=now)
        except GrantRejected as error:
            raise AuthError(401, error.code) from error
        if checked.agent != azp:
            raise AuthError(403, "agent_mismatch")
        return Caller("agent_grant", checked.sub, azp, sid)
    if not settings.allow_raw_user_token:
        raise AuthError(403, "raw_mode_disabled")
    oid = require_user(verifier.claims(user_token or ""), scope=USER_SCOPE)
    return Caller("agent_raw", oid, azp, sid)
