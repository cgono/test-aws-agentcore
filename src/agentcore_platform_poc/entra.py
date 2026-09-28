# src/agentcore_platform_poc/entra.py
"""Entra v2 token checks shared by the unified API and the Resource Hub."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import jwt

from agentcore_identity_poc.jwt_validation import (
    JwtPolicy,
    TokenRejected,
    audience_variants,
    make_http_jwks_loader,
)


class AuthError(Exception):
    """A request failed authentication or authorization. The code never contains a token."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class EntraVerifier:
    def __init__(self, policy: JwtPolicy) -> None:
        self.policy = policy

    def claims(self, token: str) -> dict[str, Any]:
        try:
            claims = self.policy.validate(token)
        except TokenRejected as error:
            # PyJWT checks exp only after the signature passed, so a forged token is never
            # labelled expired.
            expired = isinstance(error.__cause__, jwt.ExpiredSignatureError)
            raise AuthError(401, "token_expired" if expired else "token_invalid") from error
        if claims.get("ver") != "2.0" or not isinstance(claims.get("aud"), str):
            raise AuthError(401, "token_invalid")
        return claims


def build_verifier(tenant_id: str, audience: str) -> EntraVerifier:
    policy = JwtPolicy(
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        audience=audience_variants(audience),
        jwks_loader=make_http_jwks_loader(
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        ),
    )
    return EntraVerifier(policy)


def require_user(
    claims: Mapping[str, Any], *, scope: str, allowed_azp: frozenset[str] | None = None
) -> str:
    oid = claims.get("oid")
    if (
        claims.get("idtyp") == "app"
        or "roles" in claims
        and "scp" not in claims
        or not isinstance(oid, str)
    ):
        raise AuthError(403, "not_user_token")
    scopes = claims.get("scp")
    if not isinstance(scopes, str) or scope not in scopes.split():
        raise AuthError(403, "missing_scope")
    if allowed_azp is not None and claims.get("azp") not in allowed_azp:
        raise AuthError(403, "client_not_allowed")
    return oid


def require_app(claims: Mapping[str, Any], *, role: str, allowed_azp: frozenset[str]) -> str:
    if "scp" in claims or claims.get("idtyp") != "app":
        raise AuthError(403, "not_app_token")
    roles = claims.get("roles")
    if not isinstance(roles, list) or role not in roles:
        raise AuthError(403, "missing_role")
    azp = claims.get("azp")
    if not isinstance(azp, str) or azp not in allowed_azp:
        raise AuthError(403, "client_not_allowed")
    return azp
