"""App-only (client-credentials) authorization for the gateway simulation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agentcore_identity_poc.jwt_validation import (
    JwtPolicy,
    TokenRejected,
    make_http_jwks_loader,
)
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings


class CallerRejected(Exception):
    """The request is not from an authorized app-only caller. Messages never include tokens."""


class Authorizer(Protocol):
    def authorize(self, header: str | None) -> str: ...


@dataclass(frozen=True)
class AppRoleAuthorizer:
    policy: JwtPolicy
    required_role: str
    allowed_caller_ids: frozenset[str]

    def authorize(self, header: str | None) -> str:
        if not header or not header.startswith("Bearer "):
            raise CallerRejected("missing bearer token")
        token = header.removeprefix("Bearer ").strip()
        if not token:
            raise CallerRejected("missing bearer token")
        try:
            claims = self.policy.validate(token)
        except TokenRejected as error:
            raise CallerRejected("token rejected") from error
        # PyJWT accepts a list-valued aud that merely contains the audience; require exactly it.
        if claims.get("aud") != self.policy.audience:
            raise CallerRejected("audience is not exactly the gateway app")
        if claims.get("ver") != "2.0":
            raise CallerRejected("not a v2.0 token")
        if "scp" in claims:
            raise CallerRejected("delegated token")
        if claims.get("idtyp", "app") != "app":
            raise CallerRejected("not an app-only token")
        roles = claims.get("roles")
        if not isinstance(roles, list) or self.required_role not in roles:
            raise CallerRejected("missing app role")
        caller = claims.get("azp")
        if not isinstance(caller, str) or caller not in self.allowed_caller_ids:
            raise CallerRejected("caller not allowed")
        return caller


def build_authorizer(settings: GatewaySettings) -> AppRoleAuthorizer:
    policy = JwtPolicy(
        issuer=settings.issuer,
        audience=settings.gateway_app_client_id,
        jwks_loader=make_http_jwks_loader(settings.jwks_url),
    )
    return AppRoleAuthorizer(
        policy=policy,
        required_role=settings.required_role,
        allowed_caller_ids=settings.allowed_caller_ids,
    )
