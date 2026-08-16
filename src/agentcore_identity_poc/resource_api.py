"""Synthetic Entra-protected resource API used to test downstream delegation."""

from __future__ import annotations

import os
import secrets
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, status

from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.jwt_validation import JwtPolicy, TokenRejected, make_http_jwks_loader


def create_resource_app(
    jwt_policy: JwtPolicy,
    delegated_scope: str,
    *,
    subject_alias: str | None = None,
) -> FastAPI:
    """Create an API that returns synthetic, per-run metadata only."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    run_alias = subject_alias or f"run-{secrets.token_hex(8)}"

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metadata")
    def metadata(authorization: Annotated[str | None, Header()] = None) -> dict[str, object]:
        token = _extract_bearer_token(authorization)
        try:
            claims = jwt_policy.validate(token)
        except TokenRejected as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token rejected",
            ) from error

        if not _has_scope(claims.get("scp"), delegated_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Delegated scope required",
            )
        return {"subject_alias": run_alias, "items": []}

    return app


def create_app() -> FastAPI:
    """Uvicorn app factory backed by the POC environment settings."""
    settings = Settings.from_mapping(os.environ)
    jwks_url = f"https://login.microsoftonline.com/{settings.entra_tenant_id}/discovery/v2.0/keys"
    policy = JwtPolicy(
        issuer=settings.entra_issuer,
        audience=settings.resource_api_audience,
        jwks_loader=make_http_jwks_loader(jwks_url),
    )
    return create_resource_app(policy, settings.entra_downstream_scope)


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token rejected")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token rejected")
    return token


def _has_scope(scope_claim: object, required_scope: str) -> bool:
    return isinstance(scope_claim, str) and required_scope in scope_claim.split()
