"""Unified API: checks the user, signs a session grant, invokes the agent Runtime."""

from __future__ import annotations

import os
import re
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentcore_platform_poc.entra import AuthError, EntraVerifier, build_verifier, require_user
from agentcore_platform_poc.grant import (
    DEFAULT_TTL_SECONDS,
    GrantRejected,
    KmsSigner,
    Signer,
    issue_grant,
    verify_grant,
)
from agentcore_platform_poc.unified_api.runtime_client import RuntimeClient, msal_runtime_token
from agentcore_platform_poc.unified_api.settings import (
    BENCH_MAX_LIFETIME_S,
    RESEARCH_MAX_LIFETIME_S,
    UnifiedApiSettings,
)

_SID = re.compile(r"[A-Za-z0-9-]{33,100}")
SCOPE = "Research.Run"


class _Reject(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code


def create_app(
    settings: UnifiedApiSettings,
    *,
    verifier: EntraVerifier,
    signer: Signer,
    runtime: RuntimeClient,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def user(request: Request) -> str:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise AuthError(401, "missing_token")
        claims = verifier.claims(header.removeprefix("Bearer ").strip())
        return require_user(claims, scope=SCOPE, allowed_azp=frozenset({settings.cli_client_id}))

    def session(body: dict[str, Any]) -> str:
        sid = body.get("session_id")
        if sid is None:
            return f"poc3-{uuid.uuid4().hex}"
        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            raise _Reject(400, "bad_session_id")
        return sid

    def grant_for(oid: str, agent: str, sid: str, lifetime_cap: int) -> str:
        ttl = min(DEFAULT_TTL_SECONDS, settings.max_grant_ttl_s, lifetime_cap)
        return issue_grant(signer, sub=oid, agent=agent, sid=sid, ttl_seconds=ttl, now=int(clock()))

    @app.exception_handler(AuthError)
    async def auth_error(_: Request, error: AuthError) -> JSONResponse:
        return JSONResponse({"error": error.code}, status_code=error.status)

    @app.exception_handler(_Reject)
    async def reject(_: Request, error: _Reject) -> JSONResponse:
        return JSONResponse({"error": error.code}, status_code=error.status)

    async def run(
        arn: str, payload: dict[str, Any], sid: str, grant: str | None, user_token: str | None
    ) -> JSONResponse:
        status, result = await runtime.invoke(
            arn, settings.region, payload, session_id=sid, grant=grant, user_token=user_token
        )
        return JSONResponse({"status": status, "session_id": sid, "result": result})

    @app.post("/research")
    async def research(request: Request) -> JSONResponse:
        oid = user(request)
        body = await request.json()
        prompt = body.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise _Reject(400, "bad_prompt")
        sid = session(body)
        mode, supplied = body.get("mode", "grant"), body.get("grant")
        if (mode == "raw" or supplied is not None) and not settings.expiry_test_mode:
            raise _Reject(403, "test_mode_off")
        if mode == "raw":
            hub_token = body.get("user_hub_token")
            if not isinstance(hub_token, str) or not hub_token:
                raise _Reject(400, "missing_user_hub_token")
            return await run(
                settings.research_runtime_arn, {"prompt": prompt}, sid, None, hub_token
            )
        if supplied is not None:
            try:
                checked = verify_grant(
                    str(supplied), settings.grant_public_key_pem, now=int(clock())
                )
            except GrantRejected as error:
                raise _Reject(403, error.code) from error
            if checked.sub != oid or checked.agent != settings.research_agent_id:
                raise _Reject(403, "grant_not_for_caller")
            return await run(
                settings.research_runtime_arn, {"prompt": prompt}, sid, str(supplied), None
            )
        return await run(
            settings.research_runtime_arn,
            {"prompt": prompt},
            sid,
            grant_for(oid, settings.research_agent_id, sid, RESEARCH_MAX_LIFETIME_S),
            None,
        )

    @app.post("/grants")
    async def grants(request: Request) -> JSONResponse:
        oid = user(request)
        if not settings.expiry_test_mode:
            raise _Reject(403, "test_mode_off")
        ttl = (await request.json()).get("ttl_seconds")
        if not isinstance(ttl, int) or not 0 < ttl <= settings.max_grant_ttl_s:
            raise _Reject(400, "bad_ttl")
        sid = f"poc3-{uuid.uuid4().hex}"
        grant = issue_grant(
            signer,
            sub=oid,
            agent=settings.research_agent_id,
            sid=sid,
            ttl_seconds=ttl,
            now=int(clock()),
        )
        return JSONResponse({"grant": grant, "exp": int(clock()) + ttl})

    @app.post("/bench")
    async def bench(request: Request) -> JSONResponse:
        oid = user(request)
        body = await request.json()
        case = body.get("case")
        if not isinstance(case, dict):
            raise _Reject(400, "bad_case")
        sid = session(body)
        return await run(
            settings.bench_runtime_arn,
            {"case": case},
            sid,
            grant_for(oid, settings.bench_agent_id, sid, BENCH_MAX_LIFETIME_S),
            None,
        )

    return app


def create_production_app() -> FastAPI:
    from scripts.terraform_outputs import load_terraform_outputs

    settings = UnifiedApiSettings.from_env(
        os.environ, load_terraform_outputs(Path("infra/terraform/platform"))
    )
    # Sign as the dedicated signer role (the key policy lets no other principal sign).
    creds = boto3.client("sts").assume_role(
        RoleArn=settings.signer_role_arn, RoleSessionName="poc3-unified-api"
    )["Credentials"]
    kms = boto3.client(
        "kms",
        region_name=settings.region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    signer = KmsSigner(kms, settings.kms_key_id)
    runtime = RuntimeClient(httpx.AsyncClient(), msal_runtime_token(settings))
    verifier = build_verifier(settings.tenant_id, settings.client_id)
    return create_app(settings, verifier=verifier, signer=signer, runtime=runtime)
