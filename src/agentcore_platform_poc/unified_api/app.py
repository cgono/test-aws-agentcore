"""Unified API: checks the user, signs a session grant, invokes the agent Runtime."""

from __future__ import annotations

import json
import os
import re
import threading
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
from agentcore_platform_poc.unified_api.runtime_client import (
    RuntimeClient,
    RuntimeTokenError,
    msal_runtime_token,
)
from agentcore_platform_poc.unified_api.settings import (
    BENCH_MAX_LIFETIME_S,
    RESEARCH_MAX_LIFETIME_S,
    UnifiedApiSettings,
)

_SID = re.compile(r"[A-Za-z0-9-]{33,100}")
# Values forwarded as HTTP headers: visible ASCII only, so no CR/LF or header injection.
_HEADER_SAFE = re.compile(r"[\x21-\x7e]{1,16384}")
SCOPE = "Research.Run"
MAX_PROMPT = 4000  # the research agent's limit (research_agent/entrypoint.py)
MODES = ("grant", "raw")


class _Reject(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code


async def _body(request: Request) -> dict[str, Any]:
    try:
        body = json.loads(await request.body())
    except ValueError as error:
        raise _Reject(400, "bad_json") from error
    if not isinstance(body, dict):
        raise _Reject(400, "bad_json")
    return body


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

    def header_value(value: Any, code: str) -> str:
        if not isinstance(value, str) or not _HEADER_SAFE.fullmatch(value):
            raise _Reject(400, code)
        return value

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
        try:
            status, result = await runtime.invoke(
                arn, settings.region, payload, session_id=sid, grant=grant, user_token=user_token
            )
        except httpx.TimeoutException as error:
            raise _Reject(504, "runtime_timeout") from error
        except (httpx.HTTPError, RuntimeTokenError) as error:
            # Only a code goes back: transport and MSAL errors carry hosts and tenant text.
            raise _Reject(502, "runtime_unavailable") from error
        return JSONResponse({"status": status, "session_id": sid, "result": result})

    @app.post("/research")
    async def research(request: Request) -> JSONResponse:
        oid = user(request)
        body = await _body(request)
        prompt = body.get("prompt")
        if not isinstance(prompt, str) or not prompt or len(prompt) > MAX_PROMPT:
            raise _Reject(400, "bad_prompt")
        mode = body.get("mode", "grant")
        supplied, hub_token = body.get("grant"), body.get("user_hub_token")
        if mode not in MODES:
            raise _Reject(400, "bad_mode")
        if (mode == "raw" or supplied is not None) and not settings.expiry_test_mode:
            raise _Reject(403, "test_mode_off")
        if (mode == "raw" and supplied is not None) or (mode == "grant" and hub_token is not None):
            raise _Reject(400, "conflicting_inputs")
        payload = {"prompt": prompt}
        if mode == "raw":
            if hub_token is None:
                raise _Reject(400, "missing_user_hub_token")
            token = header_value(hub_token, "bad_user_hub_token")
            return await run(settings.research_runtime_arn, payload, session(body), None, token)
        if supplied is not None:
            grant = header_value(supplied, "grant_invalid")
            try:
                checked = verify_grant(grant, settings.grant_public_key_pem, now=int(clock()))
            except GrantRejected as error:
                raise _Reject(403, error.code) from error
            if checked.sub != oid or checked.agent != settings.research_agent_id:
                raise _Reject(403, "grant_not_for_caller")
            # The grant names its session; the Runtime session and the Hub audit sid must match.
            if body.get("session_id") not in (None, checked.sid):
                raise _Reject(400, "session_mismatch")
            return await run(settings.research_runtime_arn, payload, checked.sid, grant, None)
        sid = session(body)
        grant = grant_for(oid, settings.research_agent_id, sid, RESEARCH_MAX_LIFETIME_S)
        return await run(settings.research_runtime_arn, payload, sid, grant, None)

    @app.post("/grants")
    async def grants(request: Request) -> JSONResponse:
        oid = user(request)
        if not settings.expiry_test_mode:
            raise _Reject(403, "test_mode_off")
        ttl = (await _body(request)).get("ttl_seconds")
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
        body = await _body(request)
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


class AssumedRoleKmsSigner:
    """Signs with KMS as the grant signer role; re-assumes the role before its credentials end."""

    def __init__(
        self,
        sts: Any,
        role_arn: str,
        key_id: str,
        *,
        kms_factory: Callable[[dict[str, Any]], Any],
        clock: Callable[[], float] = time.time,
        refresh_margin_s: float = 300,
    ) -> None:
        self._sts = sts
        self._role_arn = role_arn
        self._key_id = key_id
        self._kms_factory = kms_factory
        self._clock = clock
        self._margin = refresh_margin_s
        self._signer: KmsSigner | None = None
        self._expires = 0.0
        self._lock = threading.Lock()

    def _current(self) -> KmsSigner:
        with self._lock:
            if self._signer is None or self._expires - self._margin <= self._clock():
                creds = self._sts.assume_role(
                    RoleArn=self._role_arn, RoleSessionName="poc3-unified-api"
                )["Credentials"]
                self._signer = KmsSigner(self._kms_factory(creds), self._key_id)
                self._expires = creds["Expiration"].timestamp()
            return self._signer

    def sign(self, message: bytes) -> bytes:
        return self._current().sign(message)


def create_production_app() -> FastAPI:
    from scripts.terraform_outputs import load_terraform_outputs

    settings = UnifiedApiSettings.from_env(
        os.environ, load_terraform_outputs(Path("infra/terraform/platform"))
    )

    def kms_client(creds: dict[str, Any]) -> Any:
        return boto3.client(
            "kms",
            region_name=settings.region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    # Sign as the dedicated signer role (the key policy lets no other principal sign).
    signer = AssumedRoleKmsSigner(
        boto3.client("sts", region_name=settings.region),
        settings.signer_role_arn,
        settings.kms_key_id,
        kms_factory=kms_client,
    )
    runtime = RuntimeClient(httpx.AsyncClient(), msal_runtime_token(settings))
    verifier = build_verifier(settings.tenant_id, settings.client_id)
    return create_app(settings, verifier=verifier, signer=signer, runtime=runtime)
