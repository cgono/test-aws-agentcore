"""Mock central LLM gateway: app-role JWT auth, fixed upstreams, strict limits."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentcore_runtime_poc.gateway_sim.auth import Authorizer, CallerRejected, build_authorizer
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings

Provider = Literal["openai", "anthropic"]

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
_TOKEN_FIELD: dict[Provider, str] = {"openai": "max_completion_tokens", "anthropic": "max_tokens"}
# Top-level fields a caller may send. Anything else (tools, web search, audio, service tiers, ...)
# could add cost outside the output-token cap, so it is rejected.
_ALLOWED_FIELDS: dict[Provider, frozenset[str]] = {
    "openai": frozenset(
        {
            "model",
            "messages",
            "max_completion_tokens",
            "n",
            "stream",
            "temperature",
            "top_p",
            "stop",
        }
    ),
    "anthropic": frozenset(
        {
            "model",
            "messages",
            "max_tokens",
            "system",
            "stream",
            "temperature",
            "top_p",
            "top_k",
            "stop_sequences",
        }
    ),
}
_SAFE_ERROR_TYPE = re.compile(r"[a-z_]{1,64}")

logger = logging.getLogger(__name__)


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status)


def _normalize_body(
    provider: Provider, body: dict[str, Any], settings: GatewaySettings
) -> str | None:
    if body.get("stream"):
        return "streaming_not_supported"
    allowed = settings.openai_models if provider == "openai" else settings.anthropic_models
    model = body.get("model")
    if not isinstance(model, str) or model not in allowed:
        return "model_not_allowed"
    if provider == "openai" and "max_tokens" in body:
        return "use_max_completion_tokens"
    if provider == "openai" and body.get("n", 1) != 1:
        return "n_must_be_1"
    if not body.keys() <= _ALLOWED_FIELDS[provider]:
        return "field_not_allowed"
    field = _TOKEN_FIELD[provider]
    value = body.get(field)
    if value is None:
        body[field] = settings.max_output_tokens
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return "max_tokens_out_of_range"
    if not 1 <= value <= settings.max_output_tokens:
        return "max_tokens_out_of_range"
    return None


def _upstream_request(provider: Provider, settings: GatewaySettings) -> tuple[str, dict[str, str]]:
    if provider == "openai":
        return OPENAI_URL, {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
    return ANTHROPIC_URL, {
        "x-api-key": settings.anthropic_api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }


async def _forward(
    client: httpx.AsyncClient, provider: Provider, body: dict[str, Any], settings: GatewaySettings
) -> tuple[int, dict[str, Any]]:
    url, headers = _upstream_request(provider, settings)
    try:
        response = await client.post(
            url,
            json=body,
            headers=headers,
            timeout=settings.upstream_timeout_seconds,
            follow_redirects=False,
        )
    except httpx.TimeoutException:
        return 504, {"error": "upstream_timeout"}
    except httpx.HTTPError:
        return 502, {"error": "upstream_unreachable"}
    if 300 <= response.status_code < 400:
        return 502, {"error": "upstream_redirect"}
    try:
        data: Any = response.json()
    except ValueError:
        data = None
    if response.status_code >= 400:
        error = data.get("error") if isinstance(data, dict) else None
        kind = error.get("type") if isinstance(error, dict) else None
        return response.status_code, {
            "error": {
                "upstream_status": response.status_code,
                "type": (
                    kind
                    if isinstance(kind, str) and _SAFE_ERROR_TYPE.fullmatch(kind)
                    else "unknown"
                ),
            }
        }
    if not isinstance(data, dict):
        return 502, {"error": "upstream_invalid_json"}
    return 200, data


async def _read_limited(request: Request, limit: int) -> bytes | None:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(
    settings: GatewaySettings,
    *,
    authorizer: Authorizer | None = None,
    upstream: httpx.AsyncClient | None = None,
) -> FastAPI:
    auth = authorizer if authorizer is not None else build_authorizer(settings)
    client = upstream if upstream is not None else httpx.AsyncClient(follow_redirects=False)
    semaphore = asyncio.Semaphore(settings.max_concurrency)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if upstream is None:
            await client.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    async def proxy(request: Request, provider: Provider) -> JSONResponse:
        try:
            caller = auth.authorize(request.headers.get("authorization"))
        except CallerRejected as rejection:
            logger.info("gateway reject provider=%s reason=%s", provider, rejection)
            return _error(401, "unauthorized")
        if semaphore.locked():
            return _error(429, "too_many_requests")
        async with semaphore:
            raw = await _read_limited(request, settings.max_body_bytes)
            if raw is None:
                return _error(413, "body_too_large")
            try:
                body = json.loads(raw)
            except ValueError:
                return _error(400, "invalid_json")
            if not isinstance(body, dict):
                return _error(400, "invalid_json")
            problem = _normalize_body(provider, body, settings)
            if problem is not None:
                return _error(400, problem)
            started = time.perf_counter()
            status, payload = await _forward(client, provider, body, settings)
        logger.info(
            "gateway forward provider=%s caller=%s status=%s ms=%.0f",
            provider,
            caller,
            status,
            (time.perf_counter() - started) * 1000,
        )
        return JSONResponse(payload, status_code=status)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/openai/v1/chat/completions")
    async def openai_route(request: Request) -> JSONResponse:
        return await proxy(request, "openai")

    @app.post("/anthropic/v1/messages")
    async def anthropic_route(request: Request) -> JSONResponse:
        return await proxy(request, "anthropic")

    return app


def create_production_app() -> FastAPI:
    return create_app(GatewaySettings.from_env(os.environ))
