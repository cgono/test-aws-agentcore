"""Mock central LLM gateway: app-role JWT auth, fixed upstreams, strict limits."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from agentcore_runtime_poc.gateway_sim.auth import Authorizer, CallerRejected, build_authorizer
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings

Provider = Literal["openai", "anthropic"]

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_COUNT_URL = "https://api.anthropic.com/v1/messages/count_tokens"
ANTHROPIC_VERSION = "2023-06-01"
_TOKEN_FIELD: dict[Provider, str] = {"openai": "max_completion_tokens", "anthropic": "max_tokens"}
# Top-level fields a caller may send. Anything else (web search, audio, service tiers, ...)
# could add cost outside the output-token cap, so it is rejected. Anthropic tools must be custom.
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
            "tools",
            "tool_choice",
            "metadata",
            "thinking",
            "context_management",
            "output_config",
        }
    ),
}
_SAFE_ERROR_TYPE = re.compile(r"[a-z_]{1,64}")
_BETA = re.compile(r"[a-z0-9,\-]{1,512}")

logger = logging.getLogger(__name__)


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status)


def _custom_tools_only(body: dict[str, Any]) -> bool:
    tools = body.get("tools", [])
    return isinstance(tools, list) and all(
        isinstance(t, dict)
        and "name" in t
        and "input_schema" in t
        and t.get("type", "custom") == "custom"
        for t in tools
    )


def _normalize_body(
    provider: Provider, body: dict[str, Any], settings: GatewaySettings, *, count_only: bool = False
) -> str | None:
    if body.get("stream") and provider == "openai":
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
    if provider == "anthropic" and not _custom_tools_only(body):
        return "field_not_allowed"
    if count_only:
        return None
    field = _TOKEN_FIELD[provider]
    value = body.get(field)
    if value is None:
        body[field] = settings.max_output_tokens
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return "max_tokens_out_of_range"
    if value < 1:
        return "max_tokens_out_of_range"
    if value > settings.max_output_tokens:
        if provider == "openai":
            return "max_tokens_out_of_range"
        body[field] = settings.max_output_tokens
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


def _upstream_error(status: int, data: Any) -> tuple[int, dict[str, Any]]:
    if 300 <= status < 400:
        return 502, {"error": "upstream_redirect"}
    error = data.get("error") if isinstance(data, dict) else None
    kind = error.get("type") if isinstance(error, dict) else None
    return status, {
        "error": {
            "upstream_status": status,
            "type": (
                kind if isinstance(kind, str) and _SAFE_ERROR_TYPE.fullmatch(kind) else "unknown"
            ),
        }
    }


async def _forward(
    client: httpx.AsyncClient,
    provider: Provider,
    body: dict[str, Any],
    settings: GatewaySettings,
    *,
    url: str | None = None,
    beta: str | None = None,
) -> tuple[int, dict[str, Any]]:
    default_url, headers = _upstream_request(provider, settings)
    url = url or default_url
    if beta:
        headers["anthropic-beta"] = beta
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
        return _upstream_error(response.status_code, None)
    try:
        data: Any = response.json()
    except ValueError:
        data = None
    if response.status_code >= 400:
        return _upstream_error(response.status_code, data)
    if not isinstance(data, dict):
        return 502, {"error": "upstream_invalid_json"}
    return 200, data


async def _stream(
    client: httpx.AsyncClient,
    body: dict[str, Any],
    settings: GatewaySettings,
    beta: str | None,
    release: Callable[[], None],
) -> StreamingResponse | JSONResponse:
    url, headers = _upstream_request("anthropic", settings)
    if beta:
        headers["anthropic-beta"] = beta
    request = client.build_request(
        "POST", url, json=body, headers=headers, timeout=settings.upstream_timeout_seconds
    )
    try:
        response = await client.send(request, stream=True, follow_redirects=False)
    except httpx.TimeoutException:
        release()
        return _error(504, "upstream_timeout")
    except httpx.HTTPError:
        release()
        return _error(502, "upstream_unreachable")
    if response.status_code != 200:
        raw = await response.aread()
        await response.aclose()
        release()
        try:
            data: Any = json.loads(raw)
        except ValueError:
            data = None
        status, payload = _upstream_error(response.status_code, data)
        return JSONResponse(payload, status_code=status)

    async def relay() -> AsyncIterator[bytes]:
        try:
            async for chunk in response.aiter_bytes():  # decoded: content-encoding is not relayed
                yield chunk
        finally:
            await response.aclose()
            release()

    return StreamingResponse(relay(), media_type="text/event-stream")


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

    async def proxy(request: Request, provider: Provider, url: str | None = None) -> Response:
        try:
            caller = auth.authorize(request.headers.get("authorization"))
        except CallerRejected as rejection:
            logger.info("gateway reject provider=%s reason=%s", provider, rejection)
            return _error(401, "unauthorized")
        if semaphore.locked():
            return _error(429, "too_many_requests")
        await semaphore.acquire()
        handed_off = False
        try:
            raw = await _read_limited(request, settings.max_body_bytes)
            if raw is None:
                return _error(413, "body_too_large")
            try:
                body = json.loads(raw)
            except ValueError:
                return _error(400, "invalid_json")
            if not isinstance(body, dict):
                return _error(400, "invalid_json")
            if provider == "anthropic":
                logger.info("gateway fields provider=anthropic fields=%s", ",".join(sorted(body)))
            problem = _normalize_body(
                provider, body, settings, count_only=url == ANTHROPIC_COUNT_URL
            )
            if problem is not None:
                return _error(400, problem)
            beta = request.headers.get("anthropic-beta")
            beta = beta if provider == "anthropic" and beta and _BETA.fullmatch(beta) else None
            started = time.perf_counter()
            if provider == "anthropic" and body.get("stream"):
                handed_off = True
                logger.info("gateway stream provider=anthropic caller=%s", caller)
                return await _stream(client, body, settings, beta, semaphore.release)
            status, payload = await _forward(client, provider, body, settings, url=url, beta=beta)
        finally:
            if not handed_off:
                semaphore.release()
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
    async def openai_route(request: Request) -> Response:
        return await proxy(request, "openai")

    @app.post("/anthropic/v1/messages")
    async def anthropic_route(request: Request) -> Response:
        return await proxy(request, "anthropic")

    @app.post("/anthropic/v1/messages/count_tokens")
    async def anthropic_count_route(request: Request) -> Response:
        return await proxy(request, "anthropic", ANTHROPIC_COUNT_URL)

    return app


def create_production_app() -> FastAPI:
    return create_app(GatewaySettings.from_env(os.environ))
