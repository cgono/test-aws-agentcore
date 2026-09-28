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
    if body.get("stream") and (provider == "openai" or count_only):
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
    elif isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return "max_tokens_out_of_range"
    elif value > settings.max_output_tokens:
        if provider == "openai":
            return "max_tokens_out_of_range"
        body[field] = settings.max_output_tokens
    if provider == "anthropic":
        _fit_thinking_budget(body)
    return None


def _fit_thinking_budget(body: dict[str, Any]) -> None:
    # Anthropic requires budget_tokens < max_tokens; keep it valid after the clamp.
    thinking = body.get("thinking")
    budget = thinking.get("budget_tokens") if isinstance(thinking, dict) else None
    if isinstance(thinking, dict) and isinstance(budget, int) and not isinstance(budget, bool):
        if budget >= body["max_tokens"]:
            body["thinking"] = {**thinking, "budget_tokens": body["max_tokens"] - 1}


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


class _Relay(StreamingResponse):
    """SSE relay that owns the upstream response and the concurrency permit.

    Cleanup is in __call__, not in the body generator: a client that disconnects before the
    first chunk never starts the generator, so its finally would never run.
    """

    def __init__(self, upstream: httpx.Response, release: Callable[[], None]) -> None:
        self._upstream = upstream
        self._release = release
        # Decoded bytes: content-encoding is not relayed.
        super().__init__(upstream.aiter_bytes(), media_type="text/event-stream")

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                await self._upstream.aclose()
            finally:
                self._release()


async def _stream(
    client: httpx.AsyncClient,
    body: dict[str, Any],
    settings: GatewaySettings,
    beta: str | None,
    release: Callable[[], None],
) -> Response:
    """Return a _Relay that owns the permit, or an error response (the caller releases)."""
    url, headers = _upstream_request("anthropic", settings)
    if beta:
        headers["anthropic-beta"] = beta
    request = client.build_request(
        "POST", url, json=body, headers=headers, timeout=settings.upstream_timeout_seconds
    )
    try:
        response = await client.send(request, stream=True, follow_redirects=False)
    except httpx.TimeoutException:
        return _error(504, "upstream_timeout")
    except httpx.HTTPError:
        return _error(502, "upstream_unreachable")
    if response.status_code == 200:
        return _Relay(response, release)
    try:
        raw = await response.aread()
    finally:
        await response.aclose()
    try:
        data: Any = json.loads(raw)
    except ValueError:
        data = None
    status, payload = _upstream_error(response.status_code, data)
    return JSONResponse(payload, status_code=status)


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
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                semaphore.release()

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
                # Keys are caller-chosen: log only known names, and count the rest.
                known = sorted(key for key in body if key in _ALLOWED_FIELDS["anthropic"])
                logger.info(
                    "gateway fields provider=anthropic fields=%s unknown=%d",
                    ",".join(known),
                    len(body) - len(known),
                )
            problem = _normalize_body(
                provider, body, settings, count_only=url == ANTHROPIC_COUNT_URL
            )
            if problem is not None:
                return _error(400, problem)
            beta = request.headers.get("anthropic-beta")
            beta = beta if provider == "anthropic" and beta and _BETA.fullmatch(beta) else None
            started = time.perf_counter()
            if provider == "anthropic" and url is None and body.get("stream"):
                logger.info("gateway stream provider=anthropic caller=%s", caller)
                result = await _stream(client, body, settings, beta, release)
                handed_off = isinstance(result, _Relay)
                return result
            status, payload = await _forward(client, provider, body, settings, url=url, beta=beta)
        finally:
            if not handed_off:
                release()
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
