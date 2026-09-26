from __future__ import annotations

import json
from collections.abc import Callable, Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from agentcore_runtime_poc.gateway_sim.app import (
    ANTHROPIC_URL,
    ANTHROPIC_VERSION,
    OPENAI_URL,
    create_app,
)
from agentcore_runtime_poc.gateway_sim.auth import CallerRejected
from agentcore_runtime_poc.gateway_sim.settings import GatewaySettings

OPENAI_KEY = "test-openai-key"
ANTHROPIC_KEY = "test-anthropic-key"
GOOD = {"Authorization": "Bearer good"}


class FakeAuthorizer:
    def authorize(self, header: str | None) -> str:
        if header != "Bearer good":
            raise CallerRejected("bad")
        return "caller-a"


def _settings(**overrides: object) -> GatewaySettings:
    values: dict[str, object] = {
        "tenant_id": "example-tenant",
        "gateway_app_client_id": "gateway-app-id",
        "allowed_caller_ids": frozenset({"caller-a"}),
        "openai_models": frozenset({"model-o"}),
        "anthropic_models": frozenset({"model-a"}),
        "openai_api_key": OPENAI_KEY,
        "anthropic_api_key": ANTHROPIC_KEY,
        "max_output_tokens": 64,
        "max_body_bytes": 2048,
    }
    values.update(overrides)
    return GatewaySettings(**values)  # type: ignore[arg-type]


Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler, **overrides: object) -> tuple[TestClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(record))
    app = create_app(_settings(**overrides), authorizer=FakeAuthorizer(), upstream=upstream)
    return TestClient(app), seen


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"id": "x", "ok": True}, headers={"x-upstream-detail": "hide"})


def test_healthz_needs_no_auth() -> None:
    client, _ = _client(_ok)

    assert client.get("/healthz").json() == {"status": "ok"}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer bad"}])
def test_unauthorized_requests_never_reach_upstream(headers: dict[str, str]) -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/openai/v1/chat/completions", json={"model": "model-o"}, headers=headers
    )

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert seen == []


def test_openai_forward_uses_fixed_url_server_key_and_default_token_cap() -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/openai/v1/chat/completions",
        json={"model": "model-o", "messages": [{"role": "user", "content": "hi"}]},
        headers=GOOD,
    )

    assert response.status_code == 200
    assert response.json() == {"id": "x", "ok": True}
    assert "x-upstream-detail" not in response.headers
    [request] = seen
    assert str(request.url) == OPENAI_URL
    assert request.headers["authorization"] == "Bearer " + OPENAI_KEY
    assert json.loads(request.content)["max_completion_tokens"] == 64


def test_anthropic_forward_uses_fixed_url_and_provider_headers() -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/anthropic/v1/messages",
        json={"model": "model-a", "max_tokens": 32, "messages": []},
        headers=GOOD,
    )

    assert response.status_code == 200
    [request] = seen
    assert str(request.url) == ANTHROPIC_URL
    assert request.headers["x-api-key"] == ANTHROPIC_KEY
    assert request.headers["anthropic-version"] == ANTHROPIC_VERSION
    assert "authorization" not in request.headers
    assert json.loads(request.content)["max_tokens"] == 32


@pytest.mark.parametrize(
    ("path", "body", "error"),
    [
        ("/openai/v1/chat/completions", {"model": "model-x"}, "model_not_allowed"),
        (
            "/openai/v1/chat/completions",
            {"model": "model-o", "stream": True},
            "streaming_not_supported",
        ),
        (
            "/openai/v1/chat/completions",
            {"model": "model-o", "max_tokens": 10},
            "use_max_completion_tokens",
        ),
        (
            "/openai/v1/chat/completions",
            {"model": "model-o", "max_completion_tokens": 65},
            "max_tokens_out_of_range",
        ),
        (
            "/anthropic/v1/messages",
            {"model": "model-a", "max_tokens": 0},
            "max_tokens_out_of_range",
        ),
        (
            "/anthropic/v1/messages",
            {"model": "model-a", "max_tokens": True},
            "max_tokens_out_of_range",
        ),
        ("/anthropic/v1/messages", ["not", "an", "object"], "invalid_json"),
        ("/openai/v1/chat/completions", {"model": "model-o", "n": 3}, "n_must_be_1"),
        ("/openai/v1/chat/completions", {"model": ["model-o"]}, "model_not_allowed"),
        (
            "/anthropic/v1/messages",
            {"model": "model-a", "tools": [{"type": "web_search_20250305", "name": "web_search"}]},
            "field_not_allowed",
        ),
        (
            "/openai/v1/chat/completions",
            {"model": "model-o", "web_search_options": {}},
            "field_not_allowed",
        ),
    ],
)
def test_request_limits(path: str, body: object, error: str) -> None:
    client, seen = _client(_ok)

    response = client.post(path, json=body, headers=GOOD)

    assert response.status_code == 400
    assert response.json() == {"error": error}
    assert seen == []


def test_oversized_body_is_rejected() -> None:
    client, seen = _client(_ok)

    response = client.post(
        "/openai/v1/chat/completions",
        content=b"{" + b" " * 4096 + b"}",
        headers={**GOOD, "content-type": "application/json"},
    )

    assert response.status_code == 413
    assert seen == []


def test_upstream_error_relays_only_status_and_type() -> None:
    def leaky(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"type": "authentication_error", "message": "bad key " + OPENAI_KEY}},
        )

    client, _ = _client(leaky)

    response = client.post("/openai/v1/chat/completions", json={"model": "model-o"}, headers=GOOD)

    assert response.status_code == 401
    assert response.json() == {"error": {"upstream_status": 401, "type": "authentication_error"}}
    assert OPENAI_KEY not in response.text


def test_upstream_error_type_outside_the_safe_shape_is_not_relayed() -> None:
    def leaky(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"type": "bad key " + OPENAI_KEY}})

    client, _ = _client(leaky)

    response = client.post("/openai/v1/chat/completions", json={"model": "model-o"}, headers=GOOD)

    assert response.json() == {"error": {"upstream_status": 400, "type": "unknown"}}
    assert OPENAI_KEY not in response.text


def test_upstream_redirect_is_not_followed() -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://elsewhere.example.test/"})

    client, seen = _client(redirect)

    response = client.post("/openai/v1/chat/completions", json={"model": "model-o"}, headers=GOOD)

    assert response.status_code == 502
    assert response.json() == {"error": "upstream_redirect"}
    assert len(seen) == 1


def test_upstream_timeout_maps_to_504() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client, _ = _client(slow)

    response = client.post("/anthropic/v1/messages", json={"model": "model-a"}, headers=GOOD)

    assert response.status_code == 504
    assert response.json() == {"error": "upstream_timeout"}


def test_saturated_gateway_returns_429() -> None:
    client, seen = _client(_ok, max_concurrency=0)

    response = client.post("/openai/v1/chat/completions", json={"model": "model-o"}, headers=GOOD)

    assert response.status_code == 429
    assert seen == []


def test_oversized_body_without_content_length_is_rejected_while_streaming() -> None:
    client, seen = _client(_ok)

    def chunks() -> Iterator[bytes]:
        for _ in range(8):
            yield b" " * 512

    response = client.post("/openai/v1/chat/completions", content=chunks(), headers=GOOD)

    assert response.status_code == 413
    assert seen == []
