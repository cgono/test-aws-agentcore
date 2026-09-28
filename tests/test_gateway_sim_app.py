from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from typing import Any

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


def test_anthropic_custom_tools_and_clamped_max_tokens() -> None:
    client, seen = _client(_ok)
    tool = {
        "name": "mcp__platform__ws_read",
        "description": "d",
        "input_schema": {"type": "object"},
    }
    response = client.post(
        "/anthropic/v1/messages",
        json={
            "model": "model-a",
            "max_tokens": 32000,
            "messages": [],
            "tools": [tool],
            "tool_choice": {"type": "auto"},
            "metadata": {"user_id": "u"},
        },
        headers={
            **GOOD,
            "anthropic-beta": "claude-code-20250219,fine-grained-tool-streaming-2025-05-14",
        },
    )
    assert response.status_code == 200
    sent = json.loads(seen[0].content)
    assert sent["max_tokens"] == 64 and sent["tools"] == [tool]
    assert (
        seen[0].headers["anthropic-beta"]
        == "claude-code-20250219,fine-grained-tool-streaming-2025-05-14"
    )


def test_bad_beta_header_is_dropped() -> None:
    client, seen = _client(_ok)
    client.post(
        "/anthropic/v1/messages",
        json={"model": "model-a", "messages": []},
        headers={**GOOD, "anthropic-beta": "x\r\ninjected: 1"},
    )
    assert "anthropic-beta" not in seen[0].headers


def test_anthropic_stream_passes_sse_through() -> None:
    sse = b"event: message_start\ndata: {}\n\nevent: message_stop\ndata: {}\n\n"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=sse, headers={"content-type": "text/event-stream"})

    client, seen = _client(handler)
    response = client.post(
        "/anthropic/v1/messages",
        json={"model": "model-a", "stream": True, "messages": []},
        headers=GOOD,
    )
    assert response.status_code == 200 and response.content == sse
    assert response.headers["content-type"].startswith("text/event-stream")
    assert json.loads(seen[0].content)["stream"] is True


def test_anthropic_stream_upstream_error_is_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"type": "rate_limit_error"}})

    client, _ = _client(handler)
    response = client.post(
        "/anthropic/v1/messages",
        json={"model": "model-a", "stream": True, "messages": []},
        headers=GOOD,
    )
    assert response.status_code == 429 and response.json() == {
        "error": {"upstream_status": 429, "type": "rate_limit_error"}
    }


def test_stream_model_allow_list_still_enforced() -> None:
    client, seen = _client(_ok)
    response = client.post(
        "/anthropic/v1/messages",
        json={"model": "model-x", "stream": True, "messages": []},
        headers=GOOD,
    )
    assert response.status_code == 400 and not seen


def test_count_tokens_route() -> None:
    client, seen = _client(_ok)
    response = client.post(
        "/anthropic/v1/messages/count_tokens",
        json={"model": "model-a", "messages": []},
        headers=GOOD,
    )
    assert response.status_code == 200 and str(seen[0].url).endswith("/v1/messages/count_tokens")


def test_field_names_are_logged_without_values(caplog: pytest.LogCaptureFixture) -> None:
    client, _ = _client(_ok)
    with caplog.at_level("INFO"):
        client.post(
            "/anthropic/v1/messages",
            json={"model": "model-a", "messages": [{"role": "user", "content": "SECRET PROMPT"}]},
            headers=GOOD,
        )
    assert "fields=messages,model" in caplog.text and "SECRET PROMPT" not in caplog.text


def test_stream_on_count_tokens_is_rejected() -> None:
    client, seen = _client(_ok)
    response = client.post(
        "/anthropic/v1/messages/count_tokens",
        json={"model": "model-a", "stream": True, "max_tokens": 32768, "messages": []},
        headers=GOOD,
    )
    assert response.status_code == 400 and response.json() == {"error": "streaming_not_supported"}
    assert seen == []


def _sse(request: httpx.Request) -> httpx.Response:
    if not json.loads(request.content).get("stream"):
        return _ok(request)
    return httpx.Response(
        200, content=b"event: ping\ndata: {}\n\n", headers={"content-type": "text/event-stream"}
    )


async def _asgi_post(app: Any, path: str, body: dict[str, Any], *, disconnect: bool) -> int:
    raw = json.dumps(body).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"authorization", b"Bearer good"), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
    }
    messages = [{"type": "http.request", "body": raw, "more_body": False}]
    statuses: list[int] = []

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        if not disconnect:
            await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            statuses.append(message["status"])
            if disconnect:
                raise OSError("client went away")

    try:
        await app(scope, receive, send)
    except OSError:
        pass
    return statuses[0] if statuses else 0


async def test_stream_permit_is_released_when_the_client_disconnects() -> None:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(_sse))
    app = create_app(_settings(max_concurrency=1), authorizer=FakeAuthorizer(), upstream=upstream)
    body = {"model": "model-a", "stream": True, "messages": []}
    await _asgi_post(app, "/anthropic/v1/messages", body, disconnect=True)
    status = await _asgi_post(
        app, "/anthropic/v1/messages", {**body, "stream": False}, disconnect=False
    )
    assert status == 200


def test_stream_permit_is_released_on_unexpected_upstream_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content).get("stream"):
            raise RuntimeError("unexpected")
        return _ok(request)

    client, _ = _client(boom, max_concurrency=1)
    with pytest.raises(RuntimeError):
        client.post(
            "/anthropic/v1/messages",
            json={"model": "model-a", "stream": True, "messages": []},
            headers=GOOD,
        )
    response = client.post(
        "/anthropic/v1/messages", json={"model": "model-a", "messages": []}, headers=GOOD
    )
    assert response.status_code == 200


def test_unknown_field_names_are_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    client, _ = _client(_ok)
    with caplog.at_level("INFO"):
        response = client.post(
            "/anthropic/v1/messages",
            json={"model": "model-a", "messages": [], "SECRET_TOKEN=abc\nFAKE LINE": 1},
            headers=GOOD,
        )
    assert response.status_code == 400
    assert "SECRET_TOKEN" not in caplog.text and "unknown=1" in caplog.text


def test_thinking_budget_follows_clamped_max_tokens() -> None:
    client, seen = _client(_ok)
    client.post(
        "/anthropic/v1/messages",
        json={
            "model": "model-a",
            "max_tokens": 32000,
            "thinking": {"type": "enabled", "budget_tokens": 10000},
            "messages": [],
        },
        headers=GOOD,
    )
    sent = json.loads(seen[0].content)
    assert sent["max_tokens"] == 64 and sent["thinking"] == {"type": "enabled", "budget_tokens": 63}
