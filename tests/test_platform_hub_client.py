from __future__ import annotations

import json

import httpx
import pytest

from agentcore_platform_poc.agent_platform.hub_client import HubError, ResourceHubClient

BASE = "https://hub.example.test"


async def _token() -> str:
    return "svc"


def _client(handler: httpx.MockTransport, **kwargs: object) -> ResourceHubClient:
    http = httpx.AsyncClient(transport=handler)
    return ResourceHubClient(BASE, _token, http=http, **kwargs)  # type: ignore[arg-type]


def test_exactly_one_credential_mode() -> None:
    http = httpx.AsyncClient()
    with pytest.raises(ValueError):
        ResourceHubClient(BASE, _token, http=http)
    with pytest.raises(ValueError):
        ResourceHubClient(BASE, _token, http=http, grant="g", user_token="u")


async def test_grant_mode_headers_and_path_encoding() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"data")

    client = _client(httpx.MockTransport(handle), grant="G", session_id="s1")
    assert await client.read("a b/c.txt", 0, 4) == b"data"
    request = seen[0]
    assert request.url.raw_path == b"/v1/files/a%20b/c.txt"
    assert request.headers["authorization"] == "Bearer svc"
    assert request.headers["x-resource-grant"] == "G" and request.headers["x-session-id"] == "s1"
    assert request.headers["range"] == "bytes=0-3"
    assert "x-user-token" not in request.headers
    assert client.requests_made == 1 and client.bytes_received == 4


async def test_raw_mode_header() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-user-token"] == "U" and "x-resource-grant" not in request.headers
        return httpx.Response(200, json={"entries": []})

    assert await _client(httpx.MockTransport(handle), user_token="U").list() == []


async def test_whole_file_read_uses_4mib_ranges() -> None:
    size = 4 * 1024 * 1024 + 3
    ranges: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/v1/stat/"):
            return httpx.Response(200, json={"path": "big", "size": size})
        ranges.append(request.headers["range"])
        start, end = (int(x) for x in request.headers["range"].removeprefix("bytes=").split("-"))
        return httpx.Response(206, content=b"z" * (end - start + 1))

    data = await _client(httpx.MockTransport(handle), grant="G").read("big")
    assert len(data) == size
    assert ranges == ["bytes=0-4194303", "bytes=4194304-4194306"]


async def test_errors_become_hub_error() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "token_expired"})

    with pytest.raises(HubError) as caught:
        await _client(httpx.MockTransport(handle), grant="G").list()
    assert (caught.value.status, caught.value.code) == (401, "token_expired")


async def test_search_and_write() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            assert request.content == b"hi"
            return httpx.Response(200, json={"path": "x", "size": 2})
        assert json.loads(request.content) == {"text": "N", "glob": "*.md", "ignore_case": True}
        return httpx.Response(200, json={"matches": [], "truncated": None})

    client = _client(httpx.MockTransport(handle), grant="G")
    await client.write("x", b"hi")
    assert (await client.search("N", "*.md", True))["matches"] == []
