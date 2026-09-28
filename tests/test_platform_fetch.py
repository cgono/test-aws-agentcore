from __future__ import annotations

import httpx
import pytest

from agentcore_platform_poc.agent_platform.fetch import FetchRejected, fetch_url


def _http(response: httpx.Response) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response))


async def test_allowed_host() -> None:
    text = await fetch_url(
        "https://api.worldbank.org/v2/x?format=json", http=_http(httpx.Response(200, text="[1]"))
    )
    assert text == "[1]"


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://api.worldbank.org/v2/x", "https_only"),
        ("https://evil.example.test/", "host_not_allowed"),
        ("https://api.worldbank.org.evil.example.test/", "host_not_allowed"),
        ("https://user@api.example.test/", "host_not_allowed"),
    ],
)
async def test_rejected_urls(url: str, code: str) -> None:
    with pytest.raises(FetchRejected) as caught:
        await fetch_url(url, http=_http(httpx.Response(200)))
    assert caught.value.code == code


async def test_redirect_not_followed() -> None:
    response = httpx.Response(302, headers={"location": "https://evil.example.test/"})
    with pytest.raises(FetchRejected, match="redirect_not_followed"):
        await fetch_url("https://api.worldbank.org/v2/x", http=_http(response))


async def test_too_large() -> None:
    with pytest.raises(FetchRejected, match="too_large"):
        await fetch_url(
            "https://api.worldbank.org/v2/x",
            http=_http(httpx.Response(200, content=b"x" * 2_000_001)),
        )
