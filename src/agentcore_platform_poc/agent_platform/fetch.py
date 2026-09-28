"""HTTPS GET to allow-listed hosts only. No redirects, bounded size."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

ALLOWED_HOSTS = frozenset({"api.worldbank.org"})
MAX_FETCH_BYTES = 2_000_000


class FetchRejected(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


async def fetch_url(url: str, *, http: httpx.AsyncClient) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchRejected("https_only")
    if (
        parts.username
        or parts.password
        or parts.hostname not in ALLOWED_HOSTS
        or parts.port not in (None, 443)
    ):
        raise FetchRejected("host_not_allowed")
    # Ask for identity encoding: a compressed body could expand far past the cap in one chunk.
    headers = {"accept-encoding": "identity"}
    async with http.stream(
        "GET", url, headers=headers, follow_redirects=False, timeout=30.0
    ) as response:
        if 300 <= response.status_code < 400:
            raise FetchRejected("redirect_not_followed")
        if response.status_code >= 400:
            raise FetchRejected(f"http_{response.status_code}")
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise FetchRejected("encoded_response")
        body = bytearray()
        async for chunk in response.aiter_bytes():  # identity only, so no decoding
            body.extend(chunk)
            if len(body) > MAX_FETCH_BYTES:
                raise FetchRejected("too_large")  # stop reading as soon as the cap is passed
        return body.decode(response.encoding or "utf-8", errors="replace")
