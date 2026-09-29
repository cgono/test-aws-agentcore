"""The only code that calls the Resource Hub. Sends the service token plus a grant or raw token."""

from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from urllib.parse import quote

import httpx

MAX_CHUNK = 4 * 1024 * 1024
# Lambda answers 429 when the account or function concurrency is full; retry with backoff.
THROTTLE_ATTEMPTS = 6
THROTTLE_BASE_S = 0.5


class HubError(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class ResourceHubClient:
    def __init__(
        self,
        base_url: str,
        token: Callable[[], Awaitable[str]],
        *,
        grant: str | None = None,
        user_token: str | None = None,
        session_id: str | None = None,
        http: httpx.AsyncClient,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if (grant is None) == (user_token is None):
            raise ValueError("pass exactly one of grant or user_token")
        self._base = base_url.rstrip("/")
        self._token = token
        self._grant = grant
        self._user_token = user_token
        self._sid = session_id
        self._http = http
        self._sleep = sleep
        self.requests_made = 0
        self.throttled = 0
        self.bytes_received = 0

    async def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"authorization": f"Bearer {await self._token()}"}
        if self._grant is not None:
            headers["x-resource-grant"] = self._grant
        if self._user_token is not None:
            headers["x-user-token"] = self._user_token
        if self._sid:
            headers["x-session-id"] = self._sid
        return headers | (extra or {})

    async def _call(
        self, method: str, route: str, *, extra: dict[str, str] | None = None, **kwargs: Any
    ) -> httpx.Response:
        for attempt in range(THROTTLE_ATTEMPTS):
            response = await self._http.request(
                method, f"{self._base}{route}", headers=await self._headers(extra), **kwargs
            )
            self.requests_made += 1
            self.bytes_received += len(response.content)
            if response.status_code != 429:
                break
            self.throttled += 1
            if attempt + 1 < THROTTLE_ATTEMPTS:
                delay = THROTTLE_BASE_S * 2**attempt
                await self._sleep(delay * (1 + random.random()))  # noqa: S311
        if response.status_code >= 400:
            try:
                data = response.json()
            except ValueError:
                data = None
            code = str(data.get("error", "unknown")) if isinstance(data, dict) else "unknown"
            raise HubError(response.status_code, code)
        return response

    @staticmethod
    def _path(path: str) -> str:
        # httpx removes literal dot segments, which would move the request to another route.
        if any(part in {".", ".."} for part in path.split("/")):
            raise HubError(400, "invalid_path")
        return quote(path, safe="/")

    async def list(self, path: str = "") -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = (
            await self._call("GET", f"/v1/list/{self._path(path)}")
        ).json()["entries"]
        return entries

    async def stat(self, path: str) -> int:
        return int((await self._call("GET", f"/v1/stat/{self._path(path)}")).json()["size"])

    async def _range(self, path: str, start: int, end: int) -> bytes:
        return (
            await self._call(
                "GET", f"/v1/files/{self._path(path)}", extra={"range": f"bytes={start}-{end}"}
            )
        ).content

    async def iter_chunks(self, path: str, chunk: int = MAX_CHUNK) -> AsyncIterator[bytes]:
        size = await self.stat(path)
        for start in range(0, size, chunk):
            yield await self._range(path, start, min(start + chunk, size) - 1)

    async def read(self, path: str, offset: int = 0, length: int | None = None) -> bytes:
        if length is None:
            if offset == 0:
                return b"".join([part async for part in self.iter_chunks(path)])
            length = max(await self.stat(path) - offset, 0)
        parts = []
        for start in range(offset, offset + length, MAX_CHUNK):
            parts.append(
                await self._range(path, start, min(start + MAX_CHUNK, offset + length) - 1)
            )
        return b"".join(parts)

    async def write(self, path: str, data: bytes) -> None:
        await self._call("PUT", f"/v1/files/{self._path(path)}", content=data)

    async def search(
        self, text: str, glob: str | None = None, ignore_case: bool = False
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"text": text, "ignore_case": ignore_case}
        if glob is not None:
            body = {"text": text, "glob": glob, "ignore_case": ignore_case}
        result: dict[str, Any] = (await self._call("POST", "/v1/search", json=body)).json()
        return result
