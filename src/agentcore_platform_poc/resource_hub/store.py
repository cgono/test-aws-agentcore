# src/agentcore_platform_poc/resource_hub/store.py
"""S3 access for one user prefix at a time. Callers pass keys built by paths.object_key."""

from __future__ import annotations

import fnmatch
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from agentcore_platform_poc.resource_hub.paths import relative, user_prefix

MAX_CHUNK = 4 * 1024 * 1024
MAX_UPLOAD = 4 * 1024 * 1024


class NotFound(Exception):
    pass


class TooLarge(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    path: str
    size: int
    modified: str


@dataclass(frozen=True)
class SearchLimits:
    max_bytes: int = 6 * 1024**3
    max_objects: int = 2000
    concurrency: int = 16
    max_seconds: float = 300.0
    max_matches: int = 200
    max_line_chars: int = 500
    max_line_bytes: int = 1024 * 1024


DEFAULT_LIMITS = SearchLimits()


@dataclass(frozen=True)
class Match:
    path: str
    line_no: int
    line: str


@dataclass(frozen=True)
class SearchResult:
    matches: list[Match]
    truncated: str | None
    bytes_scanned: int
    objects_scanned: int


class _Budget:
    def __init__(self, limits: SearchLimits, clock: Callable[[], float]) -> None:
        self.limits = limits
        self.clock = clock
        self.deadline = clock() + limits.max_seconds
        self.bytes = 0
        self.matches: list[Match] = []
        self.reason: str | None = None
        self.lock = threading.Lock()

    def stop(self) -> bool:
        with self.lock:
            if self.reason is None and self.clock() >= self.deadline:
                self.reason = "max_seconds"
            return self.reason is not None

    def add_bytes(self, n: int) -> bool:
        with self.lock:
            self.bytes += n
            if self.bytes > self.limits.max_bytes and self.reason is None:
                self.reason = "max_bytes"
            return self.reason is None

    def add_match(self, match: Match) -> bool:
        with self.lock:
            if len(self.matches) >= self.limits.max_matches:
                self.reason = self.reason or "max_matches"
                return False
            self.matches.append(match)
            return True


def _lines(body: Any, max_line_bytes: int, chunk: int = 1024 * 1024) -> Iterator[bytes]:
    """Split a streaming body into lines with bounded memory; cut an over-long line into pieces."""
    carry = b""
    while True:
        part = body.read(chunk)
        if not part:
            break
        pieces = (carry + part).split(b"\n")
        carry = pieces.pop()
        yield from pieces
        while len(carry) > max_line_bytes:
            yield carry[:max_line_bytes]
            carry = carry[max_line_bytes:]
    if carry:
        yield carry


class WorkspaceStore:
    def __init__(self, s3: Any, bucket: str, clock: Callable[[], float] = time.monotonic) -> None:
        self._s3 = s3
        self._bucket = bucket
        self._clock = clock

    def _keys(self, oid: str, path: str, limit: int | None = None) -> list[dict[str, Any]]:
        prefix = user_prefix(oid) + (f"{path}/" if path else "")
        out: list[dict[str, Any]] = []
        for page in self._s3.get_paginator("list_objects_v2").paginate(
            Bucket=self._bucket, Prefix=prefix
        ):
            out.extend(page.get("Contents", []))
            if limit is not None and len(out) > limit:
                break  # stop paginating as soon as the cap is exceeded
        return out

    def list(self, oid: str, path: str) -> list[Entry]:
        return [
            Entry(relative(oid, item["Key"]), int(item["Size"]), str(item["LastModified"]))
            for item in self._keys(oid, path)
        ]

    def size(self, key: str) -> int:
        try:
            return int(self._s3.head_object(Bucket=self._bucket, Key=key)["ContentLength"])
        except self._s3.exceptions.NoSuchKey as error:
            raise NotFound(key) from error
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") in {"404", "NoSuchKey"}:
                raise NotFound(key) from error
            raise

    def read_range(self, key: str, start: int, end: int | None) -> tuple[bytes, int]:
        total = self.size(key)
        last = total - 1 if end is None else min(end, total - 1)
        if start < 0 or start > max(last, 0) and total > 0:
            raise ValueError("range not satisfiable")
        if last - start + 1 > MAX_CHUNK:
            raise TooLarge(f"range larger than {MAX_CHUNK} bytes")
        if total == 0:
            return b"", 0
        body = self._s3.get_object(Bucket=self._bucket, Key=key, Range=f"bytes={start}-{last}")[
            "Body"
        ]
        return body.read(), total

    def put(self, key: str, data: bytes) -> None:
        if len(data) > MAX_UPLOAD:
            raise TooLarge(f"upload larger than {MAX_UPLOAD} bytes")
        self._s3.put_object(Bucket=self._bucket, Key=key, Body=data)

    def search(
        self,
        oid: str,
        text: str,
        *,
        glob: str | None,
        ignore_case: bool,
        limits: SearchLimits = DEFAULT_LIMITS,
    ) -> SearchResult:
        if not text:
            raise ValueError("search text must not be empty")
        needle = text.lower() if ignore_case else text
        budget = _Budget(limits, self._clock)
        # Cap the listing itself; the glob then filters what was listed.
        listed = self._keys(oid, "", limit=limits.max_objects * 4)
        items = [
            i for i in listed if glob is None or fnmatch.fnmatchcase(relative(oid, i["Key"]), glob)
        ]
        capped = len(items) > limits.max_objects
        items = items[: limits.max_objects]

        def scan(item: dict[str, Any]) -> None:
            if budget.stop():
                return
            body = self._s3.get_object(Bucket=self._bucket, Key=item["Key"])["Body"]
            path = relative(oid, item["Key"])
            try:
                for number, raw in enumerate(_lines(body, limits.max_line_bytes), start=1):
                    if not budget.add_bytes(len(raw) + 1) or budget.stop():
                        return
                    line = raw.decode("utf-8", errors="replace")
                    haystack = line.lower() if ignore_case else line
                    if needle in haystack and not budget.add_match(
                        Match(path, number, line[: limits.max_line_chars])
                    ):
                        return
            finally:
                body.close()

        with ThreadPoolExecutor(max_workers=limits.concurrency) as pool:
            list(pool.map(scan, items))
        matches = sorted(budget.matches, key=lambda m: (m.path, m.line_no))
        reason = budget.reason or ("max_objects" if capped else None)
        return SearchResult(matches, reason, budget.bytes, len(items))
