# src/agentcore_platform_poc/resource_hub/store.py
"""S3 access for one user prefix at a time. Callers pass keys built by paths.object_key."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any

from agentcore_platform_poc.resource_hub.paths import glob_matches, relative, user_prefix

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

    def _expired(self) -> bool:  # call with the lock held
        if self.reason is None and self.clock() >= self.deadline:
            self.reason = "max_seconds"
        return self.reason is not None

    def stop(self) -> bool:
        with self.lock:
            return self._expired()

    def remaining(self) -> float:
        return max(self.deadline - self.clock(), 0.0)

    def expire(self) -> None:
        with self.lock:
            self.reason = self.reason or "max_seconds"

    def reserve(self, n: int) -> int:
        """Charge up to n bytes before they are read; 0 means stop reading."""
        with self.lock:
            if self._expired():
                return 0
            take = min(n, self.limits.max_bytes - self.bytes)
            if take <= 0:
                self.reason = "max_bytes"
                return 0
            self.bytes += take
            return take

    def refund(self, n: int) -> None:
        with self.lock:
            self.bytes -= n

    def add_match(self, match: Match) -> bool:
        with self.lock:
            if len(self.matches) >= self.limits.max_matches:
                self.reason = self.reason or "max_matches"
                return False
            self.matches.append(match)
            return True


def _pieces(
    read: Callable[[int], bytes], max_line_bytes: int, chunk: int
) -> Iterator[tuple[bytes, bool]]:
    """Yield (piece, ends_line) with bounded memory; an over-long line comes in several pieces."""
    carry = b""
    while True:
        part = read(chunk)
        if not part:
            break
        pieces = (carry + part).split(b"\n")
        carry = pieces.pop()
        for piece in pieces:
            yield piece, True
        while len(carry) > max_line_bytes:
            yield carry[:max_line_bytes], False
            carry = carry[max_line_bytes:]
    if carry:
        yield carry, True


def _lines(body: Any, max_line_bytes: int, chunk: int = 1024 * 1024) -> Iterator[bytes]:
    """Split a streaming body into lines with bounded memory; cut an over-long line into pieces."""
    for piece, _ in _pieces(body.read, max_line_bytes, chunk):
        yield piece


def _is_missing(error: Exception, s3: Any) -> bool:
    if isinstance(error, s3.exceptions.NoSuchKey):
        return True
    code = getattr(error, "response", {}).get("Error", {}).get("Code")
    return code in {"404", "NoSuchKey"}


class WorkspaceStore:
    def __init__(self, s3: Any, bucket: str, clock: Callable[[], float] = time.monotonic) -> None:
        self._s3 = s3
        self._bucket = bucket
        self._clock = clock

    def _pages(self, prefix: str) -> Iterator[list[dict[str, Any]]]:
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            yield page.get("Contents", [])

    def _keys(self, oid: str, path: str, limit: int | None = None) -> list[dict[str, Any]]:
        prefix = user_prefix(oid) + (f"{path}/" if path else "")
        out: list[dict[str, Any]] = []
        for contents in self._pages(prefix):
            out.extend(contents)
            if limit is not None and len(out) > limit:
                break  # stop paginating as soon as the cap is exceeded
        return out

    def _matching_keys(
        self, oid: str, glob: str | None, budget: _Budget
    ) -> tuple[list[dict[str, Any]], bool]:
        """Keys the glob selects, up to max_objects; True when more matched than that."""
        items: list[dict[str, Any]] = []
        for contents in self._pages(user_prefix(oid)):
            for item in contents:
                if glob is None or glob_matches(glob, relative(oid, item["Key"])):
                    items.append(item)
                    if len(items) > budget.limits.max_objects:
                        return items[: budget.limits.max_objects], True
            if budget.stop():
                break
        return items, False

    def list(self, oid: str, path: str) -> list[Entry]:
        return [
            Entry(relative(oid, item["Key"]), int(item["Size"]), str(item["LastModified"]))
            for item in self._keys(oid, path)
        ]

    def size(self, key: str) -> int:
        try:
            return int(self._s3.head_object(Bucket=self._bucket, Key=key)["ContentLength"])
        except Exception as error:
            if _is_missing(error, self._s3):
                raise NotFound(key) from error
            raise

    def read_range(self, key: str, start: int, end: int | None) -> tuple[bytes, int]:
        if start < 0 or (end is not None and end < start):
            raise ValueError("range not satisfiable")
        total = self.size(key)
        if total == 0 and start == 0:
            return b"", 0
        if start >= total:
            raise ValueError("range not satisfiable")
        last = total - 1 if end is None else min(end, total - 1)
        if last - start + 1 > MAX_CHUNK:
            raise TooLarge(f"range larger than {MAX_CHUNK} bytes")
        try:
            response = self._s3.get_object(
                Bucket=self._bucket, Key=key, Range=f"bytes={start}-{last}"
            )
        except Exception as error:
            if _is_missing(error, self._s3):
                raise NotFound(key) from error
            raise
        return response["Body"].read(), total

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
        # Bytes kept from the previous piece of a cut line, so a needle (or a UTF-8
        # character) split by the cut is still seen. Lowercasing can grow text, hence x4.
        overlap = 4 * len(text.encode("utf-8"))
        budget = _Budget(limits, self._clock)
        items, capped = self._matching_keys(oid, glob, budget)

        def scan(item: dict[str, Any]) -> None:
            if budget.stop():
                return
            try:
                body = self._s3.get_object(Bucket=self._bucket, Key=item["Key"])["Body"]
            except Exception as error:
                if _is_missing(error, self._s3):
                    return  # deleted after the listing
                raise
            path = relative(oid, item["Key"])

            def read(n: int) -> bytes:
                take = budget.reserve(n)
                data = bytes(body.read(take)) if take else b""
                budget.refund(take - len(data))
                return data

            line_no, tail, found = 1, b"", False
            try:
                for piece, ends_line in _pieces(read, limits.max_line_bytes, limits.max_line_bytes):
                    if budget.stop():
                        return
                    if not found:
                        line = (tail + piece).decode("utf-8", errors="replace")
                        haystack = line.lower() if ignore_case else line
                        if needle in haystack:
                            found = True
                            if not budget.add_match(
                                Match(path, line_no, line[: limits.max_line_chars])
                            ):
                                return
                    if ends_line:
                        line_no, tail, found = line_no + 1, b"", False
                    else:
                        tail = piece[-overlap:]
            finally:
                body.close()

        pool = ThreadPoolExecutor(max_workers=limits.concurrency)
        try:
            futures = [pool.submit(scan, item) for item in items]
            done, pending = wait(futures, timeout=budget.remaining())
            if pending:
                budget.expire()  # workers see the reason and stop at their next piece
            for future in done:
                future.result()
        finally:
            pool.shutdown(wait=False, cancel_futures=True)  # never join a stalled read
        with budget.lock:
            matches = sorted(budget.matches, key=lambda m: (m.path, m.line_no))
            reason = budget.reason or ("max_objects" if capped else None)
            return SearchResult(matches, reason, budget.bytes, len(items))
