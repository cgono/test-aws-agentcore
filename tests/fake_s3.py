# tests/fake_s3.py
"""In-memory S3 subset used by Resource Hub and fixture tests."""

from __future__ import annotations

import io
from typing import Any


class _Body:
    def __init__(self, data: bytes) -> None:
        self._io = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._io.read(n)

    def iter_lines(self, chunk_size: int = 1024, keepends: bool = False) -> Any:
        yield from self._io.read().splitlines(keepends)

    def close(self) -> None:
        pass


class NoSuchKey(Exception):
    pass


class FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.get_calls = 0

        class _Exceptions:
            pass

        self.exceptions = _Exceptions()
        self.exceptions.NoSuchKey = NoSuchKey  # type: ignore[attr-defined]

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **_: Any) -> dict[str, str]:  # noqa: N803
        self.objects[Key] = Body
        return {"VersionId": f"v{len(self.objects)}"}

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        if Key not in self.objects:
            raise NoSuchKey(Key)
        return {"ContentLength": len(self.objects[Key])}

    def get_object(self, *, Bucket: str, Key: str, Range: str | None = None) -> dict[str, Any]:  # noqa: N803
        self.get_calls += 1
        if Key not in self.objects:
            raise NoSuchKey(Key)
        data = self.objects[Key]
        if Range:
            start_s, end_s = Range.removeprefix("bytes=").split("-")
            start, end = int(start_s), int(end_s) if end_s else len(data) - 1
            data = data[start : end + 1]
        return {"Body": _Body(data), "ContentLength": len(data)}

    def get_paginator(self, name: str) -> Any:
        assert name == "list_objects_v2"
        store = self

        class _P:
            def paginate(self, *, Bucket: str, Prefix: str) -> Any:  # noqa: N803
                keys = sorted(k for k in store.objects if k.startswith(Prefix))
                for i in range(0, max(len(keys), 1), 2):
                    yield {
                        "Contents": [
                            {
                                "Key": k,
                                "Size": len(store.objects[k]),
                                "LastModified": "2026-09-27T00:00:00Z",
                            }
                            for k in keys[i : i + 2]
                        ]
                    }

        return _P()
