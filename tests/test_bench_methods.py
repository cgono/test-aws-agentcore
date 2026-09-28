from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from agentcore_platform_poc.bench_agent.methods import (
    Case,
    DirectMethod,
    HubSearchMethod,
    MirrorMethod,
    digest,
)
from agentcore_platform_poc.bench_fixtures import NEEDLE, text

FILES = {
    "bench/small/f00.txt": text("f00", 10_000),
    "bench/small/f03.txt": text("f03", 10_000, (5,)),
    "bench/small/big.txt": text("big", 9_000_000, (1, 88_000)),
}


class FakeHub:
    def __init__(self) -> None:
        self.files = dict(FILES)
        self.requests_made = 0
        self.bytes_received = 0

    async def list(self, path: str = "") -> list[dict[str, Any]]:
        self.requests_made += 1
        return [
            {"path": p, "size": len(d), "modified": "t"}
            for p, d in sorted(self.files.items())
            if p.startswith(path + "/")
        ]

    async def stat(self, path: str) -> int:
        from agentcore_platform_poc.agent_platform.hub_client import HubError

        if path not in self.files:
            raise HubError(404, "not_found")
        return len(self.files[path])

    async def read(self, path: str, offset: int = 0, length: int | None = None) -> bytes:
        self.requests_made += 1
        data = self.files[path][offset:]
        return data if length is None else data[:length]

    async def iter_chunks(self, path: str, chunk: int = 4 * 1024 * 1024) -> Any:
        data = self.files[path]
        for start in range(0, len(data), chunk):
            self.requests_made += 1
            self.bytes_received += len(data[start : start + chunk])
            yield data[start : start + chunk]

    async def write(self, path: str, data: bytes) -> None:
        self.files[path] = data

    async def search(
        self, text: str, glob: str | None = None, ignore_case: bool = False
    ) -> dict[str, Any]:
        self.requests_made += 1
        return {
            "matches": [
                {"path": "bench/small/big.txt", "line_no": 1, "line": ""},
                {"path": "bench/small/big.txt", "line_no": 88000, "line": ""},
                {"path": "bench/small/f03.txt", "line_no": 5, "line": ""},
            ],
            "truncated": None,
        }


EXPECTED = [("bench/small/big.txt", 1), ("bench/small/big.txt", 88_000), ("bench/small/f03.txt", 5)]


def test_case_parse() -> None:
    assert (
        Case.parse(
            {
                "method": "direct",
                "op": "search",
                "target": "bench/small|bench/small/*",
                "text": NEEDLE,
            }
        ).op
        == "search"
    )
    for bad in (
        {"method": "x", "op": "list", "target": "t"},
        {"method": "direct", "op": "rm", "target": "t"},
        {"method": "direct", "op": "list", "target": "../x"},
    ):
        with pytest.raises(ValueError):
            Case.parse(bad)


async def test_direct_search_handles_chunk_boundaries() -> None:
    method = DirectMethod(FakeHub())  # type: ignore[arg-type]
    assert await method.search("bench/small", "bench/small/*", NEEDLE) == EXPECTED


async def test_hub_search_matches_direct() -> None:
    method = HubSearchMethod(FakeHub())  # type: ignore[arg-type]
    assert await method.search("bench/small", "bench/small/*", NEEDLE) == EXPECTED


async def test_direct_read_streams_and_counts() -> None:
    hub = FakeHub()
    method = DirectMethod(hub)  # type: ignore[arg-type]
    assert await method.read("bench/small/big.txt") == 9_000_000
    assert method.requests() == 3 and method.bytes() == 9_000_000


@pytest.mark.skipif(shutil.which("rg") is None, reason="needs ripgrep on PATH for the local test")
async def test_mirror_search_with_rg(tmp_path: Path) -> None:
    method = MirrorMethod(FakeHub(), root=tmp_path, rg=Path(shutil.which("rg") or "rg"))  # type: ignore[arg-type]
    assert await method.search("bench/small", "bench/small/*", NEEDLE) == EXPECTED
    assert (tmp_path / "bench/small/f03.txt").exists()


async def test_mirror_write_back(tmp_path: Path) -> None:
    hub = FakeHub()
    method = MirrorMethod(hub, root=tmp_path, rg=Path("rg"))  # type: ignore[arg-type]
    await method.write("bench/small/new.txt", b"x")
    assert (
        hub.files["bench/small/new.txt"] == b"x"
        and (tmp_path / "bench/small/new.txt").read_bytes() == b"x"
    )


def test_digest_is_order_independent() -> None:
    assert digest([("b", 1), ("a", 2)]) == digest([("a", 2), ("b", 1)])
