from __future__ import annotations

from typing import Any

import pytest
from mirage import Workspace

from agentcore_platform_poc.agent_platform.hub_client import HubError
from agentcore_platform_poc.bench_agent.mirage_resource import (
    MAX_READ_BYTES_OP,
    HubAccessor,
    MirageMethod,
    ResourceTooLarge,
    _read_bytes,
)
from agentcore_platform_poc.bench_fixtures import NEEDLE, text
from tests.test_bench_methods import EXPECTED, FakeHub


async def test_mirage_sdk_ops_all_go_through_mirage_and_the_hub() -> None:
    hub = FakeHub()
    method = MirageMethod(hub, fuse=False)  # type: ignore[arg-type]
    try:
        assert await method.list("bench/small") == [
            "bench/small/big.txt",
            "bench/small/f00.txt",
            "bench/small/f03.txt",
        ]
        assert await method.read("bench/small/f00.txt") == 10_000
        assert await method.search("bench/small", "bench/small/*", NEEDLE) == EXPECTED
        before = hub.requests_made
        await method.write("bench/small/w.txt", b"hello")
        assert hub.files["bench/small/w.txt"] == b"hello"
        assert await method.list("bench/small") == [
            "bench/small/big.txt",
            "bench/small/f00.txt",
            "bench/small/f03.txt",
            "bench/small/w.txt",
        ]
        assert hub.requests_made > before
    finally:
        await method.close()


async def test_read_bytes_refuses_huge_files() -> None:
    class HugeHub(FakeHub):
        async def stat(self, path: str) -> int:
            return MAX_READ_BYTES_OP + 1

    class P:
        virtual = "/ws/x"
        resource_path = "x"

    with pytest.raises(ResourceTooLarge):
        await _read_bytes(HubAccessor(HugeHub()), P())  # type: ignore[arg-type]


async def test_search_text_cannot_run_mirage_commands() -> None:
    hub = FakeHub()
    method = MirageMethod(hub, fuse=False)  # type: ignore[arg-type]
    try:
        text = "zzz; echo injected > /ws/bench/small/pwn.txt #"
        assert await method.search("bench/small", "bench/small/*", text) == []
        assert "bench/small/pwn.txt" not in hub.files
    finally:
        await method.close()


async def test_search_selects_files_by_the_hub_glob_before_scanning() -> None:
    hub = FakeHub()
    hub.files |= {
        "bench/small/sub/n.txt": text("n", 10_000, (3,)),  # outside the glob: never scanned
        "bench/small/a:b.txt": text("ab", 10_000, (7,)),  # ':' in a name must parse
    }
    method = MirageMethod(hub, fuse=False)  # type: ignore[arg-type]
    try:
        found = await method.search("bench/small", "bench/small/*", NEEDLE)
        assert found == sorted([*EXPECTED, ("bench/small/a:b.txt", 7)])
    finally:
        await method.close()


async def test_failed_write_is_an_error() -> None:
    class FailingHub(FakeHub):
        async def write(self, path: str, data: bytes) -> None:
            raise HubError(503, "unavailable")

    method = MirageMethod(FailingHub(), fuse=False)  # type: ignore[arg-type]
    try:
        with pytest.raises(RuntimeError, match="mirage exit"):
            await method.write("bench/small/w.txt", b"x")
    finally:
        await method.close()


async def test_sdk_read_refuses_files_mirage_would_buffer_whole() -> None:
    class HugeHub(FakeHub):
        async def stat(self, path: str) -> int:
            return MAX_READ_BYTES_OP + 1

    method = MirageMethod(HugeHub(), fuse=False)  # type: ignore[arg-type]
    try:
        with pytest.raises(ResourceTooLarge):
            await method.read("bench/small/f00.txt")
    finally:
        await method.close()


async def test_failed_fuse_mount_leaves_no_half_built_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_fuse(self: Any, prefix: str, mountpoint: str | None = None) -> str:
        raise OSError("no /dev/fuse")

    monkeypatch.setattr(Workspace, "add_fuse_mount", no_fuse)
    method = MirageMethod(FakeHub(), fuse=True, mountpoint="/nonexistent-mnt")  # type: ignore[arg-type]
    for _ in range(2):  # the second call must fail the same way, not list an empty folder
        with pytest.raises(OSError, match="fuse"):
            await method.list("bench/small")
    assert method._workspace is None
