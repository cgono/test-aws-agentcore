from __future__ import annotations

import pytest

from agentcore_platform_poc.bench_agent.mirage_resource import (
    MAX_READ_BYTES_OP,
    HubAccessor,
    MirageMethod,
    ResourceTooLarge,
    _read_bytes,
)
from agentcore_platform_poc.bench_fixtures import NEEDLE
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
