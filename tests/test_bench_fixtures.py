from __future__ import annotations

from typing import Any

import pytest

from agentcore_platform_poc.bench_fixtures import (
    BLOCK_BYTES,
    HEAD_PART_BYTES,
    NEEDLE,
    expected_matches,
    huge_parts,
    large_workspace,
    manifest,
    small_workspace,
    text,
)


def test_text_is_deterministic_line_aligned_and_places_needles() -> None:
    data = text("f03", 10_000, (5,))
    assert data == text("f03", 10_000, (5,)) and len(data) == 10_000
    lines = data.split(b"\n")[:-1]
    assert len(lines) == 100 and all(len(line) == 99 for line in lines)
    assert (
        lines[4].startswith(NEEDLE.encode()) and sum(NEEDLE.encode() in line for line in lines) == 1
    )


def test_text_without_needles_has_none() -> None:
    assert NEEDLE.encode() not in text("x", 1_000_000)


def test_workspaces() -> None:
    small = small_workspace()
    assert len(small) == 20 and {f.size for f in small} == {10_000}
    assert expected_matches(small) == [("bench/small/f03.txt", 5), ("bench/small/f11.txt", 42)]
    large = large_workspace()
    assert len([f for f in large if f.path.startswith("bench/large/small/")]) == 950
    assert (
        len([f for f in large if f.path.startswith("bench/large/small/") and f.needle_lines]) == 38
    )
    sizes = sorted(f.size for f in large if f.path.startswith("bench/large/huge/"))
    assert sizes == [50_000_000] * 3 + [200_000_000] * 2 + [1_000_000_000, 5_000_000_000]


def test_huge_parts_sum_and_alignment() -> None:
    for size in (50_000_000, 200_000_000, 1_000_000_000, 5_000_000_000):
        parts = huge_parts(size)
        assert parts[0] == ("head", HEAD_PART_BYTES) and HEAD_PART_BYTES >= 5 * 1024 * 1024
        assert all(
            n >= 5 * 1024 * 1024 for _, n in parts[:-1]
        )  # S3 minimum for every non-final part
        assert sum(n for _, n in parts) == size
        assert all(n % 100 == 0 and n <= BLOCK_BYTES for _, n in parts[1:])
        assert len(parts) <= 10_000


def test_failed_huge_upload_is_aborted(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import seed_bench_fixtures

    monkeypatch.setattr(seed_bench_fixtures, "text", lambda seed, size, needles=(): b"x")
    calls: list[str] = []

    class FailingS3:
        def create_multipart_upload(self, **kwargs: Any) -> dict[str, str]:
            return {"UploadId": "u1"}

        def upload_part(self, **kwargs: Any) -> dict[str, str]:
            return {"ETag": "e1"}

        def upload_part_copy(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("copy failed")

        def abort_multipart_upload(self, **kwargs: Any) -> None:
            calls.append(kwargs["UploadId"])

    with pytest.raises(RuntimeError, match="copy failed"):
        seed_bench_fixtures._huge(FailingS3(), "b", "k", "seed", 50_000_000, (10,))
    assert calls == ["u1"]


def test_manifest_digest_is_stable() -> None:
    assert (
        manifest(small_workspace())["digest"]
        == manifest(list(reversed(small_workspace())))["digest"]
    )
