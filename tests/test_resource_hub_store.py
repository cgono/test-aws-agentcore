# tests/test_resource_hub_store.py
from __future__ import annotations

import pytest

from agentcore_platform_poc.resource_hub.store import (
    MAX_CHUNK,
    NotFound,
    SearchLimits,
    TooLarge,
    WorkspaceStore,
)
from tests.fake_s3 import FakeS3

A = "00000000-0000-0000-0000-00000000000a"
B = "00000000-0000-0000-0000-00000000000b"


def _store() -> tuple[WorkspaceStore, FakeS3]:
    s3 = FakeS3()
    s3.objects.update(
        {
            f"users/{A}/brief.md": b"find NEEDLE here\nno\nneedle lower\n",
            f"users/{A}/docs/a.txt": b"x\nNEEDLE\n",
            f"users/{A}/docs/b.bin": b"\xff\xfeNEEDLE\n",
            f"users/{B}/secret.md": b"NEEDLE of B\n",
        }
    )
    return WorkspaceStore(s3, "bucket"), s3


def test_list_is_relative_and_scoped() -> None:
    store, _ = _store()
    assert [e.path for e in store.list(A, "")] == ["brief.md", "docs/a.txt", "docs/b.bin"]
    assert [e.path for e in store.list(A, "docs")] == ["docs/a.txt", "docs/b.bin"]


def test_list_does_not_match_sibling_prefix() -> None:
    store, s3 = _store()
    s3.objects[f"users/{A}/docsX/c.txt"] = b"c"
    assert [e.path for e in store.list(A, "docs")] == ["docs/a.txt", "docs/b.bin"]


def test_read_range_and_size() -> None:
    store, _ = _store()
    data, total = store.read_range(f"users/{A}/brief.md", 5, 10)
    assert data == b"NEEDLE" and total == 33


def test_read_range_open_end_and_too_large() -> None:
    store, s3 = _store()
    s3.objects["big"] = b"a" * (MAX_CHUNK + 10)
    with pytest.raises(TooLarge):
        store.read_range("big", 0, None)
    assert store.read_range("big", MAX_CHUNK, None)[0] == b"a" * 10


def test_missing_is_not_found() -> None:
    store, _ = _store()
    with pytest.raises(NotFound):
        store.read_range(f"users/{A}/nope", 0, 1)


def test_put_limit() -> None:
    store, s3 = _store()
    store.put("k", b"x")
    assert s3.objects["k"] == b"x"
    with pytest.raises(TooLarge):
        store.put("k", b"x" * (4 * 1024 * 1024 + 1))


def test_search_fixed_string_scoped_sorted() -> None:
    store, _ = _store()
    result = store.search(A, "NEEDLE", glob=None, ignore_case=False)
    assert [(m.path, m.line_no) for m in result.matches] == [
        ("brief.md", 1),
        ("docs/a.txt", 2),
        ("docs/b.bin", 1),
    ]
    assert result.truncated is None and result.objects_scanned == 3


def test_search_is_literal_not_regex() -> None:
    store, s3 = _store()
    s3.objects[f"users/{A}/r.txt"] = b"a.c\nabc\n"
    result = store.search(A, "a.c", glob="r.txt", ignore_case=False)
    assert [m.line_no for m in result.matches] == [1]


def test_search_ignore_case_and_glob() -> None:
    store, _ = _store()
    result = store.search(A, "needle", glob="*.md", ignore_case=True)
    assert [(m.path, m.line_no) for m in result.matches] == [("brief.md", 1), ("brief.md", 3)]


@pytest.mark.parametrize(
    ("limits", "reason"),
    [
        (SearchLimits(max_objects=1), "max_objects"),
        (SearchLimits(max_bytes=10), "max_bytes"),
        (SearchLimits(max_matches=1), "max_matches"),
    ],
)
def test_search_limits_truncate(limits: SearchLimits, reason: str) -> None:
    store, _ = _store()
    assert (
        store.search(A, "NEEDLE", glob=None, ignore_case=False, limits=limits).truncated == reason
    )


def test_search_time_limit() -> None:
    s3 = FakeS3()
    s3.objects.update({f"users/{A}/{i}.txt": b"NEEDLE\n" for i in range(5)})
    ticks = iter([0.0] + [1000.0] * 100)
    store = WorkspaceStore(s3, "bucket", clock=lambda: next(ticks))
    assert (
        store.search(
            A,
            "NEEDLE",
            glob=None,
            ignore_case=False,
            limits=SearchLimits(max_seconds=1, concurrency=1),
        ).truncated
        == "max_seconds"
    )


def test_long_lines_are_cut() -> None:
    store, s3 = _store()
    s3.objects[f"users/{A}/long.txt"] = b"NEEDLE" + b"x" * 5000 + b"\n"
    match = store.search(A, "NEEDLE", glob="long.txt", ignore_case=False).matches[0]
    assert len(match.line) == 500


def test_listing_stops_at_cap() -> None:
    s3 = FakeS3()
    s3.objects.update({f"users/{A}/{i:04d}.txt": b"NEEDLE\n" for i in range(50)})
    store = WorkspaceStore(s3, "bucket")
    result = store.search(
        A, "NEEDLE", glob=None, ignore_case=False, limits=SearchLimits(max_objects=3)
    )
    assert result.truncated == "max_objects" and result.objects_scanned == 3
    assert len(store._keys(A, "", limit=12)) <= 14  # stopped paginating (fake pages hold 2 keys)


def test_line_without_newline_is_bounded() -> None:
    from agentcore_platform_poc.resource_hub.store import _lines
    from tests.fake_s3 import _Body

    pieces = list(_lines(_Body(b"x" * 5000 + b"NEEDLE"), max_line_bytes=1000, chunk=700))
    assert all(len(p) <= 1000 for p in pieces) and b"".join(pieces) == b"x" * 5000 + b"NEEDLE"


def test_empty_search_text_rejected() -> None:
    store, _ = _store()
    with pytest.raises(ValueError):
        store.search(A, "", glob=None, ignore_case=False)
