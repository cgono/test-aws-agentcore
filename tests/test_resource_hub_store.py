# tests/test_resource_hub_store.py
from __future__ import annotations

import itertools
import time
from typing import Any

import pytest

from agentcore_platform_poc.resource_hub.store import (
    MAX_CHUNK,
    NotFound,
    SearchLimits,
    TooLarge,
    WorkspaceStore,
)
from tests.fake_s3 import FakeS3, NoSuchKey

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


def _search(store: WorkspaceStore, text: str = "NEEDLE", **kwargs: Any) -> Any:
    kwargs.setdefault("glob", None)
    kwargs.setdefault("ignore_case", False)
    return store.search(A, text, **kwargs)


def test_glob_star_does_not_cross_folders() -> None:
    store, s3 = _store()
    s3.objects[f"users/{A}/docs/c.md"] = b"NEEDLE\n"
    assert [m.path for m in _search(store, glob="*.md").matches] == ["brief.md"]


def test_match_after_many_non_matching_keys_is_found() -> None:
    s3 = FakeS3()
    s3.objects.update({f"users/{A}/{i:02d}.txt": b"NEEDLE\n" for i in range(10)})
    s3.objects[f"users/{A}/zz.md"] = b"NEEDLE\n"
    store = WorkspaceStore(s3, "bucket")
    result = _search(store, glob="*.md", limits=SearchLimits(max_objects=2))
    assert [m.path for m in result.matches] == ["zz.md"] and result.truncated is None


def test_deadline_is_checked_while_listing() -> None:
    s3 = FakeS3()
    s3.objects.update({f"users/{A}/{i:03d}.txt": b"x\n" for i in range(100)})
    ticks = itertools.count()
    store = WorkspaceStore(s3, "bucket", clock=lambda: float(next(ticks)))
    result = _search(store, glob="*.md", limits=SearchLimits(max_seconds=5))
    assert result.truncated == "max_seconds" and s3.pages < 50


class _SlowBody:
    def __init__(self, body: Any) -> None:
        self._body = body

    def read(self, n: int = -1) -> bytes:
        time.sleep(3)
        return bytes(self._body.read(n))

    def close(self) -> None:
        pass


class _StalledS3(FakeS3):
    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        response = super().get_object(**kwargs)
        if kwargs["Key"].endswith("slow.txt"):
            response["Body"] = _SlowBody(response["Body"])
        return response


def test_a_stalled_read_does_not_hold_the_search_past_the_deadline() -> None:
    s3 = _StalledS3()
    s3.objects.update({f"users/{A}/slow.txt": b"NEEDLE\n", f"users/{A}/fast.txt": b"NEEDLE\n"})
    started = time.monotonic()
    result = _search(WorkspaceStore(s3, "bucket"), limits=SearchLimits(max_seconds=0.5))
    assert time.monotonic() - started < 2
    assert result.truncated == "max_seconds"
    assert [m.path for m in result.matches] == ["fast.txt"]


def test_byte_cap_is_never_exceeded() -> None:
    store, _ = _store()
    result = _search(store, limits=SearchLimits(max_bytes=10))
    assert result.truncated == "max_bytes" and result.bytes_scanned <= 10


def test_needle_across_a_cut_keeps_logical_line_numbers() -> None:
    store, s3 = _store()
    long_line = b"x" * 995 + b"NEEDLE" + b"y" * 3000
    s3.objects[f"users/{A}/long.txt"] = b"a\n" + long_line + b"\nNEEDLE\n"
    result = _search(store, glob="long.txt", limits=SearchLimits(max_line_bytes=1000))
    assert [m.line_no for m in result.matches] == [2, 3]


def test_utf8_character_split_by_a_cut_still_matches() -> None:
    store, s3 = _store()
    s3.objects[f"users/{A}/u.txt"] = b"x" * 999 + "é".encode() + b"z" * 1500 + b"\n"
    result = _search(store, "é", glob="u.txt", limits=SearchLimits(max_line_bytes=1000))
    assert [m.line_no for m in result.matches] == [1]


class _VanishingS3(FakeS3):
    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        if kwargs["Key"].endswith("gone.txt"):
            raise NoSuchKey(kwargs["Key"])
        return super().get_object(**kwargs)


def test_key_deleted_during_search_is_skipped() -> None:
    s3 = _VanishingS3()
    s3.objects.update({f"users/{A}/gone.txt": b"NEEDLE\n", f"users/{A}/here.txt": b"NEEDLE\n"})
    assert [m.path for m in _search(WorkspaceStore(s3, "bucket")).matches] == ["here.txt"]


@pytest.mark.parametrize(("start", "end"), [(5, 2), (-1, None)])
def test_bad_ranges_are_rejected(start: int, end: int | None) -> None:
    store, _ = _store()
    with pytest.raises(ValueError):
        store.read_range(f"users/{A}/brief.md", start, end)


def test_range_on_an_empty_object() -> None:
    store, s3 = _store()
    s3.objects["empty"] = b""
    assert store.read_range("empty", 0, None) == (b"", 0)
    with pytest.raises(ValueError):
        store.read_range("empty", 99, None)


def test_object_deleted_between_head_and_get_is_not_found() -> None:
    s3 = _VanishingS3()
    s3.objects["gone.txt"] = b"data"
    with pytest.raises(NotFound):
        WorkspaceStore(s3, "bucket").read_range("gone.txt", 0, 1)
