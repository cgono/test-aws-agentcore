# tests/test_resource_hub_paths.py
from __future__ import annotations

import pytest

from agentcore_platform_poc.resource_hub.paths import (
    MAX_PATH_BYTES,
    PathRejected,
    canonical_path,
    check_glob,
    glob_matches,
    object_key,
    relative,
    user_prefix,
)

A = "00000000-0000-0000-0000-00000000000a"


def test_plain_paths() -> None:
    assert canonical_path("brief.md", decode=True) == "brief.md"
    assert canonical_path("a/b%20c.txt", decode=True) == "a/b c.txt"
    assert canonical_path("a/b%20c.txt", decode=False) == "a/b%20c.txt"
    assert object_key(A, "a/b.txt") == f"users/{A}/a/b.txt"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "/etc/passwd",
        "a//b",
        "./a",
        "a/./b",
        "../x",
        "a/../../x",
        "a/..",
        "%2e%2e/x",
        "%2E%2E%2Fx",
        "a%2Fb",
        "a%5Cb",
        "a\\b",
        "%252e%252e/x",
        "a\x00b",
        "a\nb",
        "a\x7fb",
        "x" * 1025,
        "%ZZ",
        "a/%2e/b",
    ],
)
def test_rejected(raw: str) -> None:
    with pytest.raises(PathRejected):
        canonical_path(raw, decode=True)


def test_double_encoding_is_decoded_once_then_rejected() -> None:
    # %252e -> %2e after one decode; an encoded dot left after decoding is rejected.
    with pytest.raises(PathRejected):
        canonical_path("%252e%252e%252fother", decode=True)


def test_empty_allowed_for_list_root() -> None:
    assert canonical_path("", decode=True, allow_empty=True) == ""


def test_multibyte_length_counts_bytes() -> None:
    with pytest.raises(PathRejected):
        canonical_path("é" * 513, decode=False)


@pytest.mark.parametrize("oid", ["../x", "ABC", "", "00000000-0000-0000-0000-00000000000A"])
def test_bad_oid(oid: str) -> None:
    with pytest.raises(PathRejected):
        user_prefix(oid)


def test_glob_rules() -> None:
    assert check_glob("*.md") == "*.md"
    assert check_glob("docs/**/x?.txt") == "docs/**/x?.txt"
    for bad in ("../*", "/abs/*", "a/../b", "a\\b", "[a-z]*", "a\x00", ""):
        with pytest.raises(PathRejected):
            check_glob(bad)


def test_relative_strips_prefix_and_refuses_outside() -> None:
    assert relative(A, f"users/{A}/a/b") == "a/b"
    with pytest.raises(PathRejected):
        relative(A, "users/00000000-0000-0000-0000-00000000000b/a")


@pytest.mark.parametrize("raw", ["a%2fb", "a%5cb"])
def test_encoded_separator_in_raw_input_is_rejected(raw: str) -> None:
    # One decode would turn these into real separators; the client never encodes "/".
    with pytest.raises(PathRejected):
        canonical_path(raw, decode=True)


def test_invalid_utf8_escape_is_path_rejected() -> None:
    with pytest.raises(PathRejected):
        canonical_path("a%ffb", decode=True)


def test_joined_key_over_the_s3_limit_is_rejected() -> None:
    path = "x" * (MAX_PATH_BYTES - len(user_prefix(A)) + 1)
    assert canonical_path(path, decode=False) == path  # the path alone is short enough
    with pytest.raises(PathRejected):
        object_key(A, path)


@pytest.mark.parametrize("decode", [True, False])
def test_lone_surrogate_is_path_rejected(decode: bool) -> None:
    with pytest.raises(PathRejected):
        canonical_path("a\ud800b", decode=decode)


def test_long_glob_is_rejected() -> None:
    with pytest.raises(PathRejected):
        check_glob("a" * (MAX_PATH_BYTES + 1))


@pytest.mark.parametrize(
    ("glob", "path", "expected"),
    [
        ("*.md", "brief.md", True),
        ("*.md", "docs/brief.md", False),
        ("docs/*", "docs/a.md", True),
        ("docs/*", "docs/private/secret.md", False),
        ("a?b", "a/b", False),
        ("docs/**/x?.txt", "docs/x1.txt", True),
        ("docs/**/x?.txt", "docs/a/b/x1.txt", True),
        ("**", "a/b/c", True),
        ("**/*.md", "a/b.md", True),
        ("**/*.md", "a/b.txt", False),
    ],
)
def test_glob_wildcards_stay_inside_one_segment(glob: str, path: str, expected: bool) -> None:
    assert glob_matches(glob, path) is expected


def test_many_double_stars_match_quickly() -> None:
    glob = "/".join(["**"] * 300 + ["nomatch"])
    assert glob_matches(check_glob(glob), "/".join("d" * 60)) is False
