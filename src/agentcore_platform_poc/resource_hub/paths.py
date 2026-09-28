# src/agentcore_platform_poc/resource_hub/paths.py
"""The only code that turns caller-supplied paths into S3 keys. Every operation uses it."""

from __future__ import annotations

import fnmatch
import functools
import re
from urllib.parse import unquote

MAX_PATH_BYTES = 1024
_OID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ENCODED_LEFT = re.compile(r"%(?:2f|5c|2e)", re.IGNORECASE)
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_GLOB_CHARS = re.compile(r"[A-Za-z0-9._\-*?/ ]+")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


class PathRejected(Exception):
    """The path is not allowed. The Hub answers 400."""


def user_prefix(oid: str) -> str:
    if not _OID.fullmatch(oid):
        raise PathRejected("bad user id")
    return f"users/{oid}/"


def _utf8_length(text: str) -> int:
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:  # a lone surrogate, e.g. from a JSON "\ud800" escape
        raise PathRejected("not valid Unicode") from None


def _check_segments(path: str) -> None:
    if path.startswith("/") or "\\" in path:
        raise PathRejected("absolute path or backslash")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise PathRejected("control character")
    if any(segment in ("", ".", "..") for segment in path.split("/")):
        raise PathRejected("empty, '.', or '..' segment")


def canonical_path(raw: str, *, decode: bool, allow_empty: bool = False) -> str:
    if decode:
        if _BAD_ESCAPE.search(raw):
            raise PathRejected("malformed escape")
        if _ENCODED_SEPARATOR.search(raw):
            raise PathRejected("encoded separator")
        try:
            path = unquote(raw, errors="strict")
        except UnicodeDecodeError:
            raise PathRejected("escape is not UTF-8") from None
    else:
        path = raw
    if path == "" and allow_empty:
        return ""
    if path == "" or _utf8_length(path) > MAX_PATH_BYTES:
        raise PathRejected("empty or too long")
    if _ENCODED_LEFT.search(path):
        raise PathRejected("encoded separator or dot after decoding")
    _check_segments(path)
    return path


def object_key(oid: str, path: str) -> str:
    prefix = user_prefix(oid)
    key = prefix + path
    if not key.startswith(prefix):
        raise PathRejected("outside prefix")
    if _utf8_length(key) > MAX_PATH_BYTES:  # the S3 key limit includes the user prefix
        raise PathRejected("key too long")
    return key


def check_glob(glob: str) -> str:
    if not glob or len(glob) > MAX_PATH_BYTES or not _GLOB_CHARS.fullmatch(glob):
        raise PathRejected("glob may use letters, digits, . _ - * ? / and spaces only")
    _check_segments(glob)
    return glob


def glob_matches(glob: str, path: str) -> bool:
    """Match segment by segment: `*` and `?` never cross `/`; a `**` segment spans 0+ segments."""
    pattern, parts = glob.split("/"), path.split("/")

    @functools.cache
    def match(g: int, p: int) -> bool:
        if g == len(pattern):
            return p == len(parts)
        if pattern[g] == "**":
            return match(g + 1, p) or (p < len(parts) and match(g, p + 1))
        return p < len(parts) and fnmatch.fnmatchcase(parts[p], pattern[g]) and match(g + 1, p + 1)

    return match(0, 0)


def relative(oid: str, key: str) -> str:
    prefix = user_prefix(oid)
    if not key.startswith(prefix):
        raise PathRejected("outside prefix")
    return key[len(prefix) :]
