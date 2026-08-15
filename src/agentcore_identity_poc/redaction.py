import math
import re
from collections.abc import Mapping, Sequence
from typing import Never
from urllib.parse import parse_qsl, urlsplit


class UnsafeEvidenceError(ValueError):
    """Raised when a proposed evidence record could disclose sensitive data."""


_JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"
)
_BEARER_PATTERN = re.compile(r"\bbearer\s+[^\s]+", re.IGNORECASE)
_COOKIE_PATTERN = re.compile(r"\b(?:set-cookie|cookie)\s*[:=]", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9._%+-])"
)
_URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_CAMEL_CASE_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_SECRET_FIELD_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "bearer",
        "client_secret",
        "code",
        "cookie",
        "id_token",
        "password",
        "refresh_token",
        "secret",
        "session_id",
        "set_cookie",
        "state",
        "token",
    }
)
_DRIVE_FILENAME_FIELD_NAMES = frozenset(
    {
        "drive_file_name",
        "drive_filename",
        "file_name",
        "filename",
    }
)
_AUTHORIZATION_QUERY_KEYS = frozenset({"code", "session_id", "state"})


def assert_safe_evidence(value: object) -> None:
    """Raise without exposing input when a value is unsuitable for sanitized evidence."""

    _validate_value(value)


def _validate_value(value: object, *, inside_drive_mapping: bool = False) -> None:
    if value is None or isinstance(value, bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _reject()
        return
    if isinstance(value, str):
        _validate_string(value)
        return
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if not isinstance(key, str):
                _reject()
            _validate_key(key, inside_drive_mapping=inside_drive_mapping)
            _validate_value(
                nested_value,
                inside_drive_mapping=inside_drive_mapping or _is_drive_related_key(key),
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        for nested_value in value:
            _validate_value(nested_value, inside_drive_mapping=inside_drive_mapping)
        return
    _reject()


def _validate_key(key: str, *, inside_drive_mapping: bool) -> None:
    normalized = _normalize_field_name(key)
    if (
        normalized in _SECRET_FIELD_NAMES
        or normalized in _DRIVE_FILENAME_FIELD_NAMES
        or normalized.startswith(("authorization_", "cookie_", "set_cookie_"))
        or (inside_drive_mapping and normalized == "name")
    ):
        _reject()


def _normalize_field_name(key: str) -> str:
    snake_case = _ACRONYM_BOUNDARY.sub(r"\1_\2", key)
    snake_case = _CAMEL_CASE_BOUNDARY.sub(r"\1_\2", snake_case)
    return snake_case.casefold().replace("-", "_")


def _is_drive_related_key(key: str) -> bool:
    normalized = _normalize_field_name(key)
    return normalized == "drive" or normalized.startswith("drive_")


def _validate_string(value: str) -> None:
    if (
        _JWT_PATTERN.search(value)
        or _BEARER_PATTERN.search(value)
        or _COOKIE_PATTERN.search(value)
        or _EMAIL_PATTERN.search(value)
        or _contains_authorization_url(value)
    ):
        _reject()


def _contains_authorization_url(value: str) -> bool:
    for candidate in _URL_PATTERN.findall(value):
        query = urlsplit(candidate.rstrip(".,;)")).query
        if any(key.casefold() in _AUTHORIZATION_QUERY_KEYS for key, _ in parse_qsl(query)):
            return True
    return False


def _reject() -> Never:
    raise UnsafeEvidenceError("evidence contains a prohibited value")
