"""Repository-wide checks that prevent sensitive POC artifacts from being committed."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

_JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\."
    r"[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_-])"
)
_AUTHORIZATION_HEADER_PATTERN = re.compile(
    r"(?i)authorization\s*[:=]\s*(?:f?[\"'`{[]*)?bearer\s+([A-Za-z0-9._~-]{24,})"
)
_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\."
    r"[A-Za-z]{2,}(?![A-Za-z0-9._%+-])"
)
_TENANT_UUID_PATTERN = re.compile(
    r"(?ix)(?:entra_)?tenant(?:_id)?\s*[:=]\s*[\"']?"
    r"([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})"
)
_ENTRA_AUTHORITY_UUID_PATTERN = re.compile(
    r"(?i)login\.microsoftonline\.com/"
    r"([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})(?:/|\b)"
)
_URL_PATTERN = re.compile(r"https?://[^\s\"'`<>]+", re.IGNORECASE)
_AUTHORIZATION_QUERY_KEYS = frozenset(
    {"access_token", "code", "id_token", "refresh_token", "session_id", "state", "token"}
)
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "access_token",
        "authorization",
        "bearer",
        "client_secret",
        "code",
        "cookie",
        "email",
        "email_address",
        "id_token",
        "password",
        "refresh_token",
        "secret",
        "session_id",
        "state",
        "sub",
        "subject",
        "token",
        "upn",
        "user_principal_name",
        "username",
    }
)
_EXAMPLE_EMAIL_DOMAINS = frozenset({"example.com", "example.test", "invalid", "localhost"})
_EXCLUDED_PREFIXES = (".git/", ".venv/", "evidence/raw/")
_DOCUMENTED_EXAMPLE_JWTS = frozenset(
    {"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2lnbmF0dXJl"}
)


def test_all_tracked_text_files_are_free_of_sensitive_values() -> None:
    findings = _scan_repository(Path(__file__).parents[1])

    assert findings == []


@pytest.mark.parametrize(
    ("category", "content"),
    [
        ("jwt", lambda: ".".join(("eyJ" + "a" * 16, "b" * 16, "c" * 16))),
        ("authorization_header", lambda: "Authorization: Bearer " + "a" * 24),
        ("oauth_callback_query", lambda: "https://poc.invalid/callback?code=" + "a" * 24),
        ("private_key", lambda: "-----BEGIN " + "PRIVATE KEY-----"),
        ("email", lambda: "operator" + "@" + "company.invalid"),
        (
            "tenant_uuid",
            lambda: "ENTRA_TENANT_ID=" + "12345678" + "-1234-4abc-8def-123456789abc",
        ),
    ],
)
def test_sensitive_values_are_reported(category: str, content: Callable[[], str]) -> None:
    findings = _scan_text_file(Path("fixture.txt"), content())

    assert findings == [f"fixture.txt: {category}"]


def test_examples_and_callback_placeholders_are_not_reported() -> None:
    content = "\n".join(
        (
            "https://example.test/callback?code=short-example",
            "tenant_id=11111111-1111-1111-1111-111111111111",
            "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0",
            "docs: user@example.test",
            "Authorization: Bearer placeholder",
        )
    )

    assert _scan_text_file(Path("docs/example.md"), content) == []


def test_jsonl_evidence_rejects_forbidden_keys(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.jsonl"
    evidence.write_text(
        json.dumps({"hypothesis": "H1", "details": {"access" + "_token": "value"}}) + "\n",
        encoding="utf-8",
    )

    assert _scan_text_file(evidence, evidence.read_text(encoding="utf-8")) == [
        f"{evidence}: evidence_forbidden_key:access_token"
    ]


def test_raw_evidence_paths_are_excluded() -> None:
    assert _is_excluded(Path("evidence/raw/operator.jsonl"))


def _scan_repository(repository_root: Path) -> list[str]:
    findings: list[str] = []
    for relative_path in _tracked_paths(repository_root):
        if _is_excluded(relative_path):
            continue
        path = repository_root / relative_path
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(_scan_text_file(relative_path, content))
    return findings


def _tracked_paths(repository_root: Path) -> tuple[Path, ...]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for repository safety checks")
    result = subprocess.run(  # noqa: S603 - git is resolved from the local executable path.
        [git, "ls-files", "-z"],
        cwd=repository_root,
        check=True,
        capture_output=True,
    )
    return tuple(Path(path) for path in result.stdout.decode("utf-8").split("\0") if path)


def _is_excluded(path: Path) -> bool:
    return path.as_posix().startswith(_EXCLUDED_PREFIXES)


def _scan_text_file(path: Path, content: str) -> list[str]:
    findings = _scan_string_values(path, content)
    if path.suffix == ".jsonl":
        findings.extend(_scan_jsonl_evidence(path, content))
    return findings


def _scan_string_values(path: Path, content: str) -> list[str]:
    rendered_path = str(path)
    findings: list[str] = []
    if any(
        match.group() not in _DOCUMENTED_EXAMPLE_JWTS for match in _JWT_PATTERN.finditer(content)
    ):
        findings.append(f"{rendered_path}: jwt")
    if _AUTHORIZATION_HEADER_PATTERN.search(content):
        findings.append(f"{rendered_path}: authorization_header")
    if _contains_authorization_query_value(content):
        findings.append(f"{rendered_path}: oauth_callback_query")
    if _PRIVATE_KEY_PATTERN.search(content):
        findings.append(f"{rendered_path}: private_key")
    if any(not _is_example_email(match.group()) for match in _EMAIL_PATTERN.finditer(content)):
        findings.append(f"{rendered_path}: email")
    tenant_matches = (
        *_TENANT_UUID_PATTERN.finditer(content),
        *_ENTRA_AUTHORITY_UUID_PATTERN.finditer(content),
    )
    if any(not _is_example_uuid(match.group(1)) for match in tenant_matches):
        findings.append(f"{rendered_path}: tenant_uuid")
    return findings


def _contains_authorization_query_value(content: str) -> bool:
    for candidate in _URL_PATTERN.findall(content):
        parsed = urlsplit(candidate.rstrip(".,;)"))
        if _is_example_domain(parsed.hostname):
            continue
        if any(
            key.casefold() in _AUTHORIZATION_QUERY_KEYS and value
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ):
            return True
    return False


def _is_example_email(value: str) -> bool:
    domain = value.rsplit("@", maxsplit=1)[1].casefold()
    return _is_example_domain(domain)


def _is_example_domain(domain: str | None) -> bool:
    if domain is None:
        return False
    normalized = domain.casefold()
    return normalized in _EXAMPLE_EMAIL_DOMAINS or normalized.endswith(".example.test")


def _is_example_uuid(value: str) -> bool:
    compact = value.replace("-", "")
    return len(set(compact.casefold())) == 1


def _scan_jsonl_evidence(path: Path, content: str) -> list[str]:
    findings: list[str] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return [f"{path}: invalid_jsonl_line:{line_number}"]
        forbidden_key = _first_forbidden_evidence_key(row)
        if forbidden_key is not None:
            findings.append(f"{path}: evidence_forbidden_key:{forbidden_key}")
    return findings


def _first_forbidden_evidence_key(value: object) -> str | None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_EVIDENCE_KEYS:
                return key.casefold()
            forbidden_key = _first_forbidden_evidence_key(nested_value)
            if forbidden_key is not None:
                return forbidden_key
    if isinstance(value, list):
        for nested_value in value:
            forbidden_key = _first_forbidden_evidence_key(nested_value)
            if forbidden_key is not None:
                return forbidden_key
    return None
