# tests/test_resource_hub_handler.py
from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from agentcore_platform_poc.entra import AuthError
from agentcore_platform_poc.resource_hub import handler as hub
from agentcore_platform_poc.resource_hub.auth import Caller
from agentcore_platform_poc.resource_hub.store import WorkspaceStore
from tests.fake_s3 import FakeS3

A = "00000000-0000-0000-0000-00000000000a"
B = "00000000-0000-0000-0000-00000000000b"


@pytest.fixture
def s3(monkeypatch: pytest.MonkeyPatch) -> FakeS3:
    fake = FakeS3()
    fake.objects[f"users/{A}/brief.md"] = b"hello NEEDLE\n"
    fake.objects[f"users/{A}/big.bin"] = b"z" * (4 * 1024 * 1024 + 1)
    fake.objects[f"users/{B}/brief.md"] = b"B secret\n"

    def auth(headers: dict[str, str], **_: Any) -> Caller:
        if headers.get("authorization") != "Bearer ok":
            raise AuthError(401, "token_invalid")
        return Caller("agent_grant", A, "research", "s1")

    monkeypatch.setattr(hub, "_components", lambda: (WorkspaceStore(fake, "bucket"), auth))
    return fake


def _event(
    method: str, path: str, *, headers: dict[str, str] | None = None, body: bytes | None = None
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": {"authorization": "Bearer ok", **(headers or {})},
    }
    if body is not None:
        event["body"] = base64.b64encode(body).decode()
        event["isBase64Encoded"] = True
    return event


def _json(response: dict[str, Any]) -> Any:
    return json.loads(response["body"])


def test_list(s3: FakeS3) -> None:
    response = hub.handler(_event("GET", "/v1/list/"), None)
    assert response["statusCode"] == 200
    assert [e["path"] for e in _json(response)["entries"]] == ["big.bin", "brief.md"]


def test_read_whole_small_file(s3: FakeS3) -> None:
    response = hub.handler(_event("GET", "/v1/files/brief.md"), None)
    assert response["isBase64Encoded"] and base64.b64decode(response["body"]) == b"hello NEEDLE\n"


def test_read_range(s3: FakeS3) -> None:
    response = hub.handler(
        _event("GET", "/v1/files/brief.md", headers={"range": "bytes=6-11"}), None
    )
    assert response["statusCode"] == 206
    assert base64.b64decode(response["body"]) == b"NEEDLE"
    assert response["headers"]["content-range"] == "bytes 6-11/13"


def test_big_file_without_range_is_413(s3: FakeS3) -> None:
    response = hub.handler(_event("GET", "/v1/files/big.bin"), None)
    assert response["statusCode"] == 413 and _json(response) == {
        "error": "too_large",
        "size": 4 * 1024 * 1024 + 1,
    }


@pytest.mark.parametrize(
    "path",
    [
        "/v1/files/..%2Fx",
        "/v1/files/%2e%2e/" + B + "/brief.md",
        "/v1/files/a%5Cb",
        "/v1/list/..",
        "/v1/files/",
    ],
)
def test_path_escapes_are_400(s3: FakeS3, path: str) -> None:
    assert hub.handler(_event("GET", path), None)["statusCode"] == 400


def test_other_users_file_is_404_not_readable(s3: FakeS3) -> None:
    # The caller is A; "users/B/brief.md" as a relative path lands inside A's prefix and
    # does not exist.
    response = hub.handler(_event("GET", f"/v1/files/users/{B}/brief.md"), None)
    assert response["statusCode"] == 404


def test_write_then_read(s3: FakeS3) -> None:
    put = hub.handler(_event("PUT", "/v1/files/out/report.md", body=b"# hi"), None)
    assert put["statusCode"] == 200 and s3.objects[f"users/{A}/out/report.md"] == b"# hi"


def test_write_too_large(s3: FakeS3) -> None:
    response = hub.handler(
        _event("PUT", "/v1/files/x.bin", body=b"x" * (4 * 1024 * 1024 + 1)), None
    )
    assert response["statusCode"] == 413


def test_search(s3: FakeS3) -> None:
    event = _event(
        "POST", "/v1/search", body=json.dumps({"text": "NEEDLE", "glob": "*.md"}).encode()
    )
    body = _json(hub.handler(event, None))
    assert body["matches"] == [{"path": "brief.md", "line_no": 1, "line": "hello NEEDLE"}]
    assert body["truncated"] is None


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"[1]",
        b'{"text": ""}',
        b'{"text": "x", "glob": "../*"}',
        b'{"text": 5}',
        b'{"text": "x", "glob": ""}',
        b'{"text": "\\ud800"}',
    ],
)
def test_bad_search_body(s3: FakeS3, payload: bytes) -> None:
    assert hub.handler(_event("POST", "/v1/search", body=payload), None)["statusCode"] == 400


def test_auth_failure(s3: FakeS3) -> None:
    response = hub.handler(
        _event("GET", "/v1/list/", headers={"authorization": "Bearer bad"}), None
    )
    assert response["statusCode"] == 401 and _json(response) == {"error": "token_invalid"}


def test_unknown_route(s3: FakeS3) -> None:
    assert hub.handler(_event("DELETE", "/v1/files/brief.md"), None)["statusCode"] == 404


def test_log_line_has_no_token(s3: FakeS3, capsys: pytest.CaptureFixture[str]) -> None:
    hub.handler(_event("GET", "/v1/list/"), None)
    out = capsys.readouterr().out
    assert "Bearer" not in out and '"oid": "' + A + '"' in out


def test_range_on_an_empty_file_is_416(s3: FakeS3) -> None:
    s3.objects[f"users/{A}/empty.txt"] = b""
    event = _event("GET", "/v1/files/empty.txt", headers={"range": "bytes=0-"})
    assert hub.handler(event, None)["statusCode"] == 416


def test_whole_read_of_an_empty_file_is_200(s3: FakeS3) -> None:
    s3.objects[f"users/{A}/empty.txt"] = b""
    response = hub.handler(_event("GET", "/v1/files/empty.txt"), None)
    assert response["statusCode"] == 200 and base64.b64decode(response["body"]) == b""


def test_unexpected_error_is_a_plain_500(s3: FakeS3, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise ValueError("internal detail")

    monkeypatch.setattr(WorkspaceStore, "list", boom)
    response = hub.handler(_event("GET", "/v1/list/"), None)
    assert response["statusCode"] == 500 and _json(response) == {"error": "internal"}
