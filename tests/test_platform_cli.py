from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from agentcore_platform_poc.caller import TokenStore
from scripts import platform_cli


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TokenStore:
    store = TokenStore(tmp_path / "t.json")
    store.save("a", "api", "tok")
    monkeypatch.setattr(platform_cli, "STORE", store)
    return store


def _post(response: httpx.Response) -> Any:
    def post(*args: Any, **kwargs: Any) -> httpx.Response:
        return response

    return post


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(403, json={"error": "test_mode_off"}),
        httpx.Response(502, text="<html>bad gateway</html>"),
        httpx.Response(200, json={"status": 500, "session_id": "s", "result": {}}),
        httpx.Response(200, json={"status": 200, "session_id": "s", "result": {"error": "x"}}),
    ],
)
def test_research_failure_exits_non_zero(
    store: TokenStore, monkeypatch: pytest.MonkeyPatch, response: httpx.Response
) -> None:
    monkeypatch.setattr(platform_cli.httpx, "post", _post(response))
    assert platform_cli.main(["research", "--user", "a"]) == 1


def test_research_success_exits_zero(store: TokenStore, monkeypatch: pytest.MonkeyPatch) -> None:
    ok = httpx.Response(200, json={"status": 200, "session_id": "s", "result": {"error": None}})
    monkeypatch.setattr(platform_cli.httpx, "post", _post(ok))
    assert platform_cli.main(["research", "--user", "a"]) == 0


def test_grant_failure_writes_nothing(
    store: TokenStore, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(platform_cli.httpx, "post", _post(httpx.Response(403, json={"error": "x"})))
    out = tmp_path / "g"
    assert platform_cli.main(["grant", "--user", "a", "--ttl", "60", "--out", str(out)]) == 1
    assert not out.exists()
