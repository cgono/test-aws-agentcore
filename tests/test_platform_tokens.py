from __future__ import annotations

import asyncio
import stat
import time
from pathlib import Path
from typing import Any

import jwt
import pytest

from agentcore_platform_poc.agent_platform.tokens import (
    IdentityTokenSource,
    TokenUnavailable,
    refresh_token_file,
    write_token_file,
)
from agentcore_platform_poc.research_agent import api_key_helper


def _token(exp: int) -> str:
    return jwt.encode({"exp": exp, "aud": "x"}, "k" * 32, algorithm="HS256")


class FakeIdentity:
    def __init__(self, exps: list[int]) -> None:
        self.exps = exps
        self.calls: list[dict[str, Any]] = []

    async def get_token(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return _token(self.exps.pop(0))


async def test_fetches_with_m2m_and_caches_until_margin() -> None:
    now = [1000.0]
    client = FakeIdentity([5000, 9000])
    source = IdentityTokenSource(
        "prov",
        "api://hub/.default",
        "ap-southeast-1",
        client=client,
        workload_token=lambda: "wat",
        clock=lambda: now[0],
    )
    first = await source.get()
    assert await source.get() == first and len(client.calls) == 1
    assert client.calls[0] == {
        "provider_name": "prov",
        "scopes": ["api://hub/.default"],
        "agent_identity_token": "wat",
        "auth_flow": "M2M",
    }
    now[0] = 4701.0  # inside the 300 s margin
    assert await source.get() != first and len(client.calls) == 2


async def test_no_workload_token() -> None:
    source = IdentityTokenSource(
        "p", "s", "r", client=FakeIdentity([1]), workload_token=lambda: None
    )
    with pytest.raises(TokenUnavailable, match="no_workload_token"):
        await source.get()


def test_token_file_is_private_and_atomic(tmp_path: Path) -> None:
    path = write_token_file("abc", tmp_path / "t")
    assert path.read_text() == "abc"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    write_token_file("def", path)
    assert path.read_text() == "def"


def test_helper_prints_valid_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = _token(int(time.time()) + 600)
    monkeypatch.setattr(
        api_key_helper, "GATEWAY_TOKEN_FILE", write_token_file(token, tmp_path / "t")
    )
    assert api_key_helper.main() == 0
    assert capsys.readouterr().out.strip() == token


def test_helper_refuses_expired_or_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        api_key_helper,
        "GATEWAY_TOKEN_FILE",
        write_token_file(_token(int(time.time()) - 1), tmp_path / "t"),
    )
    assert api_key_helper.main() == 1
    monkeypatch.setattr(api_key_helper, "GATEWAY_TOKEN_FILE", tmp_path / "missing")
    assert api_key_helper.main() == 1
    assert capsys.readouterr().out == ""


def test_token_file_ignores_planted_tmp_file(tmp_path: Path) -> None:
    planted = tmp_path / "t.tmp"
    planted.write_text("planted")
    planted.chmod(0o644)
    path = write_token_file("abc", tmp_path / "t")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert planted.read_text() == "planted"


async def test_identity_error_text_is_not_chained() -> None:
    class Failing:
        async def get_token(self, **kwargs: Any) -> str:
            raise RuntimeError("secret-bearing SDK text")

    source = IdentityTokenSource("p", "s", "r", client=Failing(), workload_token=lambda: "wat")
    with pytest.raises(TokenUnavailable) as caught:
        await source.get()
    assert str(caught.value) == "RuntimeError"
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


async def test_refresher_survives_a_failed_refresh(tmp_path: Path) -> None:
    class Flaky:
        def __init__(self) -> None:
            self.calls = 0

        async def get(self) -> str:
            self.calls += 1
            if self.calls == 1:
                raise TokenUnavailable("ClientError")
            if self.calls == 3:
                raise asyncio.CancelledError
            return "fresh"

    flaky = Flaky()
    with pytest.raises(asyncio.CancelledError):
        await refresh_token_file(flaky, tmp_path / "t", interval_s=0)  # type: ignore[arg-type]
    assert (tmp_path / "t").read_text() == "fresh"
