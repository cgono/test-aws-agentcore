from __future__ import annotations

from typing import Any

import jwt
import pytest

from agentcore_platform_poc.bench_agent import entrypoint

HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"


class Ctx:
    def __init__(self, grant: str) -> None:
        self.request_headers = {HEADER: grant}
        self.session_id = "poc3-" + "0" * 32


def _grant(sub: str) -> str:
    return jwt.encode({"sub": sub}, "k" * 32, algorithm="HS256")


class FakeMethod:
    def __init__(self, owner: str, log: list[str]) -> None:
        self.owner, self.log = owner, log
        self.hub = type("H", (), {"_grant": None})()

    def requests(self) -> int:
        return 0

    def bytes(self) -> int:
        return 0

    async def list(self, folder: str) -> list[str]:
        return [f"{self.owner}-file"]

    async def close(self) -> None:
        self.log.append(f"closed {self.owner}")


@pytest.fixture
def built(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    log: list[str] = []
    for name, value in {
        "IDENTITY_PROVIDER": "p",
        "HUB_SCOPE": "s",
        "POC_REGION": "r",
        "HUB_URL": "https://h",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        entrypoint, "IdentityTokenSource", lambda *a: type("T", (), {"get": None})()
    )
    monkeypatch.setattr(entrypoint, "_methods", {})
    monkeypatch.setattr(entrypoint, "_owner", None, raising=False)

    def build(name: str, hub: Any) -> FakeMethod:
        owner = jwt.decode(hub._grant, options={"verify_signature": False})["sub"]
        log.append(f"built {owner}")
        return FakeMethod(owner, log)

    monkeypatch.setattr(entrypoint, "_build", build)
    return log


async def test_cached_method_is_never_reused_for_another_user(built: list[str]) -> None:
    case = {"case": {"method": "mirror", "op": "list", "target": "bench/small"}}
    first = await entrypoint.invoke(case, Ctx(_grant("user-a")))  # type: ignore[arg-type]
    again = await entrypoint.invoke(case, Ctx(_grant("user-a")))  # type: ignore[arg-type]
    other = await entrypoint.invoke(case, Ctx(_grant("user-b")))  # type: ignore[arg-type]
    assert first["ok"] and again["ok"] and other["ok"]
    assert (first["cold"], again["cold"], other["cold"]) == (True, False, True)
    assert built == ["built user-a", "closed user-a", "built user-b"]


async def test_grant_without_a_subject_is_refused(built: list[str]) -> None:
    case = {"case": {"method": "direct", "op": "list", "target": "bench/small"}}
    result = await entrypoint.invoke(case, Ctx("not-a-jwt"))  # type: ignore[arg-type]
    assert result["error"] == "bad_grant" and not built
