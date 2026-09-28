from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agentcore_platform_poc.research_agent import entrypoint
from agentcore_platform_poc.research_agent.claude_adapter import AgentRun


class Ctx:
    def __init__(self, headers: dict[str, str]) -> None:
        self.request_headers = headers
        self.session_id = "poc3-s1"


ENV = {
    "POC_REGION": "ap-southeast-1",
    "HUB_URL": "https://hub.example.test",
    "HUB_SCOPE": "api://hub/.default",
    "GATEWAY_URL": "https://gw.example.test/anthropic",
    "GATEWAY_SCOPE": "api://gw/.default",
    "IDENTITY_PROVIDER": "prov",
    "CODE_INTERPRETER_ID": "ci-1",
    "AGENT_MODEL": "model-a",
}


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)

    class FakeSource:
        def __init__(self, provider: str, scope: str, region: str) -> None:
            self.scope = scope

        async def get(self) -> str:
            return "tok-" + self.scope

    async def fake_run(prompt: str, options: Any) -> AgentRun:
        seen["prompt"] = prompt
        return AgentRun("done", 3, 10, 20, ["mcp__platform__ws_read"], None)

    monkeypatch.setattr(entrypoint, "IdentityTokenSource", FakeSource)
    monkeypatch.setattr(
        entrypoint, "write_token_file", lambda token: seen.setdefault("token_file", token)
    )
    monkeypatch.setattr(entrypoint, "refresh_token_file", lambda source: asyncio.sleep(3600))
    monkeypatch.setattr(entrypoint, "run_agent", fake_run)
    monkeypatch.setattr(
        entrypoint,
        "Sandbox",
        lambda region, identifier: type(
            "S", (), {"stop": lambda self: seen.setdefault("stopped", True)}
        )(),
    )
    return seen


async def test_missing_grant_is_error_without_model_call(patched: dict[str, Any]) -> None:
    result = await entrypoint.invoke({"prompt": "x"}, Ctx({}))  # type: ignore[arg-type]
    assert result["error"] == "missing_grant" and "prompt" not in patched


async def test_grant_run_returns_result_and_stops_sandbox(patched: dict[str, Any]) -> None:
    headers = {"x-amzn-bedrock-agentcore-runtime-custom-grant": "G"}
    result = await entrypoint.invoke({"prompt": "Follow brief.md"}, Ctx(headers))  # type: ignore[arg-type]
    assert (
        result["summary"] == "done"
        and result["session_id"] == "poc3-s1"
        and result["error"] is None
    )
    assert patched["stopped"] and patched["token_file"] == "tok-api://gw/.default"


async def test_sdk_failure_returns_error_json_and_stops_sandbox(
    patched: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(prompt: str, options: Any) -> AgentRun:
        raise RuntimeError("secret text must not leak")

    monkeypatch.setattr(entrypoint, "run_agent", boom)
    result = await entrypoint.invoke(
        {"prompt": "x"}, Ctx({"X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant": "G"})
    )  # type: ignore[arg-type]
    assert result["error"] == "internal:RuntimeError" and "secret" not in str(result)
    assert patched["stopped"]


async def test_prompt_validation(patched: dict[str, Any]) -> None:
    headers = {"X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant": "G"}
    for payload in ({}, {"prompt": ""}, {"prompt": "x" * 4001}, {"prompt": 5}):
        assert (await entrypoint.invoke(payload, Ctx(headers)))["error"] == "bad_prompt"  # type: ignore[arg-type]
